import asyncio
import logging
import os
import sqlite3
import ssl
import threading
from pathlib import Path
from typing import Callable
import time

import flask
import flask_login
import openplc
from credentials import CertGen
from restapi import (
    app_restapi,
    db,
    register_callback_get,
    register_callback_post,
    restapi_bp,
)
from unixclient import AsyncUnixClient, queue

app = flask.Flask(__name__)
app.secret_key = str(os.urandom(16))
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

logger = logging.getLogger(__name__)
command_queue: queue.Queue = queue.Queue()

openplc_runtime = openplc.runtime()


BASE_DIR = Path(__file__).parent
CERT_FILE = (BASE_DIR / "certOPENPLC.pem").resolve()
KEY_FILE = (BASE_DIR / "keyOPENPLC.pem").resolve()
HOSTNAME = "localhost"

def create_connection(db_file):
    """ Create a connection to the database file """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        logger.error("Error creating database connection: %s", e)

    return None


def handle_start_plc(data: dict) -> dict:
    command_queue.put({"action": "start-plc", "data": data})
    return {"status": "runtime started"}


def handle_stop_plc(data: dict) -> dict:
    command_queue.put({"action": "stop-plc", "data": data})
    return {"status": "runtime stopped"}


def handle_runtime_logs(data: dict) -> dict:
    logs = openplc_runtime.logs()
    return {"runtime-logs": logs}


def handle_compilation_status(data: dict) -> dict:
    try:
        logs = openplc_runtime.compilation_status()
        _logs = logs
    except Exception as e:
        logger.error("Error retrieving compilation logs: %s", e)
        _logs = str(e)

    status = _logs
    if not isinstance(status, str):
        _status = "No compilation in progress"
        _error = ""
    elif "Compilation finished successfully!" in status:
        _status = "Success"
        _error = "No error"
    elif "Compilation finished with errors!" in status:
        _status = "Error"
        _error = openplc_runtime.get_compilation_error()
    else:
        _status = "Compiling"
        _error = openplc_runtime.get_compilation_error()
    
    logger.debug(
        "Compilation status: %s, logs: %s", _status, _logs, extra={"error": _error}
    )

    return {"status": _status, "logs": _logs, "error": _error}


def handle_status(data: dict) -> dict:
    return {"current_status": "operational", "details": data}


def handle_ping(data: dict) -> dict:
    command_queue.put({"action": "ping", "data": data})
    return {"status": "pong"}


GET_HANDLERS: dict[str, Callable[[dict], dict]] = {
    "start-plc": handle_start_plc,
    "stop-plc": handle_stop_plc,
    "runtime-logs": handle_runtime_logs,
    "compilation-status": handle_compilation_status,
    "status": handle_status,
    "ping": handle_ping,
}


def restapi_callback_get(argument: str, data: dict) -> dict:
    """
    Dispatch GET callbacks by argument.
    """
    logger.debug("GET | Received argument: %s, data: %s", argument, data)
    handler = GET_HANDLERS.get(argument)
    if handler:
        return handler(data)
    return {"error": "Unknown argument"}


def handle_upload_file(data: dict) -> dict:
    filename = None

    # Validate file presence
    if "file" not in flask.request.files:
        return {"UploadFileFail": "No file part in the request"}
    
    st_file = flask.request.files["file"]
    
    if st_file.content_length > 32 * 1024 * 1024:  # 32 MB limit
        return {"UploadFileFail": "File is too large"}

    # Database operations
    database = "openplc.db"
    conn = create_connection(database)
    if conn is None:
        return {"UploadFileFail": "Error connecting to the database"}
    
    logger.info("%s connected", database)
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM Programs WHERE Name = 'webserver_program'")
        row = cur.fetchone()
        
        if not row or len(row) < 4:
            return {"UploadFileFail": "Program record not found or invalid"}
        
        filename = str(row[3])
        st_file.save(f"st_files/{filename}")
        cur.close()
        
    except Exception as e:
        return {"UploadFileFail": f"Database operation failed: {e}"}
    finally:
        if conn:
            conn.close()

    if openplc_runtime.status() == "Compiling":
        return {"RuntimeStatus": "Compiling"}

    try:
        openplc_runtime.compile_program(filename)
        return {"CompilationStatus": "Starting program compilation"}
    except Exception as e:
        return {"CompilationStatusFail": f"Compilation failed: {e}"}


POST_HANDLERS: dict[str, Callable[[dict], dict]] = {
    "upload-file": handle_upload_file,
}


def restapi_callback_post(argument: str, data: dict) -> dict:
    """
    Dispatch POST callbacks by argument.
    """
    logger.debug("POST | Received argument: %s, data: %s", argument, data)
    handler = POST_HANDLERS.get(argument)
    
    if not handler:
        return {"PostRequestError": "Unknown argument"}
    
    return handler(data)

def run_https():
    # rest api register
    app_restapi.register_blueprint(restapi_bp, url_prefix="/api")
    register_callback_get(restapi_callback_get)
    register_callback_post(restapi_callback_post)

    with app_restapi.app_context():
        try:
            db.create_all()
            db.session.commit()
            logger.info("Database tables created successfully.")
        except Exception as e:
            logger.error("Error creating database tables: %s", e)

    try:
        cert_gen = CertGen(hostname=HOSTNAME, ip_addresses=["127.0.0.1"])
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            cert_gen.generate_self_signed_cert(cert_file=CERT_FILE, 
                                               key_file=KEY_FILE)
        elif cert_gen.is_certificate_valid(CERT_FILE):
            cert_gen.generate_self_signed_cert(cert_file=CERT_FILE, key_file=KEY_FILE)
        else:
            print("Credentials already generated!")

        context = (CERT_FILE, KEY_FILE)
        app_restapi.run(
            debug=False,
            host="0.0.0.0",
            threaded=True,
            port=8443,
            ssl_context=context,
        )

    except FileNotFoundError as e:
        logger.error("Could not find SSL credentials! %s", e)
    except ssl.SSLError as e:
        logger.error("SSL credentials FAIL! %s", e)
    except KeyboardInterrupt:
        logger.info("HTTP server stopped by KeyboardInterrupt")
    finally:
        openplc_runtime.stop_runtime()


async def async_unix_socket(command_queue: queue.Queue):
    """Main Unix client loop that runs in the background."""
    client = AsyncUnixClient(command_queue, "/run/runtime/plc_runtime.socket")

    # Wait for server socket
    for _ in range(50):
        if os.path.exists(client.socket_path):
            break
        logger.info("Waiting for server socket %s...", client.socket_path)
        await asyncio.sleep(0.1)
    else:
        logger.error("Server socket was never created!")
        return

    try:
        await client.connect()
        logger.info("Unix client connected successfully")
        await client.process_command_queue()
            
    except (FileNotFoundError, ConnectionRefusedError) as e:
        logger.error("Failed to connect to Unix socket: %s", e)
    except asyncio.CancelledError:
        logger.info("Unix client stopped by cancellation")
    finally:
        if hasattr(client, 'close'):
            await client.close()


def start_unix_socket_client(command_queue):
    """Start the Unix socket client in its own event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(async_unix_socket(command_queue))
    except KeyboardInterrupt:
        logger.info("Unix client stopped by KeyboardInterrupt")
    finally:
        # Cancel all tasks and close the loop
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        loop.close()


if __name__ == "__main__":
    # Create and start threads
    https_thread = threading.Thread(target=run_https, daemon=True)
    unix_thread = threading.Thread(target=start_unix_socket_client, args=(command_queue,), daemon=True)
    
    https_thread.start()
    unix_thread.start()
    
    logger.info("Main thread is running (REST API + Unix client). Press Ctrl+C to exit.")
    
    try:
        # Keep main thread alive, waiting for KeyboardInterrupt
        while https_thread.is_alive() or unix_thread.is_alive():
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        
    finally:
        # Stop the runtime
        openplc_runtime.stop_runtime()
        logger.info("Shutdown complete")
