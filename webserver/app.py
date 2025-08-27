import os
import ssl
import threading
import logging

import flask
import flask_login

import openplc
from credentials import CertGen
from restapi import app_restapi, restapi_bp, db, register_callback_get, register_callback_post

app = flask.Flask(__name__)
app.secret_key = str(os.urandom(16))
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.DEBUG,  # Minimum level to capture
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)

openplc_runtime = openplc.runtime()

from pathlib import Path
BASE_DIR   = Path(__file__).parent
CERT_FILE  = (BASE_DIR / "certOPENPLC.pem").resolve()
KEY_FILE   = (BASE_DIR / "keyOPENPLC.pem").resolve()
HOSTNAME = "localhost"


def restapi_callback_get(argument: str, data: dict) -> dict:
    """
    This is the central callback function that handles the logic
    based on the 'argument' from the URL and 'data' from the request.
    """
    logger.debug(f"GET | Received argument: {argument}, data: {data}")

    if argument == "start-plc":
        openplc_runtime.start_runtime()
        configure_runtime()
        return {"status": "runtime started"}

    elif argument == "stop-plc":
        openplc_runtime.stop_runtime()
        return {"status": "runtime stop"}

    elif argument == "runtime-logs":
        logs = openplc_runtime.logs()
        return {"runtime-logs": logs}

    elif argument == "compilation-status":
        try:
            logs = openplc_runtime.compilation_status()
            _logs = logs
        except Exception as e:
            logger.error(f"Error retrieving compilation logs: {e}")
            _logs = str(e)

        status = _logs
        if status is not str:
            _status = "No compilation in progress"
        if "Compilation finished successfully!" in status:
            _status = "Success"
            _error = "No error"
        elif "Compilation finished with errors!" in status:
            _status = "Error"
            _error = openplc_runtime.get_compilation_error()
        else:
            _status = "Compiling"
            _error = openplc_runtime.get_compilation_error()
        logger.debug(f"Compilation status: {_status}, logs: {_logs}", extra={"error": _error})

        return {"status": _status, "logs": _logs, "error": _error}

    elif argument == "status":
        return {"current_status": "operational", "details": data}

    elif argument == "ping":
        return {"status": "pong"}
    else:
        return {"error": "Unknown argument"}

# file upload POST handler 
def restapi_callback_post(argument: str, data: dict) -> dict:
    logger.debug(f"POST | Received argument: {argument}, data: {data}")

    if argument == "upload-file":
        try:
            # validate filename
            if 'file' not in flask.request.files:
                return {"UploadFileFail": "No file part in the request"}
            st_file = flask.request.files['file']
            # validate file size
            if st_file.content_length > 32 * 1024 * 1024:  # 32 MB limit
                return {"UploadFileFail": "File is too large"}

            # replace program file on database
            try:
                database = "openplc.db"
                conn = create_connection(database)
                logger.info(f"{database} connected")
                if (conn != None):
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT * FROM Programs WHERE Name = 'webserver_program'")
                        row = cur.fetchone()
                        cur.close()
                    except Exception as e:
                        return {"UploadFileFail": e}
            except Exception as e:
                return {"UploadFileFail": f"Error connecting to the database: {e}"}

            filename = str(row[3])
            st_file.save(f"st_files/{filename}")

        except Exception as e:
            return {"UploadFileFail": e}

        if (openplc_runtime.status() == "Compiling"): 
            return {"RuntimeStatus": "Compiling"}
        
        try:
            openplc_runtime.compile_program(f"{filename}")
            return {"CompilationStatus": "Starting program compilation"}
        except Exception as e:
            return {"CompilationStatusFail": e}

    else:
        return {"PostRequestError": "Unknown argument"}

def run_https():
    # rest api register
    app_restapi.register_blueprint(restapi_bp, url_prefix='/api')
    register_callback_get(restapi_callback_get)
    register_callback_post(restapi_callback_post)

    with app_restapi.app_context():
        try:
            db.create_all()
            db.session.commit()
            print("Database tables created successfully.")
        except Exception as e:
            print(f"Error creating database tables: {e}")

    try:
        # CertGen class is used to generate SSL certificates and verify their validity
        cert_gen = CertGen(hostname=HOSTNAME, ip_addresses=["127.0.0.1"])
        # Generate certificate if it doesn't exist
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            cert_gen.generate_self_signed_cert(cert_file=CERT_FILE, key_file=KEY_FILE)
        # Verify expiration date
        elif cert_gen.is_certificate_valid(CERT_FILE):
            print(cert_gen.generate_self_signed_cert(cert_file=CERT_FILE, key_file=KEY_FILE))
        # Credentials already created
        else:
            print("Credentials already generated!")
        
        try:
            context = (CERT_FILE, KEY_FILE)
            app_restapi.run(debug=False, host='0.0.0.0', threaded=True, port=8443, ssl_context=context)
        except KeyboardInterrupt as e:
            print(f"Exiting OpenPLC Webserver...{e}")
            openplc_runtime.stop_runtime()
        except Exception as e:
            print(f"An error occurred: {e}")
            openplc_runtime.stop_runtime()
        except:
            print("An unexpected error occurred.")
            
    # TODO handle file error
    except FileNotFoundError as e:
        print(f"Could not find SSL credentials! {e}")
    except ssl.SSLError as e:
        print(f"SSL credentials FAIL! {e}")

if __name__ == '__main__':
    # Running RestAPI in thread
    threading.Thread(target=run_https).start()