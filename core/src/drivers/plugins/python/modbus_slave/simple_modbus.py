# pylint: disable=C0103,C0301,C0413,W0107,W0602,W0621,C0415
# C0103: Method/variable naming (getValues/setValues required by pymodbus API)
# C0301: Line too long (some lines exceed 100 chars)
# C0413: Import position (shared module import must be after sys.path modification)
# W0107: Unnecessary pass (used for read-only setValues methods)
# W0602: Global variable not assigned (threading.Event uses methods, not reassignment)
# W0621: Redefining name from outer scope (runtime_args parameter shadows global)
# C0415: Import outside toplevel (traceback imported in exception handlers)

import asyncio
import os
import sys
import threading

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusServerContext,
    ModbusSparseDataBlock,
)
from pymodbus.server import ServerStop
from pymodbus.server.server import ModbusTcpServer

MAX_BITS = 8

# Add the parent directory to Python path to find shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import the correct type definitions (must be after sys.path modification)
from shared import (  # noqa: E402
    SafeBufferAccess,
    safe_extract_runtime_args_from_capsule,
)


class OpenPLCCoilsDataBlock(ModbusSparseDataBlock):
    """Custom Modbus coils data block that mirrors OpenPLC bool_output using SafeBufferAccess"""

    def __init__(self, runtime_args, num_coils=64):
        self.runtime_args = runtime_args
        self.num_coils = num_coils

        # Create safe buffer access wrapper
        self.safe_buffer_access = SafeBufferAccess(runtime_args)
        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Warning: Failed to create safe buffer access for coils: {self.safe_buffer_access.error_msg}"
            )

        # Initialize with zeros
        super().__init__([0] * num_coils)

    def getValues(self, address, count=1):
        """Get coil values from OpenPLC bool_output using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return [0] * count

        # Ensure thread-safe access
        self.safe_buffer_access.acquire_mutex()

        values = []
        for i in range(count):
            coil_addr = address + i

            if coil_addr < self.num_coils:
                # Map coil address to buffer and bit indices
                buffer_idx = coil_addr // MAX_BITS  # 8 bits per buffer
                bit_idx = coil_addr % MAX_BITS  # bit within buffer

                value, error_msg = self.safe_buffer_access.read_bool_output(
                    buffer_idx, bit_idx, thread_safe=False
                )
                if error_msg == "Success":
                    values.append(1 if value else 0)
                else:
                    print(f"[MODBUS] Error reading coil {coil_addr}: {error_msg}")
                    values.append(0)
            else:
                values.append(0)

        # Release mutex after access
        self.safe_buffer_access.release_mutex()

        return values

    def setValues(self, address, values):
        """Set coil values to OpenPLC bool_output using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return

        # Ensure thread-safe access
        self.safe_buffer_access.acquire_mutex()

        for i, value in enumerate(values):
            coil_addr = address + i

            if coil_addr < self.num_coils:
                # Map coil address to buffer and bit indices
                buffer_idx = coil_addr // MAX_BITS  # 8 bits per buffer
                bit_idx = coil_addr % MAX_BITS  # bit within buffer

                _, error_msg = self.safe_buffer_access.write_bool_output(
                    buffer_idx, bit_idx, bool(value), thread_safe=False
                )
                if error_msg != "Success":
                    print(f"[MODBUS] Error setting coil {coil_addr}: {error_msg}")

        # Release mutex after access
        self.safe_buffer_access.release_mutex()


class OpenPLCDiscreteInputsDataBlock(ModbusSparseDataBlock):
    """Custom Modbus discrete inputs data block that mirrors OpenPLC bool_input."""

    def __init__(self, runtime_args, num_inputs=64):
        self.runtime_args = runtime_args
        self.num_inputs = num_inputs

        # Create safe buffer access wrapper
        self.safe_buffer_access = SafeBufferAccess(runtime_args)
        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Warning: Failed to create safe buffer access for "
                f"discrete inputs: {self.safe_buffer_access.error_msg}"
            )

        # Initialize with zeros
        super().__init__([0] * num_inputs)

    def getValues(self, address, count=1):
        """Get discrete input values from OpenPLC bool_input using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return [0] * count

        # Ensure thread-safe access
        self.safe_buffer_access.acquire_mutex()

        values = []
        for i in range(count):
            input_addr = address + i

            if input_addr < self.num_inputs:
                # Map input address to buffer and bit indices
                buffer_idx = input_addr // MAX_BITS  # 8 bits per buffer
                bit_idx = input_addr % MAX_BITS  # bit within buffer

                value, error_msg = self.safe_buffer_access.read_bool_input(
                    buffer_idx, bit_idx, thread_safe=False
                )
                if error_msg == "Success":
                    values.append(1 if value else 0)
                else:
                    print(f"[MODBUS] Error reading discrete input {input_addr}: {error_msg}")
                    values.append(0)
            else:
                values.append(0)

        # Release mutex after access
        self.safe_buffer_access.release_mutex()

        return values

    def setValues(self, address, values):
        """Discrete inputs are read-only, this method should not be called"""
        pass  # Silently ignore writes to read-only inputs


class OpenPLCInputRegistersDataBlock(ModbusSparseDataBlock):
    """Custom Modbus input registers data block that mirrors OpenPLC analog inputs."""

    def __init__(self, runtime_args, num_registers=32):
        self.runtime_args = runtime_args
        self.num_registers = num_registers

        # Create safe buffer access wrapper
        self.safe_buffer_access = SafeBufferAccess(runtime_args)
        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Warning: Failed to create safe buffer access for "
                f"input registers: {self.safe_buffer_access.error_msg}"
            )

        # Initialize with zeros
        super().__init__([0] * num_registers)

    def getValues(self, address, count=1):
        """Get input register values from OpenPLC int_input using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return [0] * count

        # Ensure buffer mutex
        self.safe_buffer_access.acquire_mutex()

        values = []
        for i in range(count):
            reg_addr = address + i

            if reg_addr < self.num_registers:
                value, error_msg = self.safe_buffer_access.read_int_input(
                    reg_addr, thread_safe=False
                )
                if error_msg == "Success":
                    values.append(value)
                else:
                    print(f"[MODBUS] Error reading input register {reg_addr}: {error_msg}")
                    values.append(0)
            else:
                values.append(0)

        # Release mutex after access
        self.safe_buffer_access.release_mutex()

        return values

    def setValues(self, address, values):
        """Input registers are read-only, this method should not be called"""
        pass  # Silently ignore writes to read-only registers


class OpenPLCHoldingRegistersDataBlock(ModbusSparseDataBlock):
    """Custom Modbus holding registers data block that mirrors OpenPLC analog outputs."""

    def __init__(self, runtime_args, num_registers=32):
        self.runtime_args = runtime_args
        self.num_registers = num_registers

        # Create safe buffer access wrapper
        self.safe_buffer_access = SafeBufferAccess(runtime_args)
        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Warning: Failed to create safe buffer access for "
                f"holding registers: {self.safe_buffer_access.error_msg}"
            )

        # Initialize with zeros
        super().__init__([0] * num_registers)

    def getValues(self, address, count=1):
        """Get holding register values from OpenPLC int_output using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return [0] * count

        # Ensure buffer mutex
        self.safe_buffer_access.acquire_mutex()

        values = []
        for i in range(count):
            reg_addr = address + i

            if reg_addr < self.num_registers:
                value, error_msg = self.safe_buffer_access.read_int_output(
                    reg_addr, thread_safe=False
                )
                if error_msg == "Success":
                    values.append(value)
                else:
                    print(f"[MODBUS] Error reading holding register {reg_addr}: {error_msg}")
                    values.append(0)
            else:
                values.append(0)

        # Release mutex after access
        self.safe_buffer_access.release_mutex()
        return values

    def setValues(self, address, values):
        """Set holding register values to OpenPLC int_output using SafeBufferAccess"""
        address = address - 1  # Modbus addresses are 0-based

        if not self.safe_buffer_access.is_valid:
            print(
                f"[MODBUS] Error: Safe buffer access not valid: {self.safe_buffer_access.error_msg}"
            )
            return

        # Ensure buffer mutex
        self.safe_buffer_access.acquire_mutex()

        for i, value in enumerate(values):
            reg_addr = address + i

            if reg_addr < self.num_registers:
                _, error_msg = self.safe_buffer_access.write_int_output(
                    reg_addr, value, thread_safe=False
                )
                if error_msg != "Success":
                    print(f"[MODBUS] Error setting holding register {reg_addr}: {error_msg}")

        # Release mutex after access
        self.safe_buffer_access.release_mutex()


# Global variables for plugin lifecycle
server_task = None
server_context = None
runtime_args = None
running = False
server_loop = None  # Reference to the server's event loop for cross-thread operations
server_started_event = threading.Event()  # Signals successful server startup
server_error = None  # Stores any startup error message
gIp = "172.29.65.104"  # Default values
gPort = 5020

# Retry configuration for server restart
RETRY_DELAY_BASE = 2.0  # Initial delay between restart attempts (seconds)
RETRY_DELAY_MAX = 30.0  # Maximum delay between restart attempts (seconds)


def init(args_capsule):
    """Initialize the Modbus plugin"""
    global runtime_args, server_context, gIp, gPort

    print("[MODBUS] Python plugin 'simple_modbus' initializing...")

    try:
        # Print structure validation info for debugging
        print("[MODBUS] Validating plugin structure alignment...")
        # PluginStructureValidator.print_structure_info()

        # Extract runtime args from capsule using safe method
        if hasattr(args_capsule, "__class__") and "PyCapsule" in str(type(args_capsule)):
            # This is a PyCapsule from C - use safe extraction
            runtime_args, error_msg = safe_extract_runtime_args_from_capsule(args_capsule)
            if runtime_args is None:
                print(f"[MODBUS] Failed to extract runtime args: {error_msg}")
                return False

            print("[MODBUS] Runtime arguments extracted successfully")
        else:
            # This is a direct object (for testing)
            runtime_args = args_capsule
            print("[MODBUS] Using direct runtime args for testing")

        # Try to load configuration from plugin_specific_config_file_path
        try:
            config_map, status = SafeBufferAccess(runtime_args).get_config_file_args_as_map()
            if status == "Success" and config_map:
                # Try to extract network configuration
                network_config = config_map.get("network_configuration", {})
                if network_config and "host" in network_config and "port" in network_config:
                    gIp = str(network_config["host"])
                    gPort = int(network_config["port"])
                    print(f"[MODBUS] Configuration loaded - Host: {gIp}, Port: {gPort}")
                else:
                    print(
                        "[MODBUS] Config file loaded but network_configuration section missing or incomplete - using defaults"
                    )
                    print(f"[MODBUS] Available config sections: {list(config_map.keys())}")
            else:
                print(f"[MODBUS] Failed to load configuration file: {status} - using defaults")
        except Exception as config_error:
            print(f"[MODBUS] Exception while loading config: {config_error} - using defaults")
            import traceback

            traceback.print_exc()

        # Safely access buffer size using validation
        buffer_size, size_error = runtime_args.safe_access_buffer_size()
        if buffer_size == -1:
            print(f"[MODBUS] Failed to access buffer size: {size_error}")
            return False

        # print(f"[MODBUS]   Buffer size: {buffer_size}")
        # print(f"[MODBUS]   Bits per buffer: {runtime_args.bits_per_buffer}")
        # print(f"[MODBUS]   Structure details: {runtime_args}")

        # Create OpenPLC-connected data blocks for all Modbus types
        coils_block = OpenPLCCoilsDataBlock(runtime_args, num_coils=64)
        discrete_inputs_block = OpenPLCDiscreteInputsDataBlock(runtime_args, num_inputs=64)
        input_registers_block = OpenPLCInputRegistersDataBlock(runtime_args, num_registers=32)
        holding_registers_block = OpenPLCHoldingRegistersDataBlock(runtime_args, num_registers=32)

        # Create device context with all OpenPLC-connected data blocks
        # print(f"[MODBUS] Created data blocks:")
        # print(f"[MODBUS]   - Coils (bool_output): {coils_block.num_coils} coils")
        # print(f"[MODBUS]   - Discrete Inputs (bool_input): {discrete_inputs_block.num_inputs} inputs")
        # print(f"[MODBUS]   - Input Registers (int_input): {input_registers_block.num_registers} registers")
        # print(f"[MODBUS]   - Holding Registers (int_output): {holding_registers_block.num_registers} registers")

        device = ModbusDeviceContext(
            di=discrete_inputs_block,  # Discrete Inputs -> bool_input
            co=coils_block,  # Coils -> bool_output
            ir=input_registers_block,  # Input Registers -> int_input
            hr=holding_registers_block,  # Holding Registers -> int_output
        )
        server_context = ModbusServerContext(devices={1: device}, single=False)

        print(f"[MODBUS] Plugin initialized successfully - Host: {gIp}, Port: {gPort}")
        return True

    except Exception as e:
        print(f"[MODBUS] Plugin initialization failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def start_loop():
    """Start the Modbus server with automatic restart on failure."""
    global server_task, running, server_loop, server_started_event, server_error

    if server_context is None:
        print("[MODBUS] Error: Plugin not initialized")
        return False

    # Prevent double-start
    if server_task is not None and server_task.is_alive():
        print("[MODBUS] Warning: Server already running")
        return True

    running = True
    server_started_event.clear()
    server_error = None

    def run_server():
        """Server thread with automatic restart on failure (never give up)."""
        global server_loop, server_error
        backoff = RETRY_DELAY_BASE
        first_attempt = True

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server_loop = loop

        async def server_runner():
            """Main server coroutine with restart logic."""
            global server_error
            nonlocal backoff, first_attempt

            while running:
                # Check if cleanup has been called
                if server_context is None:
                    break

                try:
                    # Create and start the server
                    server = ModbusTcpServer(context=server_context, address=(gIp, gPort))

                    # serve_forever with background=True returns after successful bind
                    await server.serve_forever(background=True)

                    # If we get here, server is listening
                    if first_attempt:
                        print(f"[MODBUS] Server listening on {gIp}:{gPort}")
                        server_started_event.set()
                        first_attempt = False

                    backoff = RETRY_DELAY_BASE  # Reset backoff on success

                    # Keep server running until stop is requested
                    while running and server_context is not None:
                        await asyncio.sleep(1)

                    # Graceful shutdown
                    await server.shutdown()
                    break

                except Exception as e:
                    error_msg = str(e)
                    server_error = error_msg

                    if first_attempt:
                        # Signal startup failure on first attempt
                        print(f"[MODBUS] Failed to start server on {gIp}:{gPort}: {error_msg}")
                        server_started_event.set()  # Unblock start_loop

                    if not running:
                        break  # Stop requested, don't retry

                    print(f"[MODBUS] Server error, will retry in {backoff:.1f}s: {error_msg}")

                    # Wait before retry (check running flag periodically)
                    wait_time = 0
                    while wait_time < backoff and running:
                        await asyncio.sleep(0.5)
                        wait_time += 0.5

                    # Increase backoff for next attempt (capped at max)
                    backoff = min(backoff * 1.5, RETRY_DELAY_MAX)
                    first_attempt = False

        try:
            loop.run_until_complete(server_runner())
        except Exception as e:
            print(f"[MODBUS] Fatal error in server thread: {e}")
        finally:
            server_loop = None
            loop.close()

    server_task = threading.Thread(target=run_server, daemon=False)
    server_task.start()

    # Wait for server to start (or fail) with timeout
    startup_timeout = 5.0
    if server_started_event.wait(timeout=startup_timeout):
        if server_error is not None:
            print(f"[MODBUS] Server startup failed: {server_error}")
            return False
        return True
    else:
        print(f"[MODBUS] Timeout waiting for server to start on {gIp}:{gPort}")
        return False


def stop_loop():
    """Stop the Modbus server gracefully."""
    global server_task, running

    running = False

    if server_task:
        # Call ServerStop() directly - it's designed for cross-thread use
        # (uses asyncio.run_coroutine_threadsafe internally)
        try:
            ServerStop()
        except RuntimeError as e:
            # Server may not be running or already stopped
            print(f"[MODBUS] ServerStop warning: {e}")

        server_task.join(timeout=5.0)
        if server_task.is_alive():
            print("[MODBUS] Warning: Server thread did not stop within timeout")
        server_task = None

    print("[MODBUS] Server stopped")
    return True


def cleanup():
    """Cleanup plugin resources"""
    global server_context, runtime_args

    server_context = None
    runtime_args = None

    print("[MODBUS] Plugin cleaned up")
    return True


async def main():
    """Standalone server for testing"""
    # Create a proper mock runtime args that inherits from PluginRuntimeArgs

    # Create a mock that has the required methods
    class MockArgs:
        def __init__(self):
            self.buffer_size = 1
            self.bits_per_buffer = 8
            # Create simple boolean list for testing
            self.bool_data = [[False] * 8]  # 1 buffer, 8 booleans
            self.bool_output = self.bool_data  # Simple reference
            self.mutex_take = None
            self.mutex_give = None
            self.buffer_mutex = None

        def safe_access_buffer_size(self):
            """Mock implementation of safe_access_buffer_size"""
            return self.buffer_size, "Success"

        def validate_pointers(self):
            """Mock implementation of validate_pointers"""
            return True, "Mock validation passed"

        def __str__(self):
            return (
                f"MockArgs(buffer_size={self.buffer_size}, bits_per_buffer={self.bits_per_buffer})"
            )

    mock_args = MockArgs()

    # Initialize and start
    if init(mock_args):
        if start_loop():
            print(f"Modbus server running on {gIp}:{gPort}")
            print("Press Ctrl+C to stop...")

            try:
                # Keep server running
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping server...")
                stop_loop()
                cleanup()
        else:
            print("Failed to start server")
    else:
        print("Failed to initialize plugin")


if __name__ == "__main__":
    asyncio.run(main())
