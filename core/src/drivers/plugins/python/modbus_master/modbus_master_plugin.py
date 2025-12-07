import os
import sys
import threading
import time
import traceback
from typing import Any, List

from pymodbus.exceptions import ConnectionException, ModbusIOException
from pymodbus.pdu import ExceptionResponse

# Add the parent directory to Python path to find shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import the correct type definitions
# pylint: disable=wrong-import-position
from shared import (
    SafeBufferAccess,
    SafeLoggingAccess,
    safe_extract_runtime_args_from_capsule,
)

# Import the configuration model
from shared.plugin_config_decode.modbus_master_config_model import (
    ModbusMasterConfig,
)

# pylint: enable=wrong-import-position

# Import local modules
try:
    # Try relative imports first (when used as package)
    from .modbus_master_connection import ModbusConnectionManager
    from .modbus_master_memory import (
        read_data_for_modbus_write,
        update_iec_buffer_from_modbus_data,
    )
    from .modbus_master_utils import (
        calculate_gcd_of_cycle_times,
        get_modbus_registers_count_for_iec_size,
        parse_modbus_offset,
    )
except ImportError:
    # Fallback to absolute imports (when run standalone)
    from modbus_master_connection import ModbusConnectionManager
    from modbus_master_memory import (
        read_data_for_modbus_write,
        update_iec_buffer_from_modbus_data,
    )
    from modbus_master_utils import (
        calculate_gcd_of_cycle_times,
        get_modbus_registers_count_for_iec_size,
        parse_modbus_offset,
    )

# Global variables for plugin lifecycle and configuration
# pylint: disable=invalid-name
runtime_args = None
modbus_master_config: ModbusMasterConfig = None
safe_buffer_accessor: SafeBufferAccess = None
_safe_logging_access: SafeLoggingAccess = None
slave_threads: List[threading.Thread] = []
# pylint: enable=invalid-name


class ModbusSlaveDevice(threading.Thread):
    def __init__(self, device_config: Any, sba: SafeBufferAccess):
        super().__init__(daemon=True)
        self.device_config = device_config
        self.sba = sba
        self._stop_event = threading.Event()
        self.connection_manager = ModbusConnectionManager(
            device_config.host, device_config.port, device_config.timeout_ms
        )
        self.name = f"ModbusSlave-{device_config.name}-{device_config.host}:{device_config.port}"

        # Calculate GCD of all I/O point cycle times for this device
        self.gcd_cycle_time_ms = calculate_gcd_of_cycle_times(device_config.io_points)
        print(f"[{self.name}] Calculated GCD cycle time: {self.gcd_cycle_time_ms}ms")

    def _ensure_connection(self) -> bool:
        """
        Ensures there is a valid connection, reconnecting if necessary.

        Returns:
            True if connection is available, False if thread was interrupted
        """
        return self.connection_manager.ensure_connection(self._stop_event)

    def run(self):  # pylint: disable=too-many-locals
        print(f"[{self.name}] Thread started.")

        io_points = self.device_config.io_points
        gcd_cycle_time_seconds = self.gcd_cycle_time_ms / 1000.0

        if not io_points:
            print(f"[{self.name}] No I/O points defined. Stopping thread.")
            return

        # Connect with infinite retry
        if not self.connection_manager.connect_with_retry(self._stop_event):
            print(f"[{self.name}] Thread stopped before connection could be established.")
            return

        # Initialize cycle counter
        cycle_counter = 0

        try:
            while not self._stop_event.is_set():
                cycle_start_time = time.monotonic()

                # Ensure connection exists before cycle
                if not self._ensure_connection():
                    break  # Thread was interrupted

                # 1. READ OPERATIONS - Process only I/O points that are due for polling this cycle
                read_results_to_update = []  # Store tuples: (iec_addr, modbus_data, length)

                # Check each read point individually
                for point in io_points:
                    if self._stop_event.is_set():
                        break

                    # Skip if this point doesn't need to be polled this cycle
                    if point.fc not in [1, 2, 3, 4]:  # Read functions
                        continue

                    # Check if point should be polled this cycle
                    point_cycle_multiple = point.cycle_time_ms // self.gcd_cycle_time_ms
                    if (cycle_counter % point_cycle_multiple) != 0:
                        continue

                    try:
                        # Parse Modbus offset
                        address = parse_modbus_offset(point.offset)

                        # Calculate the correct number of Modbus registers/coils needed
                        if point.fc in [3, 4]:  # Register-based operations (FC 3,4)
                            iec_size = point.iec_location.size
                            registers_per_iec_element = get_modbus_registers_count_for_iec_size(
                                iec_size
                            )
                            count = point.length * registers_per_iec_element
                        else:  # Coil/Discrete Input operations (FC 1,2)
                            count = point.length  # 1:1 mapping for boolean operations

                        # Perform Modbus read based on function code
                        # Note: pymodbus 3.x requires count as keyword argument
                        if point.fc == 1:  # Read Coils
                            response = self.connection_manager.client.read_coils(
                                address, count=count
                            )
                        elif point.fc == 2:  # Read Discrete Inputs
                            response = self.connection_manager.client.read_discrete_inputs(
                                address, count=count
                            )
                        elif point.fc == 3:  # Read Holding Registers
                            response = self.connection_manager.client.read_holding_registers(
                                address, count=count
                            )
                        elif point.fc == 4:  # Read Input Registers
                            response = self.connection_manager.client.read_input_registers(
                                address, count=count
                            )
                        else:
                            print(f"[{self.name}] Unsupported read FC: {point.fc}")
                            continue

                        # Check if response is valid
                        if isinstance(response, (ModbusIOException, ExceptionResponse)):
                            print(
                                f"[{self.name}] (FAIL) Modbus read error "
                                f"(FC {point.fc}, addr {address}): {response}"
                            )
                            # Mark as disconnected to force reconnection on next cycle
                            self.connection_manager.mark_disconnected()
                            continue
                        if response.isError():
                            print(
                                f"[{self.name}] (FAIL) Modbus read failed "
                                f"(FC {point.fc}, addr {address}): {response}"
                            )
                            # Mark as disconnected to force reconnection on next cycle
                            self.connection_manager.mark_disconnected()
                            continue

                        # Extract data from response
                        if point.fc in [1, 2]:  # Coils/Discrete Inputs (boolean data)
                            modbus_data = response.bits
                        else:  # Holding/Input Registers (integer data)
                            modbus_data = response.registers

                        # Store for batch update
                        read_results_to_update.append(
                            (point.iec_location, modbus_data, point.length)
                        )

                    except ValueError as ve:
                        print(
                            f"[{self.name}] (FAIL) Invalid offset "
                            f"'{point.offset}' for FC {point.fc}: {ve}"
                        )
                    except ConnectionException as ce:
                        print(
                            f"[{self.name}] (FAIL) Connection error reading "
                            f"FC {point.fc}, offset {point.offset}: {ce}"
                        )
                        # Mark as disconnected to force reconnection
                        self.connection_manager.mark_disconnected()
                    except Exception as e:
                        print(
                            f"[{self.name}] (FAIL) Error reading "
                            f"FC {point.fc}, offset {point.offset}: {e}"
                        )
                        # For other errors also mark disconnected as precaution
                        self.connection_manager.mark_disconnected()

                # Batch update IEC buffers with single mutex acquisition
                if read_results_to_update:
                    lock_acquired, lock_msg = self.sba.acquire_mutex()
                    if lock_acquired:
                        try:
                            for iec_addr, modbus_data, length in read_results_to_update:
                                update_iec_buffer_from_modbus_data(
                                    self.sba, iec_addr, modbus_data, length
                                )
                        finally:
                            self.sba.release_mutex()
                    else:
                        print(
                            f"[{self.name}] (FAIL) Failed to acquire mutex "
                            f"for read updates: {lock_msg}"
                        )

                # 2. WRITE OPERATIONS - Process only I/O points that are due for polling this cycle
                for point in io_points:
                    if self._stop_event.is_set():
                        break

                    # Skip if this point doesn't need to be polled this cycle
                    if point.fc not in [5, 6, 15, 16]:  # Write functions
                        continue

                    # Check if point should be polled this cycle
                    point_cycle_multiple = point.cycle_time_ms // self.gcd_cycle_time_ms
                    if (cycle_counter % point_cycle_multiple) != 0:
                        continue

                    try:
                        # Parse Modbus offset
                        address = parse_modbus_offset(point.offset)

                        # Read data from IEC buffers (with mutex)
                        lock_acquired, lock_msg = self.sba.acquire_mutex()
                        if not lock_acquired:
                            print(
                                f"[{self.name}] (FAIL) Failed to acquire mutex "
                                f"for write prep (FC {point.fc}, "
                                f"offset {point.offset}): {lock_msg}"
                            )
                            continue

                        try:
                            values_to_write = read_data_for_modbus_write(
                                self.sba, point.iec_location, point.length
                            )
                        finally:
                            self.sba.release_mutex()

                        if values_to_write is None:
                            print(
                                f"[{self.name}] (FAIL) Failed to read data "
                                f"for Modbus write (FC {point.fc}, "
                                f"offset {point.offset})"
                            )
                            continue

                        # Perform Modbus write operation
                        if point.fc == 5:  # Write Single Coil
                            if len(values_to_write) > 0:
                                response = self.connection_manager.client.write_coil(
                                    address, values_to_write[0]
                                )
                            else:
                                print(
                                    f"[{self.name}] (FAIL) No data to write "
                                    f"for FC 5, offset {address}"
                                )
                                continue
                        elif point.fc == 6:  # Write Single Register
                            if len(values_to_write) > 0:
                                response = self.connection_manager.client.write_register(
                                    address, values_to_write[0]
                                )
                            else:
                                print(
                                    f"[{self.name}] (FAIL) No data to write "
                                    f"for FC 6, offset {address}"
                                )
                                continue
                        elif point.fc == 15:  # Write Multiple Coils
                            response = self.connection_manager.client.write_coils(
                                address, values_to_write
                            )
                        elif point.fc == 16:  # Write Multiple Registers
                            response = self.connection_manager.client.write_registers(
                                address, values_to_write
                            )
                        else:
                            print(f"[{self.name}] Unsupported write FC: {point.fc}")
                            continue

                        # Check write response
                        if isinstance(response, (ModbusIOException, ExceptionResponse)):
                            print(
                                f"[{self.name}] (FAIL) Modbus write error "
                                f"(FC {point.fc}, addr {address}): {response}"
                            )
                            # Mark as disconnected to force reconnection on next cycle
                            self.connection_manager.mark_disconnected()
                        elif response.isError():
                            print(
                                f"[{self.name}] (FAIL) Modbus write failed "
                                f"(FC {point.fc}, addr {address}): {response}"
                            )
                            # Mark as disconnected to force reconnection on next cycle
                            self.connection_manager.mark_disconnected()

                    except ValueError as ve:
                        print(
                            f"[{self.name}] (FAIL) Invalid offset "
                            f"'{point.offset}' for FC {point.fc}: {ve}"
                        )
                    except ConnectionException as ce:
                        print(
                            f"[{self.name}] (FAIL) Connection error writing "
                            f"FC {point.fc}, offset {point.offset}: {ce}"
                        )
                        # Mark as disconnected to force reconnection
                        self.connection_manager.mark_disconnected()
                    except Exception as e:
                        print(
                            f"[{self.name}] (FAIL) Error writing "
                            f"FC {point.fc}, offset {point.offset}: {e}"
                        )
                        # For other errors also mark disconnected as precaution
                        self.connection_manager.mark_disconnected()

                # 3. CYCLE TIMING - Sleep for GCD cycle time
                cycle_elapsed = time.monotonic() - cycle_start_time
                sleep_duration = max(0, gcd_cycle_time_seconds - cycle_elapsed)
                if sleep_duration > 0:
                    # Sleep in small increments (100ms each) to allow for quick shutdown
                    sleep_increment = 0.1
                    remaining_sleep = sleep_duration

                    while remaining_sleep > 0 and not self._stop_event.is_set():
                        actual_sleep = min(sleep_increment, remaining_sleep)
                        time.sleep(actual_sleep)
                        remaining_sleep -= actual_sleep

                # Increment cycle counter
                cycle_counter += 1

        except ConnectionException as ce:
            print(f"[{self.name}] (FAIL) Connection failed: {ce}")
            # Mark as disconnected to force reconnection
            self.connection_manager.mark_disconnected()
        except Exception as e:
            print(f"[{self.name}] (FAIL) Unexpected error in thread: {e}")
            traceback.print_exc()
        finally:
            self.connection_manager.disconnect()
            print(f"[{self.name}] Thread finished and connection closed.")

    def stop(self):
        print(f"[{self.name}] Stop signal received.")
        self._stop_event.set()


def init(args_capsule):
    """
    Initialize the Modbus Master plugin.
    This function is called once when the plugin is loaded.
    """
    global runtime_args, modbus_master_config, safe_buffer_accessor, _safe_logging_access

    print(" Modbus Master Plugin - Initializing...")

    try:
        # Extract runtime arguments from capsule
        runtime_args, error_msg = safe_extract_runtime_args_from_capsule(args_capsule)
        if not runtime_args:
            print(f"(FAIL) Failed to extract runtime args: {error_msg}")
            return False

        print("(PASS) Runtime arguments extracted successfully")

        _safe_logging_access = SafeLoggingAccess(runtime_args)

        # Create safe buffer accessor
        safe_buffer_accessor = SafeBufferAccess(runtime_args)
        if not safe_buffer_accessor.is_valid:
            print(f"(FAIL) Failed to create SafeBufferAccess: {safe_buffer_accessor.error_msg}")
            return False

        print("(PASS) SafeBufferAccess created successfully")

        # Load configuration
        config_path, config_error = safe_buffer_accessor.get_config_path()
        if not config_path:
            print(f"(FAIL) Failed to get config path: {config_error}")
            return False

        _safe_logging_access.log_debug(f" Loading configuration from: {config_path}")

        modbus_master_config = ModbusMasterConfig()
        modbus_master_config.import_config_from_file(config_path)
        modbus_master_config.validate()

        device_count = len(modbus_master_config.devices)
        _safe_logging_access.log_info(
            f"(PASS) Configuration loaded successfully: {device_count} device(s)"
        )

        return True

    except Exception as e:
        print(f"(FAIL) Error during initialization: {e}")
        traceback.print_exc()
        return False


def start_loop():
    """
    Start the main loop for all configured Modbus devices.
    This function is called after successful initialization.
    """
    # pylint: disable=global-variable-not-assigned
    global slave_threads, modbus_master_config, safe_buffer_accessor, _safe_logging_access
    # pylint: enable=global-variable-not-assigned

    _safe_logging_access.log_info(" Modbus Master Plugin - Starting main loop...")

    try:
        if not modbus_master_config or not safe_buffer_accessor:
            _safe_logging_access.log_error("(FAIL) Plugin not properly initialized")
            return False

        # Start a thread for each configured device
        for device_config in modbus_master_config.devices:
            try:
                device_thread = ModbusSlaveDevice(device_config, safe_buffer_accessor)
                device_thread.start()
                slave_threads.append(device_thread)
                _safe_logging_access.log_info(
                    f"(PASS) Started thread for device: {device_config.name} "
                    f"({device_config.host}:{device_config.port})"
                )
            except Exception as e:
                _safe_logging_access.log_error(
                    f"(FAIL) Failed to start thread for device {device_config.name}: {e}"
                )

        if slave_threads:
            _safe_logging_access.log_info(
                f"(PASS) Successfully started {len(slave_threads)} device thread(s)"
            )
            return True
        else:
            _safe_logging_access.log_error("(FAIL) No device threads started")
            return False

    except Exception as e:
        _safe_logging_access.log_error(f"(FAIL) Error starting main loop: {e}")
        traceback.print_exc()
        return False


def stop_loop():
    """
    Stop the main loop and all running device threads.
    This function is called when the plugin needs to be stopped.
    """
    global slave_threads, _safe_logging_access  # pylint: disable=global-variable-not-assigned

    _safe_logging_access.log_info(" Modbus Master Plugin - Stopping main loop...")

    try:
        if not slave_threads:
            _safe_logging_access.log_info(" No threads to stop")
            return True

        # Signal all threads to stop
        for thread in slave_threads:
            try:
                if hasattr(thread, "stop"):
                    thread.stop()
                else:
                    print(f" Thread {thread.name} does not have a stop method")
            except Exception as e:
                print(f"(FAIL) Error stopping thread {thread.name}: {e}")

        # Wait for all threads to finish (with timeout)
        timeout_per_thread = 5.0  # seconds
        for thread in slave_threads:
            try:
                thread.join(timeout=timeout_per_thread)
                if thread.is_alive():
                    print(f" Thread {thread.name} did not stop within timeout")
                else:
                    print(f"(PASS) Thread {thread.name} stopped successfully")
            except Exception as e:
                _safe_logging_access.log_error(f"(FAIL) Error joining thread {thread.name}: {e}")

        _safe_logging_access.log_info("(PASS) Main loop stopped")
        return True

    except Exception as e:
        _safe_logging_access.log_error(f"(FAIL) Error stopping main loop: {e}")
        traceback.print_exc()
        return False


def cleanup():
    """
    Clean up resources before plugin unload.
    This function is called when the plugin is being unloaded.
    """
    # pylint: disable=global-variable-not-assigned
    global runtime_args, modbus_master_config, safe_buffer_accessor
    global slave_threads, _safe_logging_access
    # pylint: enable=global-variable-not-assigned

    _safe_logging_access.log_info(" Modbus Master Plugin - Cleaning up...")

    try:
        # Stop all threads if not already stopped
        stop_loop()

        # Clear thread list
        slave_threads.clear()

        # Reset global variables
        runtime_args = None
        modbus_master_config = None
        safe_buffer_accessor = None
        _safe_logging_access = None

        print("(PASS) Cleanup completed successfully")
        return True

    except Exception as e:
        print(f"(FAIL) Error during cleanup: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Test mode for development purposes.
    # This allows running the plugin standalone for testing.
    print(" Modbus Master Plugin - Test Mode")
    print("This plugin is designed to be loaded by the OpenPLC runtime.")
    print("Standalone testing is not fully supported without runtime integration.")

    # You could add basic configuration validation here
    try:
        test_config = ModbusMasterConfig()
        print("(PASS) Configuration model can be instantiated")
    except Exception as e:
        print(f"(FAIL) Error testing configuration model: {e}")
