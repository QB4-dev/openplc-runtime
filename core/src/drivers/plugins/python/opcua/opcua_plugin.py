import sys
import os
import asyncio
import threading
import time
import traceback
import struct
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from asyncua import Server, ua
from asyncua.common.node import Node

# Add the parent directory to Python path to find shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the correct type definitions
from shared import (
    PluginRuntimeArgs,
    safe_extract_runtime_args_from_capsule,
    SafeBufferAccess,
)

# Import the configuration model
from shared.plugin_config_decode.opcua_config_model import OpcuaMasterConfig

# Global variables for plugin lifecycle and configuration
runtime_args = None
opcua_config: OpcuaMasterConfig = None
safe_buffer_accessor: SafeBufferAccess = None
opcua_server = None
server_thread: Optional[threading.Thread] = None
stop_event = threading.Event()


@dataclass
class VariableNode:
    """Represents an OPC-UA node mapped to a PLC debug variable."""
    node: Node
    debug_var_index: int
    datatype: str
    access_mode: str
    is_array_element: bool = False
    array_index: Optional[int] = None


class OpcuaServer:
    """OPC-UA server implementation using opcua-asyncio."""

    def __init__(self, config: Any, sba: SafeBufferAccess):
        self.config = config
        self.sba = sba
        self.server: Optional[Server] = None
        self.variable_nodes: Dict[int, VariableNode] = {}
        self.namespace_idx = None
        self.running = False

    async def setup_server(self) -> bool:
        """Initialize and configure the OPC-UA server."""
        try:
            # Create server instance
            self.server = Server()

            # Configure server
            await self.server.init()
            self.server.set_endpoint(self.config.endpoint)
            self.server.set_server_name(self.config.server_name)

            # Set up security (basic None policy for now)
            # TODO: Implement certificate loading when certificate files are available
            # await self.server.load_certificate(self.config.certificate, self.config.private_key)
            # await self.server.load_private_key(self.config.private_key)

            # Register namespace
            self.namespace_idx = await self.server.register_namespace(self.config.namespace)

            print(f"(PASS) OPC-UA server initialized: {self.config.endpoint}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to setup OPC-UA server: {e}")
            return False

    async def create_variable_nodes(self) -> bool:
        """Create OPC-UA nodes for all configured variables."""
        try:
            if not self.server or self.namespace_idx is None:
                print("(FAIL) Server not initialized")
                return False

            # Get the Objects folder
            objects = self.server.get_objects_node()

            # Create variables recursively
            for variable in self.config.variables:
                try:
                    print(f"Processing variable: {variable.node_name}")
                    await self._create_variable_recursive(objects, variable.definition, variable.node_name)

                except Exception as e:
                    print(f"(FAIL) Error processing variable {variable.node_name}: {e}")
                    traceback.print_exc()

            print(f"(PASS) Created {len(self.variable_nodes)} variable nodes")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to create variable nodes: {e}")
            return False

    async def _create_variable_recursive(self, parent_node: Node, var_def: Any, node_name: str, path: str = "") -> None:
        """Create OPC-UA nodes recursively for complex variable definitions."""
        try:
            current_path = f"{path}.{node_name}" if path else node_name

            if var_def.type in ["STRUCT", "ARRAY"]:
                # Create parent object for complex types
                print(f"Creating {var_def.type} node: {current_path}")
                complex_obj = await parent_node.add_object(self.namespace_idx, node_name)

                # Recursively create member nodes
                if var_def.members:
                    print(f"  Creating {len(var_def.members)} members:")
                    for member in var_def.members:
                        await self._create_variable_recursive(complex_obj, member, member.name, current_path)

            else:
                # Create simple variable node
                print(f"  Creating simple variable: {current_path} (type: {var_def.datatype}, index: {var_def.index})")
                opcua_type = self._map_plc_to_opcua_type(var_def.datatype)

                # Create the node
                node = await parent_node.add_variable(
                    self.namespace_idx,
                    node_name,
                    ua.Variant(0, opcua_type),
                    datatype=opcua_type
                )

                # Set access level based on configuration
                access_level = ua.AccessLevel.CurrentRead
                if var_def.access == "readwrite":
                    access_level |= ua.AccessLevel.CurrentWrite

                await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

                # Add write callback for readwrite variables
                if var_def.access == "readwrite":
                    await self._add_write_callback(node, var_def.index)

                # Store node mapping
                var_node = VariableNode(
                    node=node,
                    debug_var_index=var_def.index,
                    datatype=var_def.datatype,
                    access_mode=var_def.access,
                    is_array_element="[" in node_name and "]" in node_name
                )
                if var_node.is_array_element:
                    var_node.array_index = int(node_name.strip("[]")) if node_name.startswith("[") else 0

                self.variable_nodes[var_def.index] = var_node
                print(f"    ✓ Created variable: {current_path}")

        except Exception as e:
            print(f"(FAIL) Failed to create variable node '{current_path}': {e}")
            traceback.print_exc()
            raise



    def _map_plc_to_opcua_type(self, plc_type: str) -> ua.VariantType:
        """Map plc datatype to OPC-UA VariantType."""
        type_mapping = {
            "Bool": ua.VariantType.Boolean,
            "Byte": ua.VariantType.Byte,
            "Int": ua.VariantType.UInt16,
            "Int32": ua.VariantType.UInt32,  # Added Int32 mapping
            "Dint": ua.VariantType.UInt32,
            "Lint": ua.VariantType.UInt64,
            "Float": ua.VariantType.Float,
            "String": ua.VariantType.String,
        }
        mapped_type = type_mapping.get(plc_type, ua.VariantType.Variant)
        print(f"    Mapping {plc_type} -> {mapped_type}")
        return mapped_type

    async def update_variables_from_plc(self) -> None:
        """Read values from PLC debug variables and update OPC-UA nodes."""
        try:
            if not self.variable_nodes:
                return

            # Get list of variable indices to read
            var_indices = list(self.variable_nodes.keys())

            # Use debug utils to read variable values
            for var_index in var_indices:
                try:
                    var_node = self.variable_nodes[var_index]

                    # Read value using debug utils - index maps directly to debug variable
                    value, msg = self.sba.get_var_value(var_index)
                    if msg == "Success" and value is not None:
                        await self._update_opcua_node(var_node, value)
                    else:
                        print(f"(FAIL) Failed to read debug variable {var_index}: {msg}")

                except Exception as e:
                    print(f"(FAIL) Error reading debug variable {var_index}: {e}")

        except Exception as e:
            print(f"(FAIL) Error updating variables from PLC: {e}")

    async def _update_opcua_node(self, var_node: VariableNode, value: Any) -> None:
        """Update an OPC-UA node with a new value."""
        try:
            # Convert value if necessary for OPC-UA format
            opcua_value = self._convert_value_for_opcua(var_node.datatype, value)
            await var_node.node.write_value(ua.Variant(opcua_value))
        except Exception as e:
            print(f"(FAIL) Failed to update OPC-UA node for debug variable {var_node.debug_var_index}: {e}")

    def _convert_value_for_opcua(self, datatype: str, value: Any) -> Any:
        """Convert PLC debug variable value to OPC-UA compatible format."""
        # The debug utils return raw integer values based on variable size
        # Convert to appropriate OPC-UA types based on config datatype
        if datatype == "Bool":
            return bool(value)
        elif datatype == "Byte":
            return int(value)
        elif datatype == "Int":
            return int(value)
        elif datatype == "Dint":
            return int(value)
        elif datatype == "Lint":
            return int(value)
        elif datatype == "Float":
            # Float values are stored as integers in debug variables
            # Convert back to float if it's an integer representation
            if isinstance(value, int):
                try:
                    return struct.unpack('f', struct.pack('I', value))[0]
                except:
                    return float(value)
            return float(value)
        elif datatype == "String":
            return str(value)
        else:
            return value

    async def _add_write_callback(self, node: Node, var_index: int) -> None:
        """Add a write callback to an OPC-UA node for writing back to PLC."""
        try:
            # Define the callback function
            async def write_callback(node, val, data):
                try:
                    # Extract the value from the OPC-UA variant
                    opcua_value = val.Value

                    # Convert OPC-UA value to PLC format if needed
                    plc_value = self._convert_value_for_plc(self.variable_nodes[var_index].datatype, opcua_value)

                    # Write to PLC debug variable
                    success, msg = self.sba.set_var_value(var_index, plc_value)
                    if not success:
                        print(f"(FAIL) Failed to write to PLC variable {var_index}: {msg}")
                    else:
                        print(f"(PASS) Wrote value {plc_value} to PLC variable {var_index}")

                except Exception as e:
                    print(f"(FAIL) Error in write callback for variable {var_index}: {e}")

            # Set the callback on the node
            # await node.set_write_callback(write_callback)

        except Exception as e:
            print(f"(FAIL) Failed to add write callback for variable {var_index}: {e}")

    def _convert_value_for_plc(self, datatype: str, value: Any) -> Any:
        """Convert OPC-UA value to PLC debug variable format."""
        # For most types, the value can be used directly
        # May need conversion for certain types
        if datatype == "Float" and isinstance(value, float):
            # Convert float to int representation for storage
            try:
                return struct.unpack('I', struct.pack('f', value))[0]
            except:
                return int(value)
        return value

    async def start_server(self) -> bool:
        """Start the OPC-UA server."""
        try:
            if not self.server:
                print("(FAIL) Server not initialized")
                return False

            await self.server.start()
            self.running = True
            print(f"(PASS) OPC-UA server started on {self.config.endpoint}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to start OPC-UA server: {e}")
            return False

    async def stop_server(self) -> None:
        """Stop the OPC-UA server."""
        try:
            if self.server and self.running:
                await self.server.stop()
                self.running = False
                print("(PASS) OPC-UA server stopped")

        except Exception as e:
            print(f"(FAIL) Error stopping OPC-UA server: {e}")

    async def run_update_loop(self) -> None:
        """Main update loop for synchronizing PLC and OPC-UA data."""
        cycle_time = self.config.cycle_time_ms / 1000.0

        while self.running and not stop_event.is_set():
            try:
                await self.update_variables_from_plc()
                await asyncio.sleep(cycle_time)

            except Exception as e:
                print(f"(FAIL) Error in update loop: {e}")
                await asyncio.sleep(1.0)  # Brief pause on error


def server_thread_main():
    """Main function for the server thread."""
    global opcua_server

    async def main():
        try:
            # Setup server
            if not await opcua_server.setup_server():
                return

            if not await opcua_server.create_variable_nodes():
                return

            if not await opcua_server.start_server():
                return

            # Run update loop
            await opcua_server.run_update_loop()

        except Exception as e:
            print(f"(FAIL) Error in server thread: {e}")
        finally:
            if opcua_server:
                await opcua_server.stop_server()


    # Run the async server
    asyncio.run(main())


def init(args_capsule):
    """
    Initialize the OPC-UA plugin.
    This function is called once when the plugin is loaded.
    """
    global runtime_args, opcua_config, safe_buffer_accessor, opcua_server

    print(" OPC-UA Plugin - Initializing...")

    try:
        # Extract runtime arguments from capsule
        runtime_args, error_msg = safe_extract_runtime_args_from_capsule(args_capsule)
        if not runtime_args:
            print(f"(FAIL) Failed to extract runtime args: {error_msg}")
            return False

        print("(PASS) Runtime arguments extracted successfully")

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

        print(f" Loading configuration from: {config_path}")

        opcua_config = OpcuaMasterConfig()
        opcua_config.import_config_from_file(config_path)
        opcua_config.validate()

        print(f"(PASS) Configuration loaded successfully: {len(opcua_config.plugins)} plugin(s)")

        # Initialize server for the first plugin (simplified - assumes single plugin)
        if opcua_config.plugins:
            plugin_config = opcua_config.plugins[0]
            opcua_server = OpcuaServer(plugin_config.config, safe_buffer_accessor)
            print("(PASS) OPC-UA server instance created")
        else:
            print("(FAIL) No OPC-UA plugins configured")
            return False

        return True

    except Exception as e:
        print(f"(FAIL) Error during initialization: {e}")
        traceback.print_exc()
        return False


def start_loop():
    """
    Start the main loop for the OPC-UA server.
    This function is called after successful initialization.
    """
    global server_thread, opcua_server

    print(" OPC-UA Plugin - Starting main loop...")

    try:
        if not opcua_server:
            print("(FAIL) Plugin not properly initialized")
            return False

        # Reset stop event
        stop_event.clear()

        # Start server thread
        server_thread = threading.Thread(target=server_thread_main, daemon=True)
        server_thread.start()

        print("(PASS) OPC-UA server thread started")
        return True

    except Exception as e:
        print(f"(FAIL) Error starting main loop: {e}")
        traceback.print_exc()
        return False


def stop_loop():
    """
    Stop the main loop and OPC-UA server.
    This function is called when the plugin needs to be stopped.
    """
    global server_thread, opcua_server

    print(" OPC-UA Plugin - Stopping main loop...")

    try:
        if not server_thread:
            print(" No server thread to stop")
            return True

        # Signal thread to stop
        stop_event.set()

        # Wait for thread to finish (with timeout)
        if server_thread.is_alive():
            server_thread.join(timeout=5.0)
            if server_thread.is_alive():
                print(" Server thread did not stop within timeout")
            else:
                print("(PASS) Server thread stopped successfully")

        print("(PASS) Main loop stopped")
        return True

    except Exception as e:
        print(f"(FAIL) Error stopping main loop: {e}")
        traceback.print_exc()
        return False


def cleanup():
    """
    Clean up resources before plugin unload.
    This function is called when the plugin is being unloaded.
    """
    global runtime_args, opcua_config, safe_buffer_accessor, opcua_server, server_thread

    print(" OPC-UA Plugin - Cleaning up...")

    try:
        # Stop server if running
        stop_loop()

        # Clean up global variables
        runtime_args = None
        opcua_config = None
        safe_buffer_accessor = None
        opcua_server = None
        server_thread = None

        print("(PASS) Cleanup completed successfully")
        return True

    except Exception as e:
        print(f"(FAIL) Error during cleanup: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    """
    Test mode for development purposes.
    This allows running the plugin standalone for testing.
    """
    print(" OPC-UA Plugin - Test Mode")
    print("This plugin is designed to be loaded by the OpenPLC runtime.")
    print("Standalone testing is not fully supported without runtime integration.")
