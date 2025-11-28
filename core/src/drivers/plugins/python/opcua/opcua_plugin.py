import sys
import os
import asyncio
import threading
import time
import traceback
from typing import Optional, Dict, Any, List

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

# Import local modules
try:
    # Try relative imports first (when used as package)
    from .opcua_types import VariableNode, VariableMetadata
    from .opcua_utils import (
        map_plc_to_opcua_type,
        convert_value_for_opcua,
        convert_value_for_plc,
        infer_var_type,
    )
    from .opcua_memory import read_memory_direct, initialize_variable_cache
except ImportError:
    # Fallback to absolute imports (when run standalone)
    from opcua_types import VariableNode, VariableMetadata
    from opcua_utils import (
        map_plc_to_opcua_type,
        convert_value_for_opcua,
        convert_value_for_plc,
        infer_var_type,
    )
    from opcua_memory import read_memory_direct, initialize_variable_cache

# Global variables for plugin lifecycle and configuration
runtime_args = None
opcua_config: OpcuaMasterConfig = None
safe_buffer_accessor: SafeBufferAccess = None
opcua_server = None
server_thread: Optional[threading.Thread] = None
stop_event = threading.Event()


class OpcuaServer:
    """OPC-UA server implementation using opcua-asyncio."""

    def __init__(self, config: Any, sba: SafeBufferAccess):
        self.config = config
        self.sba = sba
        self.server: Optional[Server] = None
        self.variable_nodes: Dict[int, VariableNode] = {}
        self.variable_metadata: Dict[int, VariableMetadata] = {}
        self.namespace_idx = None
        self.running = False
        self._direct_memory_access_enabled = True

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

            # Initialize variable metadata cache for direct memory access
            var_indices = list(self.variable_nodes.keys())
            self.variable_metadata = initialize_variable_cache(self.sba, var_indices)
            if not self.variable_metadata:
                self._direct_memory_access_enabled = False

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
                opcua_type = map_plc_to_opcua_type(var_def.datatype)

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
                print(f"    Created variable: {current_path}")

        except Exception as e:
            print(f"(FAIL) Failed to create variable node '{current_path}': {e}")
            traceback.print_exc()
            raise





    async def update_variables_from_plc(self) -> None:
        """Optimized update loop with metadata cache"""
        try:
            if not self.variable_nodes:
                return

            # Optimized method: Direct memory access via cache
            if self._direct_memory_access_enabled and self.variable_metadata:
                await self._update_via_direct_memory_access()
            else:
                # Fallback: use batch methods (still better than individual)
                await self._update_via_batch_operations()

        except Exception as e:
            print(f"(FAIL) Error in optimized update loop: {e}")

    async def _update_via_direct_memory_access(self) -> None:
        """Direct memory access - ZERO C calls per variable!"""
        for var_index, metadata in self.variable_metadata.items():
            try:
                # Direct memory access - no C calls!
                value = read_memory_direct(metadata.address, metadata.size)

                var_node = self.variable_nodes[var_index]
                await self._update_opcua_node(var_node, value)

            except Exception as e:
                print(f"(FAIL) Direct memory access failed for var {var_index}: {e}")

    async def _update_via_batch_operations(self) -> None:
        """Fallback: batch operations (still much better than individual)"""
        var_indices = list(self.variable_nodes.keys())

        # Single batch call for all values
        results, msg = self.sba.get_var_values_batch(var_indices)

        if msg != "Success":
            print(f"(FAIL) Batch read failed: {msg}")
            return

        # Process results
        for i, (value, var_msg) in enumerate(results):
            var_index = var_indices[i]
            var_node = self.variable_nodes[var_index]

            if var_msg == "Success" and value is not None:
                await self._update_opcua_node(var_node, value)
            else:
                print(f"(FAIL) Failed to read variable {var_index}: {var_msg}")

    async def _update_opcua_node(self, var_node: VariableNode, value: Any) -> None:
        """Update an OPC-UA node with a new value."""
        try:
            # Convert value if necessary for OPC-UA format
            opcua_value = convert_value_for_opcua(var_node.datatype, value)
            await var_node.node.write_value(ua.Variant(opcua_value))
        except Exception as e:
            print(f"(FAIL) Failed to update OPC-UA node for debug variable {var_node.debug_var_index}: {e}")

    async def _initialize_variable_cache(self, indices: List[int]) -> None:
        """Initialize metadata cache for direct memory access."""
        self.variable_metadata = initialize_variable_cache(self.sba, indices)
        if not self.variable_metadata:
            self._direct_memory_access_enabled = False

    async def _add_write_callback(self, node: Node, var_index: int) -> None:
        """Add a write callback to an OPC-UA node for writing back to PLC."""
        try:
            # Define the callback function
            async def write_callback(node, val, data):
                try:
                    # Extract the value from the OPC-UA variant
                    opcua_value = val.Value

                    # Convert OPC-UA value to PLC format if needed
                    plc_value = convert_value_for_plc(self.variable_nodes[var_index].datatype, opcua_value)

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
