"""
Synchronization manager for OPC UA server.

This module handles bidirectional synchronization between
PLC memory and OPC UA nodes.
"""

import asyncio
from typing import Any, Optional

from asyncua import ua

from ..logging import log_info, log_error
from ..types import TypeConverter, VariableNode
from ..types.models import AccessMode


class SyncManager:
    """
    Manages synchronization between PLC and OPC UA.
    
    Handles:
    - PLC -> OPC UA: Reading PLC values and updating OPC UA nodes
    - OPC UA -> PLC: Reading OPC UA values and writing to PLC
    """
    
    def __init__(
        self,
        variable_nodes: dict[int, VariableNode],
        buffer_accessor: Any,
        cycle_time_ms: int = 100
    ):
        """
        Initialize sync manager.
        
        Args:
            variable_nodes: Dictionary mapping PLC indices to VariableNode objects
            buffer_accessor: SafeBufferAccess instance for PLC memory access
            cycle_time_ms: Synchronization cycle time in milliseconds
        """
        self.variable_nodes = variable_nodes
        self.buffer_accessor = buffer_accessor
        self.cycle_time_ms = cycle_time_ms
        self._running = False
    
    @property
    def cycle_time_seconds(self) -> float:
        """Get cycle time in seconds."""
        return self.cycle_time_ms / 1000.0
    
    async def start(self) -> None:
        """Start synchronization loops."""
        self._running = True
        log_info(f"Starting synchronization with {self.cycle_time_ms}ms cycle time")
    
    async def stop(self) -> None:
        """Stop synchronization loops."""
        self._running = False
        log_info("Synchronization stopped")
    
    async def run_plc_to_opcua_loop(self) -> None:
        """
        Main loop for PLC -> OPC UA synchronization.
        
        Reads values from PLC memory and updates OPC UA nodes.
        """
        while self._running:
            try:
                await self._sync_plc_to_opcua()
                await asyncio.sleep(self.cycle_time_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"Error in PLC->OPCUA sync: {e}")
                await asyncio.sleep(self.cycle_time_seconds)
    
    async def run_opcua_to_plc_loop(self) -> None:
        """
        Main loop for OPC UA -> PLC synchronization.
        
        Reads values from writable OPC UA nodes and writes to PLC.
        """
        while self._running:
            try:
                await self._sync_opcua_to_plc()
                await asyncio.sleep(self.cycle_time_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log_error(f"Error in OPCUA->PLC sync: {e}")
                await asyncio.sleep(self.cycle_time_seconds)
    
    async def _sync_plc_to_opcua(self) -> None:
        """Synchronize PLC values to OPC UA nodes."""
        if not self.variable_nodes:
            return
        
        # Get all PLC indices
        indices = list(self.variable_nodes.keys())
        
        # Batch read from PLC
        results, msg = self.buffer_accessor.get_var_values_batch(indices)
        if msg != "Success":
            log_error(f"Batch read from PLC failed: {msg}")
            return
        
        # Update OPC UA nodes
        for i, (value, var_msg) in enumerate(results):
            if var_msg != "Success" or value is None:
                continue
            
            plc_index = indices[i]
            var_node = self.variable_nodes.get(plc_index)
            if not var_node:
                continue
            
            try:
                await self._update_opcua_node(var_node, value)
            except Exception as e:
                log_error(f"Failed to update OPC UA node {plc_index}: {e}")
    
    async def _sync_opcua_to_plc(self) -> None:
        """Synchronize OPC UA values to PLC memory."""
        # Filter writable nodes
        writable_nodes = {
            idx: node for idx, node in self.variable_nodes.items()
            if node.access_mode == AccessMode.READ_WRITE
        }
        
        if not writable_nodes:
            return
        
        # Collect values to write
        write_pairs = []
        
        for plc_index, var_node in writable_nodes.items():
            try:
                # Read current OPC UA value
                opcua_value = await var_node.node.read_value()
                
                # Extract value from Variant if needed
                if hasattr(opcua_value, 'Value'):
                    raw_value = opcua_value.Value
                else:
                    raw_value = opcua_value
                
                # Convert to PLC format
                plc_value = TypeConverter.to_plc_value(var_node.datatype, raw_value)
                write_pairs.append((plc_index, plc_value))
                
            except Exception as e:
                # Skip this variable on error
                continue
        
        if not write_pairs:
            return
        
        # Batch write to PLC
        results, msg = self.buffer_accessor.set_var_values_batch(write_pairs)
        
        # Check for errors (but don't spam logs)
        if msg not in ("Success", "Batch write completed"):
            log_error(f"Batch write to PLC failed: {msg}")
    
    async def _update_opcua_node(self, var_node: VariableNode, plc_value: Any) -> None:
        """Update a single OPC UA node with a PLC value."""
        # Convert PLC value to OPC UA format
        opcua_value = TypeConverter.to_opcua_value(var_node.datatype, plc_value)
        opcua_type = TypeConverter.to_opcua_type(var_node.datatype)
        
        # Create Variant with explicit type
        variant = ua.Variant(opcua_value, opcua_type)
        
        # Write to node
        await var_node.node.write_value(variant)
