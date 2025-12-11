"""
Address space builder for OPC UA server.

This module handles creation of OPC UA nodes from configuration,
mapping PLC variables to the OPC UA address space.
"""

from typing import Optional
from datetime import datetime

from asyncua import Server, ua
from asyncua.common.node import Node

from ..logging import log_info, log_error
from ..types import TypeConverter, VariableNode, NodePermissions
from ..types.models import AccessMode
from ..security import OpenPLCPermissionRuleset


class AddressSpaceBuilder:
    """
    Builds OPC UA address space from configuration.
    
    Creates nodes for:
    - Simple variables
    - Struct objects with fields
    - Array variables
    """
    
    def __init__(
        self,
        server: Server,
        namespace_uri: str,
        permission_ruleset: Optional[OpenPLCPermissionRuleset] = None
    ):
        """
        Initialize address space builder.
        
        Args:
            server: asyncua Server instance
            namespace_uri: Namespace URI for created nodes
            permission_ruleset: Optional ruleset for registering permissions
        """
        self.server = server
        self.namespace_uri = namespace_uri
        self.namespace_idx: Optional[int] = None
        self.permission_ruleset = permission_ruleset
        self.variable_nodes: dict[int, VariableNode] = {}
    
    async def initialize(self) -> bool:
        """
        Initialize the address space builder.
        
        Registers namespace and prepares for node creation.
        
        Returns:
            True if initialization successful
        """
        try:
            self.namespace_idx = await self.server.register_namespace(self.namespace_uri)
            log_info(f"Registered namespace '{self.namespace_uri}' (index: {self.namespace_idx})")
            return True
        except Exception as e:
            log_error(f"Failed to register namespace: {e}")
            return False
    
    async def build_from_config(self, address_space_config: dict) -> dict[int, VariableNode]:
        """
        Build address space from configuration.
        
        Args:
            address_space_config: Address space configuration dictionary
            
        Returns:
            Dictionary mapping PLC indices to VariableNode objects
        """
        if self.namespace_idx is None:
            log_error("Address space builder not initialized")
            return {}
        
        objects_node = self.server.get_objects_node()
        
        # Create simple variables
        for var_config in address_space_config.get("variables", []):
            await self._create_variable(objects_node, var_config)
        
        # Create structures
        for struct_config in address_space_config.get("structures", []):
            await self._create_struct(objects_node, struct_config)
        
        # Create arrays
        for array_config in address_space_config.get("arrays", []):
            await self._create_array(objects_node, array_config)
        
        log_info(f"Created {len(self.variable_nodes)} variable nodes")
        return self.variable_nodes
    
    async def _create_variable(self, parent: Node, config: dict) -> Optional[VariableNode]:
        """Create a simple variable node."""
        try:
            node_id = config["node_id"]
            browse_name = config["browse_name"]
            display_name = config["display_name"]
            datatype = config["datatype"]
            initial_value = config.get("initial_value", 0)
            description = config.get("description", "")
            plc_index = config["index"]
            permissions = NodePermissions.from_dict(config.get("permissions", {}))
            
            # Get OPC UA type and convert initial value
            opcua_type = TypeConverter.to_opcua_type(datatype)
            opcua_value = TypeConverter.to_opcua_value(datatype, initial_value)
            
            # Create node
            node = await parent.add_variable(
                self.namespace_idx,
                browse_name,
                ua.Variant(opcua_value, opcua_type),
                datatype=opcua_type
            )
            
            # Set attributes
            await self._set_node_attributes(node, display_name, description, permissions)
            
            # Register permissions
            if self.permission_ruleset:
                self.permission_ruleset.register_node_permissions(node_id, permissions)
            
            # Create and store variable node
            access_mode = AccessMode.READ_WRITE if permissions.has_any_write() else AccessMode.READ_ONLY
            var_node = VariableNode(
                node=node,
                plc_index=plc_index,
                datatype=datatype,
                access_mode=access_mode,
                permissions=permissions,
                node_id=node_id
            )
            self.variable_nodes[plc_index] = var_node
            
            return var_node
            
        except Exception as e:
            log_error(f"Failed to create variable '{config.get('node_id', 'unknown')}': {e}")
            return None
    
    async def _create_struct(self, parent: Node, config: dict) -> None:
        """Create a struct object with field variables."""
        try:
            node_id = config["node_id"]
            browse_name = config["browse_name"]
            display_name = config["display_name"]
            description = config.get("description", "")
            
            # Create struct object
            struct_node = await parent.add_object(self.namespace_idx, browse_name)
            
            # Set display name and description
            await struct_node.write_attribute(
                ua.AttributeIds.DisplayName,
                ua.DataValue(ua.Variant(ua.LocalizedText(display_name)))
            )
            if description:
                await struct_node.write_attribute(
                    ua.AttributeIds.Description,
                    ua.DataValue(ua.Variant(ua.LocalizedText(description)))
                )
            
            # Create fields
            for field_config in config.get("fields", []):
                await self._create_struct_field(struct_node, node_id, field_config)
                
        except Exception as e:
            log_error(f"Failed to create struct '{config.get('node_id', 'unknown')}': {e}")
    
    async def _create_struct_field(
        self,
        parent: Node,
        struct_node_id: str,
        config: dict
    ) -> Optional[VariableNode]:
        """Create a field within a struct."""
        try:
            field_name = config["name"]
            datatype = config["datatype"]
            initial_value = config.get("initial_value", 0)
            plc_index = config["index"]
            permissions = NodePermissions.from_dict(config.get("permissions", {}))
            
            field_node_id = f"{struct_node_id}.{field_name}"
            
            # Get OPC UA type and convert initial value
            opcua_type = TypeConverter.to_opcua_type(datatype)
            opcua_value = TypeConverter.to_opcua_value(datatype, initial_value)
            
            # Create node
            node = await parent.add_variable(
                self.namespace_idx,
                field_name,
                ua.Variant(opcua_value, opcua_type),
                datatype=opcua_type
            )
            
            # Set attributes
            await self._set_node_attributes(node, field_name, "", permissions)
            
            # Register permissions
            if self.permission_ruleset:
                self.permission_ruleset.register_node_permissions(field_node_id, permissions)
            
            # Create and store variable node
            access_mode = AccessMode.READ_WRITE if permissions.has_any_write() else AccessMode.READ_ONLY
            var_node = VariableNode(
                node=node,
                plc_index=plc_index,
                datatype=datatype,
                access_mode=access_mode,
                permissions=permissions,
                node_id=field_node_id
            )
            self.variable_nodes[plc_index] = var_node
            
            return var_node
            
        except Exception as e:
            log_error(f"Failed to create struct field '{config.get('name', 'unknown')}': {e}")
            return None
    
    async def _create_array(self, parent: Node, config: dict) -> Optional[VariableNode]:
        """Create an array variable node."""
        try:
            node_id = config["node_id"]
            browse_name = config["browse_name"]
            display_name = config["display_name"]
            datatype = config["datatype"]
            length = config["length"]
            initial_value = config.get("initial_value", 0)
            plc_index = config["index"]
            permissions = NodePermissions.from_dict(config.get("permissions", {}))
            
            # Get OPC UA type and create array of initial values
            opcua_type = TypeConverter.to_opcua_type(datatype)
            opcua_value = TypeConverter.to_opcua_value(datatype, initial_value)
            array_values = [opcua_value] * length
            
            # Create node with array value
            node = await parent.add_variable(
                self.namespace_idx,
                browse_name,
                ua.Variant(array_values),
                datatype=opcua_type
            )
            
            # Set attributes
            await self._set_node_attributes(node, display_name, "", permissions)
            
            # Register permissions
            if self.permission_ruleset:
                self.permission_ruleset.register_node_permissions(node_id, permissions)
            
            # Create and store variable node
            access_mode = AccessMode.READ_WRITE if permissions.has_any_write() else AccessMode.READ_ONLY
            var_node = VariableNode(
                node=node,
                plc_index=plc_index,
                datatype=datatype,
                access_mode=access_mode,
                permissions=permissions,
                node_id=node_id,
                is_array=True,
                array_length=length
            )
            self.variable_nodes[plc_index] = var_node
            
            return var_node
            
        except Exception as e:
            log_error(f"Failed to create array '{config.get('node_id', 'unknown')}': {e}")
            return None
    
    async def _set_node_attributes(
        self,
        node: Node,
        display_name: str,
        description: str,
        permissions: NodePermissions
    ) -> None:
        """Set common node attributes."""
        # Set display name
        await node.write_attribute(
            ua.AttributeIds.DisplayName,
            ua.DataValue(ua.Variant(ua.LocalizedText(display_name)))
        )
        
        # Set description if provided
        if description:
            await node.write_attribute(
                ua.AttributeIds.Description,
                ua.DataValue(ua.Variant(ua.LocalizedText(description)))
            )
        
        # Set access level based on permissions
        access_level = ua.AccessLevel.CurrentRead
        if permissions.has_any_write():
            access_level |= ua.AccessLevel.CurrentWrite
        
        await node.write_attribute(
            ua.AttributeIds.AccessLevel,
            ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte))
        )
        await node.write_attribute(
            ua.AttributeIds.UserAccessLevel,
            ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte))
        )
