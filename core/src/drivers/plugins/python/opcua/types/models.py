"""
Data models for OPC UA plugin.

This module defines the internal data structures used by the plugin
for managing OPC UA nodes and their mapping to PLC variables.
"""

from dataclasses import dataclass, field
from typing import Optional, Any, Literal
from enum import Enum

from asyncua.common.node import Node


class AccessMode(Enum):
    """Access mode for OPC UA variables."""
    READ_ONLY = "readonly"
    READ_WRITE = "readwrite"


class UserRole(Enum):
    """User roles for permission management."""
    VIEWER = "viewer"
    OPERATOR = "operator"
    ENGINEER = "engineer"


PermissionLevel = Literal["", "r", "w", "rw"]


@dataclass
class NodePermissions:
    """
    Permission settings for an OPC UA node.
    
    Defines read/write access per user role.
    """
    viewer: PermissionLevel = "r"
    operator: PermissionLevel = "r"
    engineer: PermissionLevel = "rw"
    
    def can_read(self, role: UserRole) -> bool:
        """Check if role has read permission."""
        perm = self._get_permission(role)
        return "r" in perm
    
    def can_write(self, role: UserRole) -> bool:
        """Check if role has write permission."""
        perm = self._get_permission(role)
        return "w" in perm
    
    def has_any_write(self) -> bool:
        """Check if any role has write permission."""
        return (
            "w" in self.viewer or
            "w" in self.operator or
            "w" in self.engineer
        )
    
    def _get_permission(self, role: UserRole) -> str:
        """Get permission string for a role."""
        if role == UserRole.VIEWER:
            return self.viewer
        elif role == UserRole.OPERATOR:
            return self.operator
        elif role == UserRole.ENGINEER:
            return self.engineer
        return ""
    
    @classmethod
    def from_dict(cls, data: dict) -> 'NodePermissions':
        """Create from dictionary."""
        return cls(
            viewer=data.get("viewer", "r"),
            operator=data.get("operator", "r"),
            engineer=data.get("engineer", "rw")
        )


@dataclass
class VariableNode:
    """
    Represents an OPC UA node mapped to a PLC variable.
    
    This is the runtime representation of a variable after
    the OPC UA node has been created.
    """
    node: Node
    plc_index: int
    datatype: str
    access_mode: AccessMode
    permissions: NodePermissions
    node_id: str = ""
    is_array: bool = False
    array_length: int = 0
    
    @property
    def is_writable(self) -> bool:
        """Check if this node allows writes."""
        return self.access_mode == AccessMode.READ_WRITE


@dataclass
class VariableMetadata:
    """
    Metadata cache for direct memory access optimization.
    
    Stores pre-computed information about PLC variables
    to enable fast memory reads without repeated lookups.
    """
    index: int
    address: int
    size: int
    datatype: str
    
    def is_valid(self) -> bool:
        """Check if metadata is valid for memory access."""
        return self.address > 0 and self.size > 0


@dataclass
class VariableDefinition:
    """
    Definition of a variable from configuration.
    
    This represents the configuration-time definition before
    the OPC UA node is created.
    """
    node_id: str
    browse_name: str
    display_name: str
    datatype: str
    initial_value: Any
    description: str
    plc_index: int
    permissions: NodePermissions
    
    @classmethod
    def from_dict(cls, data: dict) -> 'VariableDefinition':
        """Create from dictionary."""
        return cls(
            node_id=data["node_id"],
            browse_name=data["browse_name"],
            display_name=data["display_name"],
            datatype=data["datatype"],
            initial_value=data.get("initial_value", 0),
            description=data.get("description", ""),
            plc_index=data["index"],
            permissions=NodePermissions.from_dict(data.get("permissions", {}))
        )


@dataclass
class StructFieldDefinition:
    """Definition of a field within a struct."""
    name: str
    datatype: str
    initial_value: Any
    plc_index: int
    permissions: NodePermissions
    
    @classmethod
    def from_dict(cls, data: dict) -> 'StructFieldDefinition':
        """Create from dictionary."""
        return cls(
            name=data["name"],
            datatype=data["datatype"],
            initial_value=data.get("initial_value", 0),
            plc_index=data["index"],
            permissions=NodePermissions.from_dict(data.get("permissions", {}))
        )


@dataclass
class StructDefinition:
    """Definition of a struct variable from configuration."""
    node_id: str
    browse_name: str
    display_name: str
    description: str
    fields: list[StructFieldDefinition] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'StructDefinition':
        """Create from dictionary."""
        fields = [
            StructFieldDefinition.from_dict(f)
            for f in data.get("fields", [])
        ]
        return cls(
            node_id=data["node_id"],
            browse_name=data["browse_name"],
            display_name=data["display_name"],
            description=data.get("description", ""),
            fields=fields
        )


@dataclass
class ArrayDefinition:
    """Definition of an array variable from configuration."""
    node_id: str
    browse_name: str
    display_name: str
    datatype: str
    length: int
    initial_value: Any
    plc_index: int
    permissions: NodePermissions
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ArrayDefinition':
        """Create from dictionary."""
        return cls(
            node_id=data["node_id"],
            browse_name=data["browse_name"],
            display_name=data["display_name"],
            datatype=data["datatype"],
            length=data["length"],
            initial_value=data.get("initial_value", 0),
            plc_index=data["index"],
            permissions=NodePermissions.from_dict(data.get("permissions", {}))
        )
