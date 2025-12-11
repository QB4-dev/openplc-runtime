"""
Permission ruleset for OPC UA server.

This module implements asyncua's PermissionRuleset interface for
enforcing role-based access control on OPC UA nodes.
"""

from typing import Optional, Any

from asyncua.crypto.permission_rules import PermissionRuleset
from asyncua.server.users import UserRole
from asyncua import ua

from ..logging import log_info, log_warn
from ..types.models import NodePermissions, UserRole as OpenPLCRole


class OpenPLCPermissionRuleset(PermissionRuleset):
    """
    Custom permission ruleset for OpenPLC.
    
    Enforces read/write permissions based on:
    - User role (viewer, operator, engineer)
    - Node-specific permission configuration
    
    This integrates with asyncua's native permission checking system.
    """
    
    def __init__(self):
        """Initialize permission ruleset."""
        super().__init__()
        self._node_permissions: dict[str, NodePermissions] = {}
    
    def register_node_permissions(self, node_id: str, permissions: NodePermissions) -> None:
        """
        Register permissions for a node.
        
        Args:
            node_id: OPC UA node identifier
            permissions: Permission settings for the node
        """
        self._node_permissions[node_id] = permissions
    
    def check_validity(self, user: Any, action_type_id: ua.ObjectIds, body: Any) -> bool:
        """
        Check if user is allowed to perform an action.
        
        This is the main entry point called by asyncua for permission checks.
        
        Args:
            user: Authenticated user object
            action_type_id: Type of action being performed
            body: Request body containing operation details
            
        Returns:
            True if action is allowed, False otherwise
        """
        # Get user role
        openplc_role = self._get_user_role(user)
        
        # Check action type
        if action_type_id == ua.ObjectIds.ReadRequest:
            return self._check_read_permission(user, openplc_role, body)
        elif action_type_id == ua.ObjectIds.WriteRequest:
            return self._check_write_permission(user, openplc_role, body)
        else:
            # Allow other operations (browse, subscribe, etc.)
            return True
    
    def _check_read_permission(self, user: Any, role: str, body: Any) -> bool:
        """Check read permission for request."""
        # Extract nodes being read
        if not hasattr(body, 'NodesToRead'):
            return True
        
        for read_value_id in body.NodesToRead:
            node_id = self._extract_node_id(read_value_id.NodeId)
            permissions = self._get_permissions(node_id)
            
            if permissions and not self._can_read(permissions, role):
                log_warn(f"Read denied for user '{self._get_username(user)}' on node '{node_id}'")
                return False
        
        return True
    
    def _check_write_permission(self, user: Any, role: str, body: Any) -> bool:
        """Check write permission for request."""
        # Extract nodes being written
        if not hasattr(body, 'NodesToWrite'):
            return True
        
        for write_value in body.NodesToWrite:
            node_id = self._extract_node_id(write_value.NodeId)
            permissions = self._get_permissions(node_id)
            
            if permissions and not self._can_write(permissions, role):
                log_warn(f"Write denied for user '{self._get_username(user)}' on node '{node_id}'")
                return False
        
        return True
    
    def _get_user_role(self, user: Any) -> str:
        """Extract OpenPLC role from user object."""
        if user is None:
            return "viewer"
        
        # Check for openplc_role attribute (set by OpenPLCUserManager)
        if hasattr(user, 'openplc_role'):
            return user.openplc_role
        
        # Fallback: map asyncua UserRole to OpenPLC role
        if hasattr(user, 'role'):
            if user.role == UserRole.Admin:
                return "engineer"
            elif user.role == UserRole.User:
                return "operator"
        
        return "viewer"
    
    def _get_username(self, user: Any) -> str:
        """Extract username from user object."""
        if user is None:
            return "anonymous"
        return getattr(user, 'username', 'unknown')
    
    def _extract_node_id(self, node_id: ua.NodeId) -> str:
        """Extract string identifier from NodeId."""
        # Handle different NodeId formats
        if node_id.Identifier is None:
            return ""
        
        if isinstance(node_id.Identifier, str):
            return node_id.Identifier
        
        return str(node_id.Identifier)
    
    def _get_permissions(self, node_id: str) -> Optional[NodePermissions]:
        """Get permissions for a node, checking various ID formats."""
        # Direct match
        if node_id in self._node_permissions:
            return self._node_permissions[node_id]
        
        # Try matching by suffix (for namespaced IDs)
        for registered_id, permissions in self._node_permissions.items():
            if node_id.endswith(registered_id) or registered_id.endswith(node_id):
                return permissions
        
        return None
    
    def _can_read(self, permissions: NodePermissions, role: str) -> bool:
        """Check if role has read permission."""
        perm = self._get_role_permission(permissions, role)
        return "r" in perm
    
    def _can_write(self, permissions: NodePermissions, role: str) -> bool:
        """Check if role has write permission."""
        perm = self._get_role_permission(permissions, role)
        return "w" in perm
    
    def _get_role_permission(self, permissions: NodePermissions, role: str) -> str:
        """Get permission string for a role."""
        if role == "viewer":
            return permissions.viewer
        elif role == "operator":
            return permissions.operator
        elif role == "engineer":
            return permissions.engineer
        return ""
