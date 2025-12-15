import sys
import os
import asyncio
import threading
import time
import traceback
import hashlib
from typing import Optional, Dict, Any, List, Tuple

from asyncua import Server, ua
from asyncua.common.node import Node
from asyncua.server.user_managers import UserManager, UserRole
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator
from asyncua.common.callback import CallbackType

# Add the parent directory to Python path to find shared module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the correct type definitions
from shared import (
    SafeBufferAccess,
    SafeLoggingAccess,
    PluginRuntimeArgs,
    safe_extract_runtime_args_from_capsule,
)

# Import the configuration model
from shared.plugin_config_decode.opcua_config_model import (
    OpcuaMasterConfig,
    SecurityProfile,
    User,
    VariablePermissions,
    VariableField,
    SimpleVariable,
    StructVariable,
    ArrayVariable,
)

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
    from .opcua_security import OpcuaSecurityManager
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
    from opcua_security import OpcuaSecurityManager

# Global variables for plugin lifecycle and configuration
runtime_args = None
opcua_config: OpcuaMasterConfig = None
safe_buffer_accessor: SafeBufferAccess = None
safe_logging_accessor: SafeLoggingAccess = None
opcua_server = None
server_thread: Optional[threading.Thread] = None
stop_event = threading.Event()


def log_info(message: str) -> None:
    """Log an informational message using the runtime logging system."""
    global safe_logging_accessor
    if safe_logging_accessor and safe_logging_accessor.is_valid:
        safe_logging_accessor.log_info(message)
    else:
        print(f"(INFO) {message}")


def log_warn(message: str) -> None:
    """Log a warning message using the runtime logging system."""
    global safe_logging_accessor
    if safe_logging_accessor and safe_logging_accessor.is_valid:
        safe_logging_accessor.log_warn(message)
    else:
        print(f"(WARN) {message}")


def log_error(message: str) -> None:
    """Log an error message using the runtime logging system."""
    global safe_logging_accessor
    if safe_logging_accessor and safe_logging_accessor.is_valid:
        safe_logging_accessor.log_error(message)
    else:
        print(f"(ERROR) {message}")


class OpenPLCUserManager(UserManager):
    """Custom user manager for OpenPLC authentication."""

    # Map OpenPLC roles to asyncua UserRole enum
    ROLE_MAPPING = {
        "viewer": UserRole.User,      # Read-only access
        "operator": UserRole.User,    # Read/write access (controlled by callbacks)
        "engineer": UserRole.Admin    # Full access
    }

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.users = {user.username: user for user in config.users if user.type == "password"}
        self.cert_users = {user.certificate_id: user for user in config.users if user.type == "certificate"}
        
        # Build security policy URI mapping
        self._policy_uri_mapping = self._build_policy_uri_mapping()

    def get_user(self, isession, username=None, password=None, certificate=None):
        """Authenticate user with security profile enforcement."""
        # Detect authentication method first
        auth_method = self._detect_auth_method(username, password, certificate)
        log_info(f"Authentication attempt detected: method={auth_method}")

        # Try to resolve the profile normally
        profile = self._get_profile_for_session(isession)

        # FALLBACK: if cannot resolve profile, try to find one that supports the auth method
        if not profile:
            policy_uri = getattr(isession, 'security_policy_uri', None)
            log_warn(
                f"No security profile mapped for session (policy_uri={policy_uri}). "
                f"Attempting fallback using auth method: {auth_method}"
            )

            # Try to find a profile that supports this authentication method
            profile = self._find_profile_by_auth_method(auth_method)
            
            if profile:
                log_info(f"Using fallback security profile: '{profile.name}' (supports {auth_method})")
            else:
                log_error(
                    f"No security profile found that supports authentication method '{auth_method}'. "
                    f"Session policy URI: {policy_uri}"
                )
                return None

        # Validate that the profile supports the authentication method
        if auth_method not in profile.auth_methods:
            log_error(
                f"Authentication method '{auth_method}' not allowed for security profile "
                f"'{profile.name}'. Allowed methods: {profile.auth_methods}"
            )
            return None

        # Authenticate based on method
        user = None

        if auth_method == "Username" and username and password:
            if username in self.users:
                user_candidate = self.users[username]
                if self._validate_password(password, user_candidate.password_hash):
                    user = user_candidate
                    # Add asyncua-compatible role and preserve OpenPLC role
                    user.openplc_role = user.role
                    user.role = self.ROLE_MAPPING.get(user.openplc_role, UserRole.User)
                else:
                    log_warn(f"Password validation failed for user '{username}'")
            else:
                log_warn(f"User '{username}' not found in configuration")

        elif auth_method == "Certificate" and certificate:
            cert_id = self._extract_cert_id(certificate)
            if cert_id and cert_id in self.cert_users:
                user = self.cert_users[cert_id]
                # Add asyncua-compatible role and preserve OpenPLC role
                user.openplc_role = user.role
                user.role = self.ROLE_MAPPING.get(user.openplc_role, UserRole.User)
                log_info(f"Certificate authenticated as user with role '{user.openplc_role}'")
            else:
                log_warn(f"Certificate not found in trusted certificates (cert_id={cert_id})")

        elif auth_method == "Anonymous":
            if "Anonymous" in profile.auth_methods:
                from types import SimpleNamespace
                user = SimpleNamespace()
                user.username = "anonymous"
                user.openplc_role = "viewer"
                user.role = UserRole.User  # Map to asyncua UserRole enum
            else:
                log_warn("Anonymous authentication not allowed for this profile")

        if user:
            log_info(
                f"User '{getattr(user, 'username', 'anonymous')}' authenticated successfully "
                f"using '{auth_method}' method for profile '{profile.name}'"
            )
            return user
        else:
            log_warn(
                f"Authentication failed for method '{auth_method}' on profile '{profile.name}'"
            )
            return None

    def _extract_cert_id(self, certificate) -> Optional[str]:
        """Extract certificate ID using fingerprint matching."""
        try:
            # Convert session certificate to fingerprint
            client_fingerprint = self._cert_to_fingerprint(certificate)
            if not client_fingerprint:
                return None
            
            # Compare with configured certificate fingerprints
            for cert_info in self.config.security.trusted_client_certificates:
                config_fingerprint = self._pem_to_fingerprint(cert_info["pem"])
                if config_fingerprint and client_fingerprint == config_fingerprint:
                    log_info(f"Certificate matched: {cert_info['id']} (fingerprint: {client_fingerprint[:16]}...)")
                    return cert_info["id"]
            
            log_warn(f"Certificate not found in trusted list (fingerprint: {client_fingerprint[:16]}...)")
        except Exception as e:
            log_error(f"Certificate fingerprint extraction failed: {e}")
        
        return None

    def _build_policy_uri_mapping(self) -> Dict[str, str]:
        """Build mapping from OPC-UA security policy URIs to profile names."""
        # Standard OPC-UA security policy URIs
        uri_mapping = {}
        
        for profile in self.config.server.security_profiles:
            if not profile.enabled:
                continue
                
            # Map config policy+mode to standard OPC-UA URI
            policy_uri = self._get_standard_policy_uri(profile.security_policy, profile.security_mode)
            if policy_uri:
                uri_mapping[policy_uri] = profile.name
        
        log_info(f"Built security policy URI mapping: {uri_mapping}")
        return uri_mapping
    
    def _get_standard_policy_uri(self, security_policy: str, security_mode: str) -> Optional[str]:
        """Get standard OPC-UA security policy URI for config values."""
        # Map config values to standard OPC-UA security policy URIs
        if security_policy == "None" and security_mode == "None":
            return "http://opcfoundation.org/UA/SecurityPolicy#None"
        elif security_policy == "Basic256Sha256":
            return "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
        elif security_policy == "Aes128_Sha256_RsaOaep":
            return "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
        elif security_policy == "Aes256_Sha256_RsaPss":
            return "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
        else:
            log_warn(f"Unknown security policy: {security_policy}")
            return None
    
    def _get_profile_for_session(self, isession) -> Optional[object]:
        """Get security profile for the session based on its security policy URI."""
        try:
            # DEBUG: Log all session attributes
            session_attrs = [attr for attr in dir(isession) if not attr.startswith('_')]
            log_info(f"Session attributes: {session_attrs}")
            
            policy_uri = getattr(isession, 'security_policy_uri', None)
            if not policy_uri:
                log_warn("Session has no security_policy_uri attribute")
                # DEBUG: Try alternative attributes
                for attr in ['security_policy', 'policy_uri', 'endpoint_url']:
                    if hasattr(isession, attr):
                        log_info(f"Session has {attr}: {getattr(isession, attr)}")
                return None
            
            profile_name = self._policy_uri_mapping.get(policy_uri)
            if not profile_name:
                log_warn(f"No profile mapping found for policy URI: {policy_uri}")
                return None
            
            # Find the profile object
            for profile in self.config.server.security_profiles:
                if profile.name == profile_name and profile.enabled:
                    return profile
            
            log_error(f"Profile '{profile_name}' not found or disabled in configuration")
            return None
        except Exception as e:
            log_error(f"Failed to resolve security profile for session: {e}")
            return None
    
    def _cert_to_fingerprint(self, certificate) -> Optional[str]:
        """Convert certificate object to SHA256 fingerprint."""
        try:
            if hasattr(certificate, 'der'):
                # Certificate object with der attribute
                cert_der = certificate.der
            elif hasattr(certificate, 'data'):
                # Certificate object with data attribute  
                cert_der = certificate.data
            elif isinstance(certificate, bytes):
                # Raw certificate data
                cert_der = certificate
            else:
                # Try to convert to string and then decode
                cert_str = str(certificate)
                if "-----BEGIN CERTIFICATE-----" in cert_str:
                    # PEM format - extract base64 content
                    import base64
                    cert_lines = cert_str.split('\n')
                    cert_b64 = ''.join([line for line in cert_lines if not line.startswith('-----')])
                    cert_der = base64.b64decode(cert_b64)
                else:
                    log_warn(f"Unknown certificate format: {type(certificate)}")
                    return None
            
            # Calculate SHA256 fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        except Exception as e:
            log_error(f"Failed to extract certificate fingerprint: {e}")
            return None
    
    def _pem_to_fingerprint(self, pem_str: str) -> Optional[str]:
        """Convert PEM certificate string to SHA256 fingerprint."""
        try:
            import base64
            # Extract base64 content from PEM
            pem_lines = pem_str.strip().split('\n')
            cert_b64 = ''.join([line for line in pem_lines if not line.startswith('-----')])
            cert_der = base64.b64decode(cert_b64)
            
            # Calculate SHA256 fingerprint
            fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        except Exception as e:
            log_error(f"Failed to convert PEM to fingerprint: {e}")
            return None

    def _detect_auth_method(self, username: Optional[str], password: Optional[str], certificate: Optional[object]) -> str:
        """Detect which authentication method is being used."""
        if certificate:
            return "Certificate"
        elif username and password:
            return "Username"
        else:
            return "Anonymous"

    def _find_profile_by_auth_method(self, auth_method: str) -> Optional[object]:
        """Find a security profile that supports the given authentication method."""
        for profile in self.config.server.security_profiles:
            if not profile.enabled:
                continue
            if auth_method in profile.auth_methods:
                log_info(f"Found profile '{profile.name}' supporting {auth_method}")
                return profile
        
        log_warn(f"No enabled profile found supporting authentication method: {auth_method}")
        return None

    def _validate_password(self, password: str, password_hash: str) -> bool:
        """Validate password against hash using bcrypt or fallback."""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except ImportError:
            # Fallback to simple comparison (not secure for production)
            log_warn("bcrypt not available, using insecure password comparison")
            return password == password_hash


class OpcuaServer:
    """OPC-UA server implementation using native asyncua APIs."""

    def __init__(self, config: Any, sba: SafeBufferAccess):
        self.config = config
        self.sba = sba
        self.server: Optional[Server] = None
        self.variable_nodes: Dict[int, VariableNode] = {}
        self.variable_metadata: Dict[int, VariableMetadata] = {}
        self.namespace_idx = None
        self.running = False
        self._direct_memory_access_enabled = True
        self.user_manager = OpenPLCUserManager(config)
        self.trust_store = None
        self.cert_validator = None
        self.temp_cert_files = []  # Track temporary certificate files for cleanup
        self.node_permissions: Dict[str, VariablePermissions] = {}  # Maps node_id -> permissions
        self.security_manager = OpcuaSecurityManager(config, os.path.dirname(__file__))

    async def setup_server(self) -> bool:
        """Initialize and configure the OPC-UA server using native asyncua APIs."""
        try:
            # Create server instance with user manager
            self.server = Server(user_manager=self.user_manager)

            # Set the endpoint URL from configuration with normalization BEFORE init
            try:
                from .opcua_endpoints_config import normalize_endpoint_url, suggest_client_endpoints
                normalized_endpoint = normalize_endpoint_url(self.config.server.endpoint_url)
                self.server.set_endpoint(normalized_endpoint)
                
                # Store suggestions for later printing
                self._client_endpoints = suggest_client_endpoints(normalized_endpoint)
                log_info(f"Server endpoint set to: {normalized_endpoint}")
            except ImportError:
                # Fallback if endpoints config is not available
                self.server.set_endpoint(self.config.server.endpoint_url)
                self._client_endpoints = {}
                log_info(f"Server endpoint set to: {self.config.server.endpoint_url}")
            
            # Set server name and URIs BEFORE init
            self.server.set_server_name(self.config.server.name)
            self.server.application_uri = self.config.server.application_uri
            
            # Configure security using SecurityManager BEFORE init
            # Pass the application_uri from config to ensure certificate matches
            await self.security_manager.setup_server_security(
                self.server, 
                self.config.server.security_profiles,
                app_uri=self.config.server.application_uri
            )
            
            # Setup certificate validation using SecurityManager BEFORE init
            await self.security_manager.setup_certificate_validation(
                self.server, 
                self.config.security.trusted_client_certificates
            )

            # NOW initialize the server
            await self.server.init()
            log_info("OPC-UA server initialized")

            # Set build info AFTER init
            from datetime import datetime
            await self.server.set_build_info(
                product_uri=self.config.server.product_uri,
                manufacturer_name="Autonomy Logic",
                product_name="OpenPLC Runtime",
                software_version="1.0.0",
                build_number="1.0.0.0",
                build_date=datetime.now()
            )

            # Register namespace AFTER init
            self.namespace_idx = await self.server.register_namespace(self.config.address_space.namespace_uri)
            log_info(f"Registered namespace: {self.config.address_space.namespace_uri} (index: {self.namespace_idx})")

            # Setup callbacks for auditing
            await self._setup_callbacks()

            log_info(f"OPC-UA server setup completed successfully")
            return True

        except Exception as e:
            log_error(f"Failed to setup OPC-UA server: {e}")
            traceback.print_exc()
            return False

    async def _debug_endpoints(self) -> None:
        """Debug method to verify endpoint configuration after server initialization."""
        try:
            log_info("=== ENDPOINT VERIFICATION ===")
            endpoints = await self.server.get_endpoints()
            log_info(f"Total endpoints created: {len(endpoints)}")
            
            for i, endpoint in enumerate(endpoints):
                log_info(f"Endpoint {i+1}:")
                log_info(f"  URL: {endpoint.EndpointUrl}")
                log_info(f"  Security Policy URI: {endpoint.SecurityPolicyUri}")
                log_info(f"  Security Mode: {endpoint.SecurityMode}")
                log_info(f"  Server Certificate: {len(endpoint.ServerCertificate) if endpoint.ServerCertificate else 0} bytes")
                
                # List user identity tokens
                log_info(f"  User Identity Tokens: {len(endpoint.UserIdentityTokens)}")
                for j, token in enumerate(endpoint.UserIdentityTokens):
                    log_info(f"    Token {j+1}: {token.TokenType}, Policy: {token.PolicyId}")
                    if hasattr(token, 'SecurityPolicyUri'):
                        log_info(f"    Token Security Policy: {token.SecurityPolicyUri}")
            
            log_info("=== END ENDPOINT VERIFICATION ===")
        except Exception as e:
            log_error(f"Error during endpoint verification: {e}")

    async def _setup_callbacks(self) -> None:
        """Setup callbacks for auditing and access control."""
        # Get all nodes that need callbacks (readwrite variables)
        nodes_requiring_callbacks = []

        # Simple variables
        for var in self.config.address_space.variables:
            if var.permissions.engineer == "rw" or var.permissions.operator == "rw":
                nodes_requiring_callbacks.append(var.node_id)

        # Struct fields
        for struct in self.config.address_space.structures:
            for field in struct.fields:
                if field.permissions.engineer == "rw" or field.permissions.operator == "rw":
                    nodes_requiring_callbacks.append(f"{struct.node_id}.{field.name}")

        # Arrays
        for arr in self.config.address_space.arrays:
            if arr.permissions.engineer == "rw" or arr.permissions.operator == "rw":
                nodes_requiring_callbacks.append(arr.node_id)

        # Register callbacks for all nodes that have any write permissions
        if nodes_requiring_callbacks:
            log_info(f"Registering callbacks for {len(nodes_requiring_callbacks)} nodes")
            try:
                # Register pre-read and pre-write callbacks with the server
                from asyncua.common.callback import CallbackType
                if self.server.iserver is not None:
                    await self.server.iserver.subscribe_server_callback(CallbackType.PreRead, self._on_pre_read)
                    await self.server.iserver.subscribe_server_callback(CallbackType.PreWrite, self._on_pre_write)
                    log_info("Successfully registered permission callbacks")
                else:
                    log_warn("Server iserver is None, cannot register callbacks")
            except Exception as e:
                log_warn(f"Failed to register callbacks: {e}")

    async def _on_pre_read(self, event, dispatcher):
        """Callback for pre-read operations with permission enforcement."""
        # Extract user from event
        user = getattr(event, 'user', None)
        
        # The event contains request_params with ReadValueIds
        if not hasattr(event, 'request_params') or not hasattr(event.request_params, 'NodesToRead'):
            return
        
        # Process each node being read
        for read_value_id in event.request_params.NodesToRead:
            node_id = str(read_value_id.NodeId)
            
            # Extract actual node_id from the full node string if needed
            if node_id.startswith("ns=") and ";" in node_id:
                # Extract the part after the last semicolon for comparison
                node_parts = node_id.split(";")[-1]
                if "=" in node_parts:
                    simple_node_id = node_parts.split("=", 1)[-1]
                else:
                    simple_node_id = node_parts
            else:
                simple_node_id = node_id
            
            # Check if we have permissions configured for this node
            permissions = None
            for stored_node_id, perms in self.node_permissions.items():
                if stored_node_id == simple_node_id or stored_node_id.endswith(simple_node_id):
                    permissions = perms
                    break
            
            if permissions and user and hasattr(user, 'openplc_role'):
                user_role = user.openplc_role  # Use OpenPLC role for permission checks
                role_permission = getattr(permissions, user_role, "")
                
                if "r" not in role_permission:
                    log_warn(f"DENY read for user {getattr(user, 'username', 'unknown')} (role: {user_role}) on node {simple_node_id}")
                    raise ua.UaError(f"Access denied: insufficient read permissions")

    async def _on_pre_write(self, event, dispatcher):
        """Callback for pre-write operations with permission enforcement."""
        # Extract user from event
        user = getattr(event, 'user', None)
        
        # The event contains request_params with WriteValues
        if not hasattr(event, 'request_params') or not hasattr(event.request_params, 'NodesToWrite'):
            return
        
        # Process each node being written
        for write_value in event.request_params.NodesToWrite:
            node_id = str(write_value.NodeId)
            value = write_value.Value.Value if hasattr(write_value, 'Value') else None
            
            # Extract actual node_id from the full node string if needed
            if node_id.startswith("ns=") and ";" in node_id:
                # Extract the part after the last semicolon for comparison
                node_parts = node_id.split(";")[-1]
                if "=" in node_parts:
                    simple_node_id = node_parts.split("=", 1)[-1]
                else:
                    simple_node_id = node_parts
            else:
                simple_node_id = node_id
            
            # Check if we have permissions configured for this node
            permissions = None
            for stored_node_id, perms in self.node_permissions.items():
                if stored_node_id == simple_node_id or stored_node_id.endswith(simple_node_id):
                    permissions = perms
                    break
            
            if not user:
                log_warn(f"DENY write for anonymous user on node {simple_node_id}")
                raise ua.UaError(f"Access denied: anonymous write not allowed")
            
            if permissions and hasattr(user, 'openplc_role'):
                user_role = user.openplc_role  # Use OpenPLC role for permission checks
                role_permission = getattr(permissions, user_role, "")
                
                if "w" not in role_permission:
                    log_warn(f"DENY write for user {getattr(user, 'username', 'unknown')} (role: {user_role}) on node {simple_node_id}: {value}")
                    raise ua.UaError(f"Access denied: insufficient write permissions")

    async def create_variable_nodes(self) -> bool:
        """Create OPC-UA nodes for all configured variables, structs and arrays."""
        try:
            if not self.server or self.namespace_idx is None:
                log_error("Server not initialized")
                return False

            # Get the Objects folder
            objects = self.server.get_objects_node()

            # Create simple variables
            for var in self.config.address_space.variables:
                try:
                    await self._create_simple_variable(objects, var)
                except Exception as e:
                    log_error(f"Error creating variable {var.node_id}: {e}")
                    traceback.print_exc()

            # Create structures
            for struct in self.config.address_space.structures:
                try:
                    await self._create_struct(objects, struct)
                except Exception as e:
                    log_error(f"Error creating struct {struct.node_id}: {e}")
                    traceback.print_exc()

            # Create arrays
            for arr in self.config.address_space.arrays:
                try:
                    await self._create_array(objects, arr)
                except Exception as e:
                    log_error(f"Error creating array {arr.node_id}: {e}")
                    traceback.print_exc()

            # Initialize variable metadata cache for direct memory access
            var_indices = list(self.variable_nodes.keys())
            self.variable_metadata = initialize_variable_cache(self.sba, var_indices)
            if not self.variable_metadata:
                self._direct_memory_access_enabled = False

            log_info(f"Created {len(self.variable_nodes)} variable nodes")
            return True

        except Exception as e:
            log_error(f"Failed to create variable nodes: {e}")
            traceback.print_exc()
            return False

    async def _create_simple_variable(self, parent_node: Node, var: SimpleVariable) -> None:
        """Create a simple OPC-UA variable node."""
        # Creating simple variable: {var.node_id} ({var.datatype}, index: {var.index})

        opcua_type = map_plc_to_opcua_type(var.datatype)
        initial_value = convert_value_for_opcua(var.datatype, var.initial_value)

        # Create the variable node
        node = await parent_node.add_variable(
            self.namespace_idx,
            var.browse_name,
            ua.Variant(initial_value, opcua_type),
            datatype=opcua_type
        )

        # Set display name and description
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(var.display_name), ua.VariantType.LocalizedText)))
        await node.write_attribute(ua.AttributeIds.Description, ua.DataValue(ua.Variant(ua.LocalizedText(var.description), ua.VariantType.LocalizedText)))

        # Set access level based on permissions - if any role has write, enable write
        access_level = ua.AccessLevel.CurrentRead
        has_write_permission = (
            "w" in var.permissions.viewer or 
            "w" in var.permissions.operator or 
            "w" in var.permissions.engineer
        )
        if has_write_permission:
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))
        await node.write_attribute(ua.AttributeIds.UserAccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        access_mode = "readwrite" if has_write_permission else "readonly"
        var_node = VariableNode(
            node=node,
            debug_var_index=var.index,
            datatype=var.datatype,
            access_mode=access_mode,
            is_array_element=False
        )

        self.variable_nodes[var.index] = var_node
        # Store node permissions for runtime checks
        self.node_permissions[var.node_id] = var.permissions
        # Created variable: {var.node_id}

    async def _create_struct(self, parent_node: Node, struct: StructVariable) -> None:
        """Create an OPC-UA struct (object with fields)."""
        # Creating struct: {struct.node_id}

        # Create parent object for the struct
        struct_obj = await parent_node.add_object(self.namespace_idx, struct.browse_name)

        # Set display name and description
        await struct_obj.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(struct.display_name), ua.VariantType.LocalizedText)))
        await struct_obj.write_attribute(ua.AttributeIds.Description, ua.DataValue(ua.Variant(ua.LocalizedText(struct.description), ua.VariantType.LocalizedText)))

        # Create fields
        for field in struct.fields:
            await self._create_struct_field(struct_obj, struct.node_id, field)

        # Created struct with {len(struct.fields)} fields

    async def _create_struct_field(self, parent_node: Node, struct_node_id: str, field: VariableField) -> None:
        """Create a field within a struct."""
        field_node_id = f"{struct_node_id}.{field.name}"
        # Creating struct field: {field_node_id} ({field.datatype}, index: {field.index})

        opcua_type = map_plc_to_opcua_type(field.datatype)
        initial_value = convert_value_for_opcua(field.datatype, field.initial_value)

        # Create the variable node
        node = await parent_node.add_variable(
            self.namespace_idx,
            field.name,
            ua.Variant(initial_value, opcua_type),
            datatype=opcua_type
        )

        # Set display name
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(field.name), ua.VariantType.LocalizedText)))

        # Set access level based on permissions - if any role has write, enable write
        access_level = ua.AccessLevel.CurrentRead
        has_write_permission = (
            "w" in field.permissions.viewer or 
            "w" in field.permissions.operator or 
            "w" in field.permissions.engineer
        )
        if has_write_permission:
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))
        await node.write_attribute(ua.AttributeIds.UserAccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        access_mode = "readwrite" if has_write_permission else "readonly"
        var_node = VariableNode(
            node=node,
            debug_var_index=field.index,
            datatype=field.datatype,
            access_mode=access_mode,
            is_array_element=False
        )

        self.variable_nodes[field.index] = var_node
        # Store node permissions for runtime checks
        self.node_permissions[field_node_id] = field.permissions
        # Created field: {field_node_id}

    async def _create_array(self, parent_node: Node, arr: ArrayVariable) -> None:
        """Create an OPC-UA array variable."""
        # Creating array: {arr.node_id} ({arr.datatype}[{arr.length}], index: {arr.index})

        opcua_type = map_plc_to_opcua_type(arr.datatype)
        initial_value = convert_value_for_opcua(arr.datatype, arr.initial_value)

        # Create array with initial values
        array_values = [initial_value] * arr.length
        array_variant = ua.Variant(array_values, opcua_type)

        # Create the variable node
        node = await parent_node.add_variable(
            self.namespace_idx,
            arr.browse_name,
            array_variant,
            datatype=opcua_type
        )

        # Set display name and description
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(arr.display_name), ua.VariantType.LocalizedText)))

        # Set access level based on permissions - if any role has write, enable write
        access_level = ua.AccessLevel.CurrentRead
        has_write_permission = (
            "w" in arr.permissions.viewer or 
            "w" in arr.permissions.operator or 
            "w" in arr.permissions.engineer
        )
        if has_write_permission:
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))
        await node.write_attribute(ua.AttributeIds.UserAccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        access_mode = "readwrite" if has_write_permission else "readonly"
        var_node = VariableNode(
            node=node,
            debug_var_index=arr.index,
            datatype=arr.datatype,
            access_mode=access_mode,
            is_array_element=False
        )

        self.variable_nodes[arr.index] = var_node
        # Store node permissions for runtime checks
        self.node_permissions[arr.node_id] = arr.permissions
        # Created array: {arr.node_id}







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
            log_error(f"Error in optimized update loop: {e}")

    async def _update_via_direct_memory_access(self) -> None:
        """Direct memory access - ZERO C calls per variable!"""
        for var_index, metadata in self.variable_metadata.items():
            try:
                # Direct memory access - no C calls!
                value = read_memory_direct(metadata.address, metadata.size)

                var_node = self.variable_nodes[var_index]
                await self._update_opcua_node(var_node, value)

            except Exception as e:
                log_error(f"Direct memory access failed for var {var_index}: {e}")

    async def _update_via_batch_operations(self) -> None:
        """Fallback: batch operations (still much better than individual)"""
        var_indices = list(self.variable_nodes.keys())

        # Single batch call for all values
        results, msg = self.sba.get_var_values_batch(var_indices)

        if msg != "Success":
            log_error(f"Batch read failed: {msg}")
            return

        # Process results
        for i, (value, var_msg) in enumerate(results):
            var_index = var_indices[i]
            var_node = self.variable_nodes[var_index]

            if var_msg == "Success" and value is not None:
                await self._update_opcua_node(var_node, value)
            else:
                log_error(f"Failed to read variable {var_index}: {var_msg}")

    async def _update_opcua_node(self, var_node: VariableNode, value: Any) -> None:
        """Update an OPC-UA node with a new value."""
        try:
            # Convert value if necessary for OPC-UA format
            opcua_value = convert_value_for_opcua(var_node.datatype, value)
            
            # Get the correct OPC-UA type for this variable
            opcua_type = map_plc_to_opcua_type(var_node.datatype)
            
            # Create Variant with explicit type to avoid auto-conversion issues
            variant = ua.Variant(opcua_value, opcua_type)
            await var_node.node.write_value(variant)
            
        except Exception as e:
            # Log the error for debugging type conversion issues
            log_error(f"Failed to update OPC-UA node for variable {var_node.debug_var_index} (type: {var_node.datatype}): {e}")

    async def _initialize_variable_cache(self, indices: List[int]) -> None:
        """Initialize metadata cache for direct memory access."""
        self.variable_metadata = initialize_variable_cache(self.sba, indices)
        if not self.variable_metadata:
            self._direct_memory_access_enabled = False

    async def sync_opcua_to_runtime(self) -> None:
        """Synchronize values from OPC-UA readwrite nodes to PLC runtime."""
        try:
            # Filter only readwrite variables
            readwrite_nodes = {
                var_index: var_node
                for var_index, var_node in self.variable_nodes.items()
                if var_node.access_mode == "readwrite"
            }

            if not readwrite_nodes:
                return

            # Collect values to write in batch
            values_to_write = []
            indices_to_write = []

            for var_index, var_node in readwrite_nodes.items():
                try:
                    # Read current value from OPC-UA node
                    opcua_value = await var_node.node.read_value()
                    
                    # Robust reading that checks if opcua_value has Value attribute
                    if hasattr(opcua_value, "Value"):
                        original_opcua_value = opcua_value.Value  # Extract from Variant
                    else:
                        original_opcua_value = opcua_value
                    # If opcua_value doesn't have Value attribute, use it directly

                    # Convert to PLC format
                    plc_value = convert_value_for_plc(var_node.datatype, original_opcua_value)
                    
                    # Debug logging for type conversion issues
                    if hasattr(opcua_value, "VariantType") and str(opcua_value.VariantType) != str(map_plc_to_opcua_type(var_node.datatype)):
                        log_info(f"Type conversion: {var_node.datatype} - OPC-UA type {opcua_value.VariantType} -> PLC value {plc_value} (original: {original_opcua_value})")

                    values_to_write.append(plc_value)
                    indices_to_write.append(var_index)

                except Exception as e:
                    # Skip this variable on error, continue with others
                    continue

            # Batch write to PLC if we have values to write
            if values_to_write and indices_to_write:
                # Combine indices and values into tuples as expected by the method
                index_value_pairs = list(zip(indices_to_write, values_to_write))
                results, msg = self.sba.set_var_values_batch(index_value_pairs)
                
                # Check if the operation was successful
                # "Batch write completed" is actually a success message, not an error
                if msg not in ["Success", "Batch write completed"]:
                    log_error(f"Batch write to PLC failed: {msg}")
                else:
                    # Check individual results for any failures
                    failed_count = 0
                    for i, (success, individual_msg) in enumerate(results):
                        if not success:
                            failed_count += 1
                            # Only log first few failures to avoid spam
                            if failed_count <= 3:
                                log_error(f"Failed to write variable index {indices_to_write[i]}: {individual_msg}")
                            elif failed_count == 4:
                                log_error(f"... and {len(results) - 3} more write failures (suppressing further messages)")
                    
                    # Log summary if there were failures
                    if failed_count > 0:
                        log_error(f"Batch write completed with {failed_count}/{len(results)} failures")

        except Exception as e:
            log_error(f"Error in OPC-UA to runtime sync: {e}")

    async def run_opcua_to_runtime_loop(self) -> None:
        """Main loop for synchronizing OPC-UA values to PLC runtime."""
        while self.running and not stop_event.is_set():
            try:
                await self.sync_opcua_to_runtime()
                await asyncio.sleep(0.050)  # 50ms interval

            except Exception as e:
                log_error(f"Error in OPC-UA to runtime loop: {e}")
                await asyncio.sleep(0.1)  # Brief pause on error



    async def start_server(self) -> bool:
        """Start the OPC-UA server."""
        try:
            if not self.server:
                log_error("Server not initialized")
                return False

            await self.server.start()
            self.running = True
            log_info(f"OPC-UA server started on {self.config.server.endpoint_url}")
            
            # DEBUG: Verify endpoints were created correctly (after server start)
            # await self._debug_endpoints()
            
            # Print alternative endpoints for client connection
            if hasattr(self, '_client_endpoints'):
                log_info("Alternative client endpoints:")
                for scenario, endpoint in self._client_endpoints.items():
                    if endpoint:
                        log_info(f"  {scenario}: {endpoint}")
            
            return True

        except Exception as e:
            log_error(f"Failed to start OPC-UA server: {e}")
            return False

    def _cleanup_temp_files(self) -> None:
        """Clean up temporary certificate files."""
        for cert_path in self.temp_cert_files:
            try:
                import os
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
                    log_info(f"Cleaned up temp certificate file: {cert_path}")
            except Exception as e:
                log_warn(f"Failed to cleanup temp certificate file {cert_path}: {e}")
        self.temp_cert_files.clear()

    async def stop_server(self) -> None:
        """Stop the OPC-UA server."""
        try:
            if self.server and self.running:
                await self.server.stop()
                self.running = False
                log_info("OPC-UA server stopped")
            
            # Clean up temporary certificate files
            self._cleanup_temp_files()

        except Exception as e:
            log_error(f"Error stopping OPC-UA server: {e}")
            # Still try to cleanup temp files even if server stop failed
            self._cleanup_temp_files()

    async def run_update_loop(self) -> None:
        """Main update loop for synchronizing PLC and OPC-UA data."""
        # Use cycle_time_ms from config, fallback to 100ms if not available
        cycle_time_ms = getattr(self.config, 'cycle_time_ms', 100)
        cycle_time = cycle_time_ms / 1000.0

        while self.running and not stop_event.is_set():
            try:
                await self.update_variables_from_plc()
                await asyncio.sleep(cycle_time)

            except Exception as e:
                log_error(f"Error in update loop: {e}")
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

            # Start both update loops in parallel
            log_info("Starting bidirectional synchronization loops")
            task_runtime_to_opcua = asyncio.create_task(opcua_server.run_update_loop())
            task_opcua_to_runtime = asyncio.create_task(opcua_server.run_opcua_to_runtime_loop())

            # Wait for both tasks to complete
            await asyncio.gather(task_runtime_to_opcua, task_opcua_to_runtime)

        except Exception as e:
            log_error(f"Error in server thread: {e}")
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

    log_info("OPC-UA Plugin - Initializing...")

    try:
        # Extract runtime arguments from capsule
        runtime_args, error_msg = safe_extract_runtime_args_from_capsule(args_capsule)
        if not runtime_args:
            log_error(f"Failed to extract runtime args: {error_msg}")
            return False

        log_info("Runtime arguments extracted successfully")

        # Create safe buffer accessor
        safe_buffer_accessor = SafeBufferAccess(runtime_args)
        if not safe_buffer_accessor.is_valid:
            log_error(f"Failed to create SafeBufferAccess: {safe_buffer_accessor.error_msg}")
            return False

        log_info("SafeBufferAccess created successfully")

        # Create safe logging accessor
        global safe_logging_accessor
        safe_logging_accessor = SafeLoggingAccess(runtime_args)
        if not safe_logging_accessor.is_valid:
            log_warn(f"Failed to create SafeLoggingAccess: {safe_logging_accessor.error_msg}")
            # Continue without logging - not a fatal error

        # Load configuration
        config_path, config_error = safe_buffer_accessor.get_config_path()
        if not config_path:
            log_error(f"Failed to get config path: {config_error}")
            return False

        log_info(f"Loading configuration from: {config_path}")

        opcua_config = OpcuaMasterConfig()
        opcua_config.import_config_from_file(config_path)
        opcua_config.validate()

        log_info(f"Configuration loaded successfully: {len(opcua_config.plugins)} plugin(s)")

        # Initialize server for the first plugin (simplified - assumes single plugin)
        if opcua_config.plugins:
            plugin_config = opcua_config.plugins[0]
            opcua_server = OpcuaServer(plugin_config.config, safe_buffer_accessor)
            log_info("OPC-UA server instance created")
        else:
            log_error("No OPC-UA plugins configured")
            return False

        return True

    except Exception as e:
        log_error(f"Error during initialization: {e}")
        traceback.print_exc()
        return False


def start_loop():
    """
    Start the main loop for the OPC-UA server.
    This function is called after successful initialization.
    """
    global server_thread, opcua_server

    log_info("OPC-UA Plugin - Starting main loop...")

    try:
        if not opcua_server:
            log_error("Plugin not properly initialized")
            return False

        # Reset stop event
        stop_event.clear()

        # Start server thread
        server_thread = threading.Thread(target=server_thread_main, daemon=True)
        server_thread.start()

        log_info("OPC-UA server thread started")
        return True

    except Exception as e:
        log_error(f"Error starting main loop: {e}")
        traceback.print_exc()
        return False


def stop_loop():
    """
    Stop the main loop and OPC-UA server.
    This function is called when the plugin needs to be stopped.
    """
    global server_thread, opcua_server

    log_info("OPC-UA Plugin - Stopping main loop...")

    try:
        if not server_thread:
            log_warn("No server thread to stop")
            return True

        # Signal thread to stop
        stop_event.set()

        # Wait for thread to finish (with timeout)
        if server_thread.is_alive():
            server_thread.join(timeout=5.0)
            if server_thread.is_alive():
                log_warn("Server thread did not stop within timeout")
            else:
                log_info("Server thread stopped successfully")

        log_info("Main loop stopped")
        return True

    except Exception as e:
        log_error(f"Error stopping main loop: {e}")
        traceback.print_exc()
        return False


def cleanup():
    """
    Clean up resources before plugin unload.
    This function is called when the plugin is being unloaded.
    """
    global runtime_args, opcua_config, safe_buffer_accessor, opcua_server, server_thread

    log_info("OPC-UA Plugin - Cleaning up...")

    try:
        # Stop server if running
        stop_loop()

        # Clean up global variables
        runtime_args = None
        opcua_config = None
        safe_buffer_accessor = None
        opcua_server = None
        server_thread = None

        log_info("Cleanup completed successfully")
        return True

    except Exception as e:
        log_error(f"Error during cleanup: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    """
    Test mode for development purposes.
    This allows running the plugin standalone for testing.
    """
