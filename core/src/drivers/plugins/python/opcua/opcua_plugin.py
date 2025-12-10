import sys
import os
import asyncio
import threading
import time
import traceback
from typing import Optional, Dict, Any, List, Tuple

from asyncua import Server, ua
from asyncua.common.node import Node
from asyncua.server.user_managers import UserManager, UserRole
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator
from asyncua.crypto.permission_rules import PermissionRuleset
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


class OpenPLCPermissionRuleset(PermissionRuleset):
    """Custom permission ruleset for OpenPLC roles."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.role_permissions = self._build_role_permissions()

    def _build_role_permissions(self) -> Dict[str, Dict[str, str]]:
        """Build permission mapping from config."""
        permissions = {}

        # Collect all variables and their permissions
        for var in self.config.address_space.variables:
            permissions[var.node_id] = {
                "viewer": var.permissions.viewer,
                "operator": var.permissions.operator,
                "engineer": var.permissions.engineer
            }

        for struct in self.config.address_space.structures:
            for field in struct.fields:
                node_id = f"{struct.node_id}.{field.name}"
                permissions[node_id] = {
                    "viewer": field.permissions.viewer,
                    "operator": field.permissions.operator,
                    "engineer": field.permissions.engineer
                }

        for arr in self.config.address_space.arrays:
            permissions[arr.node_id] = {
                "viewer": arr.permissions.viewer,
                "operator": arr.permissions.operator,
                "engineer": arr.permissions.engineer
            }

        return permissions

    def check_validity(self, user, action_type, body):
        """Check if user has permission for the action."""
        if not user or not hasattr(user, 'role'):
            return False

        user_role = user.role
        node_id = getattr(body, 'node_id', None)

        if not node_id or node_id not in self.role_permissions:
            return False

        permission = self.role_permissions[node_id].get(user_role, "r")

        if action_type == ua.AttributeIds.Value:
            if hasattr(body, 'action'):
                if body.action == "read":
                    return "r" in permission
                elif body.action == "write":
                    return "w" in permission

        return False


class OpenPLCUserManager(UserManager):
    """Custom user manager for OpenPLC authentication."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.users = {user.username: user for user in config.users if user.type == "password"}
        self.cert_users = {user.certificate_id: user for user in config.users if user.type == "certificate"}

    def get_user(self, isession, username=None, password=None, certificate=None):
        """Authenticate user."""
        if username and password:
            # Username/password authentication
            if username in self.users:
                user = self.users[username]
                # Use bcrypt for password verification if available
                try:
                    import bcrypt
                    if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                        return user
                except ImportError:
                    # Fallback to simple comparison (not secure for production)
                    if password == user.password_hash:
                        return user
        elif certificate:
            # Certificate authentication
            # Extract certificate ID from certificate
            cert_id = self._extract_cert_id(certificate)
            if cert_id in self.cert_users:
                return self.cert_users[cert_id]

        return None

    def _extract_cert_id(self, certificate) -> Optional[str]:
        """Extract certificate ID from certificate data."""
        # Simplified - in production, extract from certificate subject or fingerprint
        for cert_info in self.config.security.trusted_client_certificates:
            if cert_info["pem"] in str(certificate):
                return cert_info["id"]
        return None


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
        self.permission_ruleset = OpenPLCPermissionRuleset(config)
        self.trust_store = None
        self.cert_validator = None
        self.temp_cert_files = []  # Track temporary certificate files for cleanup

    async def setup_server(self) -> bool:
        """Initialize and configure the OPC-UA server using native asyncua APIs."""
        try:
            # Create server instance with user manager
            self.server = Server(user_manager=self.user_manager)

            # Configure basic server settings
            await self.server.init()
            
            # Set the endpoint URL from configuration with normalization
            try:
                from .opcua_endpoints_config import normalize_endpoint_url, suggest_client_endpoints
                normalized_endpoint = normalize_endpoint_url(self.config.server.endpoint_url)
                self.server.set_endpoint(normalized_endpoint)
                
                # Store suggestions for later printing
                self._client_endpoints = suggest_client_endpoints(normalized_endpoint)
            except ImportError:
                # Fallback if endpoints config is not available
                self.server.set_endpoint(self.config.server.endpoint_url)
                self._client_endpoints = {}
            
            await self.server.set_application_uri(self.config.server.application_uri)
            self.server.set_server_name(self.config.server.name)

            # Set build info
            from datetime import datetime
            await self.server.set_build_info(
                product_uri=self.config.server.product_uri,
                manufacturer_name="Autonomy Logic",
                product_name="OpenPLC Runtime",
                software_version="1.0.0",
                build_number="1.0.0.0",
                build_date=datetime.now()
            )

            # Configure security policies and endpoints
            await self._setup_security_policies()

            # Setup certificate validation
            await self._setup_certificate_validation()

            # Load server certificates
            await self._setup_server_certificates()

            # Register namespace
            self.namespace_idx = await self.server.register_namespace(self.config.address_space.namespace_uri)

            # Setup callbacks for auditing
            await self._setup_callbacks()

            print(f"(PASS) OPC-UA server initialized: {self.config.server.endpoint_url}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to setup OPC-UA server: {e}")
            traceback.print_exc()
            return False

    async def _setup_security_policies(self) -> None:
        """Setup security policies for enabled profiles."""
        security_policies = []

        for profile in self.config.server.security_profiles:
            if not profile.enabled:
                continue

            # Map security policy + mode combinations to asyncua enums
            # The SecurityPolicyType enum already includes the mode in its name
            policy_mode_map = {
                ("None", "None"): ua.SecurityPolicyType.NoSecurity,
                ("Basic256Sha256", "Sign"): ua.SecurityPolicyType.Basic256Sha256_Sign,
                ("Basic256Sha256", "SignAndEncrypt"): ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
                ("Basic256", "Sign"): ua.SecurityPolicyType.Basic256_Sign,
                ("Basic256", "SignAndEncrypt"): ua.SecurityPolicyType.Basic256_SignAndEncrypt,
                ("Basic128Rsa15", "Sign"): ua.SecurityPolicyType.Basic128Rsa15_Sign,
                ("Basic128Rsa15", "SignAndEncrypt"): ua.SecurityPolicyType.Basic128Rsa15_SignAndEncrypt,
                ("Aes128_Sha256_RsaOaep", "Sign"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
                ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
                ("Aes256_Sha256_RsaPss", "Sign"): ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
                ("Aes256_Sha256_RsaPss", "SignAndEncrypt"): ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
            }

            policy_key = (profile.security_policy, profile.security_mode)
            policy_type = policy_mode_map.get(policy_key)

            if policy_type is not None:
                security_policies.append(policy_type)
                print(f"(INFO) Added security profile '{profile.name}': {profile.security_policy}/{profile.security_mode} -> {policy_type}")
            else:
                print(f"(WARN) Unsupported security policy/mode combination '{profile.security_policy}/{profile.security_mode}' for profile '{profile.name}', skipping")

        if security_policies:
            self.server.set_security_policy(security_policies)
        else:
            # Default to no security if no profiles enabled
            self.server.set_security_policy([ua.SecurityPolicyType.NoSecurity])

    async def _setup_certificate_validation(self) -> None:
        """Setup certificate validation using TrustStore and CertificateValidator."""
        if not self.config.security.trusted_client_certificates:
            return

        try:
            # NEW APPROACH: Use cryptography library to handle PEM certificates properly
            # This fixes the ASN.1 parsing error when loading PEM certificate strings
            USE_CRYPTOGRAPHY_APPROACH = True  # Set to False to revert to old asyncua-only approach

            if USE_CRYPTOGRAPHY_APPROACH:
                # Import cryptography for certificate handling
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import serialization
                import tempfile
                import os
                from pathlib import Path

                cert_file_paths = []
                for cert_info in self.config.security.trusted_client_certificates:
                    try:
                        cert_pem = cert_info["pem"]

                        # Load certificate using cryptography (handles PEM format correctly)
                        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

                        # Convert to DER format for asyncua TrustStore
                        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)

                        # Create temporary file for the certificate
                        cert_fd, cert_path = tempfile.mkstemp(suffix='.der', prefix='trusted_cert_')
                        try:
                            with os.fdopen(cert_fd, 'wb') as f:
                                f.write(cert_der)
                            cert_file_paths.append(Path(cert_path))
                            self.temp_cert_files.append(cert_path)  # Track for cleanup
                            print(f"(INFO) Loaded trusted certificate: {cert_info['id']} -> {cert_path}")
                        except Exception as e:
                            os.close(cert_fd)  # Close if writing failed
                            raise e

                    except Exception as e:
                        print(f"(WARN) Failed to load certificate {cert_info['id']}: {e}")

            else:
                # OLD APPROACH: Direct asyncua certificate loading (kept for easy reversion)
                # This approach fails with PEM strings because load_certificate expects DER or file paths
                from asyncua.crypto.cert_gen import load_certificate
                from cryptography import x509
                import tempfile
                import os
                from pathlib import Path

                cert_file_paths = []
                for cert_info in self.config.security.trusted_client_certificates:
                    try:
                        cert_pem = cert_info["pem"]
                        # Load certificate using asyncua's function
                        cert = await load_certificate(cert_pem.encode())
                        
                        # For OLD approach, we also need to create temp files as TrustStore expects paths
                        # Convert cert to DER and save to temp file
                        cert_der = cert.public_bytes(encoding=x509.Encoding.DER)
                        cert_fd, cert_path = tempfile.mkstemp(suffix='.der', prefix='trusted_cert_')
                        try:
                            with os.fdopen(cert_fd, 'wb') as f:
                                f.write(cert_der)
                            cert_file_paths.append(Path(cert_path))
                            self.temp_cert_files.append(cert_path)  # Track for cleanup
                            print(f"(INFO) Loaded trusted certificate: {cert_info['id']} -> {cert_path}")
                        except Exception as e:
                            os.close(cert_fd)  # Close if writing failed
                            raise e
                            
                    except Exception as e:
                        print(f"(WARN) Failed to load certificate {cert_info['id']}: {e}")

            # Create trust store with certificate file paths
            self.trust_store = TrustStore(cert_file_paths, [])
            # Load the trust store (always async)
            await self.trust_store.load()

            # Create certificate validator
            self.cert_validator = CertificateValidator(trust_store=self.trust_store)

            # Set validator on server
            self.server.set_certificate_validator(self.cert_validator)
            print("(PASS) Certificate validation configured")

        except Exception as e:
            print(f"(FAIL) Failed to setup certificate validation: {e}")

    async def _setup_server_certificates(self) -> None:
        """Setup server certificates."""
        if self.config.security.server_certificate_strategy == "auto_self_signed":
            # Generate self-signed certificate
            from asyncua.crypto.cert_gen import setup_self_signed_certificate
            from pathlib import Path
            import socket
            import tempfile
            import os

            # Get hostname for certificate - use multiple names for better connectivity
            hostname = socket.gethostname()
            hostnames = [hostname, "localhost", "127.0.0.1"]
            
            # Extract hostname from endpoint URL if different
            endpoint_hostname = self.config.server.endpoint_url.split("://")[1].split(":")[0]
            if endpoint_hostname not in hostnames:
                hostnames.append(endpoint_hostname)

            # Create temporary files for certificate generation
            with tempfile.TemporaryDirectory() as temp_dir:
                key_file = Path(temp_dir) / "server_key.pem"
                cert_file = Path(temp_dir) / "server_cert.pem"

                # Generate certificate (function returns None, files are created)
                await setup_self_signed_certificate(
                    key_file=key_file,
                    cert_file=cert_file,
                    app_uri=self.config.server.application_uri,
                    host_name=hostnames[0],  # Primary hostname
                    cert_use=[],  # Default certificate uses
                    subject_attrs={}  # Default subject attributes
                )

                # Load certificate data from files
                with open(cert_file, 'rb') as f:
                    cert_pem = f.read()
                with open(key_file, 'rb') as f:
                    key_pem = f.read()

            await self.server.load_certificate(cert_pem, key_pem)
            print("(PASS) Self-signed server certificate generated and loaded")

        elif self.config.security.server_certificate_custom:
            # Load custom certificate
            try:
                cert_path = self.config.security.server_certificate_custom
                key_path = self.config.security.server_private_key_custom

                if cert_path and key_path:
                    await self.server.load_certificate(cert_path, key_path)
                    print("(PASS) Custom server certificate loaded")
                else:
                    print("(WARN) Custom certificate paths not fully specified")
            except Exception as e:
                print(f"(FAIL) Failed to load custom certificate: {e}")

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

        # Note: Callbacks are disabled for now due to NodeId parsing issues
        # TODO: Implement proper NodeId resolution for callbacks
        if nodes_requiring_callbacks:
            print(f"(INFO) Skipping callback registration for {len(nodes_requiring_callbacks)} nodes (NodeId parsing issue)")

    async def _on_pre_read(self, node, context):
        """Callback for pre-read operations."""
        user = context.user
        if user:
            log_info(f"User {user.username} ({user.role}) reading node {node}")
        else:
            log_info(f"Anonymous read on node {node}")

    async def _on_pre_write(self, node, context, value):
        """Callback for pre-write operations."""
        user = context.user
        if user:
            # Check permissions using our ruleset
            if self.permission_ruleset.check_validity(user, ua.AttributeIds.Value, context):
                log_info(f"User {user.username} ({user.role}) writing to node {node}: {value}")
                return True
            else:
                log_warn(f"Access denied: User {user.username} ({user.role}) attempted to write to node {node}")
                return False
        else:
            log_warn(f"Access denied: Anonymous write attempt on node {node}")
            return False

    async def create_variable_nodes(self) -> bool:
        """Create OPC-UA nodes for all configured variables, structs and arrays."""
        try:
            if not self.server or self.namespace_idx is None:
                print("(FAIL) Server not initialized")
                return False

            # Get the Objects folder
            objects = self.server.get_objects_node()

            # Create simple variables
            for var in self.config.address_space.variables:
                try:
                    await self._create_simple_variable(objects, var)
                except Exception as e:
                    print(f"(FAIL) Error creating variable {var.node_id}: {e}")
                    traceback.print_exc()

            # Create structures
            for struct in self.config.address_space.structures:
                try:
                    await self._create_struct(objects, struct)
                except Exception as e:
                    print(f"(FAIL) Error creating struct {struct.node_id}: {e}")
                    traceback.print_exc()

            # Create arrays
            for arr in self.config.address_space.arrays:
                try:
                    await self._create_array(objects, arr)
                except Exception as e:
                    print(f"(FAIL) Error creating array {arr.node_id}: {e}")
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
            traceback.print_exc()
            return False

    async def _create_simple_variable(self, parent_node: Node, var: SimpleVariable) -> None:
        """Create a simple OPC-UA variable node."""
        print(f"Creating simple variable: {var.node_id} ({var.datatype}, index: {var.index})")

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
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(var.display_name))))
        await node.write_attribute(ua.AttributeIds.Description, ua.DataValue(ua.Variant(ua.LocalizedText(var.description))))

        # Set access level based on permissions
        access_level = ua.AccessLevel.CurrentRead
        if var.permissions.engineer == "rw" or var.permissions.operator == "rw":
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        var_node = VariableNode(
            node=node,
            debug_var_index=var.index,
            datatype=var.datatype,
            access_mode="readwrite" if access_level & ua.AccessLevel.CurrentWrite else "readonly",
            is_array_element=False
        )

        self.variable_nodes[var.index] = var_node
        print(f"  Created variable: {var.node_id}")

    async def _create_struct(self, parent_node: Node, struct: StructVariable) -> None:
        """Create an OPC-UA struct (object with fields)."""
        print(f"Creating struct: {struct.node_id}")

        # Create parent object for the struct
        struct_obj = await parent_node.add_object(self.namespace_idx, struct.browse_name)

        # Set display name and description
        await struct_obj.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(struct.display_name))))
        await struct_obj.write_attribute(ua.AttributeIds.Description, ua.DataValue(ua.Variant(ua.LocalizedText(struct.description))))

        # Create fields
        for field in struct.fields:
            await self._create_struct_field(struct_obj, struct.node_id, field)

        print(f"  Created struct with {len(struct.fields)} fields")

    async def _create_struct_field(self, parent_node: Node, struct_node_id: str, field: VariableField) -> None:
        """Create a field within a struct."""
        field_node_id = f"{struct_node_id}.{field.name}"
        print(f"  Creating struct field: {field_node_id} ({field.datatype}, index: {field.index})")

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
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(field.name))))

        # Set access level based on permissions
        access_level = ua.AccessLevel.CurrentRead
        if field.permissions.engineer == "rw" or field.permissions.operator == "rw":
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        var_node = VariableNode(
            node=node,
            debug_var_index=field.index,
            datatype=field.datatype,
            access_mode="readwrite" if access_level & ua.AccessLevel.CurrentWrite else "readonly",
            is_array_element=False
        )

        self.variable_nodes[field.index] = var_node
        print(f"    Created field: {field_node_id}")

    async def _create_array(self, parent_node: Node, arr: ArrayVariable) -> None:
        """Create an OPC-UA array variable."""
        print(f"Creating array: {arr.node_id} ({arr.datatype}[{arr.length}], index: {arr.index})")

        opcua_type = map_plc_to_opcua_type(arr.datatype)
        initial_value = convert_value_for_opcua(arr.datatype, arr.initial_value)

        # Create array with initial values
        array_values = [initial_value] * arr.length
        array_variant = ua.Variant(array_values)

        # Create the variable node
        node = await parent_node.add_variable(
            self.namespace_idx,
            arr.browse_name,
            array_variant,
            datatype=opcua_type
        )

        # Set display name and description
        await node.write_attribute(ua.AttributeIds.DisplayName, ua.DataValue(ua.Variant(ua.LocalizedText(arr.display_name))))

        # Set access level based on permissions
        access_level = ua.AccessLevel.CurrentRead
        if arr.permissions.engineer == "rw" or arr.permissions.operator == "rw":
            access_level |= ua.AccessLevel.CurrentWrite

        await node.write_attribute(ua.AttributeIds.AccessLevel, ua.DataValue(ua.Variant(access_level, ua.VariantType.Byte)))

        # Store node mapping
        var_node = VariableNode(
            node=node,
            debug_var_index=arr.index,
            datatype=arr.datatype,
            access_mode="readwrite" if access_level & ua.AccessLevel.CurrentWrite else "readonly",
            is_array_element=False
        )

        self.variable_nodes[arr.index] = var_node
        print(f"  Created array: {arr.node_id}")







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
            pass
            # print(f"(FAIL) Failed to update OPC-UA node for debug variable {var_node.debug_var_index}: {e}")

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
                    opcua_value = opcua_value.Value  # Extract from Variant

                    # Convert to PLC format
                    plc_value = convert_value_for_plc(var_node.datatype, opcua_value)

                    values_to_write.append(plc_value)
                    indices_to_write.append(var_index)

                except Exception as e:
                    # Skip this variable on error, continue with others
                    continue

            # Batch write to PLC if we have values to write
            if values_to_write and indices_to_write:
                success, msg = self.sba.set_var_values_batch(indices_to_write, values_to_write)
                if not success:
                    log_error(f"Batch write to PLC failed: {msg}")

        except Exception as e:
            log_error(f"Error in OPC-UA to runtime sync: {e}")

    async def run_opcua_to_runtime_loop(self) -> None:
        """Main loop for synchronizing OPC-UA values to PLC runtime."""
        while self.running and not stop_event.is_set():
            try:
                await self.sync_opcua_to_runtime()
                await asyncio.sleep(0.050)  # 50ms interval

            except Exception as e:
                print(f"(FAIL) Error in OPC-UA to runtime loop: {e}")
                await asyncio.sleep(0.1)  # Brief pause on error



    async def start_server(self) -> bool:
        """Start the OPC-UA server."""
        try:
            if not self.server:
                print("(FAIL) Server not initialized")
                return False

            await self.server.start()
            self.running = True
            print(f"(PASS) OPC-UA server started on {self.config.server.endpoint_url}")
            
            # Print alternative endpoints for client connection
            if hasattr(self, '_client_endpoints'):
                print("(INFO) Alternative client endpoints:")
                for scenario, endpoint in self._client_endpoints.items():
                    if endpoint:
                        print(f"(INFO)   {scenario}: {endpoint}")
            
            return True

        except Exception as e:
            print(f"(FAIL) Failed to start OPC-UA server: {e}")
            return False

    def _cleanup_temp_files(self) -> None:
        """Clean up temporary certificate files."""
        for cert_path in self.temp_cert_files:
            try:
                import os
                if os.path.exists(cert_path):
                    os.unlink(cert_path)
                    print(f"(INFO) Cleaned up temp certificate file: {cert_path}")
            except Exception as e:
                print(f"(WARN) Failed to cleanup temp certificate file {cert_path}: {e}")
        self.temp_cert_files.clear()

    async def stop_server(self) -> None:
        """Stop the OPC-UA server."""
        try:
            if self.server and self.running:
                await self.server.stop()
                self.running = False
                print("(PASS) OPC-UA server stopped")
            
            # Clean up temporary certificate files
            self._cleanup_temp_files()

        except Exception as e:
            print(f"(FAIL) Error stopping OPC-UA server: {e}")
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

            # Start both update loops in parallel
            print("(PASS) Starting bidirectional synchronization loops")
            task_runtime_to_opcua = asyncio.create_task(opcua_server.run_update_loop())
            task_opcua_to_runtime = asyncio.create_task(opcua_server.run_opcua_to_runtime_loop())

            # Wait for both tasks to complete
            await asyncio.gather(task_runtime_to_opcua, task_opcua_to_runtime)

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

        # Create safe logging accessor
        global safe_logging_accessor
        safe_logging_accessor = SafeLoggingAccess(runtime_args)
        if not safe_logging_accessor.is_valid:
            print(f"(WARN) Failed to create SafeLoggingAccess: {safe_logging_accessor.error_msg}")
            # Continue without logging - not a fatal error

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
