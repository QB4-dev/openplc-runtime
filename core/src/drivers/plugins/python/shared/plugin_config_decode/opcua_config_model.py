from typing import List, Dict, Any, Optional, Literal
from dataclasses import dataclass
import json
import os

try:
    from .plugin_config_contact import PluginConfigContract
except ImportError:
    # For direct execution
    from plugin_config_contact import PluginConfigContract

AccessMode = Literal["readwrite", "readonly"]
VariableType = Literal["STRUCT", "ARRAY"]

@dataclass
class OpcuaVariableDefinition:
    """Represents a variable definition that can be simple or complex (recursive)."""
    name: str
    datatype: Optional[str] = None
    index: Optional[int] = None
    access: Optional[AccessMode] = None
    type: Optional[VariableType] = None
    members: Optional[List['OpcuaVariableDefinition']] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaVariableDefinition':
        """Creates an OpcuaVariableDefinition instance from a dictionary (recursive)."""
        # Check if it's a complex variable (STRUCT or ARRAY)
        var_type = data.get("type")
        if var_type in ["STRUCT", "ARRAY"]:
            # Complex variable - requires name
            try:
                name = data["name"]
            except KeyError as e:
                raise ValueError(f"Missing required field 'name' in complex OPC-UA variable definition: {e}")

            # Parse members recursively
            members_data = data.get("members", [])
            members = [cls.from_dict(member) for member in members_data]
            return cls(
                name=name,
                type=var_type,
                members=members
            )
        else:
            # Simple variable - may not have name (for root level variables)
            name = data.get("name", "")

            try:
                datatype = data["datatype"]
                index = data["index"]
                access = data["access"]
            except KeyError as e:
                raise ValueError(f"Missing required field in simple OPC-UA variable: {e}")

            if access not in ["readwrite", "readonly"]:
                raise ValueError(f"Invalid access mode: {access}. Must be 'readwrite' or 'readonly'")

            return cls(
                name=name,
                datatype=datatype,
                index=index,
                access=access
            )

    def collect_leaf_variables(self) -> List['OpcuaVariableDefinition']:
        """Recursively collect all leaf (simple) variables from this definition."""
        leaves = []
        if self.type in ["STRUCT", "ARRAY"] and self.members:
            for member in self.members:
                leaves.extend(member.collect_leaf_variables())
        else:
            leaves.append(self)
        return leaves

    def validate(self, path: str = "") -> None:
        """Validate this variable definition recursively."""
        current_path = f"{path}.{self.name}" if path else self.name

        if self.type in ["STRUCT", "ARRAY"]:
            if not self.members:
                raise ValueError(f"Complex variable '{current_path}' has no members")
            if self.datatype is not None or self.index is not None or self.access is not None:
                raise ValueError(f"Complex variable '{current_path}' should not have datatype/index/access at root level")

            # Validate members recursively
            for member in self.members:
                member.validate(current_path)
        else:
            # Simple variable validation
            if self.datatype is None:
                raise ValueError(f"Simple variable '{current_path}' missing datatype")
            if self.index is None:
                raise ValueError(f"Simple variable '{current_path}' missing index")
            if self.access is None:
                raise ValueError(f"Simple variable '{current_path}' missing access")
            if self.members is not None:
                raise ValueError(f"Simple variable '{current_path}' should not have members")

@dataclass
class OpcuaVariableMember:
    """Legacy class - represents a member of a STRUCT or ARRAY variable."""
    name: str
    datatype: str
    index: int
    access: AccessMode

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaVariableMember':
        """Creates an OpcuaVariableMember instance from a dictionary."""
        try:
            name = data["name"]
            datatype = data["datatype"]
            index = data["index"]
            access = data["access"]
        except KeyError as e:
            raise ValueError(f"Missing required field in OPC-UA variable member: {e}")

        if access not in ["readwrite", "readonly"]:
            raise ValueError(f"Invalid access mode: {access}. Must be 'readwrite' or 'readonly'")

        return cls(name=name, datatype=datatype, index=index, access=access)

@dataclass
class OpcuaVariable:
    """Represents an OPC-UA variable with recursive structure support."""
    node_name: str
    definition: OpcuaVariableDefinition

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaVariable':
        """Creates an OpcuaVariable instance from a dictionary."""
        try:
            node_name = data["node_name"]
        except KeyError as e:
            raise ValueError(f"Missing required field 'node_name' in OPC-UA variable: {e}")

        # Create the variable definition (handles both simple and complex cases recursively)
        # Copy data and ensure 'name' field exists for complex variables
        definition_data = data.copy()
        definition_data.pop("node_name", None)

        # For complex variables, we need a 'name' field - use an empty string since root level doesn't need names
        # The actual node name is stored separately in OpcuaVariable.node_name
        if "type" in definition_data and definition_data["type"] in ["STRUCT", "ARRAY"]:
            # For complex root variables, add a dummy name (not used in node creation)
            definition_data["name"] = ""

        definition = OpcuaVariableDefinition.from_dict(definition_data)

        return cls(
            node_name=node_name,
            definition=definition
        )

    def collect_leaf_variables(self) -> List[OpcuaVariableDefinition]:
        """Collect all leaf (simple) variables recursively."""
        return self.definition.collect_leaf_variables()

    def validate(self) -> None:
        """Validate the variable definition."""
        self.definition.validate(self.node_name)

@dataclass
class OpcuaConfig:
    """Represents the OPC-UA server configuration."""
    endpoint: str
    server_name: str
    security_policy: str
    security_mode: str
    certificate: str
    private_key: str
    cycle_time_ms: int
    namespace: str
    variables: List[OpcuaVariable]

    # Valid security policies and modes
    VALID_SECURITY_POLICIES = [
        "None",
        "Basic256Sha256",
        "Aes128_Sha256_RsaOaep",
        "Aes256_Sha256_RsaPss"
    ]

    VALID_SECURITY_MODES = [
        "None",
        "Sign",
        "SignAndEncrypt"
    ]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaConfig':
        """Creates an OpcuaConfig instance from a dictionary."""
        try:
            endpoint = data["endpoint"]
            server_name = data["server_name"]
            security_policy = data["security_policy"]
            security_mode = data["security_mode"]
            certificate = data["certificate"]
            private_key = data["private_key"]
            cycle_time_ms = data["cycle_time_ms"]
            namespace = data["namespace"]
            variables_data = data["variables"]
        except KeyError as e:
            raise ValueError(f"Missing required field in OPC-UA config: {e}")

        variables = [OpcuaVariable.from_dict(var) for var in variables_data]

        config = cls(
            endpoint=endpoint,
            server_name=server_name,
            security_policy=security_policy,
            security_mode=security_mode,
            certificate=certificate,
            private_key=private_key,
            cycle_time_ms=cycle_time_ms,
            namespace=namespace,
            variables=variables
        )

        # Validate security configuration
        config.validate_security_config()

        return config

    def validate_security_config(self) -> None:
        """Validate security-related configuration."""
        # Validate security policy
        if self.security_policy not in self.VALID_SECURITY_POLICIES:
            raise ValueError(
                f"Invalid security_policy: '{self.security_policy}'. "
                f"Valid options: {', '.join(self.VALID_SECURITY_POLICIES)}"
            )

        # Validate security mode
        if self.security_mode not in self.VALID_SECURITY_MODES:
            raise ValueError(
                f"Invalid security_mode: '{self.security_mode}'. "
                f"Valid options: {', '.join(self.VALID_SECURITY_MODES)}"
            )

        # Validate certificate requirements
        requires_certificates = (
            self.security_policy != "None" or
            self.security_mode != "None"
        )

        if requires_certificates:
            if not self.certificate:
                raise ValueError(
                    f"Certificate path required for security_policy='{self.security_policy}' "
                    f"and security_mode='{self.security_mode}'"
                )
            if not self.private_key:
                raise ValueError(
                    f"Private key path required for security_policy='{self.security_policy}' "
                    f"and security_mode='{self.security_mode}'"
                )

            # Check if certificate files exist
            if not os.path.isfile(self.certificate):
                raise ValueError(f"Certificate file not found: {self.certificate}")
            if not os.path.isfile(self.private_key):
                raise ValueError(f"Private key file not found: {self.private_key}")

        # Validate consistency between policy and mode
        if self.security_policy == "None" and self.security_mode != "None":
            raise ValueError(
                "Cannot use security_mode other than 'None' with security_policy='None'"
            )

        if self.security_mode == "None" and self.security_policy != "None":
            raise ValueError(
                "Cannot use security_policy other than 'None' with security_mode='None'"
            )

@dataclass
class OpcuaPluginConfig:
    """Represents a single OPC-UA plugin configuration."""
    name: str
    protocol: str
    config: OpcuaConfig

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaPluginConfig':
        """Creates an OpcuaPluginConfig instance from a dictionary."""
        try:
            name = data["name"]
            protocol = data["protocol"]
            config_data = data["config"]
        except KeyError as e:
            raise ValueError(f"Missing required field in OPC-UA plugin config: {e}")

        config = OpcuaConfig.from_dict(config_data)

        return cls(name=name, protocol=protocol, config=config)

class OpcuaMasterConfig(PluginConfigContract):
    """
    OPC-UA Master configuration model.
    """
    def __init__(self):
        super().__init__()
        self.plugins: List[OpcuaPluginConfig] = []

    def import_config_from_file(self, file_path: str):
        """Read config from a JSON file."""
        with open(file_path, 'r') as f:
            raw_config = json.load(f)

            # Clear any existing plugins
            self.plugins = []

            # Parse each plugin configuration
            for i, plugin_config in enumerate(raw_config):
                try:
                    plugin = OpcuaPluginConfig.from_dict(plugin_config)
                    self.plugins.append(plugin)
                except Exception as e:
                    raise ValueError(f"Failed to parse plugin configuration #{i+1}: {e}")

    def validate(self) -> None:
        """Validates the configuration."""
        if not self.plugins:
            raise ValueError("No plugins configured. At least one OPC-UA plugin must be defined.")

        # Validate each plugin
        for i, plugin in enumerate(self.plugins):
            if plugin.protocol != "OPC-UA":
                raise ValueError(f"Invalid protocol for plugin #{i+1}: {plugin.protocol}. Expected 'OPC-UA'")

            if not plugin.name:
                raise ValueError(f"Plugin #{i+1} has empty name")

            # Validate config
            config = plugin.config
            if config.cycle_time_ms <= 0:
                raise ValueError(f"Invalid cycle_time_ms for plugin '{plugin.name}': {config.cycle_time_ms}. Must be positive")

            if not config.variables:
                raise ValueError(f"No variables defined for plugin '{plugin.name}'")

            # Check for duplicate variable names within a plugin
            var_names = [var.node_name for var in config.variables]
            if len(var_names) != len(set(var_names)):
                raise ValueError(f"Duplicate variable names found in plugin '{plugin.name}'")

            # Check for duplicate indices within a plugin (collect from all leaf variables)
            all_indices = []
            for var in config.variables:
                leaf_vars = var.collect_leaf_variables()
                all_indices.extend([leaf.index for leaf in leaf_vars if leaf.index is not None])

            if len(all_indices) != len(set(all_indices)):
                raise ValueError(f"Duplicate indices found in plugin '{plugin.name}'")

        # Check for duplicate plugin names
        plugin_names = [plugin.name for plugin in self.plugins]
        if len(plugin_names) != len(set(plugin_names)):
            raise ValueError("Duplicate plugin names found. Each plugin must have a unique name.")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(plugins={len(self.plugins)})"
