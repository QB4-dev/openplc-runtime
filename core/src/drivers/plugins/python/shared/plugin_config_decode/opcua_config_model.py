from typing import List, Dict, Any, Optional, Literal
from dataclasses import dataclass
import json

try:
    from .plugin_config_contact import PluginConfigContract
except ImportError:
    # For direct execution
    from plugin_config_contact import PluginConfigContract

AccessMode = Literal["readwrite", "readonly"]
VariableType = Literal["STRUCT", "ARRAY"]

@dataclass
class OpcuaVariableMember:
    """Represents a member of a STRUCT or ARRAY variable."""
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
    """Represents an OPC-UA variable, which can be simple or complex (STRUCT/ARRAY)."""
    node_name: str
    datatype: Optional[str] = None
    index: Optional[int] = None
    access: Optional[AccessMode] = None
    type: Optional[VariableType] = None
    members: Optional[List[OpcuaVariableMember]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OpcuaVariable':
        """Creates an OpcuaVariable instance from a dictionary."""
        try:
            node_name = data["node_name"]
        except KeyError as e:
            raise ValueError(f"Missing required field in OPC-UA variable: {e}")

        # Check if it's a complex variable (STRUCT or ARRAY)
        var_type = data.get("type")
        if var_type in ["STRUCT", "ARRAY"]:
            # Complex variable
            members_data = data.get("members", [])
            members = [OpcuaVariableMember.from_dict(member) for member in members_data]
            return cls(
                node_name=node_name,
                type=var_type,
                members=members
            )
        else:
            # Simple variable
            try:
                datatype = data["datatype"]
                index = data["index"]
                access = data["access"]
            except KeyError as e:
                raise ValueError(f"Missing required field in simple OPC-UA variable: {e}")

            if access not in ["readwrite", "readonly"]:
                raise ValueError(f"Invalid access mode: {access}. Must be 'readwrite' or 'readonly'")

            return cls(
                node_name=node_name,
                datatype=datatype,
                index=index,
                access=access
            )

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

        return cls(
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

            # Check for duplicate indices within a plugin
            all_indices = []
            for var in config.variables:
                if var.index is not None:
                    all_indices.append(var.index)
                if var.members:
                    all_indices.extend([member.index for member in var.members])

            if len(all_indices) != len(set(all_indices)):
                raise ValueError(f"Duplicate indices found in plugin '{plugin.name}'")

        # Check for duplicate plugin names
        plugin_names = [plugin.name for plugin in self.plugins]
        if len(plugin_names) != len(set(plugin_names)):
            raise ValueError("Duplicate plugin names found. Each plugin must have a unique name.")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(plugins={len(self.plugins)})"
