"""
OPC UA plugin configuration loader.

This module provides a simplified configuration model for the OPC UA plugin,
replacing the complex multi-plugin configuration with a single-server approach.
"""

import json
from pathlib import Path
from typing import Any, Optional

from .logging import log_info, log_error


def load_config(config_path: str) -> Optional[dict]:
    """
    Load OPC UA configuration from JSON file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary or None if loading fails
    """
    try:
        path = Path(config_path)
        if not path.exists():
            log_error(f"Configuration file not found: {config_path}")
            return None
        
        with open(path, 'r') as f:
            raw_config = json.load(f)
        
        # Handle both old multi-plugin format and new single-server format
        config = _normalize_config(raw_config)
        
        # Validate configuration
        if not _validate_config(config):
            return None
        
        log_info(f"Configuration loaded from {config_path}")
        return config
        
    except json.JSONDecodeError as e:
        log_error(f"Invalid JSON in configuration file: {e}")
        return None
    except Exception as e:
        log_error(f"Failed to load configuration: {e}")
        return None


def _normalize_config(raw_config: Any) -> dict:
    """
    Normalize configuration to single-server format.
    
    Handles both:
    - Old format: List of plugin configurations
    - New format: Single server configuration dictionary
    """
    # If it's a list (old format), extract first plugin's config
    if isinstance(raw_config, list):
        if not raw_config:
            return {}
        
        first_plugin = raw_config[0]
        if "config" in first_plugin:
            return first_plugin["config"]
        return first_plugin
    
    # If it's already a dict with "config" key (wrapper format)
    if isinstance(raw_config, dict) and "config" in raw_config:
        return raw_config["config"]
    
    # Already in new format
    return raw_config


def _validate_config(config: dict) -> bool:
    """
    Validate configuration structure.
    
    Returns:
        True if configuration is valid
    """
    required_sections = ["server", "address_space"]
    
    for section in required_sections:
        if section not in config:
            log_error(f"Missing required configuration section: {section}")
            return False
    
    # Validate server section
    server = config["server"]
    if "endpoint_url" not in server:
        log_error("Missing server.endpoint_url in configuration")
        return False
    
    # Validate address space section
    address_space = config["address_space"]
    if "namespace_uri" not in address_space:
        log_error("Missing address_space.namespace_uri in configuration")
        return False
    
    return True


def get_default_config() -> dict:
    """
    Get default configuration for development/testing.
    
    Returns:
        Default configuration dictionary
    """
    return {
        "server": {
            "name": "OpenPLC OPC-UA Server",
            "application_uri": "urn:autonomy-logic:openplc:opcua:server",
            "product_uri": "urn:autonomy-logic:openplc",
            "endpoint_url": "opc.tcp://0.0.0.0:4840",
            "security_profiles": [
                {
                    "name": "insecure",
                    "enabled": True,
                    "security_policy": "None",
                    "security_mode": "None",
                    "auth_methods": ["Anonymous"]
                }
            ]
        },
        "security": {
            "server_certificate_strategy": "auto_self_signed",
            "trusted_client_certificates": []
        },
        "users": [],
        "address_space": {
            "namespace_uri": "urn:openplc:opcua",
            "namespace_index": 2,
            "variables": [],
            "structures": [],
            "arrays": []
        },
        "cycle_time_ms": 100
    }
