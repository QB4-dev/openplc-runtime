"""
OpenPLC OPC UA Plugin.

This package implements an OPC UA server for the OpenPLC runtime,
providing industrial-grade connectivity using the asyncua library.

Architecture:
    - plugin.py: Entry point with init/start_loop/stop_loop/cleanup
    - config.py: Configuration loading and validation
    - logging.py: Centralized logging
    - types/: Type definitions and converters
    - security/: Certificate, user, and permission management
    - server/: Server lifecycle, address space, and synchronization

Usage:
    The plugin is loaded by the OpenPLC runtime plugin system.
    Configuration is provided via JSON file specified in plugins.conf.
"""

# Re-export plugin interface for runtime compatibility
from .plugin import init, start_loop, stop_loop, cleanup

__version__ = "2.0.0"
__all__ = ['init', 'start_loop', 'stop_loop', 'cleanup']
