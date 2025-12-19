"""
OPC UA plugin type definitions and converters.

This package provides:
- IEC 61131-3 to OPC UA type mapping
- Value conversion utilities
- Data models for plugin internal use
"""

from .type_converter import TypeConverter, IECType
from .models import VariableNode, VariableMetadata, NodePermissions

__all__ = [
    'TypeConverter',
    'IECType',
    'VariableNode',
    'VariableMetadata',
    'NodePermissions',
]
