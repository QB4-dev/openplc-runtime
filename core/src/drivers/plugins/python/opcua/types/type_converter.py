"""
IEC 61131-3 to OPC UA type conversion.

This module provides robust type mapping and value conversion between
IEC 61131-3 PLC types and OPC UA data types.
"""

from enum import Enum
from typing import Any, Union
import struct

from asyncua import ua


class IECType(Enum):
    """
    IEC 61131-3 elementary data types.
    
    Reference: IEC 61131-3 standard
    """
    # Boolean
    BOOL = "BOOL"
    
    # Integer types (signed)
    SINT = "SINT"      # 8-bit signed
    INT = "INT"        # 16-bit signed
    DINT = "DINT"      # 32-bit signed
    LINT = "LINT"      # 64-bit signed
    
    # Integer types (unsigned)
    USINT = "USINT"    # 8-bit unsigned
    UINT = "UINT"      # 16-bit unsigned
    UDINT = "UDINT"    # 32-bit unsigned
    ULINT = "ULINT"    # 64-bit unsigned
    
    # Floating point
    REAL = "REAL"      # 32-bit float
    LREAL = "LREAL"    # 64-bit double
    
    # Bit string types
    BYTE = "BYTE"      # 8-bit
    WORD = "WORD"      # 16-bit
    DWORD = "DWORD"    # 32-bit
    LWORD = "LWORD"    # 64-bit
    
    # String types
    STRING = "STRING"
    WSTRING = "WSTRING"
    
    # Time types
    TIME = "TIME"
    DATE = "DATE"
    TIME_OF_DAY = "TIME_OF_DAY"
    DATE_AND_TIME = "DATE_AND_TIME"
    
    @classmethod
    def from_string(cls, type_str: str) -> 'IECType':
        """
        Parse IEC type from string, case-insensitive.
        
        Args:
            type_str: Type name string (e.g., "Bool", "DINT", "real")
            
        Returns:
            Corresponding IECType enum value
            
        Raises:
            ValueError: If type string is not recognized
        """
        normalized = type_str.upper().strip()
        
        # Handle common aliases
        aliases = {
            "BOOLEAN": "BOOL",
            "INT16": "INT",
            "INT32": "DINT",
            "INT64": "LINT",
            "UINT16": "UINT",
            "UINT32": "UDINT",
            "UINT64": "ULINT",
            "FLOAT": "REAL",
            "DOUBLE": "LREAL",
            "TOD": "TIME_OF_DAY",
            "DT": "DATE_AND_TIME",
        }
        
        normalized = aliases.get(normalized, normalized)
        
        try:
            return cls(normalized)
        except ValueError:
            raise ValueError(f"Unknown IEC type: {type_str}")


class TypeConverter:
    """
    Converts between IEC 61131-3 and OPC UA types.
    
    This class provides bidirectional conversion for:
    - Type mapping (IEC type -> OPC UA VariantType)
    - Value conversion (PLC value <-> OPC UA value)
    """
    
    # IEC to OPC UA type mapping
    IEC_TO_OPCUA: dict[IECType, ua.VariantType] = {
        # Boolean
        IECType.BOOL: ua.VariantType.Boolean,
        
        # Signed integers
        IECType.SINT: ua.VariantType.SByte,
        IECType.INT: ua.VariantType.Int16,
        IECType.DINT: ua.VariantType.Int32,
        IECType.LINT: ua.VariantType.Int64,
        
        # Unsigned integers
        IECType.USINT: ua.VariantType.Byte,
        IECType.UINT: ua.VariantType.UInt16,
        IECType.UDINT: ua.VariantType.UInt32,
        IECType.ULINT: ua.VariantType.UInt64,
        
        # Floating point
        IECType.REAL: ua.VariantType.Float,
        IECType.LREAL: ua.VariantType.Double,
        
        # Bit strings (mapped to unsigned integers)
        IECType.BYTE: ua.VariantType.Byte,
        IECType.WORD: ua.VariantType.UInt16,
        IECType.DWORD: ua.VariantType.UInt32,
        IECType.LWORD: ua.VariantType.UInt64,
        
        # Strings
        IECType.STRING: ua.VariantType.String,
        IECType.WSTRING: ua.VariantType.String,
        
        # Time types (mapped to appropriate OPC UA types)
        IECType.TIME: ua.VariantType.UInt32,      # Duration in ms
        IECType.DATE: ua.VariantType.DateTime,
        IECType.TIME_OF_DAY: ua.VariantType.UInt32,
        IECType.DATE_AND_TIME: ua.VariantType.DateTime,
    }
    
    # Size in bytes for each IEC type
    IEC_TYPE_SIZES: dict[IECType, int] = {
        IECType.BOOL: 1,
        IECType.SINT: 1,
        IECType.USINT: 1,
        IECType.BYTE: 1,
        IECType.INT: 2,
        IECType.UINT: 2,
        IECType.WORD: 2,
        IECType.DINT: 4,
        IECType.UDINT: 4,
        IECType.DWORD: 4,
        IECType.REAL: 4,
        IECType.TIME: 4,
        IECType.TIME_OF_DAY: 4,
        IECType.LINT: 8,
        IECType.ULINT: 8,
        IECType.LWORD: 8,
        IECType.LREAL: 8,
        IECType.DATE: 8,
        IECType.DATE_AND_TIME: 8,
    }
    
    @classmethod
    def to_opcua_type(cls, iec_type: Union[str, IECType]) -> ua.VariantType:
        """
        Get OPC UA VariantType for an IEC type.
        
        Args:
            iec_type: IEC type as string or IECType enum
            
        Returns:
            Corresponding OPC UA VariantType
            
        Raises:
            ValueError: If type is not supported
        """
        if isinstance(iec_type, str):
            iec_type = IECType.from_string(iec_type)
        
        if iec_type not in cls.IEC_TO_OPCUA:
            raise ValueError(f"No OPC UA mapping for IEC type: {iec_type}")
        
        return cls.IEC_TO_OPCUA[iec_type]
    
    @classmethod
    def get_type_size(cls, iec_type: Union[str, IECType]) -> int:
        """
        Get size in bytes for an IEC type.
        
        Args:
            iec_type: IEC type as string or IECType enum
            
        Returns:
            Size in bytes, or 0 for variable-length types (STRING)
        """
        if isinstance(iec_type, str):
            iec_type = IECType.from_string(iec_type)
        
        return cls.IEC_TYPE_SIZES.get(iec_type, 0)
    
    @classmethod
    def to_opcua_value(cls, iec_type: Union[str, IECType], value: Any) -> Any:
        """
        Convert a PLC value to OPC UA compatible format.
        
        Args:
            iec_type: IEC type of the value
            value: Raw value from PLC memory
            
        Returns:
            Value converted to appropriate Python type for OPC UA
        """
        if isinstance(iec_type, str):
            try:
                iec_type = IECType.from_string(iec_type)
            except ValueError:
                # Unknown type, return as-is
                return value
        
        try:
            if iec_type == IECType.BOOL:
                return cls._convert_bool(value)
            
            elif iec_type in (IECType.SINT,):
                return cls._convert_signed_int(value, 8)
            
            elif iec_type in (IECType.INT,):
                return cls._convert_signed_int(value, 16)
            
            elif iec_type in (IECType.DINT,):
                return cls._convert_signed_int(value, 32)
            
            elif iec_type in (IECType.LINT,):
                return cls._convert_signed_int(value, 64)
            
            elif iec_type in (IECType.USINT, IECType.BYTE):
                return cls._convert_unsigned_int(value, 8)
            
            elif iec_type in (IECType.UINT, IECType.WORD):
                return cls._convert_unsigned_int(value, 16)
            
            elif iec_type in (IECType.UDINT, IECType.DWORD, IECType.TIME, IECType.TIME_OF_DAY):
                return cls._convert_unsigned_int(value, 32)
            
            elif iec_type in (IECType.ULINT, IECType.LWORD):
                return cls._convert_unsigned_int(value, 64)
            
            elif iec_type == IECType.REAL:
                return cls._convert_real(value)
            
            elif iec_type == IECType.LREAL:
                return cls._convert_lreal(value)
            
            elif iec_type in (IECType.STRING, IECType.WSTRING):
                return str(value) if value is not None else ""
            
            else:
                return value
                
        except (ValueError, TypeError, OverflowError, struct.error):
            # Return safe default on conversion error
            return cls._get_default_value(iec_type)
    
    @classmethod
    def to_plc_value(cls, iec_type: Union[str, IECType], value: Any) -> Any:
        """
        Convert an OPC UA value to PLC memory format.
        
        Args:
            iec_type: Target IEC type
            value: Value from OPC UA client
            
        Returns:
            Value converted to format suitable for PLC memory
        """
        if isinstance(iec_type, str):
            try:
                iec_type = IECType.from_string(iec_type)
            except ValueError:
                return value
        
        try:
            if iec_type == IECType.BOOL:
                return 1 if cls._convert_bool(value) else 0
            
            elif iec_type in (IECType.SINT,):
                return cls._clamp_signed(int(value), 8)
            
            elif iec_type in (IECType.INT,):
                return cls._clamp_signed(int(value), 16)
            
            elif iec_type in (IECType.DINT,):
                return cls._clamp_signed(int(value), 32)
            
            elif iec_type in (IECType.LINT,):
                return cls._clamp_signed(int(value), 64)
            
            elif iec_type in (IECType.USINT, IECType.BYTE):
                return cls._clamp_unsigned(int(value), 8)
            
            elif iec_type in (IECType.UINT, IECType.WORD):
                return cls._clamp_unsigned(int(value), 16)
            
            elif iec_type in (IECType.UDINT, IECType.DWORD, IECType.TIME, IECType.TIME_OF_DAY):
                return cls._clamp_unsigned(int(value), 32)
            
            elif iec_type in (IECType.ULINT, IECType.LWORD):
                return cls._clamp_unsigned(int(value), 64)
            
            elif iec_type == IECType.REAL:
                # Convert float to its integer representation for PLC memory
                float_val = float(value)
                return struct.unpack('<I', struct.pack('<f', float_val))[0]
            
            elif iec_type == IECType.LREAL:
                # Convert double to its integer representation for PLC memory
                double_val = float(value)
                return struct.unpack('<Q', struct.pack('<d', double_val))[0]
            
            elif iec_type in (IECType.STRING, IECType.WSTRING):
                return str(value) if value is not None else ""
            
            else:
                return value
                
        except (ValueError, TypeError, OverflowError, struct.error):
            return cls._get_default_value(iec_type)
    
    @classmethod
    def _convert_bool(cls, value: Any) -> bool:
        """Convert any value to boolean."""
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on')
        return bool(value)
    
    @classmethod
    def _convert_signed_int(cls, value: Any, bits: int) -> int:
        """Convert value to signed integer with proper range."""
        int_val = int(value)
        return cls._clamp_signed(int_val, bits)
    
    @classmethod
    def _convert_unsigned_int(cls, value: Any, bits: int) -> int:
        """Convert value to unsigned integer with proper range."""
        int_val = int(value)
        return cls._clamp_unsigned(int_val, bits)
    
    @classmethod
    def _convert_real(cls, value: Any) -> float:
        """Convert value to 32-bit float."""
        if isinstance(value, int):
            # Value might be stored as integer representation of float
            try:
                return struct.unpack('<f', struct.pack('<I', value & 0xFFFFFFFF))[0]
            except struct.error:
                return float(value)
        return float(value)
    
    @classmethod
    def _convert_lreal(cls, value: Any) -> float:
        """Convert value to 64-bit double."""
        if isinstance(value, int):
            # Value might be stored as integer representation of double
            try:
                return struct.unpack('<d', struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))[0]
            except struct.error:
                return float(value)
        return float(value)
    
    @classmethod
    def _clamp_signed(cls, value: int, bits: int) -> int:
        """Clamp value to signed integer range."""
        min_val = -(1 << (bits - 1))
        max_val = (1 << (bits - 1)) - 1
        return max(min_val, min(max_val, value))
    
    @classmethod
    def _clamp_unsigned(cls, value: int, bits: int) -> int:
        """Clamp value to unsigned integer range."""
        max_val = (1 << bits) - 1
        return max(0, min(max_val, value))
    
    @classmethod
    def _get_default_value(cls, iec_type: IECType) -> Any:
        """Get default value for an IEC type."""
        if iec_type == IECType.BOOL:
            return False
        elif iec_type in (IECType.REAL, IECType.LREAL):
            return 0.0
        elif iec_type in (IECType.STRING, IECType.WSTRING):
            return ""
        else:
            return 0
