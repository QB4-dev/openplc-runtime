"""OPC-UA plugin utility functions."""

import struct
from typing import Any
from asyncua import ua


def map_plc_to_opcua_type(plc_type: str) -> ua.VariantType:
    """Map plc datatype to OPC-UA VariantType."""
    type_mapping = {
        "Bool": ua.VariantType.Boolean,
        "Byte": ua.VariantType.Byte,
        "Int": ua.VariantType.UInt16,
        "Int32": ua.VariantType.UInt32,  # Added Int32 mapping
        "Dint": ua.VariantType.UInt32,
        "Lint": ua.VariantType.UInt64,
        "Float": ua.VariantType.Float,
        "String": ua.VariantType.String,
    }
    mapped_type = type_mapping.get(plc_type, ua.VariantType.Variant)
    return mapped_type


def convert_value_for_opcua(datatype: str, value: Any) -> Any:
    """Convert PLC debug variable value to OPC-UA compatible format."""
    # The debug utils return raw integer values based on variable size
    # Convert to appropriate OPC-UA types based on config datatype
    try:
        if datatype.upper() in ["BOOL", "Bool"]:
            # Ensure BOOL values are proper Python booleans
            if isinstance(value, bool):
                return value
            elif isinstance(value, (int, float)):
                return bool(value != 0)
            else:
                return bool(value)
        
        elif datatype.upper() in ["BYTE", "Byte"]:
            return max(0, min(255, int(value)))  # Clamp to byte range
        
        elif datatype.upper() in ["INT", "Int"]:
            return max(-32768, min(32767, int(value)))  # Clamp to int16 range
        
        elif datatype.upper() in ["DINT", "Dint", "INT32", "Int32"]:
            return max(-2147483648, min(2147483647, int(value)))  # Clamp to int32 range
        
        elif datatype.upper() in ["LINT", "Lint"]:
            return int(value)  # int64
        
        elif datatype.upper() in ["FLOAT", "Float"]:
            # Float values are stored as integers in debug variables
            # Convert back to float if it's an integer representation
            if isinstance(value, int):
                try:
                    return struct.unpack('f', struct.pack('I', value))[0]
                except:
                    return float(value)
            return float(value)
        
        elif datatype.upper() in ["STRING", "String"]:
            return str(value)
        
        else:
            return value
            
    except (ValueError, TypeError, OverflowError) as e:
        # If conversion fails, return a safe default
        print(f"(WARN) Failed to convert value {value} to OPC-UA format for {datatype}: {e}")
        if datatype.upper() in ["BOOL", "Bool"]:
            return False
        elif datatype.upper() in ["FLOAT", "Float"]:
            return 0.0
        elif datatype.upper() in ["STRING", "String"]:
            return ""
        else:
            return 0


def convert_value_for_plc(datatype: str, value: Any) -> Any:
    """Convert OPC-UA value to PLC debug variable format."""
    # Handle different OPC-UA value types more robustly
    try:
        if datatype.upper() in ["BOOL", "Bool"]:
            # Convert any value to boolean, then to int (0/1)
            if isinstance(value, bool):
                return int(value)
            elif isinstance(value, (int, float)):
                return 1 if value != 0 else 0
            elif isinstance(value, str):
                return 1 if value.lower() in ['true', '1', 'yes', 'on'] else 0
            else:
                return int(bool(value))
        
        elif datatype.upper() in ["BYTE", "Byte"]:
            return max(0, min(255, int(value)))  # Clamp to byte range
        
        elif datatype.upper() in ["INT", "Int"]:
            return max(-32768, min(32767, int(value)))  # Clamp to int16 range
        
        elif datatype.upper() in ["DINT", "Dint", "INT32", "Int32"]:
            return max(-2147483648, min(2147483647, int(value)))  # Clamp to int32 range
        
        elif datatype.upper() in ["LINT", "Lint"]:
            return int(value)  # int64
        
        elif datatype.upper() in ["FLOAT", "Float"]:
            # Convert float to int representation for storage
            if isinstance(value, float):
                try:
                    return struct.unpack('I', struct.pack('f', value))[0]
                except:
                    return int(value)
            else:
                return int(float(value))
        
        elif datatype.upper() in ["STRING", "String"]:
            return str(value)
        
        else:
            # For unknown types, try to preserve the value
            return value
            
    except (ValueError, TypeError, OverflowError) as e:
        # If conversion fails, log and return a safe default
        print(f"(WARN) Failed to convert value {value} to {datatype}, using default: {e}")
        if datatype.upper() in ["BOOL", "Bool"]:
            return 0
        elif datatype.upper() in ["FLOAT", "Float"]:
            return 0
        elif datatype.upper() in ["STRING", "String"]:
            return ""
        else:
            return 0


def infer_var_type(size: int) -> str:
    """Infer variable type from size."""
    if size == 1:
        return "BOOL_OR_SINT"
    elif size == 2:
        return "UINT16"
    elif size == 4:
        return "UINT32_OR_TIME"
    elif size == 8:
        return "UINT64_OR_TIME"
    else:
        return "UNKNOWN"
