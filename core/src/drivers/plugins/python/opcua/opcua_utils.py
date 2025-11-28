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
    print(f"    Mapping {plc_type} -> {mapped_type}")
    return mapped_type


def convert_value_for_opcua(datatype: str, value: Any) -> Any:
    """Convert PLC debug variable value to OPC-UA compatible format."""
    # The debug utils return raw integer values based on variable size
    # Convert to appropriate OPC-UA types based on config datatype
    if datatype == "Bool":
        return bool(value)
    elif datatype == "Byte":
        return int(value)
    elif datatype == "Int":
        return int(value)
    elif datatype == "Dint":
        return int(value)
    elif datatype == "Lint":
        return int(value)
    elif datatype == "Float":
        # Float values are stored as integers in debug variables
        # Convert back to float if it's an integer representation
        if isinstance(value, int):
            try:
                return struct.unpack('f', struct.pack('I', value))[0]
            except:
                return float(value)
        return float(value)
    elif datatype == "String":
        return str(value)
    else:
        return value


def convert_value_for_plc(datatype: str, value: Any) -> Any:
    """Convert OPC-UA value to PLC debug variable format."""
    # For most types, the value can be used directly
    # May need conversion for certain types
    if datatype == "Float" and isinstance(value, float):
        # Convert float to int representation for storage
        try:
            return struct.unpack('I', struct.pack('f', value))[0]
        except:
            return int(value)
    return value


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
