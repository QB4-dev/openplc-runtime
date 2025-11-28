"""OPC-UA plugin memory access utilities."""

import ctypes
from typing import Any, List, Dict

try:
    # Try relative imports first (when used as package)
    from .opcua_types import VariableMetadata
except ImportError:
    # Fallback to absolute imports (when run standalone)
    from opcua_types import VariableMetadata


def read_memory_direct(address: int, size: int) -> Any:
    """Read value directly from memory using cached address."""
    try:
        if size == 1:
            ptr = ctypes.cast(address, ctypes.POINTER(ctypes.c_uint8))
            return ptr.contents.value
        elif size == 2:
            ptr = ctypes.cast(address, ctypes.POINTER(ctypes.c_uint16))
            return ptr.contents.value
        elif size == 4:
            ptr = ctypes.cast(address, ctypes.POINTER(ctypes.c_uint32))
            return ptr.contents.value
        elif size == 8:
            ptr = ctypes.cast(address, ctypes.POINTER(ctypes.c_uint64))
            return ptr.contents.value
        else:
            raise ValueError(f"Unsupported variable size: {size}")
    except Exception as e:
        raise RuntimeError(f"Memory access error: {e}")


def initialize_variable_cache(sba, indices: List[int]) -> Dict[int, VariableMetadata]:
    """Initialize metadata cache for direct memory access."""
    try:
        # Try relative imports first (when used as package)
        from .opcua_utils import infer_var_type
    except ImportError:
        # Fallback to absolute imports (when run standalone)
        from opcua_utils import infer_var_type

    try:
        # Batch: get addresses
        addresses, addr_msg = sba.get_var_list(indices)
        if addr_msg != "Success":
            print(f"(WARN) Failed to cache addresses: {addr_msg}")
            return {}

        # Batch: get sizes
        sizes, size_msg = sba.get_var_sizes_batch(indices)
        if size_msg != "Success":
            print(f"(WARN) Failed to cache sizes: {size_msg}")
            return {}

        # Create cache
        cache = {}
        for i, var_index in enumerate(indices):
            if addresses[i] is not None and sizes[i] > 0:
                metadata = VariableMetadata(
                    index=var_index,
                    address=addresses[i],
                    size=sizes[i],
                    inferred_type=infer_var_type(sizes[i])
                )
                cache[var_index] = metadata

        print(f"(PASS) Cached metadata for {len(cache)} variables")
        return cache

    except Exception as e:
        print(f"(WARN) Failed to initialize variable cache: {e}")
        return {}
