#!/usr/bin/env python3
"""
IEC Type Definitions

This module provides IEC type mappings used throughout OpenPLC Python plugins.
These constants must match exactly with the C definitions in iec_types.h.
"""

import ctypes

# IEC type mappings based on iec_types.h
# These must match exactly with the C definitions
IEC_BOOL = ctypes.c_uint8    # typedef uint8_t IEC_BOOL;
IEC_BYTE = ctypes.c_uint8    # typedef uint8_t IEC_BYTE;
IEC_UINT = ctypes.c_uint16   # typedef uint16_t IEC_UINT;
IEC_UDINT = ctypes.c_uint32  # typedef uint32_t IEC_UDINT;
IEC_ULINT = ctypes.c_uint64  # typedef uint64_t IEC_ULINT;
