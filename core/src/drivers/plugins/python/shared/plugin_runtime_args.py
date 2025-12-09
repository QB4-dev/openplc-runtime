#!/usr/bin/env python3
"""
Plugin Runtime Arguments Structure

This module provides the PluginRuntimeArgs ctypes structure that matches
the plugin_runtime_args_t structure from plugin_driver.h.
"""

import ctypes
from ctypes import *

# Import IEC type definitions
from .iec_types import IEC_BOOL, IEC_BYTE, IEC_UINT, IEC_UDINT, IEC_ULINT

class PluginRuntimeArgs(ctypes.Structure):
    """
    Python ctypes structure matching plugin_runtime_args_t from plugin_driver.h

    CRITICAL: This structure must match the C definition exactly to prevent
    segmentation faults and memory corruption.
    """
    _fields_ = [
        # Buffer arrays - these are pointers to arrays of pointers
        # C: IEC_BOOL *(*bool_input)[8] means pointer to array of 8 pointers
        ("bool_input", ctypes.POINTER(ctypes.POINTER(IEC_BOOL) * 8)),
        ("bool_output", ctypes.POINTER(ctypes.POINTER(IEC_BOOL) * 8)),
        ("byte_input", ctypes.POINTER(ctypes.POINTER(IEC_BYTE))),
        ("byte_output", ctypes.POINTER(ctypes.POINTER(IEC_BYTE))),
        ("int_input", ctypes.POINTER(ctypes.POINTER(IEC_UINT))),
        ("int_output", ctypes.POINTER(ctypes.POINTER(IEC_UINT))),
        ("dint_input", ctypes.POINTER(ctypes.POINTER(IEC_UDINT))),
        ("dint_output", ctypes.POINTER(ctypes.POINTER(IEC_UDINT))),
        ("lint_input", ctypes.POINTER(ctypes.POINTER(IEC_ULINT))),
        ("lint_output", ctypes.POINTER(ctypes.POINTER(IEC_ULINT))),
        ("int_memory", ctypes.POINTER(ctypes.POINTER(IEC_UINT))),
        ("dint_memory", ctypes.POINTER(ctypes.POINTER(IEC_UDINT))),
        ("lint_memory", ctypes.POINTER(ctypes.POINTER(IEC_ULINT))),

        # Mutex function pointers
        ("mutex_take", ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)),
        ("mutex_give", ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)),
        ("buffer_mutex", ctypes.c_void_p),
        ("plugin_specific_config_file_path", ctypes.c_char * 256),

        # Buffer size information
        ("buffer_size", ctypes.c_int),
        ("bits_per_buffer", ctypes.c_int),

        # Logging function pointers
        ("log_info", ctypes.CFUNCTYPE(None, ctypes.c_char_p)),
        ("log_debug", ctypes.CFUNCTYPE(None, ctypes.c_char_p)),
        ("log_warn", ctypes.CFUNCTYPE(None, ctypes.c_char_p)),
        ("log_error", ctypes.CFUNCTYPE(None, ctypes.c_char_p)),
    ]

    def validate_pointers(self):
        """
        Validate that critical pointers are not NULL
        Returns: (bool, str) - (is_valid, error_message)
        """
        try:
            # Check buffer mutex
            if not self.buffer_mutex:
                return False, "buffer_mutex is NULL"

            # Check mutex functions
            if not self.mutex_take:
                return False, "mutex_take function pointer is NULL"
            if not self.mutex_give:
                return False, "mutex_give function pointer is NULL"

            # Check buffer size is reasonable
            if self.buffer_size <= 0 or self.buffer_size > 10000:
                return False, f"buffer_size is invalid: {self.buffer_size}"

            if self.bits_per_buffer <= 0 or self.bits_per_buffer > 64:
                return False, f"bits_per_buffer is invalid: {self.bits_per_buffer}"

            return True, "All pointers valid"

        except (AttributeError, TypeError) as e:
            return False, f"Structure access error during validation: {e}"
        except (ValueError, OverflowError) as e:
            return False, f"Value validation error: {e}"
        except OSError as e:
            return False, f"System error during validation: {e}"

    def safe_access_buffer_size(self):
        """
        Safely access buffer_size with validation
        Returns: (int, str) - (buffer_size, error_message)
        """
        try:
            is_valid, msg = self.validate_pointers()
            if not is_valid:
                return -1, f"Validation failed: {msg}"

            size = self.buffer_size
            if size <= 0 or size > 10000:
                return -1, f"Invalid buffer size: {size}"

            return size, "Success"

        except (AttributeError, TypeError) as e:
            return -1, f"Structure access error: {e}"
        except (ValueError, OverflowError) as e:
            return -1, f"Value validation error: {e}"
        except OSError as e:
            return -1, f"System error accessing buffer_size: {e}"

    def __str__(self):
        """Debug representation of the structure"""
        try:
            return (f"PluginRuntimeArgs(\n"
                    f"  bool_input=0x{ctypes.addressof(self.bool_input.contents) if self.bool_input else 0:x},\n"
                    f"  bool_output=0x{ctypes.addressof(self.bool_output.contents) if self.bool_output else 0:x},\n"
                    f"  byte_input=0x{ctypes.addressof(self.byte_input.contents) if self.byte_input else 0:x},\n"
                    f"  byte_output=0x{ctypes.addressof(self.byte_output.contents) if self.byte_output else 0:x},\n"
                    f"  int_input=0x{ctypes.addressof(self.int_input.contents) if self.int_input else 0:x},\n"
                    f"  int_output=0x{ctypes.addressof(self.int_output.contents) if self.int_output else 0:x},\n"
                    f"  dint_input=0x{ctypes.addressof(self.dint_input.contents) if self.dint_input else 0:x},\n"
                    f"  dint_output=0x{ctypes.addressof(self.dint_output.contents) if self.dint_output else 0:x},\n"
                    f"  lint_input=0x{ctypes.addressof(self.lint_input.contents) if self.lint_input else 0:x},\n"
                    f"  lint_output=0x{ctypes.addressof(self.lint_output.contents) if self.lint_output else 0:x},\n"
                    f"  int_memory=0x{ctypes.addressof(self.int_memory.contents) if self.int_memory else 0:x},\n"
                    f"  buffer_size={self.buffer_size},\n"
                    f"  bits_per_buffer={self.bits_per_buffer},\n"
                    f"  buffer_mutex=0x{self.buffer_mutex or 0:x},\n"
                    f"  mutex_take={'valid' if self.mutex_take else 'NULL'},\n"
                    f"  mutex_give={'valid' if self.mutex_give else 'NULL'}\n"
                    f")")
        except:
            return "PluginRuntimeArgs(corrupted or invalid)"
