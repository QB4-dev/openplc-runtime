"""
Generic Buffer Accessor for OpenPLC Python Plugin System

This module provides generic buffer access operations that work with any buffer type.
It encapsulates the low-level ctypes operations and provides a clean interface
for reading and writing buffer values.
"""

import ctypes
from typing import Any, Optional, Tuple
try:
    # Try relative imports first (when used as package)
    from .component_interfaces import IBufferAccessor
    from .buffer_validator import BufferValidator
    from .mutex_manager import MutexManager
    from .buffer_types import get_buffer_types
except ImportError:
    # Fall back to absolute imports (when testing standalone)
    from component_interfaces import IBufferAccessor
    from buffer_validator import BufferValidator
    from mutex_manager import MutexManager
    from buffer_types import get_buffer_types


class GenericBufferAccessor(IBufferAccessor):
    """
    Generic buffer accessor that handles all buffer types uniformly.

    This class encapsulates the complex ctypes buffer access logic and provides
    a clean, type-agnostic interface for buffer operations. It eliminates the
    massive code duplication that existed in the original SafeBufferAccess class.
    """

    def __init__(self, runtime_args, validator: BufferValidator, mutex_manager: MutexManager):
        """
        Initialize the generic buffer accessor.

        Args:
            runtime_args: PluginRuntimeArgs instance
            validator: BufferValidator instance
            mutex_manager: MutexManager instance
        """
        self.args = runtime_args
        self.validator = validator
        self.mutex = mutex_manager
        self.buffer_types = get_buffer_types()

    def read_buffer(self, buffer_type: str, buffer_idx: int, bit_idx: Optional[int] = None,
                   thread_safe: bool = True) -> Tuple[Any, str]:
        """
        Generic buffer read operation.

        Args:
            buffer_type: Buffer type name (e.g., 'bool_input', 'int_output')
            buffer_idx: Buffer index
            bit_idx: Bit index (required for boolean operations)
            thread_safe: Whether to use mutex protection

        Returns:
            Tuple[Any, str]: (value, error_message)
        """
        # Validate parameters
        is_valid, msg = self.validator.validate_operation_params(buffer_type, buffer_idx, bit_idx)
        if not is_valid:
            return None, msg

        # Get buffer type info
        buffer_type_obj, direction = self.buffer_types.get_buffer_info(buffer_type)

        # Define the read operation
        def do_read():
            return self._perform_read(buffer_type, buffer_type_obj, direction, buffer_idx, bit_idx)

        # Execute with or without mutex
        if thread_safe:
            return self.mutex.with_mutex(do_read)
        else:
            return do_read()

    def write_buffer(self, buffer_type: str, buffer_idx: int, value: Any,
                    bit_idx: Optional[int] = None, thread_safe: bool = True) -> Tuple[bool, str]:
        """
        Generic buffer write operation.

        Args:
            buffer_type: Buffer type name (e.g., 'bool_output', 'int_output')
            buffer_idx: Buffer index
            value: Value to write
            bit_idx: Bit index (required for boolean operations)
            thread_safe: Whether to use mutex protection

        Returns:
            Tuple[bool, str]: (success, error_message)
        """
        # Validate parameters
        is_valid, msg = self.validator.validate_operation_params(buffer_type, buffer_idx, bit_idx, value)
        if not is_valid:
            return False, msg

        # Get buffer type info
        buffer_type_obj, direction = self.buffer_types.get_buffer_info(buffer_type)

        # Define the write operation
        def do_write():
            return self._perform_write(buffer_type, buffer_type_obj, direction, buffer_idx, value, bit_idx)

        # Execute with or without mutex
        if thread_safe:
            result = self.mutex.with_mutex(do_write)
            return result if isinstance(result, tuple) else (result, "Success")
        else:
            return do_write()

    def get_buffer_pointer(self, buffer_type: str) -> Optional[ctypes.POINTER]:
        """
        Get the buffer pointer for a given type.

        Args:
            buffer_type: Buffer type name

        Returns:
            Optional[ctypes.POINTER]: Buffer pointer or None if invalid
        """
        try:
            buffer_type_obj, direction = self.buffer_types.get_buffer_info(buffer_type)

            # Map buffer type to runtime_args field
            field_map = {
                ('bool', 'input'): 'bool_input',
                ('bool', 'output'): 'bool_output',
                ('byte', 'input'): 'byte_input',
                ('byte', 'output'): 'byte_output',
                ('int', 'input'): 'int_input',
                ('int', 'output'): 'int_output',
                ('int', 'memory'): 'int_memory',
                ('dint', 'input'): 'dint_input',
                ('dint', 'output'): 'dint_output',
                ('dint', 'memory'): 'dint_memory',
                ('lint', 'input'): 'lint_input',
                ('lint', 'output'): 'lint_output',
                ('lint', 'memory'): 'lint_memory',
            }

            field_name = field_map.get((buffer_type_obj.name, direction))
            if field_name:
                return getattr(self.args, field_name, None)

            return None

        except (AttributeError, TypeError, ValueError):
            return None

    def _perform_read(self, buffer_type: str, buffer_type_obj, direction: str,
                     buffer_idx: int, bit_idx: Optional[int]) -> Tuple[Any, str]:
        """
        Internal method to perform the actual buffer read operation.
        """
        try:
            # Get the appropriate buffer pointer
            buffer_ptr = self.get_buffer_pointer(buffer_type)
            if buffer_ptr is None or buffer_ptr.contents is None:
                return None, f"Buffer pointer not available for {buffer_type}"

            # Handle boolean operations (require bit indexing)
            if buffer_type_obj.name == 'bool':
                if bit_idx is None:
                    return None, "Bit index required for boolean operations"

                # Access the specific bit within the buffer
                value = bool(buffer_ptr[buffer_idx][bit_idx].contents.value)
                return value, "Success"

            # Handle other buffer types (direct value access)
            else:
                value = buffer_ptr[buffer_idx].contents.value
                return value, "Success"

        except (AttributeError, TypeError, ValueError, OSError, MemoryError) as e:
            return None, f"Buffer read error: {e}"

    def _perform_write(self, buffer_type: str, buffer_type_obj, direction: str,
                      buffer_idx: int, value: Any, bit_idx: Optional[int]) -> Tuple[bool, str]:
        """
        Internal method to perform the actual buffer write operation.
        """
        try:
            # Get the appropriate buffer pointer
            buffer_ptr = self.get_buffer_pointer(buffer_type)
            if buffer_ptr is None or buffer_ptr.contents is None:
                return False, f"Buffer pointer not available for {buffer_type}"

            # Handle boolean operations (require bit indexing)
            if buffer_type_obj.name == 'bool':
                if bit_idx is None:
                    return False, "Bit index required for boolean operations"

                # Set the specific bit within the buffer
                buffer_ptr[buffer_idx][bit_idx].contents.value = 1 if value else 0
                return True, "Success"

            # Handle other buffer types (direct value assignment)
            else:
                buffer_ptr[buffer_idx].contents.value = value
                return True, "Success"

        except (AttributeError, TypeError, ValueError, OSError, MemoryError) as e:
            return False, f"Buffer write error: {e}"

    def _handle_buffer_exception(self, exception, operation_name: str) -> str:
        """
        Centralized exception handling for buffer operations.

        Args:
            exception: The caught exception
            operation_name: Name of the operation that failed

        Returns:
            str: Formatted error message
        """
        if isinstance(exception, (AttributeError, TypeError)):
            return f"Structure access error during {operation_name}: {exception}"
        elif isinstance(exception, (ValueError, OverflowError)):
            return f"Value validation error during {operation_name}: {exception}"
        elif isinstance(exception, OSError):
            return f"System error during {operation_name}: {exception}"
        elif isinstance(exception, MemoryError):
            return f"Memory error during {operation_name}: {exception}"
        else:
            return f"Unexpected error during {operation_name}: {exception}"
