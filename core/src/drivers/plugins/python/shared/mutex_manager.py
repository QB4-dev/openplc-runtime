"""
Mutex Manager for OpenPLC Python Plugin System

This module provides centralized mutex management for thread-safe buffer operations.
It encapsulates all mutex-related logic and provides a clean interface for acquiring
and releasing mutexes.
"""

from typing import Any, Callable
try:
    # Try relative imports first (when used as package)
    from .component_interfaces import IMutexManager
except ImportError:
    # Fall back to absolute imports (when testing standalone)
    from component_interfaces import IMutexManager


class MutexManager(IMutexManager):
    """
    Manages mutex operations for thread-safe buffer access.

    This class encapsulates all mutex-related functionality, providing a clean
    interface for acquiring, releasing, and using mutexes in a thread-safe manner.
    """

    def __init__(self, runtime_args):
        """
        Initialize the mutex manager.

        Args:
            runtime_args: PluginRuntimeArgs instance containing mutex pointers
        """
        self.args = runtime_args

    def acquire(self) -> bool:
        """
        Acquire the buffer mutex.

        Returns:
            bool: True if mutex was acquired successfully, False otherwise
        """
        if not self.args.buffer_mutex:
            return False

        result = self.args.mutex_take(self.args.buffer_mutex)
        return result == 0  # 0 typically indicates success

    def release(self) -> bool:
        """
        Release the buffer mutex.

        Returns:
            bool: True if mutex was released successfully, False otherwise
        """
        if not self.args.buffer_mutex:
            return False

        result = self.args.mutex_give(self.args.buffer_mutex)
        return result == 0  # 0 typically indicates success

    def with_mutex(self, operation: Callable[[], Any]) -> Any:
        """
        Execute an operation within a mutex-protected context.

        This method acquires the mutex, executes the operation, and ensures
        the mutex is always released, even if the operation raises an exception.

        Args:
            operation: Callable that performs the operation to protect

        Returns:
            Any: Result of the operation, or (False, error_message) if mutex acquisition fails

        Example:
            result = mutex_manager.with_mutex(lambda: self._perform_buffer_read())
        """
        if not self.acquire():
            return False, "Failed to acquire mutex"

        try:
            return operation()
        finally:
            self.release()

    def is_mutex_available(self) -> bool:
        """
        Check if the mutex is available for use.

        Returns:
            bool: True if mutex pointers are valid, False otherwise
        """
        return (
            self.args.buffer_mutex is not None and
            self.args.mutex_take is not None and
            self.args.mutex_give is not None
        )

    def get_mutex_status(self) -> str:
        """
        Get a human-readable status of the mutex configuration.

        Returns:
            str: Status description
        """
        if not self.args.buffer_mutex:
            return "No buffer mutex available"
        if not self.args.mutex_take:
            return "No mutex_take function available"
        if not self.args.mutex_give:
            return "No mutex_give function available"
        return "Mutex properly configured"
