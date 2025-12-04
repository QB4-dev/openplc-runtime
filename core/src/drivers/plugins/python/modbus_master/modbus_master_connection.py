"""Modbus Master plugin connection management utilities."""

import time
from typing import Optional
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException


class ModbusConnectionManager:
    """Manages Modbus TCP connections with retry logic."""

    def __init__(self, host: str, port: int, timeout_ms: int):
        self.host = host
        self.port = port
        self.timeout = timeout_ms / 1000.0  # Convert to seconds

        # Retry configuration
        self.retry_delay_base = 2.0      # initial delay between attempts (seconds)
        self.retry_delay_max = 30.0      # maximum delay between attempts (seconds)
        self.retry_delay_current = self.retry_delay_base

        # Connection state
        self.client: Optional[ModbusTcpClient] = None
        self.is_connected = False

    def connect_with_retry(self, stop_event=None) -> bool:
        """
        Attempts to connect to Modbus device with infinite retry.

        Args:
            stop_event: Optional threading.Event to allow early termination

        Returns:
            True if connected successfully, False if interrupted
        """
        retry_count = 0

        while stop_event is None or not stop_event.is_set():
            try:
                # Create new client if necessary
                if self.client is None or not self.client.connected:
                    if self.client:
                        try:
                            self.client.close()
                        except:
                            pass
                    self.client = ModbusTcpClient(
                        host=self.host,
                        port=self.port,
                        timeout=self.timeout
                    )

                # Attempt to connect
                if self.client.connect():
                    print(f"(PASS) Connected to {self.host}:{self.port} (attempt {retry_count + 1})")
                    self.is_connected = True
                    self.retry_delay_current = self.retry_delay_base  # Reset delay
                    return True

            except Exception as e:
                print(f"(FAIL) Connection attempt {retry_count + 1} failed: {e}")

            # Increment counter and calculate delay
            retry_count += 1

            # Attempt logging
            if retry_count == 1:
                print(f"Failed to connect to {self.host}:{self.port}, starting retry attempts...")
            elif retry_count % 10 == 0:  # Log every 10 attempts
                print(f"Connection attempt {retry_count} failed, continuing retries...")

            # Wait with increasing delay (limited exponential backoff)
            delay = min(self.retry_delay_current, self.retry_delay_max)

            # Sleep in small increments to allow quick stop
            sleep_increments = int(delay * 10)  # 0.1s increments
            for _ in range(sleep_increments):
                if stop_event and stop_event.is_set():
                    return False
                time.sleep(0.1)

            # Increase delay for next attempt (maximum of retry_delay_max)
            self.retry_delay_current = min(self.retry_delay_current * 1.5, self.retry_delay_max)

        return False

    def ensure_connection(self, stop_event=None) -> bool:
        """
        Ensures there is a valid connection, reconnecting if necessary.

        Args:
            stop_event: Optional threading.Event to allow early termination

        Returns:
            True if connection is available, False if interrupted
        """
        # Check if already connected
        if self.client and self.client.connected:
            return True

        # Mark as disconnected
        self.is_connected = False

        # Try to reconnect
        return self.connect_with_retry(stop_event)

    def disconnect(self):
        """Close the connection and clean up resources."""
        try:
            if self.client:
                self.client.close()
                self.client = None
            self.is_connected = False
            print(f"Disconnected from {self.host}:{self.port}")
        except Exception as e:
            print(f"(FAIL) Error disconnecting from {self.host}:{self.port}: {e}")

    def is_healthy(self) -> bool:
        """
        Check if the connection is healthy.

        Returns:
            True if connection is active and healthy
        """
        return self.client is not None and self.client.connected and self.is_connected
