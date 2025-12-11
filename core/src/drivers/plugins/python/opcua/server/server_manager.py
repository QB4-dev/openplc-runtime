"""
OPC UA Server Manager.

This module provides the main server lifecycle management,
using asyncua's native context manager pattern.
"""

import asyncio
from pathlib import Path
from typing import Any, Optional
from datetime import datetime

from asyncua import Server

from ..logging import log_info, log_warn, log_error
from ..security import CertificateManager, OpenPLCUserManager, OpenPLCPermissionRuleset
from .address_space_builder import AddressSpaceBuilder
from .sync_manager import SyncManager


class OpcuaServerManager:
    """
    Manages OPC UA server lifecycle.
    
    Uses asyncua's native patterns for:
    - Server initialization and configuration
    - Security setup (certificates, authentication, authorization)
    - Address space creation
    - Bidirectional synchronization with PLC
    """
    
    def __init__(self, config: dict, buffer_accessor: Any, plugin_dir: str):
        """
        Initialize server manager.
        
        Args:
            config: Complete OPC UA configuration dictionary
            buffer_accessor: SafeBufferAccess instance for PLC memory
            plugin_dir: Plugin directory path for certificates
        """
        self.config = config
        self.buffer_accessor = buffer_accessor
        self.plugin_dir = Path(plugin_dir)
        
        # Server components (initialized during setup)
        self.server: Optional[Server] = None
        self.user_manager: Optional[OpenPLCUserManager] = None
        self.permission_ruleset: Optional[OpenPLCPermissionRuleset] = None
        self.cert_manager: Optional[CertificateManager] = None
        self.address_space_builder: Optional[AddressSpaceBuilder] = None
        self.sync_manager: Optional[SyncManager] = None
        
        # State
        self._running = False
        self._sync_tasks: list[asyncio.Task] = []
    
    async def run(self) -> None:
        """
        Run the OPC UA server.
        
        This is the main entry point that handles the complete
        server lifecycle using asyncua's context manager.
        """
        try:
            # Setup components
            await self._setup_components()
            
            # Use asyncua's context manager for proper lifecycle
            async with self.server:
                log_info("OPC UA server started")
                self._running = True
                
                # Start synchronization
                await self.sync_manager.start()
                
                # Run sync loops
                await self._run_sync_loops()
                
        except asyncio.CancelledError:
            log_info("Server shutdown requested")
        except Exception as e:
            log_error(f"Server error: {e}")
            raise
        finally:
            await self._cleanup()
    
    async def stop(self) -> None:
        """Request server shutdown."""
        self._running = False
        
        # Cancel sync tasks
        for task in self._sync_tasks:
            task.cancel()
        
        if self.sync_manager:
            await self.sync_manager.stop()
    
    async def _setup_components(self) -> None:
        """Setup all server components."""
        server_config = self.config.get("server", {})
        security_config = self.config.get("security", {})
        address_space_config = self.config.get("address_space", {})
        
        # Create user manager
        self.user_manager = OpenPLCUserManager(self.config)
        
        # Create permission ruleset
        self.permission_ruleset = OpenPLCPermissionRuleset()
        
        # Create server with user manager
        self.server = Server(user_manager=self.user_manager)
        
        # Configure server BEFORE init
        await self._configure_server(server_config)
        
        # Setup security BEFORE init
        await self._setup_security(server_config, security_config)
        
        # Initialize server
        await self.server.init()
        log_info("Server initialized")
        
        # Set build info AFTER init
        await self._set_build_info(server_config)
        
        # Build address space AFTER init
        await self._build_address_space(address_space_config)
        
        # Create sync manager
        cycle_time = self.config.get("cycle_time_ms", 100)
        self.sync_manager = SyncManager(
            variable_nodes=self.address_space_builder.variable_nodes,
            buffer_accessor=self.buffer_accessor,
            cycle_time_ms=cycle_time
        )
    
    async def _configure_server(self, server_config: dict) -> None:
        """Configure server settings before initialization."""
        # Set endpoint
        endpoint_url = server_config.get("endpoint_url", "opc.tcp://0.0.0.0:4840")
        self.server.set_endpoint(endpoint_url)
        log_info(f"Endpoint: {endpoint_url}")
        
        # Set server name
        server_name = server_config.get("name", "OpenPLC OPC-UA Server")
        self.server.set_server_name(server_name)
        
        # Set application URI
        app_uri = server_config.get("application_uri", "urn:autonomy-logic:openplc:opcua:server")
        self.server.application_uri = app_uri
    
    async def _setup_security(self, server_config: dict, security_config: dict) -> None:
        """Setup security components."""
        app_uri = server_config.get("application_uri", "urn:autonomy-logic:openplc:opcua:server")
        certs_dir = self.plugin_dir / "certs"
        
        # Create certificate manager
        self.cert_manager = CertificateManager(certs_dir, app_uri)
        
        # Setup security policies and certificates
        security_profiles = server_config.get("security_profiles", [])
        await self.cert_manager.setup_server_security(self.server, security_profiles)
        
        # Setup client certificate validation
        trusted_certs = security_config.get("trusted_client_certificates", [])
        await self.cert_manager.setup_client_validation(self.server, trusted_certs)
    
    async def _set_build_info(self, server_config: dict) -> None:
        """Set server build information."""
        product_uri = server_config.get("product_uri", "urn:autonomy-logic:openplc")
        
        await self.server.set_build_info(
            product_uri=product_uri,
            manufacturer_name="Autonomy Logic",
            product_name="OpenPLC Runtime",
            software_version="1.0.0",
            build_number="1.0.0.0",
            build_date=datetime.now()
        )
    
    async def _build_address_space(self, address_space_config: dict) -> None:
        """Build OPC UA address space from configuration."""
        namespace_uri = address_space_config.get("namespace_uri", "urn:openplc:opcua")
        
        self.address_space_builder = AddressSpaceBuilder(
            server=self.server,
            namespace_uri=namespace_uri,
            permission_ruleset=self.permission_ruleset
        )
        
        if not await self.address_space_builder.initialize():
            raise RuntimeError("Failed to initialize address space builder")
        
        await self.address_space_builder.build_from_config(address_space_config)
    
    async def _run_sync_loops(self) -> None:
        """Run synchronization loops until stopped."""
        # Create sync tasks
        plc_to_opcua_task = asyncio.create_task(
            self.sync_manager.run_plc_to_opcua_loop()
        )
        opcua_to_plc_task = asyncio.create_task(
            self.sync_manager.run_opcua_to_plc_loop()
        )
        
        self._sync_tasks = [plc_to_opcua_task, opcua_to_plc_task]
        
        # Wait for tasks (they run until cancelled)
        try:
            await asyncio.gather(*self._sync_tasks)
        except asyncio.CancelledError:
            pass
    
    async def _cleanup(self) -> None:
        """Cleanup resources."""
        self._running = False
        
        # Cancel any remaining tasks
        for task in self._sync_tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        self._sync_tasks.clear()
        log_info("Server cleanup completed")
