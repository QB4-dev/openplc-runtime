"""
Certificate management for OPC UA server.

This module handles:
- Server certificate generation (self-signed)
- Certificate loading and validation
- Trust store management for client certificates
"""

import socket
from pathlib import Path
from typing import Optional

from asyncua import Server, ua
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.truststore import TrustStore
from asyncua.crypto.validator import CertificateValidator
from cryptography.x509.oid import ExtendedKeyUsageOID

from ..logging import log_info, log_warn, log_error


class CertificateManager:
    """
    Manages server certificates and client trust store.
    
    Uses asyncua's native certificate APIs for proper integration.
    """
    
    # Security policy type mapping
    POLICY_TYPE_MAP = {
        ("None", "None"): ua.SecurityPolicyType.NoSecurity,
        ("Basic256Sha256", "Sign"): ua.SecurityPolicyType.Basic256Sha256_Sign,
        ("Basic256Sha256", "SignAndEncrypt"): ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt,
        ("Aes128_Sha256_RsaOaep", "Sign"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
        ("Aes128_Sha256_RsaOaep", "SignAndEncrypt"): ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
        ("Aes256_Sha256_RsaPss", "Sign"): ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
        ("Aes256_Sha256_RsaPss", "SignAndEncrypt"): ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
    }
    
    def __init__(self, certs_dir: Path, application_uri: str):
        """
        Initialize certificate manager.
        
        Args:
            certs_dir: Directory for storing certificates
            application_uri: OPC UA application URI for certificate
        """
        self.certs_dir = Path(certs_dir)
        self.application_uri = application_uri
        self.cert_path = self.certs_dir / "server_cert.pem"
        self.key_path = self.certs_dir / "server_key.pem"
        self._trust_store: Optional[TrustStore] = None
    
    async def setup_server_security(
        self,
        server: Server,
        security_profiles: list
    ) -> None:
        """
        Configure server security policies and certificates.
        
        Args:
            server: asyncua Server instance
            security_profiles: List of security profile configurations
        """
        # Collect enabled security policies
        policies = []
        needs_certificates = False
        
        for profile in security_profiles:
            if not profile.get("enabled", False):
                continue
            
            policy = profile.get("security_policy", "None")
            mode = profile.get("security_mode", "None")
            key = (policy, mode)
            
            policy_type = self.POLICY_TYPE_MAP.get(key)
            if policy_type is None:
                log_warn(f"Unknown security policy/mode: {policy}/{mode}")
                continue
            
            policies.append(policy_type)
            
            if policy != "None" or mode != "None":
                needs_certificates = True
            
            log_info(f"Enabled security profile: {profile.get('name', 'unnamed')} ({policy}/{mode})")
        
        if not policies:
            policies = [ua.SecurityPolicyType.NoSecurity]
            log_warn("No security profiles enabled, using NoSecurity")
        
        # Set security policies on server
        server.set_security_policy(policies)
        
        # Setup certificates if needed
        if needs_certificates:
            await self._ensure_certificates()
            await self._load_certificates(server)
    
    async def setup_client_validation(
        self,
        server: Server,
        trusted_certificates: list
    ) -> None:
        """
        Configure client certificate validation.
        
        Args:
            server: asyncua Server instance
            trusted_certificates: List of trusted client certificate configs
        """
        if not trusted_certificates:
            log_info("No trusted client certificates configured")
            return
        
        try:
            # Create trust store directory
            trust_dir = self.certs_dir / "trusted"
            trust_dir.mkdir(parents=True, exist_ok=True)
            
            # Write trusted certificates to files
            cert_files = []
            for i, cert_config in enumerate(trusted_certificates):
                pem_data = cert_config.get("pem", "")
                if not pem_data:
                    continue
                
                cert_file = trust_dir / f"client_{i}.pem"
                cert_file.write_text(pem_data)
                cert_files.append(str(cert_file))
                log_info(f"Added trusted certificate: {cert_config.get('id', f'cert_{i}')}")
            
            if cert_files:
                # Create trust store and validator
                self._trust_store = TrustStore(
                    trust_locations=[str(trust_dir)],
                    crl_locations=[]
                )
                await self._trust_store.load()
                
                validator = CertificateValidator(trust_store=self._trust_store)
                server.set_certificate_validator(validator)
                
                log_info(f"Certificate validation configured with {len(cert_files)} trusted certificates")
        
        except Exception as e:
            log_error(f"Failed to setup client certificate validation: {e}")
    
    async def _ensure_certificates(self) -> None:
        """Ensure server certificates exist, generate if needed."""
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        
        if self.cert_path.exists() and self.key_path.exists():
            log_info(f"Using existing certificates from {self.certs_dir}")
            return
        
        log_info(f"Generating self-signed certificate in {self.certs_dir}")
        
        hostname = socket.gethostname()
        
        await setup_self_signed_certificate(
            key_file=self.key_path,
            cert_file=self.cert_path,
            app_uri=self.application_uri,
            host_name=hostname,
            cert_use=[ExtendedKeyUsageOID.SERVER_AUTH],
            subject_attrs={
                "countryName": "US",
                "stateOrProvinceName": "CA",
                "organizationName": "Autonomy Logic",
                "commonName": "OpenPLC OPC-UA Server"
            }
        )
        
        log_info(f"Certificate generated: {self.cert_path}")
    
    async def _load_certificates(self, server: Server) -> None:
        """Load certificates into server."""
        try:
            # asyncua can load PEM files directly
            await server.load_certificate(str(self.cert_path))
            await server.load_private_key(str(self.key_path))
            log_info("Server certificates loaded successfully")
        except Exception as e:
            log_error(f"Failed to load certificates: {e}")
            raise
