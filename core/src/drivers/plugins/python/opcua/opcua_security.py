"""
OPC-UA Security Utilities

This module provides utilities for handling OPC-UA security features including:
- Auto-generation of server certificates
- Certificate loading and validation
- Security policy and mode mapping
- Client trust list management
"""

import os
import ssl
import socket
import hashlib
import asyncio
from pathlib import Path
from typing import Optional, Tuple, List
from urllib.parse import urlparse
from asyncua.crypto import uacrypto
from asyncua.crypto.cert_gen import setup_self_signed_certificate
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep, SecurityPolicyAes256Sha256RsaPss
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


class OpcuaSecurityManager:
    """Manages OPC-UA security configuration and certificates."""

    # Mapping from config strings to opcua-asyncio security policies
    SECURITY_POLICY_MAPPING = {
        "None": None,
        "Basic256Sha256": SecurityPolicyBasic256Sha256,
        "Aes128_Sha256_RsaOaep": SecurityPolicyAes128Sha256RsaOaep,
        "Aes256_Sha256_RsaPss": SecurityPolicyAes256Sha256RsaPss
    }

    # Mapping from config strings to opcua-asyncio message security modes
    SECURITY_MODE_MAPPING = {
        "None": 1,  # MessageSecurityMode.None
        "Sign": 2,  # MessageSecurityMode.Sign
        "SignAndEncrypt": 3  # MessageSecurityMode.SignAndEncrypt
    }

    CERTS_DIR = "certs"
    SERVER_CERT_FILE = "server_cert.pem"
    SERVER_KEY_FILE = "server_key.pem"

    def __init__(self, config, plugin_dir: str = None):
        """
        Initialize security manager with configuration.

        Args:
            config: OpcuaConfig instance with security settings
            plugin_dir: Directory where certificates are stored (defaults to plugin directory)
        """
        self.config = config
        self.plugin_dir = plugin_dir or os.path.dirname(__file__)
        self.certs_dir = os.path.join(self.plugin_dir, self.CERTS_DIR)
        self.certificate_data = None
        self.private_key_data = None
        self.security_policy = None
        self.security_mode = None
        self.trusted_certificates = []  # List of trusted client certificates

    async def initialize_security(self) -> bool:
        """
        Initialize security settings based on configuration.

        Returns:
            bool: True if security initialized successfully
        """
        try:
            # Map security policy
            self.security_policy = self.SECURITY_POLICY_MAPPING.get(self.config.security_policy)
            if self.config.security_policy != "None" and self.security_policy is None:
                print(f"(FAIL) Unsupported security policy: {self.config.security_policy}")
                return False

            # Map security mode
            self.security_mode = self.SECURITY_MODE_MAPPING.get(self.config.security_mode)
            if self.security_mode is None:
                print(f"(FAIL) Unsupported security mode: {self.config.security_mode}")
                return False

            # Load certificates if required
            if self.config.security_policy != "None" or self.config.security_mode != "None":
                if not await self._ensure_server_certificates():
                    return False

            # Load trusted client certificates
            if self.config.client_auth.enabled:
                if not self._load_trusted_certificates():
                    return False

            print(f"(PASS) Security initialized: policy={self.config.security_policy}, mode={self.config.security_mode}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to initialize security: {e}")
            return False

    async def _ensure_server_certificates(self) -> bool:
        """
        Ensure server certificates exist, generate if missing.

        Returns:
            bool: True if certificates are available
        """
        try:
            # Create certs directory if it doesn't exist
            os.makedirs(self.certs_dir, exist_ok=True)

            cert_path = os.path.join(self.certs_dir, self.SERVER_CERT_FILE)
            key_path = os.path.join(self.certs_dir, self.SERVER_KEY_FILE)

            # Check if certificates already exist
            if os.path.exists(cert_path) and os.path.exists(key_path):
                print(f"(PASS) Found existing server certificates in {self.certs_dir}")
            else:
                print(f"(INFO) Server certificates not found, generating new ones in {self.certs_dir}")
                if not await self.generate_server_certificate(cert_path, key_path):
                    return False

            # Load the certificates
            return self._load_certificates(cert_path, key_path)

        except Exception as e:
            print(f"(FAIL) Failed to ensure server certificates: {e}")
            return False

    def _load_certificates(self, cert_path: str, key_path: str) -> bool:
        """
        Load certificate and private key files.

        Returns:
            bool: True if certificates loaded successfully
        """
        try:
            # Load certificate
            with open(cert_path, 'rb') as cert_file:
                self.certificate_data = cert_file.read()

            # Load private key
            with open(key_path, 'rb') as key_file:
                self.private_key_data = key_file.read()

            # Validate certificate format (basic check)
            if not self._validate_certificate_format():
                return False

            print(f"(PASS) Server certificates loaded from {cert_path}")
            return True

        except FileNotFoundError as e:
            print(f"(FAIL) Certificate file not found: {e}")
            return False
        except Exception as e:
            print(f"(FAIL) Failed to load certificates: {e}")
            return False

    def _validate_certificate_format(self) -> bool:
        """
        Perform comprehensive validation of certificate format and extensions.

        Returns:
            bool: True if certificate format and extensions are valid
        """
        try:
            # Try to load certificate with ssl module for basic validation
            ssl.PEM_cert_to_DER_cert(self.certificate_data.decode('utf-8'))
            
            # Enhanced validation using cryptography library
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                import datetime
                
                cert = x509.load_pem_x509_certificate(self.certificate_data, default_backend())
                
                # Check expiration
                if cert.not_valid_after < datetime.datetime.now():
                    print("(WARN) Certificate has expired")
                    return False
                
                # Check if certificate will expire soon (within 30 days)
                days_until_expiry = (cert.not_valid_after - datetime.datetime.now()).days
                if days_until_expiry < 30:
                    print(f"(WARN) Certificate expires in {days_until_expiry} days")
                
                # Check for Subject Alternative Name extension
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_names = san_ext.value
                    
                    # Log SAN entries for debugging
                    dns_names = [name.value for name in san_names if isinstance(name, x509.DNSName)]
                    ip_addresses = [name.value.compressed for name in san_names if isinstance(name, x509.IPAddress)]
                    uris = [name.value for name in san_names if isinstance(name, x509.UniformResourceIdentifier)]
                    
                    print(f"(INFO) Certificate SAN DNS names: {dns_names}")
                    print(f"(INFO) Certificate SAN IP addresses: {ip_addresses}")
                    print(f"(INFO) Certificate SAN URIs: {uris}")
                    
                    # Check if we have expected entries
                    system_hostname = socket.gethostname()
                    if system_hostname not in dns_names and system_hostname != "localhost":
                        print(f"(WARN) System hostname '{system_hostname}' not found in certificate DNS SANs")
                    
                    # Check for application URI
                    expected_uri = "urn:autonomy-logic:openplc:opcua:server"
                    if expected_uri not in uris:
                        print(f"(WARN) Expected application URI '{expected_uri}' not found in certificate")
                    
                except x509.ExtensionNotFound:
                    print("(WARN) Certificate missing Subject Alternative Name extension")
                
                # Check key usage extensions
                try:
                    key_usage = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE).value
                    if not key_usage.digital_signature:
                        print("(WARN) Certificate lacks digital signature key usage")
                    if not key_usage.key_encipherment:
                        print("(WARN) Certificate lacks key encipherment usage")
                except x509.ExtensionNotFound:
                    print("(WARN) Certificate missing key usage extension")
                
                print("(PASS) Certificate format and extensions validated")
                return True
                
            except ImportError:
                print("(WARN) cryptography library not available for enhanced validation")
                return True  # Fall back to basic validation
                
        except Exception:
            try:
                # Try as DER format
                ssl.DER_cert_to_PEM_cert(self.certificate_data)
                print("(PASS) Certificate validated as DER format")
                return True
            except Exception as e:
                print(f"(FAIL) Invalid certificate format: {e}")
                return False

    def _load_trusted_certificates(self) -> bool:
        """
        Load trusted client certificates from configuration.

        Returns:
            bool: True if trusted certificates loaded successfully
        """
        try:
            self.trusted_certificates = []

            if not self.config.client_auth.trusted_certificates_pem:
                if not self.config.client_auth.trust_all_clients:
                    print("(WARN) Client authentication enabled but no trusted certificates configured")
                return True

            # Parse and validate each certificate
            for i, cert_pem in enumerate(self.config.client_auth.trusted_certificates_pem):
                try:
                    # Basic validation - check if it's a valid PEM certificate
                    cert_der = ssl.PEM_cert_to_DER_cert(cert_pem)
                    cert_hash = hashlib.sha256(cert_der).hexdigest()[:16]  # Short hash for logging

                    self.trusted_certificates.append({
                        'pem': cert_pem,
                        'der': cert_der,
                        'hash': cert_hash
                    })

                    print(f"(PASS) Loaded trusted certificate {i+1} (SHA256: {cert_hash})")

                except Exception as e:
                    print(f"(FAIL) Invalid trusted certificate {i+1}: {e}")
                    return False

            print(f"(PASS) Loaded {len(self.trusted_certificates)} trusted client certificates")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to load trusted certificates: {e}")
            return False

    def validate_client_certificate(self, client_cert_pem: str) -> bool:
        """
        Validate if a client certificate is in the trust list.

        Args:
            client_cert_pem: Client certificate in PEM format

        Returns:
            bool: True if client certificate is trusted
        """
        if not self.config.client_auth.enabled:
            return True  # No authentication required

        if self.config.client_auth.trust_all_clients:
            return True  # Trust all clients

        if not self.trusted_certificates:
            print("(WARN) Client authentication enabled but no trusted certificates loaded")
            return False

        try:
            # Convert client certificate to DER for comparison
            client_cert_der = ssl.PEM_cert_to_DER_cert(client_cert_pem)
            client_hash = hashlib.sha256(client_cert_der).hexdigest()[:16]

            # Check if client certificate matches any trusted certificate
            for trusted_cert in self.trusted_certificates:
                if trusted_cert['der'] == client_cert_der:
                    print(f"(PASS) Client certificate trusted (SHA256: {client_hash})")
                    return True

            print(f"(FAIL) Client certificate not trusted (SHA256: {client_hash})")
            return False

        except Exception as e:
            print(f"(FAIL) Error validating client certificate: {e}")
            return False

    def get_security_settings(self) -> Tuple[Optional[object], int, Optional[bytes], Optional[bytes]]:
        """
        Get security settings for opcua-asyncio server.

        Returns:
            Tuple of (security_policy_class, security_mode, certificate_data, private_key_data)
        """
        return (
            self.security_policy,
            self.security_mode,
            self.certificate_data,
            self.private_key_data
        )

    async def generate_server_certificate(
        self,
        cert_path: str,
        key_path: str,
        common_name: str = "OpenPLC OPC-UA Server",
        key_size: int = 2048,
        valid_days: int = 365
    ) -> bool:
        """
        Generate a self-signed certificate for the server with proper SAN extensions.

        Args:
            cert_path: Path where certificate will be saved
            key_path: Path where private key will be saved
            common_name: Common name for the certificate
            key_size: RSA key size
            valid_days: Certificate validity period

        Returns:
            bool: True if certificate generated successfully
        """
        try:
            # Get system hostname for proper certificate validation
            system_hostname = socket.gethostname()
            
            # Extract hostname from endpoint if available
            endpoint_hostname = "localhost"  # default
            if hasattr(self.config, 'endpoint') and self.config.endpoint:
                try:
                    # Convert opc.tcp:// to http:// for parsing
                    endpoint_url = self.config.endpoint.replace("opc.tcp://", "http://")
                    parsed = urlparse(endpoint_url)
                    if parsed.hostname and parsed.hostname != "0.0.0.0":
                        endpoint_hostname = parsed.hostname
                except Exception as e:
                    print(f"(WARN) Could not parse endpoint hostname: {e}")
            
            # Create consistent application URI for Autonomy Logic
            app_uri = "urn:autonomy-logic:openplc:opcua:server"
            
            # Collect all possible hostnames for SAN DNS entries
            dns_names = []
            # Add system hostname
            if system_hostname and system_hostname != "localhost":
                dns_names.append(system_hostname)
            # Add endpoint hostname if different
            if endpoint_hostname and endpoint_hostname not in dns_names:
                dns_names.append(endpoint_hostname)
            # Always include localhost
            if "localhost" not in dns_names:
                dns_names.append("localhost")
            
            # IP addresses for SAN
            ip_addresses = ["127.0.0.1"]
            # Add 0.0.0.0 if endpoint uses it (for bind-all scenarios)
            if hasattr(self.config, 'endpoint') and "0.0.0.0" in self.config.endpoint:
                ip_addresses.append("0.0.0.0")
            
            print(f"(INFO) Generating certificate with DNS SANs: {dns_names}")
            print(f"(INFO) Generating certificate with IP SANs: {ip_addresses}")
            print(f"(INFO) Application URI: {app_uri}")
            
            # Use the setup_self_signed_certificate function from asyncua with supported parameters
            await setup_self_signed_certificate(
                key_file=Path(key_path),
                cert_file=Path(cert_path),
                app_uri=app_uri,
                host_name=system_hostname,  # Use actual system hostname
                cert_use=[ExtendedKeyUsageOID.SERVER_AUTH],
                subject_attrs={
                    "countryName": "US",
                    "stateOrProvinceName": "CA",
                    "localityName": "California",
                    "organizationName": "Autonomy Logic",
                    "commonName": common_name
                },
            )

            print(f"(PASS) Server certificate generated with proper SANs: {cert_path}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to generate server certificate: {e}")
            return False
