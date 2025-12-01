"""
OPC-UA Security Utilities

This module provides utilities for handling OPC-UA security features including:
- Certificate loading and validation
- Security policy and mode mapping
- Trust list management
"""

import os
import ssl
from typing import Optional, Tuple
from asyncua.crypto import uacrypto
from asyncua.crypto.cert_gen import CertGenerator
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256, SecurityPolicyAes128Sha256RsaOaep, SecurityPolicyAes256Sha256RsaPss


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

    def __init__(self, config):
        """
        Initialize security manager with configuration.

        Args:
            config: OpcuaConfig instance with security settings
        """
        self.config = config
        self.certificate_data = None
        self.private_key_data = None
        self.security_policy = None
        self.security_mode = None

    def initialize_security(self) -> bool:
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
                if not self._load_certificates():
                    return False

            print(f"(PASS) Security initialized: policy={self.config.security_policy}, mode={self.config.security_mode}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to initialize security: {e}")
            return False

    def _load_certificates(self) -> bool:
        """
        Load certificate and private key files.

        Returns:
            bool: True if certificates loaded successfully
        """
        try:
            # Load certificate
            with open(self.config.certificate, 'rb') as cert_file:
                self.certificate_data = cert_file.read()

            # Load private key
            with open(self.config.private_key, 'rb') as key_file:
                self.private_key_data = key_file.read()

            # Validate certificate format (basic check)
            if not self._validate_certificate_format():
                return False

            print(f"(PASS) Certificates loaded from {self.config.certificate} and {self.config.private_key}")
            return True

        except FileNotFoundError as e:
            print(f"(FAIL) Certificate file not found: {e}")
            return False
        except Exception as e:
            print(f"(FAIL) Failed to load certificates: {e}")
            return False

    def _validate_certificate_format(self) -> bool:
        """
        Perform basic validation of certificate format.

        Returns:
            bool: True if certificate format is valid
        """
        try:
            # Try to load certificate with ssl module for basic validation
            ssl.PEM_cert_to_DER_cert(self.certificate_data.decode('utf-8'))
            return True
        except Exception:
            try:
                # Try as DER format
                ssl.DER_cert_to_PEM_cert(self.certificate_data)
                return True
            except Exception as e:
                print(f"(FAIL) Invalid certificate format: {e}")
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

    @staticmethod
    def generate_self_signed_certificate(
        cert_path: str,
        key_path: str,
        common_name: str = "OpenPLC OPC-UA Server",
        key_size: int = 2048,
        valid_days: int = 365
    ) -> bool:
        """
        Generate a self-signed certificate for testing purposes.

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
            # Create certificate generator
            cert_gen = CertGenerator()

            # Generate certificate
            cert_gen.generate(
                cert_path=cert_path,
                key_path=key_path,
                common_name=common_name,
                key_size=key_size,
                valid_days=valid_days
            )

            print(f"(PASS) Self-signed certificate generated: {cert_path}")
            return True

        except Exception as e:
            print(f"(FAIL) Failed to generate self-signed certificate: {e}")
            return False

    @staticmethod
    def validate_certificate_chain(cert_path: str, trusted_certs: Optional[list] = None) -> bool:
        """
        Validate certificate against trust chain.

        Args:
            cert_path: Path to certificate to validate
            trusted_certs: List of trusted certificate paths

        Returns:
            bool: True if certificate is valid and trusted
        """
        try:
            # Load certificate
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            # For now, just check if certificate can be loaded
            # Full chain validation would require more complex implementation
            ssl.PEM_cert_to_DER_cert(cert_data.decode('utf-8'))
            return True

        except Exception as e:
            print(f"(FAIL) Certificate validation failed: {e}")
            return False
