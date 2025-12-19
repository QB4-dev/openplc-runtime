"""
User authentication manager for OPC UA server.

This module implements asyncua's UserManager interface for
authenticating OPC UA clients using various methods.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional, Any

from asyncua.server.users import UserRole
from asyncua.server.user_managers import UserManager

from ..logging import log_info, log_warn, log_error
from ..types.models import UserRole as OpenPLCRole


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user session."""
    username: str
    openplc_role: str
    role: UserRole
    auth_method: str


class OpenPLCUserManager(UserManager):
    """
    Custom user manager for OpenPLC authentication.
    
    Supports:
    - Anonymous access (configurable per security profile)
    - Username/password authentication
    - Certificate-based authentication
    
    Maps OpenPLC roles (viewer, operator, engineer) to asyncua UserRole.
    """
    
    # Map OpenPLC roles to asyncua UserRole
    ROLE_MAP = {
        "viewer": UserRole.User,
        "operator": UserRole.User,
        "engineer": UserRole.Admin,
    }
    
    def __init__(self, config: dict):
        """
        Initialize user manager with configuration.
        
        Args:
            config: Configuration dictionary containing users and security profiles
        """
        super().__init__()
        self._users: dict[str, dict] = {}
        self._cert_users: dict[str, dict] = {}
        self._security_profiles: dict[str, dict] = {}
        self._policy_uri_to_profile: dict[str, str] = {}
        
        self._load_config(config)
    
    def _load_config(self, config: dict) -> None:
        """Load users and security profiles from configuration."""
        # Load users
        for user_config in config.get("users", []):
            user_type = user_config.get("type", "password")
            
            if user_type == "password":
                username = user_config.get("username", "")
                if username:
                    self._users[username] = user_config
            elif user_type == "certificate":
                cert_id = user_config.get("certificate_id", "")
                if cert_id:
                    self._cert_users[cert_id] = user_config
        
        # Load security profiles and build URI mapping
        server_config = config.get("server", {})
        for profile in server_config.get("security_profiles", []):
            if not profile.get("enabled", False):
                continue
            
            name = profile.get("name", "")
            self._security_profiles[name] = profile
            
            # Map policy URI to profile name
            policy_uri = self._get_policy_uri(
                profile.get("security_policy", "None"),
                profile.get("security_mode", "None")
            )
            if policy_uri:
                self._policy_uri_to_profile[policy_uri] = name
        
        log_info(f"Loaded {len(self._users)} password users, {len(self._cert_users)} certificate users")
        log_info(f"Loaded {len(self._security_profiles)} security profiles")
    
    def get_user(
        self,
        iserver,
        username: Optional[str] = None,
        password: Optional[str] = None,
        certificate: Optional[Any] = None
    ) -> Optional[AuthenticatedUser]:
        """
        Authenticate a user.
        
        This method is called by asyncua when a client connects.
        
        Args:
            iserver: Internal server session
            username: Username for password auth
            password: Password for password auth
            certificate: Client certificate for cert auth
            
        Returns:
            AuthenticatedUser if successful, None otherwise
        """
        # Get security profile for this session
        profile = self._get_session_profile(iserver)
        if not profile:
            log_warn("No security profile found for session")
            # Try fallback to insecure profile
            profile = self._security_profiles.get("insecure")
            if not profile:
                return None
        
        profile_name = profile.get("name", "unknown")
        allowed_methods = profile.get("auth_methods", [])
        
        # Determine authentication method
        if username and password:
            return self._auth_password(username, password, profile_name, allowed_methods)
        elif certificate:
            return self._auth_certificate(certificate, profile_name, allowed_methods)
        else:
            return self._auth_anonymous(profile_name, allowed_methods)
    
    def _auth_password(
        self,
        username: str,
        password: str,
        profile_name: str,
        allowed_methods: list
    ) -> Optional[AuthenticatedUser]:
        """Authenticate with username/password."""
        if "Username" not in allowed_methods:
            log_warn(f"Username auth not allowed for profile '{profile_name}'")
            return None
        
        user_config = self._users.get(username)
        if not user_config:
            log_warn(f"Unknown user: {username}")
            return None
        
        # Validate password
        password_hash = user_config.get("password_hash", "")
        if not self._verify_password(password, password_hash):
            log_warn(f"Invalid password for user: {username}")
            return None
        
        # Create authenticated user
        openplc_role = user_config.get("role", "viewer")
        user = AuthenticatedUser(
            username=username,
            openplc_role=openplc_role,
            role=self.ROLE_MAP.get(openplc_role, UserRole.User),
            auth_method="Username"
        )
        
        log_info(f"User '{username}' authenticated (role: {openplc_role}, profile: {profile_name})")
        return user
    
    def _auth_certificate(
        self,
        certificate: Any,
        profile_name: str,
        allowed_methods: list
    ) -> Optional[AuthenticatedUser]:
        """Authenticate with client certificate."""
        if "Certificate" not in allowed_methods:
            log_warn(f"Certificate auth not allowed for profile '{profile_name}'")
            return None
        
        # Extract certificate fingerprint
        cert_id = self._get_cert_fingerprint(certificate)
        if not cert_id:
            log_warn("Could not extract certificate fingerprint")
            return None
        
        user_config = self._cert_users.get(cert_id)
        if not user_config:
            log_warn(f"Unknown certificate: {cert_id[:32]}...")
            return None
        
        # Create authenticated user
        openplc_role = user_config.get("role", "viewer")
        username = user_config.get("username", f"cert:{cert_id[:16]}")
        
        user = AuthenticatedUser(
            username=username,
            openplc_role=openplc_role,
            role=self.ROLE_MAP.get(openplc_role, UserRole.User),
            auth_method="Certificate"
        )
        
        log_info(f"Certificate user authenticated (role: {openplc_role}, profile: {profile_name})")
        return user
    
    def _auth_anonymous(
        self,
        profile_name: str,
        allowed_methods: list
    ) -> Optional[AuthenticatedUser]:
        """Authenticate anonymous user."""
        if "Anonymous" not in allowed_methods:
            log_warn(f"Anonymous auth not allowed for profile '{profile_name}'")
            return None
        
        user = AuthenticatedUser(
            username="anonymous",
            openplc_role="viewer",
            role=UserRole.User,
            auth_method="Anonymous"
        )
        
        log_info(f"Anonymous user connected (profile: {profile_name})")
        return user
    
    def _get_session_profile(self, iserver) -> Optional[dict]:
        """Get security profile for a session based on its policy URI."""
        policy_uri = getattr(iserver, 'security_policy_uri', None)
        if not policy_uri:
            return None
        
        profile_name = self._policy_uri_to_profile.get(policy_uri)
        if not profile_name:
            return None
        
        return self._security_profiles.get(profile_name)
    
    def _get_policy_uri(self, policy: str, mode: str) -> Optional[str]:
        """Get OPC UA security policy URI from config values."""
        uri_map = {
            "None": "http://opcfoundation.org/UA/SecurityPolicy#None",
            "Basic256Sha256": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            "Aes128_Sha256_RsaOaep": "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
            "Aes256_Sha256_RsaPss": "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
        }
        return uri_map.get(policy)
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against stored hash."""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except ImportError:
            # Fallback: direct comparison (not secure, for development only)
            log_warn("bcrypt not available, using insecure password comparison")
            return password == password_hash
        except Exception as e:
            log_error(f"Password verification error: {e}")
            return False
    
    def _get_cert_fingerprint(self, certificate: Any) -> Optional[str]:
        """Extract SHA256 fingerprint from certificate."""
        try:
            # Get certificate bytes
            if hasattr(certificate, 'der'):
                cert_bytes = certificate.der
            elif hasattr(certificate, 'data'):
                cert_bytes = certificate.data
            elif isinstance(certificate, bytes):
                cert_bytes = certificate
            else:
                return None
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_bytes).hexdigest().upper()
            return ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        except Exception as e:
            log_error(f"Certificate fingerprint extraction failed: {e}")
            return None
