"""
Configuration helper for OPC-UA endpoints to handle connectivity issues.
This module provides utilities to configure endpoints that work with different clients.
"""
import socket
from urllib.parse import urlparse
from typing import List, Dict


def get_available_hostnames() -> List[str]:
    """Get list of available hostnames/IPs for the server."""
    hostnames = ["localhost", "127.0.0.1"]
    
    try:
        # Add actual hostname
        hostname = socket.gethostname()
        if hostname not in hostnames:
            hostnames.append(hostname)
            
        # Add FQDN if different
        fqdn = socket.getfqdn()
        if fqdn not in hostnames:
            hostnames.append(fqdn)
            
        # Add local IP addresses
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a remote address to get local IP
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            if local_ip not in hostnames:
                hostnames.append(local_ip)
        except:
            pass
        finally:
            s.close()
            
    except Exception:
        pass
    
    return hostnames


def normalize_endpoint_url(endpoint_url: str) -> str:
    """Normalize endpoint URL for better client compatibility."""
    parsed = urlparse(endpoint_url)
    
    # If using 0.0.0.0, replace with localhost for better compatibility
    if parsed.hostname == "0.0.0.0":
        # Reconstruct with localhost
        return f"{parsed.scheme}://localhost:{parsed.port}{parsed.path}"
    
    return endpoint_url


def create_multiple_endpoints(base_endpoint: str) -> List[str]:
    """Create multiple endpoint variations for better connectivity."""
    parsed = urlparse(base_endpoint)
    endpoints = []
    
    hostnames = get_available_hostnames()
    
    for hostname in hostnames:
        endpoint = f"{parsed.scheme}://{hostname}:{parsed.port}{parsed.path}"
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    
    return endpoints


def suggest_client_endpoints(server_endpoint: str) -> Dict[str, str]:
    """Suggest different endpoint URLs for different client scenarios."""
    parsed = urlparse(server_endpoint)
    
    return {
        "local_connection": f"opc.tcp://localhost:{parsed.port}{parsed.path}",
        "same_machine": f"opc.tcp://127.0.0.1:{parsed.port}{parsed.path}",
        "network_hostname": f"opc.tcp://{socket.gethostname()}:{parsed.port}{parsed.path}",
        "network_ip": f"opc.tcp://{get_local_ip()}:{parsed.port}{parsed.path}" if get_local_ip() else None
    }


def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None


def validate_endpoint_format(endpoint_url: str) -> bool:
    """Validate if endpoint URL has correct OPC-UA format."""
    try:
        parsed = urlparse(endpoint_url)
        return (
            parsed.scheme == "opc.tcp" and
            parsed.hostname is not None and
            parsed.port is not None and
            len(parsed.path) > 0
        )
    except:
        return False