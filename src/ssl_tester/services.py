"""Multi-service support (HTTPS, SMTP, IMAP, POP3, FTP, LDAP, etc.)."""

import logging
import socket
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Service definitions: (name, default_ports, starttls_ports, direct_tls_ports)
SERVICES = {
    "HTTPS": ("HTTPS", [443], [], [443]),
    "SMTP": ("SMTP", [25, 587], [25, 587], [465]),
    "IMAP": ("IMAP", [143], [143], [993]),
    "POP3": ("POP3", [110], [110], [995]),
    "FTP": ("FTP", [21], [21], [990]),
    "LDAP": ("LDAP", [389], [389], [636]),
    "XMPP": ("XMPP", [5222], [5222], []),
    "RDP": ("RDP", [3389], [], [3389]),
    "PostgreSQL": ("PostgreSQL", [5432], [], [5432]),
    "MySQL": ("MySQL", [3306], [], [3306]),
}


def detect_service(port: int) -> Optional[str]:
    """
    Detect service type based on port number.
    
    Args:
        port: Port number
        
    Returns:
        Service name or None if unknown
    """
    for service_name, (_, default_ports, starttls_ports, direct_tls_ports) in SERVICES.items():
        if port in default_ports or port in starttls_ports or port in direct_tls_ports:
            return service_name
    
    return None


def get_service_info(service_name: str) -> Optional[Tuple[str, list, list, list]]:
    """
    Get service information.
    
    Args:
        service_name: Service name (e.g., "HTTPS", "SMTP")
        
    Returns:
        Tuple of (name, default_ports, starttls_ports, direct_tls_ports) or None
    """
    return SERVICES.get(service_name.upper())


def is_starttls_port(port: int, service_name: Optional[str] = None) -> bool:
    """
    Check if port requires STARTTLS.
    
    Args:
        port: Port number
        service_name: Optional service name (if None, will be detected)
        
    Returns:
        True if port requires STARTTLS
    """
    if service_name is None:
        service_name = detect_service(port)
    
    if service_name:
        _, _, starttls_ports, _ = SERVICES.get(service_name.upper(), (None, [], [], []))
        return port in starttls_ports
    
    return False


def is_direct_tls_port(port: int, service_name: Optional[str] = None) -> bool:
    """
    Check if port uses direct TLS (not STARTTLS).
    
    Args:
        port: Port number
        service_name: Optional service name (if None, will be detected)
        
    Returns:
        True if port uses direct TLS
    """
    if service_name is None:
        service_name = detect_service(port)
    
    if service_name:
        _, _, _, direct_tls_ports = SERVICES.get(service_name.upper(), (None, [], [], []))
        return port in direct_tls_ports
    
    # Default: assume direct TLS for HTTPS
    return service_name == "HTTPS" or port == 443


def get_default_port(service_name: str) -> Optional[int]:
    """
    Get default port for a service.
    
    Args:
        service_name: Service name
        
    Returns:
        Default port or None
    """
    service_info = get_service_info(service_name)
    if service_info:
        _, default_ports, _, _ = service_info
        return default_ports[0] if default_ports else None
    return None

