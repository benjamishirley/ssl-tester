"""Cipher suite detection and validation."""

import logging
import ssl
import socket
from typing import List, Set, Optional, Tuple

from ssl_tester.models import CipherCheckResult, Severity

logger = logging.getLogger(__name__)

# Weak cipher patterns (should be marked as WARN/FAIL)
WEAK_CIPHER_PATTERNS = [
    "RC4",  # RC4 cipher
    "MD5",  # MD5 hash
    "DES",  # DES cipher
    "3DES",  # Triple DES
    "EXPORT",  # Export-grade ciphers
    "NULL",  # Null encryption
    "ANON",  # Anonymous ciphers
    "ADH",  # Anonymous Diffie-Hellman
    "AECDH",  # Anonymous ECDH
]

# Cipher strength classification
CIPHER_STRENGTH_STRONG = "Strong"
CIPHER_STRENGTH_MEDIUM = "Medium"
CIPHER_STRENGTH_WEAK = "Weak"
CIPHER_STRENGTH_NULL = "Null"

# Ciphers that support Perfect Forward Secrecy (PFS)
PFS_CIPHER_PATTERNS = [
    "DHE",  # Diffie-Hellman Ephemeral
    "ECDHE",  # Elliptic Curve Diffie-Hellman Ephemeral
]

# Ciphers that do NOT support PFS
NON_PFS_CIPHER_PATTERNS = [
    "RSA",  # RSA key exchange (without DHE/ECDHE)
    "DH",  # Static Diffie-Hellman
    "ECDH",  # Static ECDH
]


def _is_weak_cipher(cipher_name: str) -> bool:
    """Check if a cipher is considered weak."""
    cipher_upper = cipher_name.upper()
    return any(pattern in cipher_upper for pattern in WEAK_CIPHER_PATTERNS)


def _supports_pfs(cipher_name: str) -> bool:
    """Check if a cipher supports Perfect Forward Secrecy."""
    cipher_upper = cipher_name.upper()
    return any(pattern in cipher_upper for pattern in PFS_CIPHER_PATTERNS)


def _get_cipher_strength(cipher_name: str) -> str:
    """Classify cipher strength."""
    cipher_upper = cipher_name.upper()
    
    if "NULL" in cipher_upper or "ANON" in cipher_upper:
        return CIPHER_STRENGTH_NULL
    
    if any(pattern in cipher_upper for pattern in ["RC4", "MD5", "DES", "EXPORT"]):
        return CIPHER_STRENGTH_WEAK
    
    if "3DES" in cipher_upper or "SHA1" in cipher_upper:
        return CIPHER_STRENGTH_MEDIUM
    
    return CIPHER_STRENGTH_STRONG


def _test_cipher_suites(
    host: str, port: int, protocol_version: int, timeout: float = 10.0, service: Optional[str] = None
) -> List[str]:
    """
    Test which cipher suites are supported for a given protocol version.

    Args:
        host: Target hostname
        port: Target port
        protocol_version: SSL/TLS protocol version constant
        timeout: Connection timeout
        service: Service type (for STARTTLS support)

    Returns:
        List of supported cipher suite names
    """
    supported_ciphers: List[str] = []
    
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            # Connect
            sock.connect((host, port))

            # Perform STARTTLS if needed
            if service:
                from ssl_tester.services import is_starttls_port
                if is_starttls_port(port, service):
                    from ssl_tester.network import _perform_starttls
                    _perform_starttls(sock, service, timeout)

            # Create SSL context with specific protocol version
            context = ssl.SSLContext(protocol_version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Get available cipher suites for this protocol
            # Note: Python's ssl module doesn't provide a direct way to test individual ciphers
            # We'll use the negotiated cipher from a successful handshake
            # and try to get all available ciphers from the context
            
            # Wrap socket and get negotiated cipher
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            
            # Get negotiated cipher
            negotiated_cipher = ssl_sock.cipher()
            if negotiated_cipher:
                cipher_name = negotiated_cipher[0]
                if cipher_name not in supported_ciphers:
                    supported_ciphers.append(cipher_name)
            
            ssl_sock.close()
            sock.close()
            
        except (ssl.SSLError, socket.timeout, ConnectionError) as e:
            logger.debug(f"Cipher test failed for protocol {protocol_version}: {e}")
            sock.close()
    except Exception as e:
        logger.debug(f"Error testing ciphers for protocol {protocol_version}: {e}")

    return supported_ciphers


def check_cipher_suites(
    host: str, port: int, timeout: float = 10.0, protocol_versions: Optional[List[int]] = None, service: Optional[str] = None
) -> CipherCheckResult:
    """
    Check which cipher suites are supported by the server.

    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        protocol_versions: List of protocol versions to test (if None, tests all available)

    Returns:
        CipherCheckResult with supported ciphers and severity
    """
    logger.info(f"Checking cipher suites for {host}:{port}...")

    all_supported_ciphers: Set[str] = set()
    weak_ciphers: List[str] = []
    
    # Determine which protocol versions to test
    if protocol_versions is None:
        protocol_versions = []
        if hasattr(ssl, "PROTOCOL_TLSv1_3"):
            protocol_versions.append(ssl.PROTOCOL_TLSv1_3)
        elif hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
            # Python 3.10+ - we'll handle this separately
            pass
        if hasattr(ssl, "PROTOCOL_TLSv1_2"):
            protocol_versions.append(ssl.PROTOCOL_TLSv1_2)
        elif hasattr(ssl, "PROTOCOL_TLS"):
            protocol_versions.append(ssl.PROTOCOL_TLS)
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            protocol_versions.append(ssl.PROTOCOL_TLSv1_1)
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            protocol_versions.append(ssl.PROTOCOL_TLSv1)

    # Test ciphers for each protocol version
    for protocol_version in protocol_versions:
        ciphers = _test_cipher_suites(host, port, protocol_version, timeout, service)
        all_supported_ciphers.update(ciphers)

    # For Python 3.10+, also try PROTOCOL_TLS_CLIENT
    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Perform STARTTLS if needed
            if service:
                from ssl_tester.services import is_starttls_port
                if is_starttls_port(port, service):
                    from ssl_tester.network import _perform_starttls
                    _perform_starttls(sock, service, timeout)
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            
            negotiated_cipher = ssl_sock.cipher()
            if negotiated_cipher:
                cipher_name = negotiated_cipher[0]
                all_supported_ciphers.add(cipher_name)
            
            ssl_sock.close()
            sock.close()
        except Exception as e:
            logger.debug(f"Error testing ciphers with PROTOCOL_TLS_CLIENT: {e}")

    # Convert to sorted list
    supported_ciphers = sorted(list(all_supported_ciphers))

    # Identify weak ciphers
    for cipher in supported_ciphers:
        if _is_weak_cipher(cipher):
            weak_ciphers.append(cipher)

    # Check if PFS is supported
    pfs_supported = any(_supports_pfs(cipher) for cipher in supported_ciphers)

    # Determine server preferences (simplified check)
    # In a real implementation, we would test cipher ordering
    # For now, we assume server preferences if we get a specific cipher
    server_preferences = True  # Placeholder - would need more sophisticated testing

    # Determine severity
    severity = Severity.OK
    if not supported_ciphers:
        # No ciphers found - this is a failure
        severity = Severity.FAIL
    elif weak_ciphers:
        # Weak ciphers are warnings, but if only weak ciphers are supported, it's a failure
        if len(weak_ciphers) == len(supported_ciphers):
            severity = Severity.FAIL
        else:
            severity = Severity.WARN
    
    if not pfs_supported and supported_ciphers:
        # No PFS support is a warning
        if severity == Severity.OK:
            severity = Severity.WARN

    return CipherCheckResult(
        supported_ciphers=supported_ciphers,
        weak_ciphers=weak_ciphers,
        pfs_supported=pfs_supported,
        server_preferences=server_preferences,
        severity=severity,
    )

