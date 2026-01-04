"""Protocol version detection and validation."""

import logging
import ssl
import socket
from typing import List, Tuple, Optional

from ssl_tester.models import ProtocolCheckResult, Severity

logger = logging.getLogger(__name__)

# Protocol version constants
PROTOCOL_SSL2 = "SSLv2"
PROTOCOL_SSL3 = "SSLv3"
PROTOCOL_TLS10 = "TLSv1.0"
PROTOCOL_TLS11 = "TLSv1.1"
PROTOCOL_TLS12 = "TLSv1.2"
PROTOCOL_TLS13 = "TLSv1.3"

# Deprecated protocols (should be marked as WARN or FAIL)
DEPRECATED_PROTOCOLS = [PROTOCOL_SSL2, PROTOCOL_SSL3, PROTOCOL_TLS10, PROTOCOL_TLS11]

# SSL protocols (should be marked as FAIL)
SSL_PROTOCOLS = [PROTOCOL_SSL2, PROTOCOL_SSL3]

# Protocol priority (higher is better)
PROTOCOL_PRIORITY = {
    PROTOCOL_TLS13: 4,
    PROTOCOL_TLS12: 3,
    PROTOCOL_TLS11: 2,
    PROTOCOL_TLS10: 1,
    PROTOCOL_SSL3: 0,
    PROTOCOL_SSL2: -1,
}


def _test_protocol_version(
    host: str, port: int, protocol_version: int, timeout: float = 10.0
) -> bool:
    """
    Test if a specific protocol version is supported.

    Args:
        host: Target hostname
        port: Target port
        protocol_version: SSL/TLS protocol version constant (e.g., ssl.PROTOCOL_TLSv1_2)
        timeout: Connection timeout

    Returns:
        True if protocol is supported, False otherwise
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            # Connect
            sock.connect((host, port))

            # Create SSL context with specific protocol version
            context = ssl.SSLContext(protocol_version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Wrap socket
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()

            # Get protocol version
            negotiated_version = ssl_sock.version()
            ssl_sock.close()
            sock.close()

            logger.debug(f"Protocol {protocol_version} test successful, negotiated: {negotiated_version}")
            return True
        except (ssl.SSLError, socket.timeout, ConnectionError) as e:
            logger.debug(f"Protocol {protocol_version} test failed: {e}")
            sock.close()
            return False
    except Exception as e:
        logger.debug(f"Error testing protocol {protocol_version}: {e}")
        return False


def _get_protocol_name(version: int) -> Optional[str]:
    """Convert SSL/TLS protocol version constant to string name."""
    mapping = {
        ssl.PROTOCOL_TLS_CLIENT: PROTOCOL_TLS13,  # Python 3.10+ uses PROTOCOL_TLS_CLIENT for TLS 1.3
        ssl.PROTOCOL_TLS: PROTOCOL_TLS12,  # PROTOCOL_TLS is usually TLS 1.2+
    }

    # Try to map known constants
    if version in mapping:
        return mapping[version]

    # For older Python versions, try to detect
    if hasattr(ssl, "PROTOCOL_TLSv1_3"):
        if version == ssl.PROTOCOL_TLSv1_3:
            return PROTOCOL_TLS13
    if hasattr(ssl, "PROTOCOL_TLSv1_2"):
        if version == ssl.PROTOCOL_TLSv1_2:
            return PROTOCOL_TLS12
    if hasattr(ssl, "PROTOCOL_TLSv1_1"):
        if version == ssl.PROTOCOL_TLSv1_1:
            return PROTOCOL_TLS11
    if hasattr(ssl, "PROTOCOL_TLSv1"):
        if version == ssl.PROTOCOL_TLSv1:
            return PROTOCOL_TLS10
    if hasattr(ssl, "PROTOCOL_SSLv3"):
        if version == ssl.PROTOCOL_SSLv3:
            return PROTOCOL_SSL3
    if hasattr(ssl, "PROTOCOL_SSLv2"):
        if version == ssl.PROTOCOL_SSLv2:
            return PROTOCOL_SSL2

    return None


def check_protocol_versions(
    host: str, port: int, timeout: float = 10.0
) -> ProtocolCheckResult:
    """
    Check which SSL/TLS protocol versions are supported by the server.

    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ProtocolCheckResult with supported versions and severity
    """
    logger.info(f"Checking protocol versions for {host}:{port}...")

    supported_versions: List[str] = []
    deprecated_versions: List[str] = []
    ssl_versions: List[str] = []

    # Test TLS 1.3 (if available in Python)
    if hasattr(ssl, "PROTOCOL_TLSv1_3"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_TLSv1_3, timeout):
            supported_versions.append(PROTOCOL_TLS13)
    elif hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        # Python 3.10+ uses PROTOCOL_TLS_CLIENT which supports TLS 1.3
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        if _test_protocol_with_context(host, port, context, timeout):
            supported_versions.append(PROTOCOL_TLS13)

    # Test TLS 1.2
    if hasattr(ssl, "PROTOCOL_TLSv1_2"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_TLSv1_2, timeout):
            supported_versions.append(PROTOCOL_TLS12)
    elif hasattr(ssl, "PROTOCOL_TLS"):
        # Fallback for older Python versions
        if _test_protocol_version(host, port, ssl.PROTOCOL_TLS, timeout):
            supported_versions.append(PROTOCOL_TLS12)

    # Test TLS 1.1
    if hasattr(ssl, "PROTOCOL_TLSv1_1"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_TLSv1_1, timeout):
            supported_versions.append(PROTOCOL_TLS11)
            deprecated_versions.append(PROTOCOL_TLS11)

    # Test TLS 1.0
    if hasattr(ssl, "PROTOCOL_TLSv1"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_TLSv1, timeout):
            supported_versions.append(PROTOCOL_TLS10)
            deprecated_versions.append(PROTOCOL_TLS10)

    # Test SSL 3.0
    if hasattr(ssl, "PROTOCOL_SSLv3"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_SSLv3, timeout):
            supported_versions.append(PROTOCOL_SSL3)
            deprecated_versions.append(PROTOCOL_SSL3)
            ssl_versions.append(PROTOCOL_SSL3)

    # Test SSL 2.0 (usually not available in modern Python)
    if hasattr(ssl, "PROTOCOL_SSLv2"):
        if _test_protocol_version(host, port, ssl.PROTOCOL_SSLv2, timeout):
            supported_versions.append(PROTOCOL_SSL2)
            deprecated_versions.append(PROTOCOL_SSL2)
            ssl_versions.append(PROTOCOL_SSL2)

    # Determine best version (highest priority)
    best_version = ""
    if supported_versions:
        best_version = max(
            supported_versions, key=lambda v: PROTOCOL_PRIORITY.get(v, -10)
        )

    # Determine severity
    severity = Severity.OK
    if ssl_versions:
        # SSL protocols are critical failures
        severity = Severity.FAIL
    elif deprecated_versions:
        # Deprecated TLS versions are warnings
        severity = Severity.WARN
        # If only deprecated versions are supported, it's a failure
        if not any(v for v in supported_versions if v not in DEPRECATED_PROTOCOLS):
            severity = Severity.FAIL

    return ProtocolCheckResult(
        supported_versions=supported_versions,
        best_version=best_version,
        deprecated_versions=deprecated_versions,
        ssl_versions=ssl_versions,
        severity=severity,
    )


def _test_protocol_with_context(
    host: str, port: int, context: ssl.SSLContext, timeout: float = 10.0
) -> bool:
    """Test protocol using a custom SSL context."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            negotiated_version = ssl_sock.version()
            ssl_sock.close()
            sock.close()
            logger.debug(f"Protocol test successful, negotiated: {negotiated_version}")
            return True
        except (ssl.SSLError, socket.timeout, ConnectionError) as e:
            logger.debug(f"Protocol test failed: {e}")
            sock.close()
            return False
    except Exception as e:
        logger.debug(f"Error testing protocol: {e}")
        return False

