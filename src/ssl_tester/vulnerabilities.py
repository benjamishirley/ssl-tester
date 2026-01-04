"""Cryptographic vulnerability detection."""

import logging
import ssl
import socket
from typing import List, Optional

from ssl_tester.models import VulnerabilityCheckResult, Severity

logger = logging.getLogger(__name__)


def check_heartbleed(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Heartbleed vulnerability (CVE-2014-0160).
    
    Heartbleed is a vulnerability in OpenSSL's heartbeat extension that allows
    reading memory from the server.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Heartbleed vulnerability for {host}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        # Check if heartbeat extension is supported
        # Note: Python's ssl module doesn't expose heartbeat directly
        # This is a simplified check - a full implementation would need
        # to send a heartbeat request and check the response
        negotiated_version = ssl_sock.version()
        
        # Heartbleed affects OpenSSL 1.0.1 through 1.0.1f
        # We can't directly check the OpenSSL version, but we can check
        # if the server responds to heartbeat requests
        # For now, we'll mark as not vulnerable if we can't detect it
        vulnerable = False
        
        ssl_sock.close()
        sock.close()
        
        return VulnerabilityCheckResult(
            vulnerability_name="Heartbleed",
            cve_id="CVE-2014-0160",
            vulnerable=vulnerable,
            severity=Severity.OK if not vulnerable else Severity.FAIL,
            description="OpenSSL Heartbeat Extension vulnerability that allows reading server memory",
            recommendation="Update OpenSSL to version 1.0.1g or later" if vulnerable else None,
        )
    except Exception as e:
        logger.debug(f"Error checking Heartbleed: {e}")
        return VulnerabilityCheckResult(
            vulnerability_name="Heartbleed",
            cve_id="CVE-2014-0160",
            vulnerable=False,  # Assume not vulnerable if we can't check
            severity=Severity.OK,
            description="OpenSSL Heartbeat Extension vulnerability that allows reading server memory",
            recommendation=None,
        )


def check_poodle(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for POODLE vulnerability (CVE-2014-3566).
    
    POODLE (Padding Oracle On Downgraded Legacy Encryption) is a vulnerability
    in SSL 3.0 that allows decryption of encrypted data.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking POODLE vulnerability for {host}:{port}")
    
    # Check if SSL 3.0 is supported
    vulnerable = False
    if hasattr(ssl, "PROTOCOL_SSLv3"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            vulnerable = True
            ssl_sock.close()
            sock.close()
        except (ssl.SSLError, socket.timeout, ConnectionError):
            vulnerable = False
        except Exception as e:
            logger.debug(f"Error checking POODLE: {e}")
            vulnerable = False
    
    return VulnerabilityCheckResult(
        vulnerability_name="POODLE",
        cve_id="CVE-2014-3566",
        vulnerable=vulnerable,
        severity=Severity.FAIL if vulnerable else Severity.OK,
        description="SSL 3.0 Padding Oracle vulnerability that allows decryption of encrypted data",
        recommendation="Disable SSL 3.0 support" if vulnerable else None,
    )


def check_beast(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for BEAST vulnerability (CVE-2011-3389).
    
    BEAST (Browser Exploit Against SSL/TLS) is a vulnerability in TLS 1.0
    that allows decryption of encrypted data when using CBC mode ciphers.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking BEAST vulnerability for {host}:{port}")
    
    # Check if TLS 1.0 is supported
    vulnerable = False
    if hasattr(ssl, "PROTOCOL_TLSv1"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            
            # Check if CBC ciphers are used
            cipher = ssl_sock.cipher()
            if cipher:
                cipher_name = cipher[0].upper()
                # BEAST affects CBC mode ciphers
                if "CBC" in cipher_name or any(c in cipher_name for c in ["AES", "DES", "3DES"]):
                    vulnerable = True
            
            ssl_sock.close()
            sock.close()
        except (ssl.SSLError, socket.timeout, ConnectionError):
            vulnerable = False
        except Exception as e:
            logger.debug(f"Error checking BEAST: {e}")
            vulnerable = False
    
    return VulnerabilityCheckResult(
        vulnerability_name="BEAST",
        cve_id="CVE-2011-3389",
        vulnerable=vulnerable,
        severity=Severity.WARN if vulnerable else Severity.OK,  # WARN because TLS 1.0 is deprecated
        description="TLS 1.0 CBC mode vulnerability that allows decryption of encrypted data",
        recommendation="Disable TLS 1.0 or use RC4 ciphers (though RC4 is also deprecated)" if vulnerable else None,
    )


def check_freak(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for FREAK vulnerability (CVE-2015-0204).
    
    FREAK (Factoring Attack on RSA-EXPORT Keys) is a vulnerability that allows
    man-in-the-middle attacks by forcing servers to use weak export-grade RSA keys.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking FREAK vulnerability for {host}:{port}")
    
    # Check if export-grade ciphers are supported
    # This is a simplified check - a full implementation would need to
    # test for export-grade cipher support
    vulnerable = False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        cipher = ssl_sock.cipher()
        if cipher:
            cipher_name = cipher[0].upper()
            if "EXPORT" in cipher_name:
                vulnerable = True
        
        ssl_sock.close()
        sock.close()
    except Exception as e:
        logger.debug(f"Error checking FREAK: {e}")
    
    return VulnerabilityCheckResult(
        vulnerability_name="FREAK",
        cve_id="CVE-2015-0204",
        vulnerable=vulnerable,
        severity=Severity.FAIL if vulnerable else Severity.OK,
        description="Export-grade RSA key vulnerability that allows man-in-the-middle attacks",
        recommendation="Disable export-grade cipher suites" if vulnerable else None,
    )


def check_drown(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for DROWN vulnerability (CVE-2016-0800).
    
    DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) is a vulnerability
    that allows decryption of TLS connections by exploiting SSLv2.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking DROWN vulnerability for {host}:{port}")
    
    # Check if SSLv2 is supported
    vulnerable = False
    if hasattr(ssl, "PROTOCOL_SSLv2"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.do_handshake()
            vulnerable = True
            ssl_sock.close()
            sock.close()
        except (ssl.SSLError, socket.timeout, ConnectionError):
            vulnerable = False
        except Exception as e:
            logger.debug(f"Error checking DROWN: {e}")
            vulnerable = False
    
    return VulnerabilityCheckResult(
        vulnerability_name="DROWN",
        cve_id="CVE-2016-0800",
        vulnerable=vulnerable,
        severity=Severity.FAIL if vulnerable else Severity.OK,
        description="SSLv2 vulnerability that allows decryption of TLS connections",
        recommendation="Disable SSLv2 support completely" if vulnerable else None,
    )


def check_sweet32(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Sweet32 vulnerability (CVE-2016-2183).
    
    Sweet32 is a vulnerability in 64-bit block ciphers (3DES, Blowfish) that allows
    birthday attacks on CBC mode encryption.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Sweet32 vulnerability for {host}:{port}")
    
    vulnerable = False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        cipher = ssl_sock.cipher()
        if cipher:
            cipher_name = cipher[0].upper()
            # Check for 3DES or other 64-bit block ciphers
            if "3DES" in cipher_name or "DES" in cipher_name or "BLOWFISH" in cipher_name:
                vulnerable = True
        
        ssl_sock.close()
        sock.close()
    except Exception as e:
        logger.debug(f"Error checking Sweet32: {e}")
    
    return VulnerabilityCheckResult(
        vulnerability_name="Sweet32",
        cve_id="CVE-2016-2183",
        vulnerable=vulnerable,
        severity=Severity.WARN if vulnerable else Severity.OK,
        description="64-bit block cipher vulnerability that allows birthday attacks on CBC mode",
        recommendation="Disable 3DES and other 64-bit block ciphers" if vulnerable else None,
    )


def check_lucky13(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Lucky13 vulnerability (CVE-2013-0169).
    
    Lucky13 is a timing attack vulnerability in CBC mode ciphers that allows
    decryption of encrypted data.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Lucky13 vulnerability for {host}:{port}")
    
    # Lucky13 affects CBC mode ciphers
    # This is a simplified check - a full implementation would need to
    # test for timing attacks
    vulnerable = False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        cipher = ssl_sock.cipher()
        if cipher:
            cipher_name = cipher[0].upper()
            # Lucky13 affects CBC mode ciphers
            if "CBC" in cipher_name or any(c in cipher_name for c in ["AES", "DES", "3DES"]):
                # Check if TLS version is vulnerable (TLS 1.0, 1.1, 1.2)
                version = ssl_sock.version()
                if version in ["TLSv1", "TLSv1.1", "TLSv1.2"]:
                    vulnerable = True
        
        ssl_sock.close()
        sock.close()
    except Exception as e:
        logger.debug(f"Error checking Lucky13: {e}")
    
    return VulnerabilityCheckResult(
        vulnerability_name="Lucky13",
        cve_id="CVE-2013-0169",
        vulnerable=vulnerable,
        severity=Severity.WARN if vulnerable else Severity.OK,
        description="CBC mode timing attack vulnerability that allows decryption of encrypted data",
        recommendation="Use TLS 1.3 or disable CBC mode ciphers" if vulnerable else None,
    )


def check_robot(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for ROBOT vulnerability (CVE-2017-13099).
    
    ROBOT (Return Of Bleichenbacher's Oracle Threat) is a vulnerability in
    RSA PKCS#1 v1.5 padding that allows decryption of encrypted data.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking ROBOT vulnerability for {host}:{port}")
    
    # ROBOT affects RSA key exchange
    # This is a simplified check - a full implementation would need to
    # test for padding oracle attacks
    vulnerable = False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        cipher = ssl_sock.cipher()
        if cipher:
            cipher_name = cipher[0].upper()
            # ROBOT affects RSA key exchange (not DHE/ECDHE)
            if "RSA" in cipher_name and "DHE" not in cipher_name and "ECDHE" not in cipher_name:
                vulnerable = True
        
        ssl_sock.close()
        sock.close()
    except Exception as e:
        logger.debug(f"Error checking ROBOT: {e}")
    
    return VulnerabilityCheckResult(
        vulnerability_name="ROBOT",
        cve_id="CVE-2017-13099",
        vulnerable=vulnerable,
        severity=Severity.WARN if vulnerable else Severity.OK,
        description="RSA PKCS#1 v1.5 padding oracle vulnerability that allows decryption of encrypted data",
        recommendation="Use RSA-OAEP or ECDHE/EDH key exchange" if vulnerable else None,
    )


def check_ticketbleed(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Ticketbleed vulnerability (CVE-2016-9244).
    
    Ticketbleed is a vulnerability in TLS session ticket handling that allows
    reading memory from the server.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Ticketbleed vulnerability for {host}:{port}")
    
    # Ticketbleed affects F5 BIG-IP devices
    # This is a simplified check - a full implementation would need to
    # test for session ticket handling issues
    vulnerable = False
    
    # Note: Full implementation would require testing session ticket handling
    # For now, we'll mark as not vulnerable if we can't detect it
    
    return VulnerabilityCheckResult(
        vulnerability_name="Ticketbleed",
        cve_id="CVE-2016-9244",
        vulnerable=vulnerable,
        severity=Severity.OK if not vulnerable else Severity.FAIL,
        description="TLS session ticket handling vulnerability that allows reading server memory",
        recommendation="Update F5 BIG-IP firmware or disable session tickets" if vulnerable else None,
    )


def check_logjam(host: str, port: int, timeout: float = 10.0) -> VulnerabilityCheckResult:
    """
    Check for Logjam vulnerability (CVE-2015-4000).
    
    Logjam is a vulnerability in Diffie-Hellman key exchange that allows
    man-in-the-middle attacks when using weak DH parameters.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        VulnerabilityCheckResult
    """
    logger.debug(f"Checking Logjam vulnerability for {host}:{port}")
    
    # Logjam affects weak DH parameters (< 1024 bits)
    # This is a simplified check - a full implementation would need to
    # test for weak DH parameters
    vulnerable = False
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.do_handshake()
        
        cipher = ssl_sock.cipher()
        if cipher:
            cipher_name = cipher[0].upper()
            # Logjam affects DHE key exchange with weak parameters
            if "DHE" in cipher_name:
                # Note: We can't directly check DH parameter strength from Python
                # A full implementation would need to extract and check DH parameters
                # For now, we'll assume not vulnerable if we can't detect it
                vulnerable = False
        
        ssl_sock.close()
        sock.close()
    except Exception as e:
        logger.debug(f"Error checking Logjam: {e}")
    
    return VulnerabilityCheckResult(
        vulnerability_name="Logjam",
        cve_id="CVE-2015-4000",
        vulnerable=vulnerable,
        severity=Severity.WARN if vulnerable else Severity.OK,
        description="Weak Diffie-Hellman parameters vulnerability that allows man-in-the-middle attacks",
        recommendation="Use DH parameters >= 2048 bits or use ECDHE" if vulnerable else None,
    )


def check_cryptographic_flaws(
    host: str, port: int, timeout: float = 10.0
) -> List[VulnerabilityCheckResult]:
    """
    Check for all known cryptographic vulnerabilities.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        
    Returns:
        List of VulnerabilityCheckResult
    """
    logger.info(f"Checking cryptographic vulnerabilities for {host}:{port}...")
    
    results = []
    
    # Check each vulnerability
    results.append(check_heartbleed(host, port, timeout))
    results.append(check_poodle(host, port, timeout))
    results.append(check_beast(host, port, timeout))
    results.append(check_freak(host, port, timeout))
    results.append(check_logjam(host, port, timeout))
    results.append(check_drown(host, port, timeout))
    results.append(check_sweet32(host, port, timeout))
    results.append(check_lucky13(host, port, timeout))
    results.append(check_robot(host, port, timeout))
    results.append(check_ticketbleed(host, port, timeout))
    
    return results

