"""Network operations for TLS connections."""

import socket
import ssl
import sys
import logging
import subprocess
from typing import Tuple, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


def _extract_chain_via_openssl(host: str, port: int, timeout: float, ignore_hostname: bool = False) -> List[bytes]:
    """
    Extract certificate chain using OpenSSL command line tool.
    This is a fallback when getpeercert_chain() is not available.
    
    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout
        ignore_hostname: Ignore hostname verification
    
    Returns:
        List of DER-encoded certificates (excluding leaf)
    """
    chain_certs_der: List[bytes] = []
    
    try:
        # Use openssl s_client to get the certificate chain
        openssl_cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-showcerts",
        ]
        
        # Add servername if not ignoring hostname
        if not ignore_hostname:
            openssl_cmd.extend(["-servername", host])
        
        # For ignore_hostname, we still want to get certificates even if validation fails
        # OpenSSL will output certificates regardless of validation status
        
        # Run openssl command
        try:
            result = subprocess.run(
                openssl_cmd,
                input=b"Q\n",  # Send quit command
                capture_output=True,
                timeout=timeout + 2,
                check=False,  # Don't raise on non-zero exit
            )
        except subprocess.TimeoutExpired:
            logger.debug("OpenSSL command timed out")
            return []
        except FileNotFoundError:
            logger.debug("OpenSSL command not found")
            return []
        
        # Parse the output to extract certificates
        # OpenSSL outputs certificates in PEM format between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
        output = result.stdout
        if not output:
            return []
        
        # Find all certificate blocks
        cert_start = b"-----BEGIN CERTIFICATE-----"
        cert_end = b"-----END CERTIFICATE-----"
        
        start_idx = 0
        while True:
            start_pos = output.find(cert_start, start_idx)
            if start_pos == -1:
                break
            
            end_pos = output.find(cert_end, start_pos)
            if end_pos == -1:
                break
            
            # Extract PEM certificate
            pem_cert = output[start_pos:end_pos + len(cert_end)]
            
            # Convert PEM to DER
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization
                
                from ssl_tester.certificate import _load_cert_with_cache
                cert, _ = _load_cert_with_cache(pem_cert, pem=True)
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                chain_certs_der.append(cert_der)
            except Exception as e:
                logger.debug(f"Error parsing certificate from OpenSSL output: {e}")
            
            start_idx = end_pos + len(cert_end)
        
        # Remove the first certificate (leaf) - we already have it from getpeercert()
        if chain_certs_der:
            chain_certs_der = chain_certs_der[1:]
            logger.debug(f"Extracted {len(chain_certs_der)} intermediate certificate(s) via OpenSSL")
        
    except Exception as e:
        logger.debug(f"Error extracting chain via OpenSSL: {e}")
    
    return chain_certs_der


def connect_tls(
    host: str,
    port: int,
    timeout: float = 10.0,
    insecure: bool = False,
    ca_bundle: Optional[Path] = None,
    ipv6: bool = False,
    ignore_hostname: bool = False,
) -> Tuple[bytes, List[bytes]]:
    """
    Establish TLS connection and extract certificate chain.

    Args:
        host: Target hostname
        port: Target port
        timeout: Connection timeout in seconds
        insecure: Accept self-signed certificates
        ca_bundle: Custom CA bundle path
        ipv6: Prefer IPv6
        ignore_hostname: Ignore hostname verification (for error recovery)

    Returns:
        Tuple of (leaf_certificate_der, chain_certificates_der_list)

    Raises:
        ConnectionError: If connection fails
        ssl.SSLError: If TLS handshake fails
    """
    logger.debug(f"Connecting to {host}:{port} (timeout={timeout}s)")

    # Resolve address
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    try:
        addr_info = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        if not addr_info:
            raise ConnectionError(f"Could not resolve {host}:{port}")
        addr = addr_info[0][4]
    except socket.gaierror as e:
        raise ConnectionError(f"DNS resolution failed for {host}: {e}")

    # Create socket
    sock = socket.socket(addr_info[0][0], socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Connect
        sock.connect(addr)
        logger.debug(f"TCP connection established to {addr}")

        # Create SSL context
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("Insecure mode enabled - certificate validation disabled")
        elif ignore_hostname:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            logger.debug("Hostname verification disabled for certificate extraction")

        if ca_bundle:
            context.load_verify_locations(str(ca_bundle))
            logger.debug(f"Using custom CA bundle: {ca_bundle}")

        # Wrap socket
        server_hostname = None if ignore_hostname else host
        ssl_sock = context.wrap_socket(sock, server_hostname=server_hostname)
        ssl_sock.do_handshake()
        logger.debug("TLS handshake completed")

        # Get leaf certificate
        leaf_cert_der = ssl_sock.getpeercert(binary_form=True)
        if not leaf_cert_der:
            raise ssl.SSLError("No certificate received from server")

        # Get certificate chain (Python 3.10+)
        # Note: getpeercert_chain() availability depends on the SSL backend used to compile Python,
        # not just the Python version. Some Python builds (especially on macOS) may not have this method.
        chain_certs_der: List[bytes] = []
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        ssl_version = ssl.OPENSSL_VERSION
        
        # Check if method is available
        if hasattr(ssl_sock, 'getpeercert_chain'):
            try:
                chain = ssl_sock.getpeercert_chain()
                if chain:
                    chain_certs_der = [cert for cert in chain if cert]
                    logger.debug(f"Received {len(chain_certs_der)} certificates in chain")
                else:
                    logger.warning("Server did not send certificate chain (only leaf)")
            except Exception as e:
                logger.debug(f"Error calling getpeercert_chain(): {e}")
        
        # Fallback: Try OpenSSL if getpeercert_chain() is not available or returned nothing
        if not chain_certs_der:
            if not hasattr(ssl_sock, 'getpeercert_chain'):
                logger.debug(
                    f"getpeercert_chain() not available in this Python build "
                    f"(Python {python_version}, {ssl_version}). "
                    "This is normal for some Python installations. Using OpenSSL fallback..."
                )
                logger.info("Extracting certificate chain via OpenSSL...")
            else:
                logger.info("No chain received via getpeercert_chain(), attempting to extract via OpenSSL...")
            
            # Close the current connection first
            try:
                ssl_sock.close()
            except Exception:
                pass
            
            # Try to extract chain via OpenSSL
            chain_certs_der = _extract_chain_via_openssl(host, port, timeout, ignore_hostname)
            
            if chain_certs_der:
                logger.info(f"Successfully extracted {len(chain_certs_der)} intermediate certificate(s) via OpenSSL")
            else:
                logger.warning("Could not extract certificate chain via OpenSSL. Will attempt to fetch intermediates via AIA if available.")

        return leaf_cert_der, chain_certs_der

    except socket.timeout:
        raise ConnectionError(f"Connection timeout after {timeout}s")
    except ssl.SSLError as e:
        raise ssl.SSLError(f"TLS handshake failed: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

