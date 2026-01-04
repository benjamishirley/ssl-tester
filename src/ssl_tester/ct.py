"""Certificate Transparency (CT) checks."""

import logging
from typing import Optional, List
from cryptography import x509
from cryptography.x509.extension import ExtensionNotFound

from ssl_tester.models import Severity

logger = logging.getLogger(__name__)


def check_certificate_transparency(cert_der: bytes) -> dict:
    """
    Check Certificate Transparency information from certificate.
    
    Note: This checks for SCT (Signed Certificate Timestamps) in the certificate.
    Full CT log checking would require API access to CT logs, which we avoid
    for privacy reasons (all checks are performed locally).
    
    Args:
        cert_der: Certificate in DER format
        
    Returns:
        Dictionary with CT information:
        {
            "sct_count": int,
            "sct_sources": List[str],  # "embedded", "tls_extension", "ocsp_response"
            "severity": Severity
        }
    """
    try:
        cert = x509.load_der_x509_certificate(cert_der)
        
        sct_count = 0
        sct_sources: List[str] = []
        
        # Check for SCT in certificate extension (embedded)
        try:
            sct_extension = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
            )
            if sct_extension:
                sct_count += len(sct_extension.value) if hasattr(sct_extension.value, '__len__') else 1
                sct_sources.append("embedded")
        except ExtensionNotFound:
            pass
        
        # Note: SCT can also be provided via:
        # - TLS extension (during handshake) - would need to check during TLS handshake
        # - OCSP response - would need to check OCSP response
        # For now, we only check embedded SCTs
        
        # Determine severity
        # CT is recommended but not strictly required
        if sct_count > 0:
            severity = Severity.OK
        else:
            severity = Severity.WARN  # CT not present, but not critical
        
        return {
            "sct_count": sct_count,
            "sct_sources": sct_sources,
            "severity": severity,
        }
    except Exception as e:
        logger.debug(f"Error checking Certificate Transparency: {e}")
        return {
            "sct_count": 0,
            "sct_sources": [],
            "severity": Severity.WARN,
        }

