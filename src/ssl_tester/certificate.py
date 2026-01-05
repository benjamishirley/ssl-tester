"""Certificate parsing and validation."""

import hashlib
import logging
import warnings
from contextlib import contextmanager
from datetime import datetime
from typing import List, Optional, Tuple
import idna

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning

from ssl_tester.models import (
    CertificateInfo,
    HostnameCheckResult,
    ValidityCheckResult,
    Severity,
    CertificateFinding,
)

logger = logging.getLogger(__name__)

# Global flag to control warning display (set via CLI --debug-warnings)
_DEBUG_WARNINGS = False

# Global certificate cache: sha256(cert_bytes) -> x509.Certificate
_certificate_cache: dict[str, x509.Certificate] = {}


def set_debug_warnings(enabled: bool) -> None:
    """Set whether to show original warnings in addition to Findings."""
    global _DEBUG_WARNINGS
    _DEBUG_WARNINGS = enabled


@contextmanager
def capture_crypto_serial_warnings():
    """
    Context manager to capture CryptographyDeprecationWarning about non-positive serial numbers.
    
    Yields:
        List of captured warning messages (deduplicated) - will be populated after the context exits
    """
    captured_warnings: List[str] = []
    
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        
        # Show warnings if debug mode is enabled
        if _DEBUG_WARNINGS:
            # Let warnings pass through normally
            warnings.filterwarnings("default", category=CryptographyDeprecationWarning)
        else:
            # Suppress warnings from stderr
            warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
        
        # Yield the list (will be populated after context exits)
        yield captured_warnings
        
        # Process captured warnings after the context block
        for warning in w:
            warning_msg = str(warning.message)
            warning_category = warning.category.__name__ if hasattr(warning.category, '__name__') else str(warning.category)
            
            # Debug: Log all CryptographyDeprecationWarning to understand the format
            if issubclass(warning.category, CryptographyDeprecationWarning):
                logger.debug(f"Captured CryptographyDeprecationWarning: {warning_msg} (category: {warning_category})")
            
            # Check if this is a serial number warning
            if (
                issubclass(warning.category, CryptographyDeprecationWarning)
                and "serial" in warning_msg.lower()
                and ("positive" in warning_msg.lower() or "wasn't" in warning_msg.lower() or "was not" in warning_msg.lower())
            ):
                if warning_msg not in captured_warnings:
                    captured_warnings.append(warning_msg)
                    logger.debug(f"Added serial number warning to findings: {warning_msg}")


def _load_cert_with_cache(
    cert_data: bytes, pem: bool = False
) -> Tuple[x509.Certificate, List[str]]:
    """
    Load a certificate with caching and warning capture.
    
    Args:
        cert_data: Certificate data (DER or PEM bytes)
        pem: If True, treat as PEM format; otherwise DER
    
    Returns:
        Tuple of (loaded certificate, list of captured warning messages)
    """
    # Use cache key based on certificate bytes
    cache_key = hashlib.sha256(cert_data).hexdigest()
    
    # Check cache first
    if cache_key in _certificate_cache:
        return _certificate_cache[cache_key], []
    
    # Load certificate and capture warnings
    with capture_crypto_serial_warnings() as warnings_list:
        if pem:
            cert = x509.load_pem_x509_certificate(cert_data)
        else:
            cert = x509.load_der_x509_certificate(cert_data)
    # warnings_list is now populated after context exit
    captured_warnings = warnings_list
    
    # Store in cache
    _certificate_cache[cache_key] = cert
    
    return cert, captured_warnings


def _load_cert_without_warnings(cert_data: bytes, pem: bool = False) -> x509.Certificate:
    """
    Load a certificate while suppressing CryptographyDeprecationWarning about serial numbers.
    Legacy function for backward compatibility.
    
    Args:
        cert_data: Certificate data (DER or PEM bytes)
        pem: If True, treat as PEM format; otherwise DER
    
    Returns:
        Loaded certificate
    """
    cert, _ = _load_cert_with_cache(cert_data, pem=pem)
    return cert


def parse_certificate(cert_der: bytes) -> Tuple[CertificateInfo, List[CertificateFinding]]:
    """
    Parse DER-encoded certificate and extract all relevant information.

    Args:
        cert_der: DER-encoded certificate bytes

    Returns:
        Tuple of (CertificateInfo with all extracted data, List of CertificateFindings)
    """
    cert, _ = _load_cert_with_cache(cert_der, pem=False)
    findings: List[CertificateFinding] = []
    
    # Capture warnings from all certificate attribute access
    # Warnings are triggered when accessing serial_number and extensions
    captured_warnings: List[str] = []
    
    with capture_crypto_serial_warnings() as warning_list:
        # Subject and Issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Serial number - this triggers the warning
        serial_number = str(cert.serial_number)
        serial_number_int = cert.serial_number  # Keep as int for validation

        # Validity dates (use UTC-aware methods to avoid deprecation warnings)
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            # Fallback for older cryptography versions
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

        # SAN extraction - also triggers warnings
        san_dns_names: List[str] = []
        san_ip_addresses: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ip_addresses.append(str(name.value))
        except x509.ExtensionNotFound:
            pass

        # CRL Distribution Points
        crl_dps: List[str] = []
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                for full_name in dp.full_name:
                    if isinstance(full_name, x509.UniformResourceIdentifier):
                        crl_dps.append(full_name.value)
        except x509.ExtensionNotFound:
            pass

        # Authority Information Access
        ocsp_urls: List[str] = []
        ca_issuers_urls: List[str] = []
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        ocsp_urls.append(access_desc.access_location.value)
                elif access_desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        ca_issuers_urls.append(access_desc.access_location.value)
        except x509.ExtensionNotFound:
            pass

        # Signature algorithm
        signature_algorithm = cert.signature_algorithm_oid._name

        # Public key algorithm
        public_key_algorithm = cert.public_key().__class__.__name__

        # Fingerprint
        fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
    
    # warnings_list is now populated after context exit
    captured_warnings = warning_list
    
    # Check for non-positive serial number (RFC 5280 violation)
    # Serial number should be positive integer (0 and negative are invalid)
    # cryptography returns serial_number as int, so we can check directly
    is_non_positive = serial_number_int <= 0
    
    # Create findings from captured warnings OR direct serial number check
    # Always check directly, but prefer warnings if available (they come from cryptography library)
    if is_non_positive:
        # Create finding if serial is non-positive (regardless of whether warning was captured)
        # If we have warnings, include them in context
        warning_context = {}
        if captured_warnings:
            warning_context["warnings"] = captured_warnings
        warning_context["serial_number"] = serial_number
        
        findings.append(
            CertificateFinding(
                code="CERT_SERIAL_NON_POSITIVE",
                severity=Severity.WARN,
                message="Certificate serial number is not positive (RFC 5280 violation). Future cryptography versions may reject this certificate.",
                subject=subject,
                issuer=issuer,
                fingerprint_sha256=fingerprint_sha256,
                context=warning_context,
            )
        )

    # Key Usage
    key_usage: Optional[List[str]] = None
    try:
        ku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        key_usage = []
        if ku_ext.value.digital_signature:
            key_usage.append("digital_signature")
        if ku_ext.value.content_commitment:
            key_usage.append("content_commitment")
        if ku_ext.value.key_encipherment:
            key_usage.append("key_encipherment")
        if ku_ext.value.data_encipherment:
            key_usage.append("data_encipherment")
        if ku_ext.value.key_agreement:
            key_usage.append("key_agreement")
            # encipher_only and decipher_only are only defined when key_agreement is true
            if ku_ext.value.encipher_only:
                key_usage.append("encipher_only")
            if ku_ext.value.decipher_only:
                key_usage.append("decipher_only")
        if ku_ext.value.key_cert_sign:
            key_usage.append("key_cert_sign")
        if ku_ext.value.crl_sign:
            key_usage.append("crl_sign")
    except x509.ExtensionNotFound:
        pass

    # Extended Key Usage
    extended_key_usage: Optional[List[str]] = None
    try:
        eku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        extended_key_usage = [eku._name for eku in eku_ext.value]
    except x509.ExtensionNotFound:
        pass

    # Basic Constraints
    basic_constraints: Optional[dict] = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
        basic_constraints = {
            "ca": bc_ext.value.ca,
            "path_length": bc_ext.value.path_length,
        }
    except x509.ExtensionNotFound:
        pass

    # Authority Key Identifier
    authority_key_identifier: Optional[str] = None
    try:
        aki_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        if aki_ext.value.key_identifier:
            authority_key_identifier = aki_ext.value.key_identifier.hex()
    except x509.ExtensionNotFound:
        pass

    # Subject Key Identifier
    subject_key_identifier: Optional[str] = None
    try:
        ski_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        subject_key_identifier = ski_ext.value.digest.hex()
    except x509.ExtensionNotFound:
        pass

    cert_info = CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=serial_number,
        not_before=not_before,
        not_after=not_after,
        san_dns_names=san_dns_names,
        san_ip_addresses=san_ip_addresses,
        crl_distribution_points=crl_dps,
        ocsp_responder_urls=ocsp_urls,
        ca_issuers_urls=ca_issuers_urls,
        signature_algorithm=signature_algorithm,
        public_key_algorithm=public_key_algorithm,
        fingerprint_sha256=fingerprint_sha256,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        basic_constraints=basic_constraints,
        authority_key_identifier=authority_key_identifier,
        subject_key_identifier=subject_key_identifier,
    )
    
    return cert_info, findings


def check_hostname(cert_info: CertificateInfo, hostname: str) -> HostnameCheckResult:
    """
    Check if certificate matches the given hostname.

    Args:
        cert_info: Parsed certificate information
        hostname: Expected hostname

    Returns:
        HostnameCheckResult with match status
    """
    # Normalize hostname (IDNA/Punycode) - RFC 6125 Section 6.2.2
    try:
        # Encode to ASCII using IDNA
        normalized_hostname = idna.encode(hostname, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        # If IDNA encoding fails, try without UTS46
        try:
            normalized_hostname = idna.encode(hostname).decode("ascii")
        except Exception:
            normalized_hostname = hostname

    # Check SAN DNS names first (preferred) - RFC 6125 Section 6.4.1
    matched_san_dns: Optional[str] = None
    for san_dns in cert_info.san_dns_names:
        # Normalize SAN DNS name as well
        try:
            normalized_san = idna.encode(san_dns, uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            try:
                normalized_san = idna.encode(san_dns).decode("ascii")
            except Exception:
                normalized_san = san_dns

        if _match_dns_name(normalized_hostname, normalized_san):
            matched_san_dns = san_dns
            break

    # Check SAN IP addresses if hostname is an IP
    if not matched_san_dns:
        try:
            import ipaddress
            host_ip = ipaddress.ip_address(hostname)
            for san_ip_str in cert_info.san_ip_addresses:
                if str(host_ip) == san_ip_str:
                    matched_san_dns = san_ip_str
                    break
        except ValueError:
            pass  # Not an IP address

    # Fallback to CN (deprecated, but check anyway)
    matched_cn: Optional[str] = None
    if not matched_san_dns:
        # Extract CN from subject
        subject_parts = cert_info.subject.split(",")
        for part in subject_parts:
            part = part.strip()
            if part.startswith("CN="):
                cn_value = part[3:].strip()
                if _match_dns_name(normalized_hostname, cn_value):
                    matched_cn = cn_value
                    logger.warning("Hostname matched via CN (deprecated, should use SAN)")
                    break

    matches = matched_san_dns is not None or matched_cn is not None

    severity = Severity.OK if matches else Severity.FAIL

    return HostnameCheckResult(
        matches=matches,
        expected_hostname=hostname,
        matched_san_dns=matched_san_dns,
        matched_cn=matched_cn,
        severity=severity,
    )


def _match_dns_name(hostname: str, pattern: str) -> bool:
    """
    Match hostname against DNS pattern (RFC 6125 compliant wildcard matching).

    Args:
        hostname: Hostname to match (normalized, IDNA-encoded)
        pattern: Pattern (may contain wildcard *)

    Returns:
        True if matches according to RFC 6125
    """
    # Exact match
    if pattern == hostname:
        return True

    # RFC 6125: Wildcard matching rules
    # 1. Wildcard must be in leftmost label
    # 2. Wildcard matches only one label
    # 3. Wildcard cannot match empty label
    # 4. Wildcard must be entire leftmost label (e.g., *.example.com, not *a.example.com)

    if "*" not in pattern:
        return False

    # Check if wildcard is in leftmost label only
    pattern_parts = pattern.split(".")
    if len(pattern_parts) < 2:
        return False  # Need at least domain and TLD

    leftmost = pattern_parts[0]
    if "*" not in leftmost:
        return False  # Wildcard not in leftmost label

    # Wildcard must be entire leftmost label (RFC 6125 Section 6.4.3)
    if leftmost != "*":
        return False  # Invalid: *a.example.com is not allowed

    # Extract domain part (everything after first label)
    domain_part = ".".join(pattern_parts[1:])
    if not domain_part:
        return False  # Invalid pattern

    # Hostname must have at least one label before domain
    hostname_parts = hostname.split(".")
    if len(hostname_parts) < len(pattern_parts):
        return False  # Hostname has fewer labels than pattern

    # Match domain part
    hostname_domain = ".".join(hostname_parts[-(len(pattern_parts) - 1):])
    if hostname_domain != domain_part:
        return False

    # RFC 6125: Wildcard matches exactly one label
    # So *.example.com matches www.example.com but not www.sub.example.com
    # (unless pattern is *.sub.example.com)
    if len(hostname_parts) != len(pattern_parts):
        return False  # Different number of labels

    return True


def check_validity(cert_info: CertificateInfo) -> ValidityCheckResult:
    """
    Check certificate validity dates.

    Args:
        cert_info: Parsed certificate information

    Returns:
        ValidityCheckResult with validity status
    """
    from datetime import timezone
    
    now = datetime.now(timezone.utc)
    not_before = cert_info.not_before
    not_after = cert_info.not_after
    
    # Convert to timezone-aware if needed
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    is_expired = now > not_after
    not_yet_valid = now < not_before
    is_valid = not_before <= now <= not_after

    # Calculate days until expiry
    if is_expired:
        days_until_expiry = 0
    else:
        delta = not_after - now
        days_until_expiry = delta.days

    # Determine severity
    if is_expired or not_yet_valid:
        severity = Severity.FAIL
    elif days_until_expiry < 30:
        severity = Severity.WARN
    else:
        severity = Severity.OK

    return ValidityCheckResult(
        is_valid=is_valid,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        is_expired=is_expired,
        severity=severity,
    )

