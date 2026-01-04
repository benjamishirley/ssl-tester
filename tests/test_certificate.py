"""Tests for certificate parsing and validation."""

import pytest
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ssl_tester.certificate import parse_certificate, check_hostname, check_validity, _match_dns_name
from ssl_tester.models import Severity


@pytest.fixture
def sample_cert_der():
    """Create a sample certificate for testing."""
    # Generate a private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com"), x509.DNSName("*.example.com")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate(sample_cert_der):
    """Test certificate parsing."""
    print("\n" + "="*80)
    print("TEST: Zertifikat-Parsing")
    print("="*80)
    
    print("→ Zertifikat parsen...")
    cert_info, findings = parse_certificate(sample_cert_der)

    print(f"\n📊 Geparste Zertifikats-Informationen:")
    print(f"  - Subject: {cert_info.subject}")
    print(f"  - Issuer: {cert_info.issuer}")
    print(f"  - Serial Number: {cert_info.serial_number}")
    print(f"  - Not Before: {cert_info.not_before}")
    print(f"  - Not After: {cert_info.not_after}")
    print(f"  - SAN DNS Names: {cert_info.san_dns_names}")
    print(f"  - Fingerprint SHA256: {cert_info.fingerprint_sha256[:16]}...")
    print(f"  - Findings: {len(findings)}")

    assert cert_info.subject is not None
    assert cert_info.issuer is not None
    assert cert_info.serial_number is not None
    assert cert_info.not_before is not None
    assert cert_info.not_after is not None
    assert "example.com" in cert_info.san_dns_names
    assert cert_info.fingerprint_sha256 is not None
    print("\n✅ Test erfolgreich: Zertifikat wurde korrekt geparst")
    print("="*80 + "\n")


def test_check_hostname_match(sample_cert_der):
    """Test hostname matching."""
    print("\n" + "="*80)
    print("TEST: Hostname-Matching (Exakt)")
    print("="*80)
    
    cert_info, _ = parse_certificate(sample_cert_der)
    print(f"✓ Zertifikat geparst: Subject={cert_info.subject}")
    print(f"✓ SAN DNS Names: {cert_info.san_dns_names}")
    
    print(f"→ Hostname-Prüfung: 'example.com'")
    result = check_hostname(cert_info, "example.com")

    print(f"\n📊 Ergebnis:")
    print(f"  - Matches: {result.matches}")
    print(f"  - Expected Hostname: {result.expected_hostname}")
    print(f"  - Matched SAN DNS: {result.matched_san_dns}")
    print(f"  - Matched CN: {result.matched_cn}")
    print(f"  - Severity: {result.severity}")

    assert result.matches is True
    assert result.severity == Severity.OK
    assert result.matched_san_dns == "example.com"
    print("\n✅ Test erfolgreich: Hostname wurde korrekt gematcht")
    print("="*80 + "\n")


def test_check_hostname_wildcard(sample_cert_der):
    """Test wildcard hostname matching."""
    print("\n" + "="*80)
    print("TEST: Hostname-Matching (Wildcard)")
    print("="*80)
    
    cert_info, _ = parse_certificate(sample_cert_der)
    print(f"✓ Zertifikat geparst: Subject={cert_info.subject}")
    print(f"✓ SAN DNS Names: {cert_info.san_dns_names}")
    
    print(f"→ Hostname-Prüfung: 'sub.example.com' (sollte mit '*.example.com' matchen)")
    result = check_hostname(cert_info, "sub.example.com")

    print(f"\n📊 Ergebnis:")
    print(f"  - Matches: {result.matches}")
    print(f"  - Expected Hostname: {result.expected_hostname}")
    print(f"  - Matched SAN DNS: {result.matched_san_dns}")
    print(f"  - Severity: {result.severity}")

    assert result.matches is True
    assert result.matched_san_dns == "*.example.com"
    print("\n✅ Test erfolgreich: Wildcard-Hostname wurde korrekt gematcht")
    print("="*80 + "\n")


def test_check_hostname_no_match(sample_cert_der):
    """Test hostname mismatch."""
    print("\n" + "="*80)
    print("TEST: Hostname-Mismatch")
    print("="*80)
    
    cert_info, _ = parse_certificate(sample_cert_der)
    print(f"✓ Zertifikat geparst: Subject={cert_info.subject}")
    print(f"✓ SAN DNS Names: {cert_info.san_dns_names}")
    
    print(f"→ Hostname-Prüfung: 'other.com' (sollte NICHT matchen)")
    result = check_hostname(cert_info, "other.com")

    print(f"\n📊 Ergebnis:")
    print(f"  - Matches: {result.matches}")
    print(f"  - Expected Hostname: {result.expected_hostname}")
    print(f"  - Matched SAN DNS: {result.matched_san_dns}")
    print(f"  - Matched CN: {result.matched_cn}")
    print(f"  - Severity: {result.severity}")

    assert result.matches is False
    assert result.severity == Severity.FAIL
    print("\n✅ Test erfolgreich: Hostname-Mismatch wurde korrekt erkannt")
    print("="*80 + "\n")


def test_check_validity_valid(sample_cert_der):
    """Test validity check for valid certificate."""
    print("\n" + "="*80)
    print("TEST: Gültigkeitsprüfung (Gültiges Zertifikat)")
    print("="*80)
    
    cert_info, _ = parse_certificate(sample_cert_der)
    print(f"✓ Zertifikat geparst: Subject={cert_info.subject}")
    print(f"  - Not Before: {cert_info.not_before}")
    print(f"  - Not After: {cert_info.not_after}")
    
    print("→ Gültigkeitsprüfung durchführen...")
    result = check_validity(cert_info)

    print(f"\n📊 Ergebnis:")
    print(f"  - Is Valid: {result.is_valid}")
    print(f"  - Is Expired: {result.is_expired}")
    print(f"  - Days Until Expiry: {result.days_until_expiry}")
    print(f"  - Not Before: {result.not_before}")
    print(f"  - Not After: {result.not_after}")
    print(f"  - Severity: {result.severity}")

    assert result.is_valid is True
    assert result.is_expired is False
    assert result.days_until_expiry > 0
    assert result.severity == Severity.OK
    print("\n✅ Test erfolgreich: Zertifikat ist gültig")
    print("="*80 + "\n")


def test_check_validity_expired():
    """Test validity check for expired certificate."""
    print("\n" + "="*80)
    print("TEST: Gültigkeitsprüfung (Abgelaufenes Zertifikat)")
    print("="*80)
    
    # Create expired certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=365))
        .not_valid_after(datetime.utcnow() - timedelta(days=1))  # Expired
        .sign(private_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_info, _ = parse_certificate(cert_der)
    print(f"✓ Abgelaufenes Zertifikat erstellt: Subject={cert_info.subject}")
    print(f"  - Not Before: {cert_info.not_before}")
    print(f"  - Not After: {cert_info.not_after} (ABGELAUFEN)")
    
    print("→ Gültigkeitsprüfung durchführen...")
    result = check_validity(cert_info)

    print(f"\n📊 Ergebnis:")
    print(f"  - Is Valid: {result.is_valid}")
    print(f"  - Is Expired: {result.is_expired}")
    print(f"  - Days Until Expiry: {result.days_until_expiry}")
    print(f"  - Severity: {result.severity}")

    assert result.is_valid is False
    assert result.is_expired is True
    assert result.severity == Severity.FAIL
    print("\n✅ Test erfolgreich: Abgelaufenes Zertifikat wurde korrekt erkannt")
    print("="*80 + "\n")


def test_match_dns_name_exact_match():
    """Test exact DNS name matching."""
    print("\n" + "="*80)
    print("TEST: DNS-Name-Matching (Exakt)")
    print("="*80)
    
    print("→ Exakte Matches testen...")
    result1 = _match_dns_name("example.com", "example.com")
    result2 = _match_dns_name("sub.example.com", "sub.example.com")
    
    print(f"\n📊 Ergebnisse:")
    print(f"  - 'example.com' == 'example.com': {result1}")
    print(f"  - 'sub.example.com' == 'sub.example.com': {result2}")
    
    assert result1 is True
    assert result2 is True
    print("\n✅ Test erfolgreich: Exakte DNS-Name-Matches funktionieren")
    print("="*80 + "\n")


def test_match_dns_name_wildcard_valid():
    """Test valid wildcard matching according to RFC 6125."""
    print("\n" + "="*80)
    print("TEST: DNS-Name-Matching (Gültige Wildcards)")
    print("="*80)
    
    print("→ Gültige Wildcard-Matches testen (RFC 6125)...")
    result1 = _match_dns_name("www.example.com", "*.example.com")
    result2 = _match_dns_name("api.example.com", "*.example.com")
    result3 = _match_dns_name("test.sub.example.com", "*.sub.example.com")
    
    print(f"\n📊 Ergebnisse:")
    print(f"  - 'www.example.com' matcht '*.example.com': {result1}")
    print(f"  - 'api.example.com' matcht '*.example.com': {result2}")
    print(f"  - 'test.sub.example.com' matcht '*.sub.example.com': {result3}")
    
    assert result1 is True
    assert result2 is True
    assert result3 is True
    print("\n✅ Test erfolgreich: Gültige Wildcard-Matches funktionieren")
    print("="*80 + "\n")


def test_match_dns_name_wildcard_invalid():
    """Test invalid wildcard patterns."""
    print("\n" + "="*80)
    print("TEST: DNS-Name-Matching (Ungültige Wildcards)")
    print("="*80)
    
    print("→ Ungültige Wildcard-Patterns testen...")
    result1 = _match_dns_name("www.example.com", "www.*.com")  # Wildcard nicht im linkesten Label
    result2 = _match_dns_name("www.example.com", "*a.example.com")  # Wildcard nicht gesamtes Label
    result3 = _match_dns_name("www.example.com", "example.*.com")  # Wildcard in falscher Position
    result4 = _match_dns_name("www.sub.example.com", "*.example.com")  # Zu viele Labels
    result5 = _match_dns_name("example.com", "*.example.com")  # Zu wenige Labels
    
    print(f"\n📊 Ergebnisse (alle sollten False sein):")
    print(f"  - 'www.example.com' matcht 'www.*.com': {result1}")
    print(f"  - 'www.example.com' matcht '*a.example.com': {result2}")
    print(f"  - 'www.example.com' matcht 'example.*.com': {result3}")
    print(f"  - 'www.sub.example.com' matcht '*.example.com': {result4}")
    print(f"  - 'example.com' matcht '*.example.com': {result5}")
    
    assert result1 is False
    assert result2 is False
    assert result3 is False
    assert result4 is False
    assert result5 is False
    print("\n✅ Test erfolgreich: Ungültige Wildcard-Patterns wurden korrekt abgelehnt")
    print("="*80 + "\n")


def test_match_dns_name_no_wildcard():
    """Test matching without wildcard."""
    print("\n" + "="*80)
    print("TEST: DNS-Name-Matching (Ohne Wildcard)")
    print("="*80)
    
    print("→ Matches ohne Wildcard testen...")
    result1 = _match_dns_name("example.com", "other.com")
    result2 = _match_dns_name("www.example.com", "example.com")
    
    print(f"\n📊 Ergebnisse (beide sollten False sein):")
    print(f"  - 'example.com' matcht 'other.com': {result1}")
    print(f"  - 'www.example.com' matcht 'example.com': {result2}")
    
    assert result1 is False
    assert result2 is False
    print("\n✅ Test erfolgreich: Nicht-Matches wurden korrekt erkannt")
    print("="*80 + "\n")


def test_match_dns_name_edge_cases():
    """Test edge cases for DNS matching."""
    print("\n" + "="*80)
    print("TEST: DNS-Name-Matching (Edge Cases)")
    print("="*80)
    
    print("→ Edge Cases testen...")
    result1 = _match_dns_name("example", "*")  # Einzelnes Label (ungültig für Wildcard)
    result2 = _match_dns_name("", "")  # Beide leer
    result3 = _match_dns_name("example.com", "")  # Pattern leer
    result4 = _match_dns_name("www.example.com", "*.other.com")  # Domain-Mismatch
    
    print(f"\n📊 Ergebnisse:")
    print(f"  - 'example' matcht '*': {result1} (sollte False sein)")
    print(f"  - '' matcht '': {result2} (sollte True sein)")
    print(f"  - 'example.com' matcht '': {result3} (sollte False sein)")
    print(f"  - 'www.example.com' matcht '*.other.com': {result4} (sollte False sein)")
    
    assert result1 is False
    assert result2 is True
    assert result3 is False
    assert result4 is False
    print("\n✅ Test erfolgreich: Edge Cases wurden korrekt behandelt")
    print("="*80 + "\n")

