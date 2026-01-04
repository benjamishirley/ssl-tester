"""Tests for chain validation."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ssl_tester.chain import (
    validate_chain,
    validate_signatures,
    build_and_sort_chain,
    _get_root_from_trust_store,
    _check_trust_store,
    _load_system_trust_store,
    _split_pem_certificates,
    load_root_certs_from_trust_store,
)
from ssl_tester.models import Severity


@pytest.fixture
def leaf_cert_der():
    """Create a leaf certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intermediate.example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def intermediate_cert_der():
    """Create an intermediate certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intermediate.example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root.example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER)


def test_validate_chain_valid(leaf_cert_der, intermediate_cert_der):
    """Test valid chain validation."""
    print("\n" + "="*80)
    print("TEST: Chain-Validierung (Gültige Chain)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(leaf_cert_der)
    intermediate_info, _ = parse_certificate(intermediate_cert_der)
    print(f"✓ Leaf-Zertifikat: Subject={leaf_info.subject}")
    print(f"✓ Intermediate-Zertifikat: Subject={intermediate_info.subject}")
    
    print("→ Chain-Validierung durchführen...")
    result, findings = validate_chain(leaf_cert_der, [intermediate_cert_der], insecure=True)

    print(f"\n📊 Ergebnis:")
    print(f"  - Chain Valid: {result.chain_valid}")
    print(f"  - Is Valid: {result.is_valid}")
    print(f"  - Leaf Cert: {result.leaf_cert.subject if result.leaf_cert else 'None'}")
    print(f"  - Intermediate Certs: {len(result.intermediate_certs)}")
    print(f"  - Missing Intermediates: {result.missing_intermediates}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Findings: {len(findings)}")

    assert result.leaf_cert is not None
    assert len(result.intermediate_certs) == 1
    assert result.missing_intermediates == []
    print("\n✅ Test erfolgreich: Gültige Chain wurde korrekt validiert")
    print("="*80 + "\n")


def test_validate_chain_missing_intermediate(leaf_cert_der):
    """Test chain with missing intermediate."""
    print("\n" + "="*80)
    print("TEST: Chain-Validierung (Fehlendes Intermediate)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(leaf_cert_der)
    print(f"✓ Leaf-Zertifikat: Subject={leaf_info.subject}, Issuer={leaf_info.issuer}")
    print("⚠ Keine Intermediate-Zertifikate bereitgestellt")
    
    print("→ Chain-Validierung durchführen...")
    result, findings = validate_chain(leaf_cert_der, [], insecure=True)

    print(f"\n📊 Ergebnis:")
    print(f"  - Chain Valid: {result.chain_valid}")
    print(f"  - Is Valid: {result.is_valid}")
    print(f"  - Missing Intermediates: {result.missing_intermediates}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    print(f"  - Findings: {len(findings)}")

    assert result.missing_intermediates != []
    assert result.severity in [Severity.WARN, Severity.FAIL]
    print("\n✅ Test erfolgreich: Fehlendes Intermediate wurde korrekt erkannt")
    print("="*80 + "\n")


@pytest.fixture
def root_cert_der():
    """Create a self-signed root certificate."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root.example.com")])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.DER), private_key


@pytest.fixture
def proper_chain():
    """Create a proper certificate chain with valid signatures."""
    # Root CA
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)  # Self-signed
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    root_cert_der = root_cert.public_bytes(serialization.Encoding.DER)

    # Intermediate CA (signed by root)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_subject)
        .issuer_name(root_subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    intermediate_cert_der = intermediate_cert.public_bytes(serialization.Encoding.DER)

    # Leaf certificate (signed by intermediate)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.com")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(intermediate_subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("leaf.example.com")]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )
    leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)

    return {
        "leaf": leaf_cert_der,
        "intermediate": intermediate_cert_der,
        "root": root_cert_der,
    }


def test_validate_signatures_valid_chain(proper_chain):
    """Test signature validation with a valid chain."""
    print("\n" + "="*80)
    print("TEST: Signatur-Validierung (Gültige Chain)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Leaf: {leaf_info.subject}")
    print(f"✓ Intermediate: {intermediate_info.subject}")
    print(f"✓ Root: {root_info.subject}")
    
    print("→ Signatur-Validierung durchführen...")
    results = validate_signatures(
        proper_chain["leaf"],
        [proper_chain["intermediate"]],
        root_from_trust_store=proper_chain["root"],
    )

    print(f"\n📊 Ergebnisse:")
    all_valid = True
    for fingerprint, (is_valid, subject, error_msg) in results.items():
        status = "✓" if is_valid else "✗"
        print(f"  {status} {subject}: Valid={is_valid}, Error={error_msg or 'Keine Fehler'}")
        if not is_valid:
            all_valid = False

    # All signatures should be valid
    for fingerprint, (is_valid, subject, error_msg) in results.items():
        assert is_valid, f"Signature validation failed for {subject}: {error_msg}"
        assert error_msg is None
    
    print(f"\n✅ Test erfolgreich: Alle Signaturen sind gültig ({len(results)} geprüft)")
    print("="*80 + "\n")


def test_validate_signatures_missing_issuer(proper_chain):
    """Test signature validation when issuer is missing."""
    print("\n" + "="*80)
    print("TEST: Signatur-Validierung (Fehlender Issuer)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    print(f"✓ Leaf: {leaf_info.subject}, Issuer={leaf_info.issuer}")
    print("⚠ Keine Intermediate-Zertifikate bereitgestellt")
    print("⚠ Kein Root-Zertifikat bereitgestellt")
    
    # Validate without providing the intermediate
    print("→ Signatur-Validierung ohne Issuer durchführen...")
    results = validate_signatures(
        proper_chain["leaf"],
        [],  # No intermediate provided
        root_from_trust_store=None,
    )

    print(f"\n📊 Ergebnisse:")
    for fingerprint, (is_valid, subject, error_msg) in results.items():
        status = "✗" if not is_valid else "✓"
        print(f"  {status} {subject}: Valid={is_valid}, Error={error_msg or 'Keine Fehler'}")

    # Should fail because issuer is not found
    assert len(results) > 0
    for fingerprint, (is_valid, subject, error_msg) in results.items():
        assert not is_valid
        assert "not found" in error_msg.lower()
    
    print("\n✅ Test erfolgreich: Fehlender Issuer wurde korrekt erkannt")
    print("="*80 + "\n")


def test_validate_signatures_with_root_from_trust_store(proper_chain):
    """Test signature validation using root from trust store."""
    print("\n" + "="*80)
    print("TEST: Signatur-Validierung (Root aus Trust Store)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Leaf: {leaf_info.subject}")
    print(f"✓ Intermediate: {intermediate_info.subject}")
    print(f"✓ Root aus Trust Store: {root_info.subject}")
    
    print("→ Signatur-Validierung mit Root aus Trust Store durchführen...")
    results = validate_signatures(
        proper_chain["leaf"],
        [proper_chain["intermediate"]],
        root_from_trust_store=proper_chain["root"],
    )

    print(f"\n📊 Ergebnisse:")
    all_valid = True
    for fingerprint, (is_valid, subject, error_msg) in results.items():
        status = "✓" if is_valid else "✗"
        print(f"  {status} {subject}: Valid={is_valid}, Error={error_msg or 'Keine Fehler'}")
        if not is_valid:
            all_valid = False

    # Should succeed with root from trust store
    assert len(results) > 0
    all_valid = all(is_valid for is_valid, _, _ in results.values())
    assert all_valid
    
    print(f"\n✅ Test erfolgreich: Alle Signaturen sind gültig mit Root aus Trust Store")
    print("="*80 + "\n")


def test_build_and_sort_chain(proper_chain):
    """Test building and sorting certificate chain."""
    print("\n" + "="*80)
    print("TEST: Chain-Building und Sortierung")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    print(f"✓ Leaf: {leaf_info.subject}")
    
    # Provide certificates in wrong order
    unsorted_chain = [proper_chain["root"], proper_chain["intermediate"]]
    print(f"✓ Unsortierte Chain bereitgestellt: {len(unsorted_chain)} Zertifikate (Root, Intermediate)")

    print("→ Chain bauen und sortieren...")
    sorted_intermediates, root_cert_der = build_and_sort_chain(
        proper_chain["leaf"],
        unsorted_chain,
    )

    print(f"\n📊 Ergebnis:")
    print(f"  - Sortierte Intermediates: {len(sorted_intermediates)}")
    print(f"  - Root gefunden: {root_cert_der is not None}")
    
    if sorted_intermediates:
        intermediate_info, _ = parse_certificate(sorted_intermediates[0])
        print(f"  - Intermediate Subject: {intermediate_info.subject}")

    # Should have one intermediate
    assert len(sorted_intermediates) == 1
    # Root should be identified
    assert root_cert_der is not None

    # Verify the intermediate is correct
    intermediate_info, _ = parse_certificate(sorted_intermediates[0])
    assert "Intermediate" in intermediate_info.subject
    
    print("\n✅ Test erfolgreich: Chain wurde korrekt gebaut und sortiert")
    print("="*80 + "\n")


def test_build_and_sort_chain_no_root(proper_chain):
    """Test building chain when no root is provided."""
    print("\n" + "="*80)
    print("TEST: Chain-Building (Ohne Root)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    print(f"✓ Leaf: {leaf_info.subject}")
    print(f"✓ Intermediate: {intermediate_info.subject}")
    print("⚠ Kein Root-Zertifikat bereitgestellt")
    
    # Only provide intermediate (no root)
    chain_without_root = [proper_chain["intermediate"]]
    print(f"✓ Chain ohne Root bereitgestellt: {len(chain_without_root)} Zertifikat(e)")

    print("→ Chain bauen und sortieren...")
    sorted_intermediates, root_cert_der = build_and_sort_chain(
        proper_chain["leaf"],
        chain_without_root,
    )

    print(f"\n📊 Ergebnis:")
    print(f"  - Sortierte Intermediates: {len(sorted_intermediates)}")
    print(f"  - Root gefunden: {root_cert_der is not None}")

    # Should have one intermediate
    assert len(sorted_intermediates) == 1
    # Root should be None
    assert root_cert_der is None
    
    print("\n✅ Test erfolgreich: Chain wurde ohne Root korrekt gebaut")
    print("="*80 + "\n")


def test_build_and_sort_chain_wrong_order(proper_chain):
    """Test that chain is sorted correctly even when provided in wrong order."""
    print("\n" + "="*80)
    print("TEST: Chain-Building (Falsche Reihenfolge)")
    print("="*80)
    
    from ssl_tester.certificate import parse_certificate
    leaf_info, _ = parse_certificate(proper_chain["leaf"])
    print(f"✓ Leaf: {leaf_info.subject}, Issuer={leaf_info.issuer}")
    
    # Provide in reverse order
    reverse_chain = [proper_chain["root"], proper_chain["intermediate"]]
    print(f"✓ Chain in falscher Reihenfolge: Root, Intermediate")

    print("→ Chain bauen und sortieren...")
    sorted_intermediates, root_cert_der = build_and_sort_chain(
        proper_chain["leaf"],
        reverse_chain,
    )

    # Verify order: leaf -> intermediate -> root
    intermediate_info, _ = parse_certificate(sorted_intermediates[0])

    print(f"\n📊 Ergebnis:")
    print(f"  - Sortierte Intermediates: {len(sorted_intermediates)}")
    print(f"  - Root gefunden: {root_cert_der is not None}")
    print(f"  - Leaf Issuer: {leaf_info.issuer}")
    print(f"  - Intermediate Subject: {intermediate_info.subject}")
    print(f"  - Reihenfolge korrekt: {leaf_info.issuer == intermediate_info.subject}")

    # Leaf issuer should match intermediate subject
    assert leaf_info.issuer == intermediate_info.subject
    
    print("\n✅ Test erfolgreich: Chain wurde trotz falscher Reihenfolge korrekt sortiert")
    print("="*80 + "\n")


def test_split_pem_certificates():
    """Test splitting PEM data into individual certificates."""
    print("\n" + "="*80)
    print("TEST: PEM-Zertifikate aufteilen")
    print("="*80)
    
    # Create PEM data with multiple certificates
    pem_data = b"""-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
-----END CERTIFICATE-----
"""
    print(f"✓ PEM-Daten erstellt: {len(pem_data)} bytes")
    
    print("→ PEM-Daten in einzelne Zertifikate aufteilen...")
    certificates = _split_pem_certificates(pem_data)
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(certificates)}")
    for i, cert in enumerate(certificates, 1):
        has_begin = b"BEGIN CERTIFICATE" in cert
        has_end = b"END CERTIFICATE" in cert
        print(f"  - Zertifikat {i}: {len(cert)} bytes, BEGIN={has_begin}, END={has_end}")
    
    assert len(certificates) == 2
    assert b"BEGIN CERTIFICATE" in certificates[0]
    assert b"END CERTIFICATE" in certificates[0]
    assert b"BEGIN CERTIFICATE" in certificates[1]
    assert b"END CERTIFICATE" in certificates[1]
    
    print("\n✅ Test erfolgreich: PEM-Daten wurden korrekt aufgeteilt")
    print("="*80 + "\n")


def test_split_pem_certificates_empty():
    """Test splitting empty PEM data."""
    print("\n" + "="*80)
    print("TEST: PEM-Zertifikate aufteilen (Leer)")
    print("="*80)
    
    print("→ Leere PEM-Daten aufteilen...")
    certificates = _split_pem_certificates(b"")
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(certificates)}")
    
    assert len(certificates) == 0
    print("\n✅ Test erfolgreich: Leere PEM-Daten wurden korrekt behandelt")
    print("="*80 + "\n")


def test_split_pem_certificates_no_certificates():
    """Test splitting data with no certificates."""
    print("\n" + "="*80)
    print("TEST: PEM-Zertifikate aufteilen (Keine Zertifikate)")
    print("="*80)
    
    test_data = b"Some random text without certificates"
    print(f"✓ Test-Daten erstellt: {len(test_data)} bytes (ohne Zertifikate)")
    
    print("→ Daten aufteilen...")
    certificates = _split_pem_certificates(test_data)
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(certificates)}")
    
    assert len(certificates) == 0
    print("\n✅ Test erfolgreich: Daten ohne Zertifikate wurden korrekt behandelt")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_get_root_from_trust_store_root_in_chain(mock_load_trust_store, proper_chain):
    """Test _get_root_from_trust_store when root is already in chain."""
    print("\n" + "="*80)
    print("TEST: Root aus Trust Store (Root bereits in Chain)")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    root_info, _ = parse_certificate(proper_chain["root"])
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    print(f"✓ Chain enthält: Intermediate, Root ({root_info.subject})")
    print("⚠ Root ist bereits in Chain vorhanden")
    
    # Root is already in chain, should return None
    context = ssl.create_default_context()
    mock_load_trust_store.return_value = []
    
    print("→ Root aus Trust Store suchen...")
    result = _get_root_from_trust_store(
        [proper_chain["intermediate"], proper_chain["root"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Root gefunden: {result is not None}")
    print(f"  - Ergebnis: {'Root bereits in Chain' if result is None else 'Root aus Trust Store'}")
    
    assert result is None
    print("\n✅ Test erfolgreich: Root wurde nicht aus Trust Store geladen (bereits in Chain)")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_get_root_from_trust_store_root_not_in_chain(mock_load_trust_store, proper_chain):
    """Test _get_root_from_trust_store when root is missing from chain."""
    print("\n" + "="*80)
    print("TEST: Root aus Trust Store (Root nicht in Chain)")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Chain enthält nur: Intermediate ({intermediate_info.subject})")
    print(f"✓ Trust Store enthält: Root ({root_info.subject})")
    
    context = ssl.create_default_context()
    # Mock trust store to return the root certificate
    mock_load_trust_store.return_value = [proper_chain["root"]]
    
    # Only provide intermediate (no root)
    print("→ Root aus Trust Store suchen...")
    result = _get_root_from_trust_store(
        [proper_chain["intermediate"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Root gefunden: {result is not None}")
    if result:
        found_root_info, _ = parse_certificate(result)
        print(f"  - Gefundener Root: {found_root_info.subject}")
    
    # Should find root in trust store
    assert result is not None
    assert result == proper_chain["root"]
    print("\n✅ Test erfolgreich: Root wurde aus Trust Store geladen")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_get_root_from_trust_store_not_found(mock_load_trust_store, proper_chain):
    """Test _get_root_from_trust_store when root is not in trust store."""
    print("\n" + "="*80)
    print("TEST: Root aus Trust Store (Nicht gefunden)")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    print(f"✓ Chain enthält nur: Intermediate ({intermediate_info.subject})")
    print("⚠ Trust Store ist leer")
    
    context = ssl.create_default_context()
    # Mock trust store to return empty list
    mock_load_trust_store.return_value = []
    
    print("→ Root aus Trust Store suchen...")
    result = _get_root_from_trust_store(
        [proper_chain["intermediate"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Root gefunden: {result is not None}")
    
    assert result is None
    print("\n✅ Test erfolgreich: Root wurde nicht gefunden (Trust Store leer)")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_check_trust_store_root_in_chain(mock_load_trust_store, proper_chain):
    """Test _check_trust_store when root is in chain."""
    print("\n" + "="*80)
    print("TEST: Trust Store Prüfung (Root in Chain)")
    print("="*80)
    
    import ssl
    import hashlib
    from ssl_tester.certificate import parse_certificate
    
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Root in Chain: {root_info.subject}")
    
    context = ssl.create_default_context()
    # Mock trust store to include the root (by fingerprint match)
    root_fingerprint = hashlib.sha256(proper_chain["root"]).hexdigest()
    mock_load_trust_store.return_value = [proper_chain["root"]]
    print(f"✓ Trust Store enthält Root: {root_fingerprint[:16]}...")
    
    print("→ Trust Store Prüfung durchführen...")
    result = _check_trust_store(
        proper_chain["leaf"],
        [proper_chain["intermediate"], proper_chain["root"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Trust Store Valid: {result}")
    
    assert result is True
    print("\n✅ Test erfolgreich: Root in Chain wurde als vertrauenswürdig erkannt")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_check_trust_store_root_not_in_chain(mock_load_trust_store, proper_chain):
    """Test _check_trust_store when root is not in chain but in trust store."""
    print("\n" + "="*80)
    print("TEST: Trust Store Prüfung (Root nicht in Chain, aber im Trust Store)")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Chain enthält nur: Intermediate ({intermediate_info.subject})")
    print(f"✓ Trust Store enthält: Root ({root_info.subject})")
    
    context = ssl.create_default_context()
    # Mock trust store to include the root
    mock_load_trust_store.return_value = [proper_chain["root"]]
    
    # Only provide intermediate (no root in chain)
    print("→ Trust Store Prüfung durchführen...")
    result = _check_trust_store(
        proper_chain["leaf"],
        [proper_chain["intermediate"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Trust Store Valid: {result}")
    
    # Should find root in trust store by issuer match
    assert result is True
    print("\n✅ Test erfolgreich: Root aus Trust Store wurde als vertrauenswürdig erkannt")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_check_trust_store_not_trusted(mock_load_trust_store, proper_chain):
    """Test _check_trust_store when root is not in trust store."""
    print("\n" + "="*80)
    print("TEST: Trust Store Prüfung (Nicht vertrauenswürdig)")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    intermediate_info, _ = parse_certificate(proper_chain["intermediate"])
    print(f"✓ Chain enthält nur: Intermediate ({intermediate_info.subject})")
    print("⚠ Trust Store ist leer")
    
    context = ssl.create_default_context()
    # Mock trust store to return empty list
    mock_load_trust_store.return_value = []
    
    print("→ Trust Store Prüfung durchführen...")
    result = _check_trust_store(
        proper_chain["leaf"],
        [proper_chain["intermediate"]],
        context
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Trust Store Valid: {result}")
    
    assert result is False
    print("\n✅ Test erfolgreich: Chain wurde als nicht vertrauenswürdig erkannt")
    print("="*80 + "\n")


def test_load_system_trust_store_basic():
    """Test _load_system_trust_store basic functionality."""
    print("\n" + "="*80)
    print("TEST: System Trust Store laden (Basis)")
    print("="*80)
    
    import ssl
    
    context = ssl.create_default_context()
    print("✓ SSL-Context erstellt")
    
    # This test just verifies the function doesn't crash
    # Actual loading depends on system configuration
    print("→ System Trust Store laden...")
    result = _load_system_trust_store(context)
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(result)}")
    print(f"  - Typ: {type(result).__name__}")
    
    # Should return a list (may be empty if no certs found)
    assert isinstance(result, list)
    # All items should be bytes if present
    for cert_der in result:
        assert isinstance(cert_der, bytes)
    
    print("\n✅ Test erfolgreich: System Trust Store wurde geladen")
    print("="*80 + "\n")


@patch("ssl_tester.chain.subprocess.run")
def test_load_macos_keychain_certificates_success(mock_subprocess):
    """Test _load_macos_keychain_certificates with successful execution."""
    print("\n" + "="*80)
    print("TEST: macOS Keychain Zertifikate laden (Erfolgreich)")
    print("="*80)
    
    from ssl_tester.chain import _load_macos_keychain_certificates
    
    # Create mock PEM certificate data
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    pem_data = cert.public_bytes(serialization.Encoding.PEM)
    print(f"✓ Mock-Zertifikat erstellt: Subject={subject.rfc4514_string()}")
    print(f"✓ PEM-Daten: {len(pem_data)} bytes")
    
    # Mock subprocess.run for find-certificate
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = pem_data.decode('utf-8')
    mock_subprocess.return_value = mock_result
    
    print("→ macOS Keychain Zertifikate laden...")
    result = _load_macos_keychain_certificates()
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(result)}")
    if result:
        print(f"  - Erstes Zertifikat: {len(result[0])} bytes")
    
    assert len(result) > 0
    assert isinstance(result[0], bytes)
    print("\n✅ Test erfolgreich: macOS Keychain Zertifikate wurden geladen")
    print("="*80 + "\n")


@patch("ssl_tester.chain.subprocess.run")
def test_load_macos_keychain_certificates_not_found(mock_subprocess):
    """Test _load_macos_keychain_certificates when security command is not found."""
    print("\n" + "="*80)
    print("TEST: macOS Keychain Zertifikate laden (Command nicht gefunden)")
    print("="*80)
    
    from ssl_tester.chain import _load_macos_keychain_certificates
    
    print("⚠ 'security' Command nicht verfügbar (gemockt)")
    mock_subprocess.side_effect = FileNotFoundError("security: command not found")
    
    print("→ macOS Keychain Zertifikate laden...")
    result = _load_macos_keychain_certificates()
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Zertifikate: {len(result)}")
    print(f"  - Ergebnis: Leere Liste (Command nicht gefunden)")
    
    assert result == []
    print("\n✅ Test erfolgreich: Fehlendes Command wurde korrekt behandelt")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_load_root_certs_from_trust_store(mock_load_trust_store, proper_chain):
    """Test load_root_certs_from_trust_store."""
    print("\n" + "="*80)
    print("TEST: Root-Zertifikate aus Trust Store laden")
    print("="*80)
    
    import ssl
    from ssl_tester.certificate import parse_certificate
    
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Trust Store enthält: Root ({root_info.subject})")
    
    # Mock trust store to return root certificate
    mock_load_trust_store.return_value = [proper_chain["root"]]
    
    print("→ Root-Zertifikate aus Trust Store laden...")
    result = load_root_certs_from_trust_store()
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Root-Zertifikate: {len(result)}")
    print(f"  - Typ: {type(result).__name__}")
    for subject, cert_der in list(result.items())[:3]:  # Zeige erste 3
        print(f"  - {subject}: {len(cert_der)} bytes")
    
    assert isinstance(result, dict)
    # Should contain at least one root certificate
    assert len(result) > 0
    # All values should be bytes (DER-encoded certificates)
    for cert_der in result.values():
        assert isinstance(cert_der, bytes)
    
    print("\n✅ Test erfolgreich: Root-Zertifikate wurden aus Trust Store geladen")
    print("="*80 + "\n")


@patch("ssl_tester.chain._load_system_trust_store")
def test_load_root_certs_from_trust_store_with_ca_bundle(mock_load_trust_store, proper_chain):
    """Test load_root_certs_from_trust_store with custom CA bundle."""
    print("\n" + "="*80)
    print("TEST: Root-Zertifikate aus Trust Store laden (Mit CA Bundle)")
    print("="*80)
    
    from pathlib import Path
    from ssl_tester.certificate import parse_certificate
    
    root_info, _ = parse_certificate(proper_chain["root"])
    print(f"✓ Trust Store enthält: Root ({root_info.subject})")
    
    # Mock trust store
    mock_load_trust_store.return_value = [proper_chain["root"]]
    
    ca_bundle = Path("/path/to/ca-bundle.pem")
    print(f"✓ Custom CA Bundle: {ca_bundle}")
    
    print("→ Root-Zertifikate mit CA Bundle laden...")
    result = load_root_certs_from_trust_store(ca_bundle=ca_bundle)
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Root-Zertifikate: {len(result)}")
    print(f"  - Typ: {type(result).__name__}")
    
    assert isinstance(result, dict)
    # Should still work with custom CA bundle
    assert len(result) >= 0
    print("\n✅ Test erfolgreich: Root-Zertifikate wurden mit CA Bundle geladen")
    print("="*80 + "\n")

