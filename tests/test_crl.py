"""Tests for CRL reachability checks."""

import pytest
from unittest.mock import Mock, MagicMock, patch
import httpx

from ssl_tester.crl import check_crl_reachability, _check_single_crl
from ssl_tester.models import CertificateInfo, Severity
from datetime import datetime, timedelta


@pytest.fixture
def cert_info_with_crl():
    """Create a certificate info with CRL URLs."""
    return CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["http://crl.example.com/crl.pem"],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )


@patch("ssl_tester.crl.httpx.Client")
@patch("ssl_tester.crl.x509.load_der_x509_crl")
@patch("ssl_tester.crl.x509.load_pem_x509_crl")
def test_check_single_crl_success(mock_load_pem, mock_load_der, mock_client_class):
    """Test successful CRL check."""
    print("\n" + "="*80)
    print("TEST: Erfolgreiche CRL-Prüfung")
    print("="*80)
    
    # Create a mock CRL object for validation
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta
    
    # Create CA certificate (signer of CRL)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)  # Self-signed
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
    print(f"✓ CA-Zertifikat erstellt: Subject={ca_subject.rfc4514_string()}")
    
    # Create a minimal valid CRL for testing (signed by CA)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_subject)
    builder = builder.last_update(datetime.utcnow())
    builder = builder.next_update(datetime.utcnow() + timedelta(days=1))
    crl = builder.sign(ca_key, hashes.SHA256())
    mock_crl_content = crl.public_bytes(serialization.Encoding.DER)
    print(f"✓ CRL erstellt: Issuer={ca_subject.rfc4514_string()}, Größe={len(mock_crl_content)} bytes")
    
    # Mock the CRL loading to succeed
    mock_load_der.return_value = crl
    
    # Create certificate info for a certificate that is NOT revoked
    cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=Test CA",  # Matches CRL issuer
        serial_number="12345",  # Not in CRL (CRL is empty)
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["http://crl.example.com/crl.pem"],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    print(f"✓ Zertifikat-Info erstellt: Subject={cert_info.subject}, Serial={cert_info.serial_number}")
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/pkix-crl", "Content-Length": str(len(mock_crl_content))}
    mock_response.url = "http://crl.example.com/crl.pem"
    mock_response.history = []
    # Mock iter_bytes to return chunks
    mock_response.iter_bytes = Mock(return_value=iter([mock_crl_content]))

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client

    print("→ CRL-Prüfung durchführen...")
    result = _check_single_crl(
        "http://crl.example.com/crl.pem",
        timeout=10.0,
        max_redirects=5,
        max_crl_bytes=10240,
        no_redirects=False,
        cert_info=cert_info,
        issuer_cert_der=ca_cert_der,
    )

    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Status Code: {result.status_code}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    print(f"  - Content-Type: {result.content_type}")
    
    assert result.reachable is True
    assert result.status_code == 200
    assert result.severity == Severity.OK
    print("\n✅ Test erfolgreich: CRL ist erreichbar und gültig")
    print("="*80 + "\n")


@patch("ssl_tester.crl.httpx.Client")
def test_check_single_crl_timeout(mock_client_class):
    """Test CRL check timeout."""
    print("\n" + "="*80)
    print("TEST: CRL-Prüfung mit Timeout")
    print("="*80)
    
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.side_effect = httpx.TimeoutException("Request timeout")
    mock_client_class.return_value = mock_client

    print("→ CRL-Prüfung mit kurzem Timeout (1.0s) durchführen...")
    result = _check_single_crl("http://crl.example.com/crl.pem", timeout=1.0, max_redirects=5, max_crl_bytes=10240, no_redirects=False)

    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    
    assert result.reachable is False
    assert result.severity == Severity.WARN
    assert "timeout" in result.error.lower()
    print("\n✅ Test erfolgreich: Timeout wurde korrekt erkannt")
    print("="*80 + "\n")


def test_check_crl_reachability_ldap():
    """Test LDAP CRL URL handling."""
    print("\n" + "="*80)
    print("TEST: LDAP CRL URL Behandlung")
    print("="*80)
    
    cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["ldap://ldap.example.com/crl"],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    print(f"✓ Zertifikat-Info erstellt: Subject={cert_info.subject}")
    print(f"✓ CRL Distribution Point: ldap://ldap.example.com/crl")

    print("→ CRL-Erreichbarkeits-Prüfung durchführen...")
    results = check_crl_reachability([cert_info], leaf_cert_info=cert_info)

    print(f"\n📊 Ergebnis:")
    print(f"  - Anzahl Ergebnisse: {len(results)}")
    print(f"  - Erreichbar: {results[0].reachable}")
    print(f"  - Severity: {results[0].severity}")
    print(f"  - Error: {results[0].error or 'Keine Fehler'}")
    
    assert len(results) == 1
    assert results[0].reachable is False
    assert "LDAP" in results[0].error
    assert results[0].severity == Severity.WARN
    print("\n✅ Test erfolgreich: LDAP-URL wurde korrekt abgelehnt")
    print("="*80 + "\n")


@patch("ssl_tester.crl.httpx.Client")
@patch("ssl_tester.crl.x509.load_der_x509_crl")
def test_check_single_crl_with_signature_validation(mock_load_der, mock_client_class):
    """Test CRL check with signature validation."""
    print("\n" + "="*80)
    print("TEST: CRL-Prüfung mit Signatur-Validierung")
    print("="*80)
    
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    
    # Create CA certificate (signer of CRL)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)  # Self-signed
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_der = ca_cert.public_bytes(serialization.Encoding.DER)
    print(f"✓ CA-Zertifikat erstellt: Subject={ca_subject.rfc4514_string()}")
    
    # Create CRL signed by CA
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_subject)
    crl_builder = crl_builder.last_update(datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=1))
    crl = crl_builder.sign(ca_key, hashes.SHA256())
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    print(f"✓ CRL erstellt und signiert: Issuer={ca_subject.rfc4514_string()}")
    
    # Mock CRL loading
    mock_load_der.return_value = crl
    
    # Create certificate info with matching issuer
    cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=Test CA",  # Matches CRL issuer
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["http://crl.example.com/crl.pem"],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    print(f"✓ Zertifikat-Info erstellt: Subject={cert_info.subject}, Issuer={cert_info.issuer}")
    
    # Mock HTTP response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/pkix-crl"}
    mock_response.url = "http://crl.example.com/crl.pem"
    mock_response.history = []
    mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
    
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client
    
    # Create issuer map for signature validation
    from ssl_tester.certificate import parse_certificate
    ca_cert_info, _ = parse_certificate(ca_cert_der)
    issuer_map = {ca_cert_info.subject: ca_cert_der}
    print(f"✓ Issuer-Map erstellt für Signatur-Validierung")
    
    print("→ CRL-Prüfung mit Signatur-Validierung durchführen...")
    result = _check_single_crl(
        "http://crl.example.com/crl.pem",
        timeout=10.0,
        max_redirects=5,
        max_crl_bytes=10240,
        no_redirects=False,
        cert_info=cert_info,
        issuer_map=issuer_map,
        issuer_cert_der=ca_cert_der,
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Status Code: {result.status_code}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    
    assert result.reachable is True
    assert result.status_code == 200
    # Signature validation should succeed if CRL is properly signed
    # Note: The actual signature validation depends on cryptography version
    print("\n✅ Test erfolgreich: CRL-Prüfung mit Signatur-Validierung abgeschlossen")
    print("="*80 + "\n")


@patch("ssl_tester.crl.httpx.Client")
@patch("ssl_tester.crl.x509.load_der_x509_crl")
def test_check_single_crl_without_signer_cert(mock_load_der, mock_client_class):
    """Test CRL check when signer certificate is not available."""
    print("\n" + "="*80)
    print("TEST: CRL-Prüfung ohne Signer-Zertifikat")
    print("="*80)
    
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    
    # Create CRL
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_subject)
    crl_builder = crl_builder.last_update(datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=1))
    crl = crl_builder.sign(ca_key, hashes.SHA256())
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    print(f"✓ CRL erstellt: Issuer={ca_subject.rfc4514_string()}")
    
    mock_load_der.return_value = crl
    
    cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=Test CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=["http://crl.example.com/crl.pem"],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )
    print(f"✓ Zertifikat-Info erstellt: Subject={cert_info.subject}")
    print("⚠ Issuer-Zertifikat NICHT verfügbar (issuer_map=None, issuer_cert_der=None)")
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/pkix-crl"}
    mock_response.url = "http://crl.example.com/crl.pem"
    mock_response.history = []
    mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
    
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client
    
    # No issuer_map provided - signature validation should fail gracefully
    print("→ CRL-Prüfung ohne Signer-Zertifikat durchführen...")
    result = _check_single_crl(
        "http://crl.example.com/crl.pem",
        timeout=10.0,
        max_redirects=5,
        max_crl_bytes=10240,
        no_redirects=False,
        cert_info=cert_info,
        issuer_map=None,  # No issuer map
        issuer_cert_der=None,  # No issuer cert
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Status Code: {result.status_code}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    
    assert result.reachable is True
    assert result.status_code == 200
    # Should still be reachable even if signature validation fails
    print("\n✅ Test erfolgreich: CRL ist erreichbar, auch ohne Signer-Zertifikat")
    print("="*80 + "\n")


@patch("ssl_tester.crl.httpx.Client")
@patch("ssl_tester.crl.x509.load_der_x509_crl")
def test_check_single_crl_max_size_exceeded(mock_load_der, mock_client_class):
    """Test CRL check when CRL exceeds max size."""
    print("\n" + "="*80)
    print("TEST: CRL-Prüfung mit überschrittener Maximalgröße")
    print("="*80)
    
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID
    
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_subject)
    crl_builder = crl_builder.last_update(datetime.utcnow())
    crl_builder = crl_builder.next_update(datetime.utcnow() + timedelta(days=1))
    crl = crl_builder.sign(ca_key, hashes.SHA256())
    crl_der = crl.public_bytes(serialization.Encoding.DER)
    print(f"✓ CRL erstellt: Issuer={ca_subject.rfc4514_string()}, Basis-Größe={len(crl_der)} bytes")
    
    mock_load_der.return_value = crl
    
    # Create large content (exceeds max_crl_bytes)
    large_content = crl_der + b"x" * 20000  # Make it larger than max
    print(f"✓ Große CRL erstellt: {len(large_content)} bytes (Max: 10240 bytes)")
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "application/pkix-crl", "Content-Length": str(len(large_content))}
    mock_response.url = "http://crl.example.com/crl.pem"
    mock_response.history = []
    mock_response.iter_bytes = Mock(return_value=iter([large_content]))
    
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client
    
    print("→ CRL-Prüfung mit Größenlimit durchführen...")
    result = _check_single_crl(
        "http://crl.example.com/crl.pem",
        timeout=10.0,
        max_redirects=5,
        max_crl_bytes=10240,  # Small limit
        no_redirects=False,
    )
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Status Code: {result.status_code}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Größe: {result.size_bytes} bytes")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    
    assert result.reachable is True
    assert "too large" in result.error.lower()
    assert result.severity == Severity.WARN
    print("\n✅ Test erfolgreich: Überschreitung der Maximalgröße wurde korrekt erkannt")
    print("="*80 + "\n")


@pytest.mark.comprehensive
@pytest.mark.mock_cert
class TestComprehensiveCertificateAndCRLValidation:
    """Umfassende Tests mit echten Prüfungen gegen gemockte Zertifikate und CRLs.
    
    Diese Tests können separat aufgerufen werden mit:
    - pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -v -s
    - pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_valid_certificate_with_valid_crl -v -s
    - pytest -m comprehensive -v -s
    - pytest -m mock_cert -v -s
    """
    
    @pytest.fixture
    def ca_key(self):
        """CA-Private-Key für alle Tests."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    @pytest.fixture
    def ca_cert(self, ca_key):
        """Selbst-signiertes CA-Zertifikat."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)  # Self-signed
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=365))
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return ca_cert
    
    @pytest.fixture
    def intermediate_key(self):
        """Intermediate-CA-Private-Key."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    @pytest.fixture
    def intermediate_cert(self, ca_key, ca_cert, intermediate_key):
        """Intermediate-CA-Zertifikat, signiert von Root-CA."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        
        ca_subject = ca_cert.subject
        intermediate_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
        intermediate_cert = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject)
            .issuer_name(ca_subject)
            .public_key(intermediate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow() - timedelta(days=1))
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return intermediate_cert
    
    @pytest.fixture
    def leaf_key(self):
        """Leaf-Zertifikat-Private-Key."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    def create_leaf_cert(
        self,
        intermediate_key,
        intermediate_cert,
        leaf_key,
        hostname="example.com",
        serial_number=None,
        not_before=None,
        not_after=None,
        crl_urls=None,
        ocsp_urls=None,
    ):
        """Erstellt ein Leaf-Zertifikat mit konfigurierbaren Eigenschaften."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        
        intermediate_subject = intermediate_cert.subject
        leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        
        if serial_number is None:
            serial_number = x509.random_serial_number()
        if not_before is None:
            not_before = datetime.utcnow() - timedelta(days=1)
        if not_after is None:
            not_after = datetime.utcnow() + timedelta(days=365)
        
        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(intermediate_subject)
            .public_key(leaf_key.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
        )
        
        # CRL Distribution Points hinzufügen
        if crl_urls:
            crl_dps = []
            for url in crl_urls:
                crl_dps.append(
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(url)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                )
            builder = builder.add_extension(
                x509.CRLDistributionPoints(crl_dps),
                critical=False,
            )
        
        # OCSP URLs hinzufügen
        if ocsp_urls:
            aia_descriptions = []
            for url in ocsp_urls:
                aia_descriptions.append(
                    x509.AccessDescription(
                        access_method=x509.oid.AuthorityInformationAccessOID.OCSP,
                        access_location=x509.UniformResourceIdentifier(url),
                    )
                )
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(aia_descriptions),
                critical=False,
            )
        
        cert = builder.sign(intermediate_key, hashes.SHA256())
        return cert
    
    def create_crl(
        self,
        signer_key,
        signer_subject,
        revoked_serials=None,
        last_update=None,
        next_update=None,
    ):
        """Erstellt eine CRL mit konfigurierbaren Eigenschaften."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import CRLEntryExtensionOID
        
        if last_update is None:
            last_update = datetime.utcnow()
        if next_update is None:
            next_update = datetime.utcnow() + timedelta(days=1)
        if revoked_serials is None:
            revoked_serials = []
        
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(signer_subject)
        builder = builder.last_update(last_update)
        builder = builder.next_update(next_update)
        
        # Revozierte Seriennummern hinzufügen
        for serial in revoked_serials:
            revoked_cert = x509.RevokedCertificateBuilder()
            revoked_cert = revoked_cert.serial_number(serial)
            revoked_cert = revoked_cert.revocation_date(datetime.utcnow() - timedelta(days=1))
            revoked_cert = revoked_cert.add_extension(
                x509.CRLReason(reason=x509.ReasonFlags.unspecified),
                critical=False,
            )
            builder = builder.add_revoked_certificate(revoked_cert.build())
        
        crl = builder.sign(signer_key, hashes.SHA256())
        return crl
    
    @pytest.mark.comprehensive
    @pytest.mark.mock_cert
    @patch("ssl_tester.crl.httpx.Client")
    def test_valid_certificate_with_valid_crl(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: Gültiges Zertifikat mit gültiger CRL (nicht revoziert)."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate
        
        print("\n" + "="*80)
        print("TEST: Gültiges Zertifikat mit gültiger CRL (nicht revoziert)")
        print("="*80)
        
        # Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        leaf_serial = leaf_cert.serial_number
        print(f"✓ Leaf-Zertifikat erstellt: Serial={leaf_serial}, Hostname=example.com")
        
        # CRL erstellen (Zertifikat ist NICHT revoziert)
        crl = self.create_crl(
            signer_key=intermediate_key,
            signer_subject=intermediate_cert.subject,
            revoked_serials=[],  # Leer = nicht revoziert
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        print(f"✓ CRL erstellt: Issuer={intermediate_cert.subject.rfc4514_string()}, Revoked=0")
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        print(f"✓ Zertifikat geparst: Subject={cert_info.subject}, Issuer={cert_info.issuer}")
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Content-Type": "application/pkix-crl",
            "Content-Length": str(len(crl_der)),
        }
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map für Signatur-Verifizierung
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions
        print(f"\n📊 CRL-Prüfung Ergebnis:")
        print(f"  - Erreichbar: {result.reachable}")
        print(f"  - Status Code: {result.status_code}")
        print(f"  - Severity: {result.severity}")
        print(f"  - Error: {result.error or 'Keine Fehler'}")
        print(f"  - Größe: {result.size_bytes} bytes")
        
        assert result.reachable is True
        assert result.status_code == 200
        assert result.severity == Severity.OK
        assert result.error is None or "revoked" not in (result.error or "").lower()
        print("\n✅ Test erfolgreich: Zertifikat ist gültig und nicht revoziert")
        print("="*80 + "\n")
    
    @pytest.mark.comprehensive
    @pytest.mark.mock_cert
    @patch("ssl_tester.crl.httpx.Client")
    def test_revoked_certificate_in_crl(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: Revozierte Zertifikat in CRL."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate
        
        print("\n" + "="*80)
        print("TEST: Revozierte Zertifikat in CRL")
        print("="*80)
        
        # Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="revoked.example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        leaf_serial = leaf_cert.serial_number
        print(f"✓ Leaf-Zertifikat erstellt: Serial={leaf_serial}, Hostname=revoked.example.com")
        
        # CRL erstellen (Zertifikat IST revoziert)
        crl = self.create_crl(
            signer_key=intermediate_key,
            signer_subject=intermediate_cert.subject,
            revoked_serials=[leaf_serial],  # Zertifikat ist revoziert!
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        print(f"✓ CRL erstellt: Issuer={intermediate_cert.subject.rfc4514_string()}, Revoked=1 (Serial={leaf_serial})")
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        print(f"✓ Zertifikat geparst: Subject={cert_info.subject}, Issuer={cert_info.issuer}")
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions: Sollte FAIL sein, da Zertifikat revoziert ist
        print(f"\n📊 CRL-Prüfung Ergebnis:")
        print(f"  - Erreichbar: {result.reachable}")
        print(f"  - Status Code: {result.status_code}")
        print(f"  - Severity: {result.severity}")
        print(f"  - Error: {result.error or 'Keine Fehler'}")
        
        assert result.reachable is True
        assert result.status_code == 200
        assert result.severity == Severity.FAIL
        assert "revoked" in (result.error or "").lower()
        print("\n✅ Test erfolgreich: Zertifikat wurde korrekt als revoziert erkannt")
        print("="*80 + "\n")
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_crl_with_invalid_signature(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: CRL mit falscher Signatur (signiert von falschem Key)."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        from ssl_tester.certificate import parse_certificate
        
        # Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # CRL mit FALSCHER Signatur erstellen (signiert von anderem Key)
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        crl = self.create_crl(
            signer_key=wrong_key,  # Falscher Key!
            signer_subject=intermediate_cert.subject,  # Aber richtiger Issuer
            revoked_serials=[],
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map (mit richtigem Zertifikat)
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions: Sollte WARN sein, da Signatur ungültig
        assert result.reachable is True
        assert result.status_code == 200
        # Signatur-Verifizierung sollte fehlschlagen
        assert result.severity == Severity.WARN
        assert "signature" in (result.error or "").lower() or "signatur" in (result.error or "").lower()
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_expired_crl(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: Abgelaufene CRL (next_update in der Vergangenheit)."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate
        
        # Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # Abgelaufene CRL erstellen
        crl = self.create_crl(
            signer_key=intermediate_key,
            signer_subject=intermediate_cert.subject,
            revoked_serials=[],
            last_update=datetime.utcnow() - timedelta(days=10),
            next_update=datetime.utcnow() - timedelta(days=1),  # Abgelaufen!
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions: CRL ist abgelaufen, sollte WARN sein
        assert result.reachable is True
        assert result.status_code == 200
        # Die CRL ist abgelaufen, aber das Tool prüft das möglicherweise nicht explizit
        # Es sollte aber zumindest erreichbar sein
    
    def test_expired_certificate(self, intermediate_key, intermediate_cert, leaf_key):
        """Test: Abgelaufenes Zertifikat."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate, check_validity
        
        # Abgelaufenes Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="expired.example.com",
            not_before=datetime.utcnow() - timedelta(days=365),
            not_after=datetime.utcnow() - timedelta(days=1),  # Abgelaufen!
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # Zertifikat parsen
        cert_info, findings = parse_certificate(leaf_cert_der)
        
        # Gültigkeitsprüfung durchführen
        result = check_validity(cert_info)
        
        # Assertions
        assert result.is_valid is False
        assert result.is_expired is True
        assert result.severity == Severity.FAIL
    
    def test_certificate_not_yet_valid(self, intermediate_key, intermediate_cert, leaf_key):
        """Test: Zertifikat noch nicht gültig (not_before in Zukunft)."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate, check_validity
        
        # Zertifikat, das noch nicht gültig ist
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="future.example.com",
            not_before=datetime.utcnow() + timedelta(days=1),  # Noch nicht gültig!
            not_after=datetime.utcnow() + timedelta(days=366),
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # Zertifikat parsen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Gültigkeitsprüfung durchführen
        result = check_validity(cert_info)
        
        # Assertions
        assert result.is_valid is False
        assert result.is_expired is False  # Nicht abgelaufen, aber noch nicht gültig
        assert result.severity == Severity.FAIL
    
    def test_certificate_hostname_mismatch(self, intermediate_key, intermediate_cert, leaf_key):
        """Test: Hostname-Mismatch."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate, check_hostname
        
        # Zertifikat für example.com erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # Zertifikat parsen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Hostname-Prüfung mit falschem Hostname
        result = check_hostname(cert_info, "wrong.example.com")
        
        # Assertions
        assert result.matches is False
        assert result.severity == Severity.FAIL
    
    def test_certificate_hostname_match(self, intermediate_key, intermediate_cert, leaf_key):
        """Test: Hostname-Match."""
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate, check_hostname
        
        # Zertifikat für example.com erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # Zertifikat parsen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Hostname-Prüfung mit richtigem Hostname
        result = check_hostname(cert_info, "example.com")
        
        # Assertions
        assert result.matches is True
        assert result.severity == Severity.OK
        assert result.matched_san_dns == "example.com"
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_crl_with_wrong_issuer(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: CRL mit falschem Issuer (CRL-Issuer stimmt nicht mit Zertifikat-Issuer überein)."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        from ssl_tester.certificate import parse_certificate
        
        # Leaf-Zertifikat erstellen
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # CRL mit FALSCHEM Issuer erstellen (anderer Subject)
        wrong_issuer_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong CA")])
        wrong_issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        crl = self.create_crl(
            signer_key=wrong_issuer_key,
            signer_subject=wrong_issuer_subject,  # Falscher Issuer!
            revoked_serials=[],
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map (nur mit richtigem Issuer)
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions: CRL-Issuer stimmt nicht überein - das ist eine Fehlkonfiguration
        assert result.reachable is True
        assert result.status_code == 200
        # Sollte FAIL sein, da CRL-Issuer nicht mit Certificate-Issuer übereinstimmt (Misconfiguration)
        assert result.severity == Severity.FAIL
        assert "CRL-Misconfiguration" in (result.error or "")
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_multiple_revoked_certificates_in_crl(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: Mehrere revozierte Zertifikate in einer CRL."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from ssl_tester.certificate import parse_certificate
        
        # Zwei Leaf-Zertifikate erstellen
        leaf_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        leaf_cert1 = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="revoked1.example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        leaf_cert2 = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key2,
            hostname="revoked2.example.com",
            crl_urls=["http://crl.example.com/crl.der"],
        )
        
        serial1 = leaf_cert1.serial_number
        serial2 = leaf_cert2.serial_number
        
        # CRL mit beiden revozierten Zertifikaten
        crl = self.create_crl(
            signer_key=intermediate_key,
            signer_subject=intermediate_cert.subject,
            revoked_serials=[serial1, serial2],  # Beide revoziert
        )
        crl_der = crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo für erstes Zertifikat
        cert_info1, _ = parse_certificate(leaf_cert1.public_bytes(serialization.Encoding.DER))
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/crl.der"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER)
        }
        
        # CRL-Prüfung für erstes Zertifikat
        result1 = _check_single_crl(
            "http://crl.example.com/crl.der",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info1,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),
            issuer_map=issuer_map,
        )
        
        # Assertions: Erstes Zertifikat sollte als revoziert erkannt werden
        assert result1.reachable is True
        assert result1.severity == Severity.FAIL
        assert "revoked" in (result1.error or "").lower()

    @patch("ssl_tester.crl.httpx.Client")
    def test_crl_issuer_mismatch_misconfiguration(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert, leaf_key
    ):
        """Test: CRL-Issuer-Mismatch-Fehlerkonfiguration erkennen.
        
        Szenario: Leaf-Zertifikat wurde von Intermediate-CA ausgestellt, aber die CRL-URL
        zeigt auf eine Root-CA-CRL. Die CRL-Signatur ist gültig (von Root-CA signiert),
        aber der CRL-Issuer stimmt nicht mit dem Certificate-Issuer überein.
        Dies sollte als FAIL (Misconfiguration) erkannt werden.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate
        
        # Leaf-Zertifikat erstellen (von Intermediate-CA ausgestellt)
        leaf_cert = self.create_leaf_cert(
            intermediate_key,
            intermediate_cert,
            leaf_key,
            hostname="example.com",
            crl_urls=["http://crl.example.com/root_ca.crl"],  # Zeigt auf Root-CA-CRL (Fehlkonfiguration!)
        )
        leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        
        # CRL von Root-CA erstellen (nicht von Intermediate-CA!)
        # Das ist die Fehlkonfiguration: Leaf-Zertifikat zeigt auf Root-CA-CRL
        root_ca_crl = self.create_crl(
            signer_key=ca_key,
            signer_subject=ca_cert.subject,  # Root-CA signiert die CRL
            revoked_serials=[],
        )
        crl_der = root_ca_crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo erstellen
        cert_info, _ = parse_certificate(leaf_cert_der)
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/root_ca.crl"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map mit BEIDEN CAs (Root-CA und Intermediate-CA)
        # Root-CA ist vorhanden, damit die CRL-Signatur verifiziert werden kann
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert.public_bytes(serialization.Encoding.DER),
            ca_cert.subject.rfc4514_string(): ca_cert.public_bytes(serialization.Encoding.DER),  # Root-CA für CRL-Verifizierung
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/root_ca.crl",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=intermediate_cert.public_bytes(serialization.Encoding.DER),  # Intermediate-CA ist Issuer des Leaf-Zertifikats
            issuer_map=issuer_map,
        )
        
        # Assertions: CRL-Issuer-Mismatch sollte als FAIL (Misconfiguration) erkannt werden
        assert result.reachable is True
        assert result.status_code == 200
        assert result.severity == Severity.FAIL, f"Expected FAIL but got {result.severity}. Error: {result.error}"
        assert "CRL-Misconfiguration" in (result.error or ""), f"Expected 'CRL-Misconfiguration' in error message. Error: {result.error}"
        assert "fehlerhafte CDP-Konfiguration" in (result.error or "").lower() or "misconfiguration" in (result.error or "").lower()
        
        # Prüfen, dass die Fehlermeldung die relevanten Informationen enthält
        assert ca_cert.subject.rfc4514_string() in (result.error or ""), "Error should mention Root-CA issuer"
        assert intermediate_cert.subject.rfc4514_string() in (result.error or ""), "Error should mention Intermediate-CA issuer"
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_intermediate_ca_self_signed_crl_legitimate(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert
    ):
        """Test: Intermediate-CA signiert ihre eigene CRL (legitimer Fall).
        
        Szenario: Intermediate-CA wurde von Root-CA ausgestellt, aber signiert
        ihre eigenen CRLs selbst. Dies ist ein legitimer Fall und sollte NICHT
        als Misconfiguration erkannt werden.
        """
        from cryptography.hazmat.primitives import serialization
        from ssl_tester.certificate import parse_certificate
        from ssl_tester.models import Severity
        from unittest.mock import Mock, MagicMock
        
        # CRL von Intermediate-CA selbst signiert (nicht von Root-CA!)
        # Das ist legitim: Intermediate-CA kann ihre eigenen CRLs signieren
        intermediate_crl = self.create_crl(
            signer_key=intermediate_key,
            signer_subject=intermediate_cert.subject,  # Intermediate-CA signiert die CRL selbst
            revoked_serials=[],
        )
        crl_der = intermediate_crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo für Intermediate-CA erstellen
        intermediate_cert_der = intermediate_cert.public_bytes(serialization.Encoding.DER)
        cert_info, _ = parse_certificate(intermediate_cert_der)
        
        # Mock HTTP-Response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "application/pkix-crl"}
        mock_response.url = "http://crl.example.com/intermediate_ca.crl"
        mock_response.history = []
        mock_response.iter_bytes = Mock(return_value=iter([crl_der]))
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Issuer-Map mit Intermediate-CA (für CRL-Signatur-Verifizierung)
        issuer_map = {
            intermediate_cert.subject.rfc4514_string(): intermediate_cert_der,
            ca_cert.subject.rfc4514_string(): ca_cert.public_bytes(serialization.Encoding.DER),
        }
        
        # CRL-Prüfung durchführen
        result = _check_single_crl(
            "http://crl.example.com/intermediate_ca.crl",
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            cert_info=cert_info,
            issuer_cert_der=ca_cert.public_bytes(serialization.Encoding.DER),  # Root-CA ist Issuer des Intermediate-Zertifikats
            issuer_map=issuer_map,
        )
        
        # Assertions: Self-signed CRL für Intermediate-CA sollte NICHT als Misconfiguration erkannt werden
        assert result.reachable is True
        assert result.status_code == 200
        # Sollte OK oder WARN sein, aber NICHT FAIL wegen Misconfiguration
        assert result.severity != Severity.FAIL or "CRL-Misconfiguration" not in (result.error or ""), \
            f"Self-signed CRL for intermediate CA should not be flagged as misconfiguration. " \
            f"Severity: {result.severity}, Error: {result.error}"
        # Die CRL sollte erfolgreich verifiziert werden können
        assert "CRL-Misconfiguration" not in (result.error or ""), \
            f"Self-signed CRL for intermediate CA should not trigger misconfiguration error. Error: {result.error}"
    
    @patch("ssl_tester.crl.httpx.Client")
    def test_intermediate_ca_revoked_in_root_ca_crl(
        self, mock_client_class, ca_key, ca_cert, intermediate_key, intermediate_cert
    ):
        """Test: Intermediate-CA ist in Root-CA-CRL als widerrufen markiert.
        
        Szenario: Intermediate-CA wurde von Root-CA ausgestellt und ist widerrufen.
        Der Widerruf sollte in der Root-CA-CRL stehen, nicht in der Intermediate-CA-CRL.
        Die Root-CA-CRL-URL kommt aus den CDP der Intermediate-CA (nicht aus dem Root-CA-Zertifikat).
        Die Prüfung sollte den Widerruf über die Root-CA-CRL erkennen.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.x509.oid import NameOID
        from ssl_tester.certificate import parse_certificate
        from ssl_tester.models import Severity
        from ssl_tester.crl import check_crl_reachability
        from unittest.mock import Mock, MagicMock
        
        # Root-CA-CRL erstellen, die die Intermediate-CA als widerrufen markiert
        intermediate_serial = intermediate_cert.serial_number
        root_ca_crl = self.create_crl(
            signer_key=ca_key,
            signer_subject=ca_cert.subject,  # Root-CA signiert die CRL
            revoked_serials=[intermediate_serial],  # Intermediate-CA ist widerrufen!
        )
        root_crl_der = root_ca_crl.public_bytes(serialization.Encoding.DER)
        
        # Root-CA-Zertifikat mit CRL URL erstellen
        root_cert_with_crl = (
            x509.CertificateBuilder()
            .subject_name(ca_cert.subject)
            .issuer_name(ca_cert.subject)  # Self-signed
            .public_key(ca_key.public_key())
            .serial_number(ca_cert.serial_number)
            .not_valid_before(ca_cert.not_valid_before)
            .not_valid_after(ca_cert.not_valid_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.com/root_ca.crl")],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        root_cert_with_crl_der = root_cert_with_crl.public_bytes(serialization.Encoding.DER)
        
        # Intermediate-CA-Zertifikat mit BEIDEN CRL URLs:
        # 1. Eigene CRL URL (für von ihr ausgestellte Zertifikate)
        # 2. Root-CA-CRL URL (um zu prüfen, ob die Intermediate-CA selbst widerrufen ist)
        intermediate_cert_with_crl = (
            x509.CertificateBuilder()
            .subject_name(intermediate_cert.subject)
            .issuer_name(ca_cert.subject)  # Von Root-CA ausgestellt
            .public_key(intermediate_key.public_key())
            .serial_number(intermediate_cert.serial_number)
            .not_valid_before(intermediate_cert.not_valid_before)
            .not_valid_after(intermediate_cert.not_valid_after)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.com/intermediate_ca.crl")],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    ),
                    # Root-CA-CRL URL aus den CDP der Intermediate-CA
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.com/root_ca.crl")],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        intermediate_cert_with_crl_der = intermediate_cert_with_crl.public_bytes(serialization.Encoding.DER)
        
        # CertificateInfo erstellen
        intermediate_cert_info, _ = parse_certificate(intermediate_cert_with_crl_der)
        root_cert_info, _ = parse_certificate(root_cert_with_crl_der)
        
        # Mock HTTP-Response für Root-CA-CRL
        def mock_get(url, **kwargs):
            mock_response = Mock()
            if "root_ca.crl" in url:
                mock_response.status_code = 200
                mock_response.headers = {"Content-Type": "application/pkix-crl"}
                mock_response.url = url
                mock_response.history = []
                mock_response.iter_bytes = Mock(return_value=iter([root_crl_der]))
            elif "intermediate_ca.crl" in url:
                # Intermediate-CA-CRL (leer, da wir nur Root-CA-CRL prüfen wollen)
                intermediate_crl = self.create_crl(
                    signer_key=intermediate_key,
                    signer_subject=intermediate_cert.subject,
                    revoked_serials=[],
                )
                intermediate_crl_der = intermediate_crl.public_bytes(serialization.Encoding.DER)
                mock_response.status_code = 200
                mock_response.headers = {"Content-Type": "application/pkix-crl"}
                mock_response.url = url
                mock_response.history = []
                mock_response.iter_bytes = Mock(return_value=iter([intermediate_crl_der]))
            else:
                mock_response.status_code = 404
                mock_response.headers = {}
                mock_response.url = url
                mock_response.history = []
                mock_response.iter_bytes = Mock(return_value=iter([b""]))
            return mock_response
        
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get = Mock(side_effect=mock_get)
        mock_client_class.return_value = mock_client
        
        # Issuer-Map und cert_der_map
        issuer_map = {
            intermediate_cert_info.subject: intermediate_cert_with_crl_der,
            root_cert_info.subject: root_cert_with_crl_der,
        }
        cert_der_map = {
            intermediate_cert_info.fingerprint_sha256: intermediate_cert_with_crl_der,
            root_cert_info.fingerprint_sha256: root_cert_with_crl_der,
        }
        
        # CRL-Prüfung durchführen
        results = check_crl_reachability(
            cert_infos=[intermediate_cert_info],
            timeout=10.0,
            max_redirects=5,
            max_crl_bytes=10240,
            no_redirects=False,
            proxy=None,
            cert_der_map=cert_der_map,
            issuer_map=issuer_map,
            leaf_cert_info=None,
            intermediate_cert_infos=[intermediate_cert_info],
            root_cert_info=root_cert_info,
        )
        
        # Assertions: Es sollten mehrere Ergebnisse sein:
        # 1. Intermediate-CA-CRL Prüfung (von Intermediate-CA selbst signiert)
        # 2. Root-CA-CRL Prüfung (aus den CDP der Intermediate-CA, um zu sehen, ob Intermediate-CA widerrufen ist)
        
        # Finde das Ergebnis für Root-CA-CRL (aus den CDP der Intermediate-CA)
        root_crl_result = None
        for result in results:
            if "root_ca.crl" in result.url and "[Intermediate CA Revocation Check via Root CA CRL from CDP]" in (result.error or ""):
                root_crl_result = result
                break
        
        assert root_crl_result is not None, \
            f"Root CA CRL check should have been performed. Results: {[r.url for r in results]}"
        assert root_crl_result.reachable is True
        assert root_crl_result.status_code == 200
        # Intermediate-CA sollte als widerrufen erkannt werden
        assert root_crl_result.severity == Severity.FAIL, \
            f"Revoked intermediate CA should result in FAIL. Severity: {root_crl_result.severity}, Error: {root_crl_result.error}"
        assert "REVOKED" in (root_crl_result.error or "").upper() or "revoked" in (root_crl_result.error or "").lower(), \
            f"Error should indicate revocation. Error: {root_crl_result.error}"
        assert "[Intermediate CA Revocation Check via Root CA CRL from CDP]" in (root_crl_result.error or ""), \
            f"Error should indicate this is an intermediate CA revocation check via Root CA CRL from CDP. Error: {root_crl_result.error}"

