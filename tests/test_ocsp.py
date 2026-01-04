"""Tests for OCSP reachability checks."""

import pytest
from unittest.mock import Mock, MagicMock, patch
import httpx
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ssl_tester.ocsp import check_ocsp_reachability, _check_ocsp_with_request
from ssl_tester.models import CertificateInfo, Severity
from datetime import datetime, timedelta


@pytest.fixture
def cert_info_with_ocsp():
    """Create a certificate info with OCSP URLs."""
    return CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=["http://ocsp.example.com"],
        ca_issuers_urls=[],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )


@pytest.fixture
def mock_certificates():
    """Create mock certificates for OCSP testing."""
    # Generate a simple RSA key for testing
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Create a simple certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test.example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256())
    
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    # Use the same cert as issuer for simplicity
    issuer_cert_der = cert_der
    
    return cert_der, issuer_cert_der


@patch("ssl_tester.ocsp.create_http_client")
def test_check_ocsp_with_request_success(mock_create_client, mock_certificates):
    """Test successful OCSP check with proper request."""
    print("\n" + "="*80)
    print("TEST: OCSP-Prüfung (Erfolgreich)")
    print("="*80)
    
    cert_der, issuer_cert_der = mock_certificates
    from ssl_tester.certificate import parse_certificate
    cert_info, _ = parse_certificate(cert_der)
    print(f"✓ Zertifikat: Subject={cert_info.subject}, Serial={cert_info.serial_number}")
    print(f"✓ OCSP URL: http://ocsp.example.com")
    
    # Mock OCSP response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"mock_ocsp_response"
    
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mock_client.close = MagicMock()
    mock_create_client.return_value = mock_client
    
    # Mock OCSP response parsing
    with patch("ssl_tester.ocsp.ocsp.load_der_ocsp_response") as mock_load:
        mock_ocsp_response = Mock()
        mock_ocsp_response.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_single_response = Mock()
        mock_single_response.certificate_status = ocsp.OCSPCertStatus.GOOD
        mock_ocsp_response.responses = [mock_single_response]
        mock_load.return_value = mock_ocsp_response
        
        print("→ OCSP-Request durchführen...")
        result = _check_ocsp_with_request(cert_der, issuer_cert_der, "http://ocsp.example.com", 10.0)
        
        print(f"\n📊 Ergebnis:")
        print(f"  - Erreichbar: {result.reachable}")
        print(f"  - Status Code: {result.status_code}")
        print(f"  - Severity: {result.severity}")
        print(f"  - Error: {result.error or 'Keine Fehler'}")
        print(f"  - OCSP Status: GOOD")
        
        assert result.reachable is True
        assert result.status_code == 200
        assert result.severity == Severity.OK
        assert result.error is None
        print("\n✅ Test erfolgreich: OCSP-Prüfung war erfolgreich")
        print("="*80 + "\n")


@patch("ssl_tester.ocsp.create_http_client")
def test_check_ocsp_with_request_timeout(mock_create_client, mock_certificates):
    """Test OCSP check timeout."""
    print("\n" + "="*80)
    print("TEST: OCSP-Prüfung (Timeout)")
    print("="*80)
    
    cert_der, issuer_cert_der = mock_certificates
    from ssl_tester.certificate import parse_certificate
    cert_info, _ = parse_certificate(cert_der)
    print(f"✓ Zertifikat: Subject={cert_info.subject}")
    print(f"✓ OCSP URL: http://ocsp.example.com")
    print(f"✓ Timeout: 1.0s")
    
    mock_client = MagicMock()
    mock_client.post.side_effect = httpx.TimeoutException("Request timeout")
    mock_client.close = MagicMock()
    mock_create_client.return_value = mock_client
    
    print("→ OCSP-Request mit kurzem Timeout durchführen...")
    result = _check_ocsp_with_request(cert_der, issuer_cert_der, "http://ocsp.example.com", 1.0)
    
    print(f"\n📊 Ergebnis:")
    print(f"  - Erreichbar: {result.reachable}")
    print(f"  - Severity: {result.severity}")
    print(f"  - Error: {result.error or 'Keine Fehler'}")
    
    assert result.reachable is False
    assert result.severity == Severity.WARN
    assert "timeout" in result.error.lower()
    print("\n✅ Test erfolgreich: Timeout wurde korrekt erkannt")
    print("="*80 + "\n")


def test_check_ocsp_reachability(cert_info_with_ocsp, mock_certificates):
    """Test OCSP reachability check."""
    print("\n" + "="*80)
    print("TEST: OCSP-Erreichbarkeits-Prüfung")
    print("="*80)
    
    cert_der, issuer_cert_der = mock_certificates
    print(f"✓ Zertifikat-Info: Subject={cert_info_with_ocsp.subject}")
    print(f"✓ OCSP URLs: {cert_info_with_ocsp.ocsp_responder_urls}")
    
    with patch("ssl_tester.ocsp._check_ocsp_with_request") as mock_check:
        mock_check.return_value = Mock(
            url="http://ocsp.example.com",
            reachable=True,
            status_code=200,
            error=None,
            severity=Severity.OK,
        )

        print("→ OCSP-Erreichbarkeits-Prüfung durchführen...")
        results = check_ocsp_reachability(
            cert_info_with_ocsp,
            cert_der=cert_der,
            issuer_cert_der=issuer_cert_der,
        )

        print(f"\n📊 Ergebnis:")
        print(f"  - Anzahl Ergebnisse: {len(results)}")
        for i, result in enumerate(results, 1):
            print(f"  - Ergebnis {i}:")
            print(f"    - URL: {result.url}")
            print(f"    - Erreichbar: {result.reachable}")
            print(f"    - Status Code: {result.status_code}")
            print(f"    - Severity: {result.severity}")

        assert len(results) == 1
        mock_check.assert_called_once()
        print("\n✅ Test erfolgreich: OCSP-Erreichbarkeits-Prüfung abgeschlossen")
        print("="*80 + "\n")

