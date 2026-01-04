"""Tests for AIA intermediate fetching."""

import pytest
from unittest.mock import Mock, MagicMock, patch
import httpx
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from ssl_tester.chain import fetch_intermediates_via_aia
from ssl_tester.models import CertificateInfo


@pytest.fixture
def leaf_cert_info_with_aia():
    """Create a leaf certificate info with AIA CA Issuers URLs."""
    return CertificateInfo(
        subject="CN=example.com",
        issuer="CN=Intermediate CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=["http://ca.example.com/intermediate.crt"],
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )


@pytest.fixture
def intermediate_cert_der():
    """Create a sample intermediate certificate in DER format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])

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


@patch("ssl_tester.chain.httpx.Client")
def test_fetch_intermediates_via_aia_success_der(mock_client_class, leaf_cert_info_with_aia, intermediate_cert_der):
    """Test successful AIA fetching with DER format."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = intermediate_cert_der

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client

    result = fetch_intermediates_via_aia(leaf_cert_info_with_aia, timeout=10.0)

    assert len(result) == 1
    assert result[0] == intermediate_cert_der
    mock_client.get.assert_called_once()


@patch("ssl_tester.chain.httpx.Client")
def test_fetch_intermediates_via_aia_success_pem(mock_client_class, leaf_cert_info_with_aia, intermediate_cert_der):
    """Test successful AIA fetching with PEM format."""
    # Convert DER to PEM
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(intermediate_cert_der)
    pem_content = cert.public_bytes(serialization.Encoding.PEM)

    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = pem_content

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client

    result = fetch_intermediates_via_aia(leaf_cert_info_with_aia, timeout=10.0)

    assert len(result) == 1
    # Should be converted to DER
    assert len(result[0]) > 0


@patch("ssl_tester.chain.httpx.Client")
def test_fetch_intermediates_via_aia_timeout(mock_client_class, leaf_cert_info_with_aia):
    """Test AIA fetching with timeout."""
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.side_effect = httpx.TimeoutException("Request timeout")
    mock_client_class.return_value = mock_client

    result = fetch_intermediates_via_aia(leaf_cert_info_with_aia, timeout=1.0)

    assert len(result) == 0


@patch("ssl_tester.chain.httpx.Client")
def test_fetch_intermediates_via_aia_http_error(mock_client_class, leaf_cert_info_with_aia):
    """Test AIA fetching with HTTP error."""
    mock_response = Mock()
    mock_response.status_code = 404

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=None)
    mock_client.get.return_value = mock_response
    mock_client_class.return_value = mock_client

    result = fetch_intermediates_via_aia(leaf_cert_info_with_aia, timeout=10.0)

    assert len(result) == 0


def test_fetch_intermediates_via_aia_no_urls():
    """Test AIA fetching when no URLs are available."""
    cert_info = CertificateInfo(
        subject="CN=example.com",
        issuer="CN=CA",
        serial_number="123",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        san_dns_names=["example.com"],
        san_ip_addresses=[],
        crl_distribution_points=[],
        ocsp_responder_urls=[],
        ca_issuers_urls=[],  # No URLs
        signature_algorithm="sha256",
        public_key_algorithm="RSA",
        fingerprint_sha256="abc123",
    )

    result = fetch_intermediates_via_aia(cert_info, timeout=10.0)

    assert len(result) == 0



