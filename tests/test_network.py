"""Tests for network operations."""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock

from ssl_tester.network import connect_tls, _extract_chain_via_openssl


@patch("ssl_tester.network.socket.socket")
@patch("ssl_tester.network.ssl.create_default_context")
def test_connect_tls_success(mock_ssl_context, mock_socket_class):
    """Test successful TLS connection."""
    # Mock socket
    mock_sock = Mock()
    mock_socket_class.return_value = mock_sock

    # Mock SSL context and socket
    mock_context = Mock()
    mock_ssl_context.return_value = mock_context
    mock_ssl_sock = Mock()
    mock_context.wrap_socket.return_value = mock_ssl_sock

    # Mock certificate data
    leaf_cert = b"fake_leaf_cert"
    chain_certs = [b"fake_intermediate_cert"]
    mock_ssl_sock.getpeercert.return_value = leaf_cert
    mock_ssl_sock.getpeercert_chain.return_value = chain_certs

    # Mock getaddrinfo
    with patch("ssl_tester.network.socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]

        result_leaf, result_chain = connect_tls("example.com", 443, timeout=10.0)

        assert result_leaf == leaf_cert
        assert result_chain == chain_certs
        mock_sock.connect.assert_called_once()
        mock_ssl_sock.do_handshake.assert_called_once()


@patch("ssl_tester.network.socket.socket")
def test_connect_tls_timeout(mock_socket_class):
    """Test TLS connection timeout."""
    mock_sock = Mock()
    mock_socket_class.return_value = mock_sock
    mock_sock.connect.side_effect = socket.timeout("Connection timeout")

    with patch("ssl_tester.network.socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 443))]

        with pytest.raises(ConnectionError, match="Connection timeout"):
            connect_tls("example.com", 443, timeout=1.0)


@patch("ssl_tester.network.socket.getaddrinfo")
def test_connect_tls_dns_failure(mock_getaddrinfo):
    """Test DNS resolution failure."""
    mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")

    with pytest.raises(ConnectionError, match="DNS resolution failed"):
        connect_tls("nonexistent.example.com", 443)


@patch("ssl_tester.network.subprocess.run")
@patch("ssl_tester.network._load_cert_with_cache")
def test_extract_chain_via_openssl_success(mock_load, mock_subprocess):
    """Test successful chain extraction via OpenSSL."""
    # Mock OpenSSL output with PEM certificates
    mock_output = b"""-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
-----END CERTIFICATE-----
"""
    mock_result = Mock()
    mock_result.stdout = mock_output
    mock_result.returncode = 0
    mock_subprocess.return_value = mock_result

    # Mock certificate parsing
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta

    # Create a mock certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
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
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    # Mock _load_cert_with_cache to return the cert
    mock_load.return_value = (cert, None)

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    # Should return one intermediate (first cert is leaf, removed)
    assert len(result) == 1
    mock_subprocess.assert_called_once()


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_timeout(mock_subprocess):
    """Test OpenSSL extraction timeout."""
    import subprocess
    mock_subprocess.side_effect = subprocess.TimeoutExpired("openssl", 10.0)

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_not_found(mock_subprocess):
    """Test when OpenSSL command is not found."""
    mock_subprocess.side_effect = FileNotFoundError("openssl: command not found")

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_no_output(mock_subprocess):
    """Test when OpenSSL produces no output."""
    mock_result = Mock()
    mock_result.stdout = b""
    mock_result.returncode = 1
    mock_subprocess.return_value = mock_result

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_success(mock_subprocess):
    """Test successful chain extraction via OpenSSL."""
    # Mock OpenSSL output with PEM certificates
    mock_output = b"""-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
-----END CERTIFICATE-----
"""
    mock_result = Mock()
    mock_result.stdout = mock_output
    mock_result.returncode = 0
    mock_subprocess.return_value = mock_result

    # Mock certificate parsing
    with patch("ssl_tester.certificate._load_cert_with_cache") as mock_load:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta

        # Create a mock certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
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
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Mock _load_cert_with_cache to return the cert
        mock_load.return_value = (cert, None)

        result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

        # Should return one intermediate (first cert is leaf, removed)
        assert len(result) == 1
        mock_subprocess.assert_called_once()


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_timeout(mock_subprocess):
    """Test OpenSSL extraction timeout."""
    import subprocess
    mock_subprocess.side_effect = subprocess.TimeoutExpired("openssl", 10.0)

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_not_found(mock_subprocess):
    """Test when OpenSSL command is not found."""
    mock_subprocess.side_effect = FileNotFoundError("openssl: command not found")

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_no_output(mock_subprocess):
    """Test when OpenSSL produces no output."""
    mock_result = Mock()
    mock_result.stdout = b""
    mock_result.returncode = 1
    mock_subprocess.return_value = mock_result

    result = _extract_chain_via_openssl("example.com", 443, timeout=10.0)

    assert result == []


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_with_servername(mock_subprocess):
    """Test that servername is used when not ignoring hostname."""
    mock_result = Mock()
    mock_result.stdout = b""
    mock_result.returncode = 0
    mock_subprocess.return_value = mock_result

    _extract_chain_via_openssl("example.com", 443, timeout=10.0, ignore_hostname=False)

    # Check that servername was included in command
    call_args = mock_subprocess.call_args[0][0]
    assert "-servername" in call_args
    assert "example.com" in call_args


@patch("ssl_tester.network.subprocess.run")
def test_extract_chain_via_openssl_without_servername(mock_subprocess):
    """Test that servername is not used when ignoring hostname."""
    mock_result = Mock()
    mock_result.stdout = b""
    mock_result.returncode = 0
    mock_subprocess.return_value = mock_result

    _extract_chain_via_openssl("example.com", 443, timeout=10.0, ignore_hostname=True)

    # Check that servername was NOT included in command
    call_args = mock_subprocess.call_args[0][0]
    assert "-servername" not in call_args


