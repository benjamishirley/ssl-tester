"""Tests for service detection."""

import pytest
from ssl_tester.services import (
    detect_service,
    get_service_info,
    is_starttls_port,
    is_direct_tls_port,
    get_default_port,
)


def test_detect_service_https():
    """Test HTTPS service detection."""
    assert detect_service(443) == "HTTPS"
    assert detect_service(8443) is None  # Custom HTTPS port


def test_detect_service_smtp():
    """Test SMTP service detection."""
    assert detect_service(25) == "SMTP"
    assert detect_service(465) == "SMTP"
    assert detect_service(587) == "SMTP"


def test_detect_service_imap():
    """Test IMAP service detection."""
    assert detect_service(143) == "IMAP"
    assert detect_service(993) == "IMAP"


def test_detect_service_pop3():
    """Test POP3 service detection."""
    assert detect_service(110) == "POP3"
    assert detect_service(995) == "POP3"


def test_detect_service_ldap():
    """Test LDAP service detection."""
    assert detect_service(389) == "LDAP"
    assert detect_service(636) == "LDAP"


def test_get_service_info():
    """Test getting service information."""
    info = get_service_info("HTTPS")
    assert info is not None
    name, default_ports, starttls_ports, direct_tls_ports = info
    assert name == "HTTPS"
    assert 443 in default_ports
    
    info = get_service_info("SMTP")
    assert info is not None
    name, default_ports, starttls_ports, direct_tls_ports = info
    assert name == "SMTP"
    assert 25 in default_ports or 25 in starttls_ports


def test_is_starttls_port():
    """Test STARTTLS port detection."""
    assert is_starttls_port(25, "SMTP")
    assert is_starttls_port(587, "SMTP")
    assert is_starttls_port(143, "IMAP")
    assert not is_starttls_port(465, "SMTP")  # Direct TLS
    assert not is_starttls_port(443, "HTTPS")  # Direct TLS


def test_is_direct_tls_port():
    """Test direct TLS port detection."""
    assert is_direct_tls_port(443, "HTTPS")
    assert is_direct_tls_port(465, "SMTP")
    assert is_direct_tls_port(993, "IMAP")
    assert is_direct_tls_port(995, "POP3")
    assert not is_direct_tls_port(25, "SMTP")  # STARTTLS


def test_get_default_port():
    """Test getting default port for service."""
    assert get_default_port("HTTPS") == 443
    assert get_default_port("SMTP") == 25
    assert get_default_port("IMAP") == 143
    assert get_default_port("POP3") == 110
    assert get_default_port("LDAP") == 389
    
    assert get_default_port("UNKNOWN") is None

