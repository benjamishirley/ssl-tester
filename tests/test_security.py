"""Tests for security best practices checking."""

import pytest
from ssl_tester.security import (
    check_security_best_practices,
    check_hsts,
    check_ocsp_stapling,
    check_tls_compression,
    check_session_resumption,
)
from ssl_tester.models import Severity


def test_check_hsts_structure():
    """Test HSTS check result structure."""
    result = check_hsts("example.com", timeout=5.0)
    
    assert hasattr(result, "hsts_enabled")
    assert hasattr(result, "hsts_max_age")
    assert hasattr(result, "severity")
    assert isinstance(result.hsts_enabled, bool)
    assert result.hsts_max_age is None or isinstance(result.hsts_max_age, int)
    assert result.severity in [Severity.OK, Severity.WARN]


def test_check_ocsp_stapling_structure():
    """Test OCSP Stapling check result structure."""
    result = check_ocsp_stapling("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "ocsp_stapling_enabled")
    assert hasattr(result, "severity")
    assert isinstance(result.ocsp_stapling_enabled, bool)
    assert result.severity in [Severity.OK, Severity.WARN]


def test_check_tls_compression_structure():
    """Test TLS Compression check result structure."""
    result = check_tls_compression("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "tls_compression_enabled")
    assert hasattr(result, "severity")
    assert isinstance(result.tls_compression_enabled, bool)
    assert result.severity in [Severity.OK, Severity.FAIL]


def test_check_session_resumption_structure():
    """Test Session Resumption check result structure."""
    result = check_session_resumption("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "session_resumption_enabled")
    assert hasattr(result, "severity")
    assert isinstance(result.session_resumption_enabled, bool)
    assert result.severity in [Severity.OK]


def test_check_security_best_practices_structure():
    """Test security best practices check result structure."""
    result = check_security_best_practices("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "hsts_enabled")
    assert hasattr(result, "hsts_max_age")
    assert hasattr(result, "ocsp_stapling_enabled")
    assert hasattr(result, "tls_compression_enabled")
    assert hasattr(result, "session_resumption_enabled")
    assert hasattr(result, "severity")
    
    assert isinstance(result.hsts_enabled, bool)
    assert result.hsts_max_age is None or isinstance(result.hsts_max_age, int)
    assert isinstance(result.ocsp_stapling_enabled, bool)
    assert isinstance(result.tls_compression_enabled, bool)
    assert isinstance(result.session_resumption_enabled, bool)
    assert result.severity in [Severity.OK, Severity.WARN, Severity.FAIL]

