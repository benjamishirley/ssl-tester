"""Tests for cipher suite checking."""

import pytest
from ssl_tester.cipher import (
    check_cipher_suites,
    _is_weak_cipher,
    _supports_pfs,
    _get_cipher_strength,
)
from ssl_tester.models import Severity


def test_is_weak_cipher():
    """Test weak cipher detection."""
    assert _is_weak_cipher("RC4-SHA")
    assert _is_weak_cipher("DES-CBC-SHA")
    assert _is_weak_cipher("3DES-CBC-SHA")
    assert _is_weak_cipher("EXPORT-RC4-MD5")
    assert _is_weak_cipher("NULL-SHA")
    assert _is_weak_cipher("ANON-DH")
    
    assert not _is_weak_cipher("AES256-GCM-SHA384")
    assert not _is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384")


def test_supports_pfs():
    """Test PFS detection."""
    assert _supports_pfs("ECDHE-RSA-AES256-GCM-SHA384")
    assert _supports_pfs("DHE-RSA-AES256-GCM-SHA384")
    assert _supports_pfs("ECDHE-ECDSA-AES256-GCM-SHA384")
    
    assert not _supports_pfs("RSA-AES256-GCM-SHA384")
    assert not _supports_pfs("AES256-GCM-SHA384")


def test_get_cipher_strength():
    """Test cipher strength classification."""
    from ssl_tester.cipher import (
        CIPHER_STRENGTH_NULL,
        CIPHER_STRENGTH_WEAK,
        CIPHER_STRENGTH_MEDIUM,
        CIPHER_STRENGTH_STRONG,
    )
    
    assert _get_cipher_strength("NULL-SHA") == CIPHER_STRENGTH_NULL
    assert _get_cipher_strength("ANON-DH") == CIPHER_STRENGTH_NULL
    assert _get_cipher_strength("RC4-SHA") == CIPHER_STRENGTH_WEAK
    assert _get_cipher_strength("DES-CBC-SHA") == CIPHER_STRENGTH_WEAK
    # Note: 3DES is classified as WEAK due to Sweet32 vulnerability
    assert _get_cipher_strength("3DES-CBC-SHA") == CIPHER_STRENGTH_WEAK
    assert _get_cipher_strength("AES256-GCM-SHA384") == CIPHER_STRENGTH_STRONG


def test_check_cipher_suites_invalid_host():
    """Test cipher check with invalid host."""
    result = check_cipher_suites("invalid-host-that-does-not-exist-12345.com", 443, timeout=2.0)
    
    assert result is not None
    assert isinstance(result.supported_ciphers, list)
    assert isinstance(result.weak_ciphers, list)
    assert isinstance(result.pfs_supported, bool)
    assert isinstance(result.server_preferences, bool)
    assert result.severity in [Severity.OK, Severity.WARN, Severity.FAIL]


def test_cipher_check_result_structure():
    """Test that cipher check result has correct structure."""
    result = check_cipher_suites("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "supported_ciphers")
    assert hasattr(result, "weak_ciphers")
    assert hasattr(result, "pfs_supported")
    assert hasattr(result, "server_preferences")
    assert hasattr(result, "severity")
    
    assert isinstance(result.supported_ciphers, list)
    assert isinstance(result.weak_ciphers, list)
    assert isinstance(result.pfs_supported, bool)
    assert isinstance(result.server_preferences, bool)
    assert result.severity in [Severity.OK, Severity.WARN, Severity.FAIL]

