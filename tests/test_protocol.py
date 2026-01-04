"""Tests for protocol version checking."""

import pytest
from ssl_tester.protocol import (
    check_protocol_versions,
    PROTOCOL_TLS13,
    PROTOCOL_TLS12,
    PROTOCOL_TLS11,
    PROTOCOL_TLS10,
    PROTOCOL_SSL3,
    PROTOCOL_SSL2,
)
from ssl_tester.models import Severity


def test_check_protocol_versions_invalid_host():
    """Test protocol check with invalid host."""
    result = check_protocol_versions("invalid-host-that-does-not-exist-12345.com", 443, timeout=2.0)
    
    assert result is not None
    assert isinstance(result.supported_versions, list)
    # Should have no supported versions for invalid host
    assert len(result.supported_versions) == 0


def test_protocol_check_result_structure():
    """Test that protocol check result has correct structure."""
    result = check_protocol_versions("example.com", 443, timeout=5.0)
    
    assert hasattr(result, "supported_versions")
    assert hasattr(result, "best_version")
    assert hasattr(result, "deprecated_versions")
    assert hasattr(result, "ssl_versions")
    assert hasattr(result, "severity")
    
    assert isinstance(result.supported_versions, list)
    assert isinstance(result.deprecated_versions, list)
    assert isinstance(result.ssl_versions, list)
    assert result.severity in [Severity.OK, Severity.WARN, Severity.FAIL]


def test_protocol_priority():
    """Test protocol priority ordering."""
    from ssl_tester.protocol import PROTOCOL_PRIORITY
    
    # TLS 1.3 should have higher priority than TLS 1.2
    assert PROTOCOL_PRIORITY[PROTOCOL_TLS13] > PROTOCOL_PRIORITY[PROTOCOL_TLS12]
    # TLS 1.2 should have higher priority than TLS 1.1
    assert PROTOCOL_PRIORITY[PROTOCOL_TLS12] > PROTOCOL_PRIORITY[PROTOCOL_TLS11]
    # TLS 1.1 should have higher priority than TLS 1.0
    assert PROTOCOL_PRIORITY[PROTOCOL_TLS11] > PROTOCOL_PRIORITY[PROTOCOL_TLS10]
    # TLS 1.0 should have higher priority than SSL 3.0
    assert PROTOCOL_PRIORITY[PROTOCOL_TLS10] > PROTOCOL_PRIORITY[PROTOCOL_SSL3]
    # SSL 3.0 should have higher priority than SSL 2.0
    assert PROTOCOL_PRIORITY[PROTOCOL_SSL3] > PROTOCOL_PRIORITY[PROTOCOL_SSL2]

