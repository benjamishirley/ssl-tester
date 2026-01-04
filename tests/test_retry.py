"""Tests for retry logic with exponential backoff."""

import pytest
import time
from unittest.mock import Mock, patch

from ssl_tester.retry import retry_with_backoff


def test_retry_success_on_first_attempt():
    """Test that function succeeds on first attempt without retry."""
    @retry_with_backoff(max_retries=3)
    def successful_function():
        return "success"

    result = successful_function()
    assert result == "success"


def test_retry_success_after_failures():
    """Test that function succeeds after some failures."""
    call_count = [0]

    @retry_with_backoff(max_retries=3, initial_delay=0.01)
    def flaky_function():
        call_count[0] += 1
        if call_count[0] < 2:
            raise ValueError("Temporary failure")
        return "success"

    result = flaky_function()
    assert result == "success"
    assert call_count[0] == 2


def test_retry_exhausts_all_attempts():
    """Test that function raises exception after all retries are exhausted."""
    call_count = [0]

    @retry_with_backoff(max_retries=2, initial_delay=0.01)
    def always_failing_function():
        call_count[0] += 1
        raise ValueError("Always fails")

    with pytest.raises(ValueError, match="Always fails"):
        always_failing_function()

    assert call_count[0] == 3  # Initial attempt + 2 retries


def test_retry_exponential_backoff():
    """Test that delay increases exponentially."""
    call_count = [0]
    delays = []

    original_sleep = time.sleep

    def mock_sleep(delay):
        delays.append(delay)
        original_sleep(0.001)  # Use minimal delay for testing

    @retry_with_backoff(max_retries=3, initial_delay=0.1, backoff_factor=2.0)
    def flaky_function():
        call_count[0] += 1
        if call_count[0] < 4:
            raise ValueError("Temporary failure")
        return "success"

    with patch('time.sleep', side_effect=mock_sleep):
        result = flaky_function()

    assert result == "success"
    assert len(delays) == 3  # 3 retries
    assert delays[0] == 0.1  # Initial delay
    assert delays[1] == 0.2  # 0.1 * 2
    assert delays[2] == 0.4  # 0.2 * 2


def test_retry_max_delay_limit():
    """Test that delay is capped at max_delay."""
    call_count = [0]
    delays = []

    original_sleep = time.sleep

    def mock_sleep(delay):
        delays.append(delay)
        original_sleep(0.001)

    @retry_with_backoff(max_retries=5, initial_delay=0.5, max_delay=1.0, backoff_factor=2.0)
    def flaky_function():
        call_count[0] += 1
        if call_count[0] < 6:
            raise ValueError("Temporary failure")
        return "success"

    with patch('time.sleep', side_effect=mock_sleep):
        result = flaky_function()

    assert result == "success"
    # Check that delays don't exceed max_delay
    assert all(delay <= 1.0 for delay in delays)
    # Check that at least one delay is at max_delay
    assert max(delays) == 1.0


def test_retry_specific_exception_types():
    """Test that retry only catches specified exception types."""
    call_count = [0]

    @retry_with_backoff(max_retries=2, initial_delay=0.01, exceptions=(ValueError,))
    def function_with_wrong_exception():
        call_count[0] += 1
        raise TypeError("Wrong exception type")

    with pytest.raises(TypeError, match="Wrong exception type"):
        function_with_wrong_exception()

    assert call_count[0] == 1  # No retries, exception not caught


def test_retry_multiple_exception_types():
    """Test that retry catches multiple exception types."""
    call_count = [0]

    @retry_with_backoff(max_retries=2, initial_delay=0.01, exceptions=(ValueError, KeyError))
    def function_with_multiple_exceptions():
        call_count[0] += 1
        if call_count[0] == 1:
            raise ValueError("First error")
        elif call_count[0] == 2:
            raise KeyError("Second error")
        return "success"

    result = function_with_multiple_exceptions()
    assert result == "success"
    assert call_count[0] == 3


def test_retry_preserves_function_metadata():
    """Test that decorator preserves function name and docstring."""
    @retry_with_backoff()
    def test_function():
        """Test docstring."""
        return "test"

    assert test_function.__name__ == "test_function"
    assert "Test docstring" in test_function.__doc__


def test_retry_with_arguments():
    """Test that retry works with function arguments."""
    @retry_with_backoff(max_retries=2, initial_delay=0.01)
    def function_with_args(a, b, c=None):
        if a == 1:
            raise ValueError("Retry needed")
        return a + b + (c or 0)

    result = function_with_args(2, 3, c=5)
    assert result == 10

    call_count = [0]

    @retry_with_backoff(max_retries=2, initial_delay=0.01)
    def flaky_with_args(x):
        call_count[0] += 1
        if call_count[0] < 2:
            raise ValueError("Retry")
        return x * 2

    result = flaky_with_args(5)
    assert result == 10
    assert call_count[0] == 2


