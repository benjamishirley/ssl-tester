# Comprehensive Mock Tests for Certificates and CRLs

This documentation describes how to run the comprehensive mock tests for certificates and CRLs.

## Overview

The test class `TestComprehensiveCertificateAndCRLValidation` contains tests that create real certificates and CRLs (using the `cryptography` library) and perform real validations, while only HTTP requests are mocked.

## Test Scenarios

1. **test_valid_certificate_with_valid_crl** - Valid certificate with valid CRL
2. **test_revoked_certificate_in_crl** - Revoked certificates
3. **test_crl_with_invalid_signature** - CRL with invalid signature
4. **test_expired_crl** - Expired CRL
5. **test_expired_certificate** - Expired certificates
6. **test_certificate_not_yet_valid** - Certificate not yet valid
7. **test_certificate_hostname_mismatch** - Hostname mismatch
8. **test_certificate_hostname_match** - Hostname match
9. **test_crl_with_wrong_issuer** - CRL with wrong issuer
10. **test_multiple_revoked_certificates_in_crl** - Multiple revoked certificates

## Test Execution

### Run All Tests

```bash
# All comprehensive tests
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -v -s

# With markers
pytest -m comprehensive -v -s
pytest -m mock_cert -v -s
```

### Run Individual Tests

```bash
# Single test
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_valid_certificate_with_valid_crl -v -s

# Revoked certificates
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_revoked_certificate_in_crl -v -s

# Invalid signature
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_crl_with_invalid_signature -v -s

# Expired certificates
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_expired_certificate -v -s

# Hostname tests
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_certificate_hostname_match -v -s
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation::test_certificate_hostname_mismatch -v -s
```

### Detailed Output

The options `-v` (verbose) and `-s` (no capture) show detailed output:

- `-v` or `--verbose`: Shows each test with details
- `-s` or `--capture=no`: Shows print statements during tests
- `-vv`: Even more detailed output

```bash
# Maximum details
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -vv -s

# With coverage
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -v -s --cov=src/ssl_tester/crl --cov=src/ssl_tester/certificate
```

### Filter Tests by Marker

```bash
# Only comprehensive tests
pytest -m comprehensive -v -s

# Only mock_cert tests
pytest -m mock_cert -v -s

# Exclude tests
pytest -m "not comprehensive" -v
```

## Example Output

When using `-v -s`, you'll see detailed information:

```
================================================================================
TEST: Valid certificate with valid CRL (not revoked)
================================================================================
✓ Leaf certificate created: Serial=123456789, Hostname=example.com
✓ CRL created: Issuer=CN=Test Intermediate CA, Revoked=0
✓ Certificate parsed: Subject=CN=example.com, Issuer=CN=Test Intermediate CA

📊 CRL check result:
  - Reachable: True
  - Status Code: 200
  - Severity: OK
  - Error: No errors
  - Size: 1234 bytes

✅ Test successful: Certificate is valid and not revoked
================================================================================
```

## Additional Options

```bash
# Only rerun failed tests
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation --lf -v -s

# Stop tests at first error
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -x -v -s

# With HTML report
pytest tests/test_crl.py::TestComprehensiveCertificateAndCRLValidation -v -s --html=report.html
```
