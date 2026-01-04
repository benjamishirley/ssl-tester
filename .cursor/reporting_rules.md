# Reporting Rules für SSL/TLS Certificate Inspection Tool

## Root Cause Visibility Rule

**RULE: All problems (WARN/FAIL) must be visible in the Summary with their Root Cause (root cause).**

### Requirements:

1. **Summary must always contain the Root Cause:**
   - For CRL problems: The specific error message (e.g., "CRL signature verification failed", "CRL issuer mismatch")
   - For Chain problems: The specific error (e.g., "Missing intermediate certificates", "Chain validation failed")
   - For OCSP problems: The specific error message
   - For Hostname problems: The specific reason
   - For Validity problems: The specific reason (e.g., "Certificate expired", "Certificate not yet valid")

2. **No generic messages without context:**
   - ❌ Wrong: "1 CRL(s) not reachable" (without Root Cause)
   - ✅ Correct: "CRL issue (http://crl.example.com/crl.crl): CRL signature verification failed: invalid signature"

3. **All Severity levels must be considered:**
   - WARN: Must appear in Summary with Root Cause
   - FAIL: Must appear in Summary with Root Cause
   - OK: Only appears if everything is OK

4. **Prefer specific error messages:**
   - If `error` field is present, it must be used in the Summary
   - If no `error` field is present, a meaningful description must be generated

### Implementation:

The `generate_summary()` function in `reporter.py` must:
- Go through all checks with WARN/FAIL
- Extract the Root Cause for each check
- Include the Root Cause in human-readable form in the Summary
- Not use generic messages without context

### Examples:

**Good:**
```
Summary:
  Overall Status: WARN ⚠
  CRL issue (http://crl.example.com/crl.crl): CRL signature verification failed: invalid signature; Certificate expires in 30 days
```

**Bad:**
```
Summary:
  Overall Status: WARN ⚠
  1 CRL(s) not reachable; Certificate expires in 30 days
```

---

## Cross-Signed Certificate Reporting Rules

**RULE: Cross-signed certificates must be reported clearly and informatively, without causing alarm.**

### Requirements:

1. **Status and Severity:**
   - Cross-signed certificates must be reported with `Severity.OK` (INFO level)
   - They must NOT be treated as errors or warnings
   - They must NOT downgrade the security rating

2. **Report Structure:**
   - Include a dedicated section titled "Cross-Signing Resolution"
   - Provide a clear explanation that both variants represent the same CA identity
   - Show a comparison table with:
     - Subject
     - Issuer
     - Serial Number
     - Role (Cross-signed / Trust Anchor)

3. **Information to Include:**
   - Which variant was provided by the server (issuer, serial number)
   - Which variant was selected from the trust store (issuer, serial number)
   - Why the replacement happened:
     - The trust store already contains a self-signed root for this CA
     - Browsers and TLS clients always prefer a trust anchor over a cross-signed path
   - Clear statement that this is normal, RFC-compliant (RFC 4158 path building), and not a security issue

4. **Language Guidelines:**
   - Use precise, neutral technical wording suitable for security engineers
   - Do not use alarming language
   - Emphasize that this is informational
   - Explain that both certificates are cryptographically equivalent

### Implementation:

The reporting must be implemented in:
- `generate_text_report()` in `reporter.py` - Text output
- `_generate_cross_signed_section()` in `reporter_html.py` - HTML output
- Both must follow the same structure and include all required information

### Example Structure:

```
Cross-Signing Resolution:

  Overview:
    The detected certificate represents the same CA identity (same Subject and public key),
    but exists in multiple signed variants (cross-signed vs. self-signed).

  Certificate Comparison:
    [Table showing Subject, Issuer, Serial Number, Role for both variants]

  Details:
    • Server provided variant: Issuer=..., Serial=...
    • Trust store variant: Issuer=..., Serial=...
    • Actual signer of cross-signed variant: ...

  Resolution:
    The cross-signed certificate was replaced by the self-signed trust anchor because:
    1. The trust store already contains a self-signed root for this CA
    2. Browsers and TLS clients always prefer a trust anchor over a cross-signed path

  Status: INFO ℹ️
    This behavior is normal, RFC-compliant (RFC 4158 path building), and not a security issue.
    Both certificates represent the same CA identity and are cryptographically equivalent.
```

### Notes:

- Cross-signed certificates are a normal part of PKI infrastructure
- They allow CAs to maintain compatibility across different trust stores
- The replacement behavior matches standard browser/TLS client behavior
- This should never trigger security concerns or rating downgrades

