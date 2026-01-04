# Reporting Rules

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


