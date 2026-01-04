#!/usr/bin/env python3
"""Test OCSP request structure."""

import sys
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization, hashes
from ssl_tester.network import connect_tls

def test_ocsp_request_structure(hostname: str):
    """Test different OCSP request structures."""
    leaf_cert_der, chain_certs_der = connect_tls(hostname, 443, timeout=10.0)
    cert = x509.load_der_x509_certificate(leaf_cert_der)
    
    # Find issuer
    issuer_cert = None
    for chain_cert_der in chain_certs_der:
        chain_cert = x509.load_der_x509_certificate(chain_cert_der)
        if chain_cert.subject == cert.issuer:
            issuer_cert = chain_cert
            break
    
    if not issuer_cert:
        print("❌ Cannot find issuer")
        return
    
    print("Testing different OCSP request structures...")
    
    # Method 1: Standard request (what we currently use)
    print("\n1. Standard request:")
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    request1 = builder.build()
    request1_der = request1.public_bytes(serialization.Encoding.DER)
    print(f"   Length: {len(request1_der)} bytes")
    print(f"   Hex (first 50): {request1_der[:50].hex()}")
    
    # Method 2: Try with SHA1 instead of SHA256
    print("\n2. Request with SHA1:")
    builder2 = ocsp.OCSPRequestBuilder()
    builder2 = builder2.add_certificate(cert, issuer_cert, hashes.SHA1())
    request2 = builder2.build()
    request2_der = request2.public_bytes(serialization.Encoding.DER)
    print(f"   Length: {len(request2_der)} bytes")
    print(f"   Hex (first 50): {request2_der[:50].hex()}")
    
    # Check request structure
    print("\n3. Analyzing request structure:")
    print(f"   Request extensions: {len(request1.extensions)}")
    for ext in request1.extensions:
        print(f"     Extension: {ext.oid}")
    
    print(f"\n   Request nonce: {request1.extensions.get_extension_for_oid(ocsp.OCSPNonce.oid) if request1.extensions.get_extension_for_oid(ocsp.OCSPNonce.oid) else 'None'}")
    
    # Check certificate serial numbers
    print(f"\n4. Certificate info:")
    print(f"   Cert serial: {cert.serial_number}")
    print(f"   Issuer serial: {issuer_cert.serial_number}")
    print(f"   Cert subject: {cert.subject}")
    print(f"   Cert issuer: {cert.issuer}")
    print(f"   Issuer subject: {issuer_cert.subject}")
    print(f"   Issuer issuer: {issuer_cert.issuer}")

if __name__ == "__main__":
    test_ocsp_request_structure(sys.argv[1] if len(sys.argv) > 1 else "owa.simplicity.ag")

