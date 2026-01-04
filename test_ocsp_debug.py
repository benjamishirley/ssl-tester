#!/usr/bin/env python3
"""Debug script to test OCSP responder directly."""

import sys
import base64
import logging
import httpx
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization, hashes

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_ocsp_direct(hostname: str):
    """Test OCSP directly with real certificate."""
    from ssl_tester.network import connect_tls
    from ssl_tester.certificate import parse_certificate
    
    # Get certificate from server using existing infrastructure
    print(f"Connecting to {hostname}:443...")
    leaf_cert_der, chain_certs_der = connect_tls(hostname, 443, timeout=10.0)
    
    # Get leaf certificate
    cert = x509.load_der_x509_certificate(leaf_cert_der)
    print(f"✓ Got certificate: {cert.subject}")
    
    # Find issuer certificate from chain
    issuer_cert = None
    issuer_cert_der = None
    
    for chain_cert_der in chain_certs_der:
        try:
            chain_cert = x509.load_der_x509_certificate(chain_cert_der)
            if chain_cert.subject == cert.issuer:
                issuer_cert = chain_cert
                issuer_cert_der = chain_cert_der
                print(f"✓ Found issuer certificate: {issuer_cert.subject}")
                break
        except Exception as e:
            logger.debug(f"Error parsing chain cert: {e}")
    
    if not issuer_cert:
        print("⚠ Could not find issuer certificate in chain, trying to fetch via AIA...")
        # Try to get issuer via AIA
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    issuer_url = access_desc.access_location.value
                    print(f"  Fetching issuer from: {issuer_url}")
                    client = httpx.Client(timeout=10.0, follow_redirects=True)
                    try:
                        issuer_resp = client.get(issuer_url)
                        issuer_cert = x509.load_der_x509_certificate(issuer_resp.content)
                        issuer_cert_der = issuer_resp.content
                        print(f"✓ Fetched issuer certificate: {issuer_cert.subject}")
                    finally:
                        client.close()
                    break
        except x509.ExtensionNotFound:
            print("⚠ No AIA extension found")
    
    if not issuer_cert:
        print("❌ Cannot proceed without issuer certificate")
        return
    
    # Get OCSP URL
    try:
        aia_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_url = None
        for access_desc in aia_ext.value:
            if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                ocsp_url = access_desc.access_location.value
                print(f"✓ Found OCSP URL: {ocsp_url}")
                break
    except x509.ExtensionNotFound:
        print("❌ No OCSP URL found in certificate")
        return
    
    if not ocsp_url:
        print("❌ No OCSP URL found")
        return
    
    # Build OCSP request
    print("\n" + "="*80)
    print("Building OCSP Request...")
    print("="*80)
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    request = builder.build()
    request_der = request.public_bytes(serialization.Encoding.DER)
    print(f"✓ OCSP request built: {len(request_der)} bytes")
    
    # Try POST first
    print("\n" + "="*80)
    print("Trying POST request...")
    print("="*80)
    client = httpx.Client(timeout=10.0, follow_redirects=False)
    try:
        post_response = client.post(
            ocsp_url,
            content=request_der,
            headers={
                "Content-Type": "application/ocsp-request",
                "User-Agent": "ssl-tester/0.1.0",
            },
        )
        
        print(f"HTTP Status: {post_response.status_code}")
        print(f"Response Length: {len(post_response.content)} bytes")
        print(f"Content-Type: {post_response.headers.get('Content-Type', 'N/A')}")
        
        if post_response.status_code == 200:
            try:
                ocsp_response = ocsp.load_der_ocsp_response(post_response.content)
                print(f"\n✓ OCSP Response parsed successfully")
                print(f"  Response Status: {ocsp_response.response_status}")
                
                if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                    print(f"  ✓ Response Status: SUCCESSFUL")
                    for single_response in ocsp_response.responses:
                        print(f"  Certificate Status: {single_response.certificate_status}")
                        if single_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                            print(f"  ✓ Certificate is GOOD")
                        elif single_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                            print(f"  ❌ Certificate is REVOKED")
                            if hasattr(single_response, 'revocation_time'):
                                print(f"    Revocation Time: {single_response.revocation_time}")
                        else:
                            print(f"  ⚠ Unknown status: {single_response.certificate_status}")
                        break
                elif ocsp_response.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED:
                    print(f"  ⚠ Response Status: UNAUTHORIZED")
                    print(f"  Raw response bytes: {post_response.content.hex()}")
                    print(f"  Raw response (repr): {repr(post_response.content)}")
                    
                    # Check if response is actually valid DER
                    print(f"\n  Analyzing response structure...")
                    print(f"  Response length: {len(post_response.content)} bytes")
                    
                    print("\nTrying GET fallback...")
                    
                    # Try GET
                    request_b64 = base64.urlsafe_b64encode(request_der).decode('ascii').rstrip('=')
                    get_url = f"{ocsp_url.rstrip('/')}/{request_b64}"
                    print(f"GET URL: {get_url[:100]}...")
                    
                    get_response = client.get(
                        get_url,
                        headers={
                            "User-Agent": "ssl-tester/0.1.0",
                        },
                    )
                    
                    print(f"\nGET Response:")
                    print(f"  HTTP Status: {get_response.status_code}")
                    print(f"  Response Length: {len(get_response.content)} bytes")
                    print(f"  Raw response bytes: {get_response.content.hex()}")
                    print(f"  Raw response (repr): {repr(get_response.content)}")
                    
                    if get_response.status_code == 200:
                        try:
                            ocsp_response_get = ocsp.load_der_ocsp_response(get_response.content)
                            print(f"  ✓ OCSP Response parsed successfully")
                            print(f"  Response Status: {ocsp_response_get.response_status}")
                            
                            if ocsp_response_get.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                                print(f"  ✓ Response Status: SUCCESSFUL")
                                for single_response in ocsp_response_get.responses:
                                    print(f"  Certificate Status: {single_response.certificate_status}")
                                    if single_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                                        print(f"  ✓ Certificate is GOOD")
                                    elif single_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                                        print(f"  ❌ Certificate is REVOKED")
                                        if hasattr(single_response, 'revocation_time'):
                                            print(f"    Revocation Time: {single_response.revocation_time}")
                                    break
                        except Exception as e:
                            print(f"  ❌ Error parsing GET response: {e}")
                            import traceback
                            traceback.print_exc()
                            
                            # Try to understand what we got
                            print(f"\n  Trying to understand the response...")
                            if len(get_response.content) == 5:
                                print(f"  Response is exactly 5 bytes - this might be an error code")
                                print(f"  Bytes: {get_response.content}")
                            
                            # The response is only 5 bytes - this is unusual
                            # Let's check what standard OCSP UNAUTHORIZED responses look like
                            print(f"\n  Note: OCSP UNAUTHORIZED responses are typically valid DER-encoded")
                            print(f"  responses with status UNAUTHORIZED. A 5-byte response is unusual.")
                            print(f"  This might indicate the server is rejecting our request format.")
                else:
                    print(f"  ⚠ Response Status: {ocsp_response.response_status}")
            except Exception as e:
                print(f"❌ Error parsing OCSP response: {e}")
                import traceback
                traceback.print_exc()
                print(f"\nRaw response (first 200 bytes):")
                print(post_response.content[:200])
        else:
            print(f"❌ POST failed with HTTP {post_response.status_code}")
    finally:
        client.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_ocsp_debug.py <hostname>")
        sys.exit(1)
    
    test_ocsp_direct(sys.argv[1])

