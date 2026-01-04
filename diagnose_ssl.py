#!/usr/bin/env python3
"""Diagnose-Skript für getpeercert_chain() Verfügbarkeit."""

import ssl
import socket
import sys

print("=" * 60)
print("Python SSL Backend Diagnose")
print("=" * 60)
print(f"Python Version: {sys.version}")
print(f"Python Executable: {sys.executable}")
print(f"SSL Module Location: {ssl.__file__}")
print(f"OpenSSL Version: {ssl.OPENSSL_VERSION}")
print(f"OpenSSL Version Number: {ssl.OPENSSL_VERSION_NUMBER}")
if hasattr(ssl, 'OPENSSL_VERSION_INFO'):
    print(f"SSL Version Info: {ssl.OPENSSL_VERSION_INFO}")

print("\n" + "=" * 60)
print("SSLSocket Methoden Check")
print("=" * 60)

# Prüfe SSLSocket Klasse
print(f"SSLSocket Klasse: {ssl.SSLSocket}")
print(f"hasattr(ssl.SSLSocket, 'getpeercert_chain'): {hasattr(ssl.SSLSocket, 'getpeercert_chain')}")

# Prüfe alle Methoden
ssl_methods = [m for m in dir(ssl.SSLSocket) if not m.startswith('_')]
peer_methods = [m for m in ssl_methods if 'peer' in m.lower()]
print(f"\nAlle 'peer'-Methoden: {peer_methods}")

# Prüfe ob getpeercert_chain in der Klasse existiert
if hasattr(ssl.SSLSocket, 'getpeercert_chain'):
    try:
        method = getattr(ssl.SSLSocket, 'getpeercert_chain')
        print(f"\ngetpeercert_chain Methode gefunden: {method}")
        print(f"Method Type: {type(method)}")
        # Versuche die Dokumentation zu lesen
        try:
            help_text = help(ssl.SSLSocket.getpeercert_chain)
            print("Dokumentation verfügbar")
        except:
            pass
    except Exception as e:
        print(f"\nFehler beim Zugriff auf getpeercert_chain: {e}")

# Versuche eine echte Verbindung
print("\n" + "=" * 60)
print("Live Connection Test")
print("=" * 60)

try:
    host = 'ntsh024.opus.local'
    port = 443
    
    sock = socket.socket()
    sock.settimeout(10)
    sock.connect((host, port))
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    ssl_sock = ctx.wrap_socket(sock, server_hostname=host)
    ssl_sock.do_handshake()
    
    print(f"✓ Verbindung zu {host}:{port} erfolgreich")
    print(f"SSL Socket Type: {type(ssl_sock)}")
    print(f"SSL Socket Class: {ssl_sock.__class__}")
    print(f"SSL Socket MRO: {ssl_sock.__class__.__mro__}")
    
    print(f"\nhasattr(ssl_sock, 'getpeercert_chain'): {hasattr(ssl_sock, 'getpeercert_chain')}")
    
    # Prüfe ob es in __dict__ ist
    print(f"In __dict__: {'getpeercert_chain' in ssl_sock.__dict__}")
    
    # Prüfe ob es in dir() ist
    all_attrs = dir(ssl_sock)
    print(f"In dir(): {'getpeercert_chain' in all_attrs}")
    
    # Versuche getattr
    try:
        method = getattr(ssl_sock, 'getpeercert_chain', None)
        print(f"getattr() result: {method}")
        if method:
            print(f"Method type: {type(method)}")
            print(f"Callable: {callable(method)}")
    except Exception as e:
        print(f"getattr() error: {e}")
    
    # Prüfe getpeercert (sollte verfügbar sein)
    print(f"\nhasattr(ssl_sock, 'getpeercert'): {hasattr(ssl_sock, 'getpeercert')}")
    if hasattr(ssl_sock, 'getpeercert'):
        try:
            cert = ssl_sock.getpeercert(binary_form=True)
            print(f"getpeercert() works: {len(cert)} bytes")
        except Exception as e:
            print(f"getpeercert() error: {e}")
    
    # Prüfe die SSL-Version
    print(f"\nSSL Protocol: {ssl_sock.version()}")
    print(f"Cipher: {ssl_sock.cipher()}")
    
    ssl_sock.close()
    sock.close()
    
except Exception as e:
    print(f"✗ Fehler: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("Fazit")
print("=" * 60)
if hasattr(ssl.SSLSocket, 'getpeercert_chain'):
    print("✓ getpeercert_chain() ist in der SSLSocket-Klasse definiert")
    print("  → Die Methode sollte verfügbar sein, aber möglicherweise")
    print("    funktioniert sie nur unter bestimmten Bedingungen")
else:
    print("✗ getpeercert_chain() ist NICHT in der SSLSocket-Klasse definiert")
    print("  → Python wurde wahrscheinlich mit einem SSL-Backend kompiliert,")
    print("    das diese Methode nicht unterstützt")
    print("  → Dies ist bei manchen Python-Builds auf macOS der Fall")


