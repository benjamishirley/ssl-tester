# Analyse: Warum getpeercert_chain() nicht verfügbar ist

## Problem
`getpeercert_chain()` ist in Python 3.11.9 nicht verfügbar, obwohl es ab Python 3.10 verfügbar sein sollte.

## Diagnose-Ergebnisse

### System-Informationen
- **Python Version**: 3.11.9
- **Python Installation**: pyenv (`/Users/b.shirley/.pyenv/versions/3.11.9/`)
- **OpenSSL Version (Runtime)**: OpenSSL 3.6.0 1 Oct 2025
- **SSL Module**: `/Users/b.shirley/.pyenv/versions/3.11.9/lib/python3.11/ssl.py`
- **_ssl C-Modul**: `/Users/b.shirley/.pyenv/versions/3.11.9/lib/python3.11/lib-dynload/_ssl.cpython-311-darwin.so`

### Befunde
1. ✅ `getpeercert()` ist verfügbar
2. ❌ `getpeercert_chain()` ist NICHT verfügbar
3. ❌ `_ssl` Modul hat `getpeercert_chain()` nicht
4. ✅ Python-Version ist >= 3.10 (sollte also verfügbar sein)

### Root Cause
**Das `_ssl` C-Modul wurde ohne `getpeercert_chain()` kompiliert.**

Die Funktion wurde zwar in Python 3.10 eingeführt, aber sie ist nur verfügbar, wenn:
- OpenSSL 1.1.1+ beim **Kompilieren** verfügbar war
- Die Build-Konfiguration die Funktion aktiviert hat
- Die richtigen Build-Flags gesetzt waren

## Warum ist das passiert?

### Mögliche Ursachen:
1. **OpenSSL-Version beim Kompilieren**: 
   - Zur Zeit der Python-Kompilierung war möglicherweise eine ältere OpenSSL-Version aktiv
   - Aktuell ist OpenSSL 3.6.0 verfügbar, aber das hilft nicht, da Python bereits kompiliert ist

2. **pyenv Build-Konfiguration**:
   - pyenv könnte beim Build eine andere OpenSSL-Version verwendet haben
   - Die Build-Flags könnten die Funktion nicht aktiviert haben

3. **Build-Prozess**:
   - Python wurde möglicherweise mit `--without-ssl` oder ähnlichen Optionen kompiliert
   - Oder die OpenSSL-Entwicklungsbibliotheken fehlten beim Build

## Lösungen

### Option 1: Python mit korrekter OpenSSL-Version neu kompilieren (Empfohlen)

```bash
# 1. OpenSSL-Version prüfen
brew info openssl@3

# 2. Python mit pyenv neu installieren
# Stelle sicher, dass OpenSSL 3 beim Build gefunden wird
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"
pyenv install 3.11.9 --force

# Oder eine neuere Version installieren
pyenv install 3.12.0
```

### Option 2: Python von python.org verwenden
Die offiziellen Python-Builds von python.org sollten `getpeercert_chain()` enthalten.

### Option 3: OpenSSL-Fallback verwenden (Aktuell implementiert)
Der Code verwendet bereits einen funktionierenden OpenSSL-Fallback, der die Chain korrekt extrahiert.

## Empfehlung

**Kurzfristig**: Der aktuelle OpenSSL-Fallback funktioniert einwandfrei. Keine Änderung nötig.

**Langfristig**: Python mit korrekter OpenSSL-Version neu kompilieren, um native `getpeercert_chain()` Unterstützung zu haben.

## Technische Details

### Was ist getpeercert_chain()?
- Eingeführt in Python 3.10 (PEP 543)
- Gibt die vollständige Zertifikatskette zurück (nicht nur das Leaf-Zertifikat)
- Implementiert im `_ssl` C-Modul
- Erfordert OpenSSL 1.1.1+ beim Kompilieren

### Warum funktioniert der OpenSSL-Fallback?
- Verwendet `openssl s_client -showcerts` Kommando
- Extrahiert alle Zertifikate aus der TLS-Verbindung
- Konvertiert PEM zu DER Format
- Funktioniert unabhängig von der Python SSL-Implementierung


