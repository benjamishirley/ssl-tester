"""Structured exception taxonomy for SSL/TLS certificate checking."""


class SSLTesterError(Exception):
    """Base exception for all SSL-Tester errors."""

    pass


class NetworkError(SSLTesterError):
    """Network-related errors (connection, timeout, DNS, etc.)."""

    def __init__(self, message: str, hostname: str | None = None, port: int | None = None):
        super().__init__(message)
        self.hostname = hostname
        self.port = port


class TLSHandshakeError(NetworkError):
    """TLS handshake failed."""

    pass


class ConnectionTimeoutError(NetworkError):
    """Connection timeout."""

    pass


class DNSResolutionError(NetworkError):
    """DNS resolution failed."""

    pass


class ChainError(SSLTesterError):
    """Certificate chain validation errors."""

    def __init__(self, message: str, missing_intermediates: list[str] | None = None):
        super().__init__(message)
        self.missing_intermediates = missing_intermediates or []


class ChainBuildingError(ChainError):
    """Error building certificate chain (e.g., missing intermediates)."""

    pass


class ChainValidationError(ChainError):
    """Error validating certificate chain structure."""

    pass


class TrustError(SSLTesterError):
    """Trust store validation errors."""

    def __init__(self, message: str, root_ca: str | None = None):
        super().__init__(message)
        self.root_ca = root_ca


class TrustStoreError(TrustError):
    """Error accessing or loading trust store."""

    pass


class RootCANotFoundError(TrustError):
    """Root CA not found in trust store."""

    pass


class CertificateError(SSLTesterError):
    """Certificate parsing or validation errors."""

    pass


class CertificateParseError(CertificateError):
    """Error parsing certificate (DER/PEM)."""

    pass


class HostnameMismatchError(CertificateError):
    """Hostname does not match certificate."""

    def __init__(self, message: str, expected: str, actual: str | None = None):
        super().__init__(message)
        self.expected = expected
        self.actual = actual


class CertificateExpiredError(CertificateError):
    """Certificate is expired or not yet valid."""

    pass


class CRLError(SSLTesterError):
    """CRL-related errors."""

    def __init__(self, message: str, url: str | None = None):
        super().__init__(message)
        self.url = url


class CRLUnreachableError(CRLError):
    """CRL Distribution Point is not reachable."""

    pass


class CRLParseError(CRLError):
    """Error parsing CRL."""

    pass


class OCSPError(SSLTesterError):
    """OCSP-related errors."""

    def __init__(self, message: str, url: str | None = None):
        super().__init__(message)
        self.url = url


class OCSPUnreachableError(OCSPError):
    """OCSP responder is not reachable."""

    pass


class OCSPRequestError(OCSPError):
    """Error building or sending OCSP request."""

    pass


class OCSPResponseError(OCSPError):
    """Error parsing or validating OCSP response."""

    pass


class AIAError(SSLTesterError):
    """Authority Information Access (AIA) fetching errors."""

    def __init__(self, message: str, url: str | None = None):
        super().__init__(message)
        self.url = url


class AIAFetchError(AIAError):
    """Error fetching certificate via AIA."""

    pass



