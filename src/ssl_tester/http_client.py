"""HTTP client utilities with proxy support."""

import os
from typing import Optional
import httpx


def create_http_client(
    proxy: Optional[str] = None,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    max_redirects: int = 5,
) -> httpx.Client:
    """
    Create HTTP client with proxy support.

    Args:
        proxy: Proxy URL (e.g., http://proxy:8080) or None to use environment variables
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        max_redirects: Maximum number of redirects

    Returns:
        Configured httpx.Client
    """
    proxy_config: Optional[str | dict[str, str]] = None

    if proxy:
        # Use explicit proxy - httpx accepts a single proxy URL for all schemes
        proxy_config = proxy
    else:
        # Check environment variables
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")

        if http_proxy and https_proxy and http_proxy != https_proxy:
            # Different proxies for http and https - use dictionary
            proxy_config = {"http://": http_proxy, "https://": https_proxy}
        elif http_proxy:
            # Use http_proxy for both
            proxy_config = http_proxy
        elif https_proxy:
            # Use https_proxy for both
            proxy_config = https_proxy

    # Build client arguments
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        "max_redirects": max_redirects if follow_redirects else 0,
    }
    
    # Only add proxy if it is set (httpx uses trust_env=True by default for env vars)
    if proxy_config:
        client_kwargs["proxy"] = proxy_config
    
    return httpx.Client(**client_kwargs)

