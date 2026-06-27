"""Shared outbound HTTP URL validation for CapGuard network clients."""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Callable, Optional


class URLSafetyError(ValueError):
    """Raised when a configured outbound URL is unsafe by default."""


def is_loopback_host(host: Optional[str]) -> bool:
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_http_url(
    url: str,
    *,
    label: str = "URL",
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    error_cls: Callable[[str], Exception] = URLSafetyError,
) -> str:
    """Validate a configured outbound HTTP(S) URL before opening a socket."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise error_cls(f"{label} must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise error_cls(f"{label} must not contain userinfo")
    if parsed.fragment:
        raise error_cls(f"{label} must not contain a fragment")
    host = parsed.hostname
    if parsed.scheme != "https" and not allow_insecure_http and not is_loopback_host(host):
        raise error_cls(f"{label} requires https outside loopback")
    if host is not None and not is_loopback_host(host) and not allow_private_network:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not ip.is_global:
                raise error_cls(f"{label} must not use a non-public IP literal")
    return url
