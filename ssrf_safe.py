"""
MEOK AI Labs — SSRF-safe attestation API resolver (V-06 FIX)
=============================================================

Hardens MEOK_ATTESTATION_API env var against tampering. The MCPs use this URL
to POST signed-cert requests; if an attacker sets the env to an internal /
attacker-controlled host, they can pivot or steal API keys.

Pattern:

    from ssrf_safe import resolve_attestation_api
    _ATTESTATION_API = resolve_attestation_api()  # always returns a safe URL

All calls to attestation API MUST flow through this resolver.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Final

# Authoritative MEOK domains. Any other host falls back to the canonical default.
_ALLOWED_HOSTS: Final[frozenset[str]] = frozenset({
    "meok-attestation-api.vercel.app",
    "meok-verify.vercel.app",
    "meok-attestation-api-niks-projects-0a2ef942.vercel.app",  # Vercel preview alias
    "meok.ai",
    "www.meok.ai",
    "csoai.org",
    "www.csoai.org",
    "councilof.ai",
    "compliance.meok.ai",
})

DEFAULT_API: Final[str] = "https://meok-attestation-api.vercel.app"


def resolve_attestation_api(env_var: str = "MEOK_ATTESTATION_API") -> str:
    """Return a safe attestation API URL. Falls back to DEFAULT_API if the env
    value points to an untrusted host or uses a non-HTTPS scheme."""
    raw = (os.environ.get(env_var, "") or "").strip()
    if not raw:
        return DEFAULT_API
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return DEFAULT_API
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",):  # never accept http for production signing
        # Allow http only for explicit local-dev testing
        if scheme == "http" and host in ("localhost", "127.0.0.1") and os.environ.get("MEOK_ALLOW_HTTP_ATTESTATION") == "1":
            return raw.rstrip("/")
        return DEFAULT_API
    if host not in _ALLOWED_HOSTS:
        return DEFAULT_API
    return raw.rstrip("/")


def is_safe_url(url: str) -> bool:
    """Generic SSRF safety check for any outbound URL the MCP fetches."""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    if p.scheme not in ("http", "https"):
        return False
    # Block private / loopback / link-local / metadata IPs
    if host in ("localhost", "0.0.0.0", "metadata.google.internal"):
        return False
    if host.startswith(("127.", "10.", "169.254.", "192.168.", "::1")):
        return False
    if any(host.startswith(f"172.{n}.") for n in range(16, 32)):
        return False
    return True
