"""Local-only runtime configuration shared by the Phase 2 services."""

from __future__ import annotations

from urllib.parse import urlparse


LOOPBACK_HOST = "127.0.0.1"
CONTROL_PLANE_PORT = 8000
VULNERABLE_GATEWAY_PORT = 8101
PATCHED_GATEWAY_PORT = 8102
DEVICE_PORT = 8200
DEFAULT_DEVICE_URL = f"http://{LOOPBACK_HOST}:{DEVICE_PORT}"


def require_local_device_url(value: str) -> str:
    """Accept only the fixed loopback device endpoint used by the lab."""

    parsed = urlparse(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != LOOPBACK_HOST
        or parsed.port != DEVICE_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"FIXREPRO_DEVICE_URL must be {DEFAULT_DEVICE_URL}")
    return DEFAULT_DEVICE_URL
