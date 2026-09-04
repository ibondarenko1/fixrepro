"""Patched synthetic OTA gateway with explicit Ed25519 signer trust."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from fixrepro_core.config import DEFAULT_DEVICE_URL, require_local_device_url
from fixrepro_core.crypto import load_public_key_bytes
from fixrepro_core.evaluation import (
    Decision,
    GatewayRole,
    PolicyResult,
    ReasonCode,
    evaluate_patched_policy,
)
from fixrepro_core.gateway import process_gateway_update


app = FastAPI(title="FixRepro Patched OTA Gateway", version="0.2.0")


def _device_url() -> str:
    return require_local_device_url(os.environ.get("FIXREPRO_DEVICE_URL", DEFAULT_DEVICE_URL))


def _trusted_public_key() -> bytes:
    configured = os.environ.get("FIXREPRO_TRUSTED_PUBLIC_KEY")
    if not configured:
        raise ValueError("FIXREPRO_TRUSTED_PUBLIC_KEY is required")
    return load_public_key_bytes(Path(configured))


def _trust_configuration_error(_: bytes) -> PolicyResult:
    return PolicyResult(Decision.ERROR, ReasonCode.TRUST_CONFIGURATION_ERROR)


@app.get("/health")
def health() -> JSONResponse:
    try:
        _device_url()
        _trusted_public_key()
    except ValueError as exc:
        return JSONResponse(status_code=503, content={"status": "error", "message": str(exc)})
    return JSONResponse(
        status_code=200,
        content={"status": "ok", "gateway_role": GatewayRole.PATCHED.value},
    )


@app.post("/api/v1/updates")
async def submit_update(request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    raw_package = await request.body() if content_type == "application/json" else b""
    try:
        trusted_public_key = _trusted_public_key()
    except ValueError:
        policy = _trust_configuration_error
    else:
        def policy(package: bytes) -> PolicyResult:
            return evaluate_patched_policy(package, trusted_public_key)

    status, response = await process_gateway_update(
        raw_package=raw_package,
        role=GatewayRole.PATCHED,
        device_url=_device_url(),
        policy=policy,
    )
    return JSONResponse(status_code=status, content=response.model_dump(mode="json"))
