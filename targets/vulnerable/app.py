"""Vulnerable synthetic OTA gateway.

This isolated policy deliberately treats a valid payload checksum as enough
authorization to apply an update. It does not establish signer trust and does
not verify the signature. It is not suitable for production use.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from fixrepro_core.config import (
    DEFAULT_DEVICE_URL,
    VULNERABLE_BUILD_ID,
    require_local_device_url,
)
from fixrepro_core.evaluation import GatewayRole, evaluate_vulnerable_policy
from fixrepro_core.gateway import process_gateway_update


app = FastAPI(title="FixRepro Vulnerable OTA Gateway", version="0.3.0")


def _device_url() -> str:
    return require_local_device_url(os.environ.get("FIXREPRO_DEVICE_URL", DEFAULT_DEVICE_URL))


@app.get("/health")
def health() -> dict[str, str]:
    _device_url()
    return {
        "status": "ok",
        "gateway_role": GatewayRole.VULNERABLE.value,
        "build_id": VULNERABLE_BUILD_ID,
    }


@app.post("/api/v1/updates")
async def submit_update(request: Request) -> JSONResponse:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    raw_package = await request.body() if content_type == "application/json" else b""
    status, response = await process_gateway_update(
        raw_package=raw_package,
        role=GatewayRole.VULNERABLE,
        device_url=_device_url(),
        policy=evaluate_vulnerable_policy,
    )
    return JSONResponse(status_code=status, content=response.model_dump(mode="json"))
