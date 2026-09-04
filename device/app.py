"""Local-only FastAPI interface for the synthetic virtual device.

Reset and apply are intentionally unauthenticated for this isolated simulator.
They are not production interfaces and must be exposed only on loopback.
"""

from __future__ import annotations

from fastapi import FastAPI

from fixrepro_core.models import DeviceApplyRequest, DeviceState

from .state import VirtualDevice


app = FastAPI(title="FixRepro Synthetic Device", version="0.2.0")
device = VirtualDevice()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "virtual-device"}


@app.get("/api/v1/state", response_model=DeviceState)
def get_state() -> DeviceState:
    return device.state()


@app.post("/api/v1/reset", response_model=DeviceState)
def reset_device() -> DeviceState:
    return device.reset()


@app.post("/api/v1/apply", response_model=DeviceState)
def apply_update(request: DeviceApplyRequest) -> DeviceState:
    return device.apply(request)
