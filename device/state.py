"""Thread-safe in-memory state for the synthetic device."""

from __future__ import annotations

from threading import Lock

from fixrepro_core.models import DeviceApplyRequest, DeviceState


INITIAL_FIRMWARE_VERSION = "1.0.0"


class VirtualDevice:
    def __init__(self) -> None:
        self._lock = Lock()
        self._firmware_version = INITIAL_FIRMWARE_VERSION
        self._update_counter = 0
        self._last_payload_sha256: str | None = None

    def _snapshot_unlocked(self) -> DeviceState:
        return DeviceState(
            firmware_version=self._firmware_version,
            update_counter=self._update_counter,
            last_payload_sha256=self._last_payload_sha256,
        )

    def state(self) -> DeviceState:
        with self._lock:
            return self._snapshot_unlocked()

    def reset(self) -> DeviceState:
        with self._lock:
            self._firmware_version = INITIAL_FIRMWARE_VERSION
            self._update_counter = 0
            self._last_payload_sha256 = None
            return self._snapshot_unlocked()

    def apply(self, request: DeviceApplyRequest) -> DeviceState:
        with self._lock:
            self._firmware_version = request.firmware_version
            self._update_counter += 1
            self._last_payload_sha256 = request.payload_sha256
            return self._snapshot_unlocked()
