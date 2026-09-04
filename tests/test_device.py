from __future__ import annotations

from device.state import VirtualDevice
from fixrepro_core.models import DeviceApplyRequest


def test_device_reset_restores_initial_state() -> None:
    device = VirtualDevice()
    device.apply(DeviceApplyRequest(firmware_version="1.1.0", payload_sha256="a" * 64))
    state = device.reset()
    assert state.firmware_version == "1.0.0"
    assert state.update_counter == 0
    assert state.last_payload_sha256 is None


def test_device_apply_changes_version_and_increments_counter() -> None:
    device = VirtualDevice()
    first = device.apply(
        DeviceApplyRequest(firmware_version="1.1.0", payload_sha256="a" * 64)
    )
    second = device.apply(
        DeviceApplyRequest(firmware_version="1.2.0", payload_sha256="b" * 64)
    )
    assert first.firmware_version == "1.1.0"
    assert first.update_counter == 1
    assert first.last_payload_sha256 == "a" * 64
    assert second.firmware_version == "1.2.0"
    assert second.update_counter == 2
    assert second.last_payload_sha256 == "b" * 64
