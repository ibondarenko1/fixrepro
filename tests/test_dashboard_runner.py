from __future__ import annotations

import pytest

from scripts.run_dashboard import validate_host, valid_port


def test_local_host_validation_accepts_only_loopback() -> None:
    assert validate_host("127.0.0.1", container_mode=False) == "127.0.0.1"
    with pytest.raises(ValueError):
        validate_host("0.0.0.0", container_mode=False)
    with pytest.raises(ValueError):
        validate_host("localhost", container_mode=False)


def test_container_mode_alone_permits_all_interface_bind() -> None:
    assert validate_host("0.0.0.0", container_mode=True) == "0.0.0.0"


@pytest.mark.parametrize("value", ["0", "65536", "not-a-port"])
def test_dashboard_port_validation_rejects_invalid_values(value: str) -> None:
    with pytest.raises(Exception):
        valid_port(value)


def test_dashboard_port_validation_accepts_valid_value() -> None:
    assert valid_port("8000") == 8000
