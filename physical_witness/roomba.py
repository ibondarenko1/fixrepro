"""Narrow, default-off Roomba Locate physical-output witness."""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
from enum import StrEnum
import ipaddress
import json
import os
from pathlib import Path
import ssl
import time
from typing import Callable, Protocol


LOCATE_TOPIC = "cmd"
LOCATE_COMMAND = "find"
LOCATE_INITIATOR = "localApp"
MQTT_TLS_PORT = 8883
EXPECTED_MODEL = "Roomba s9+"
_RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


class WitnessConfigurationError(RuntimeError):
    """Raised when the local witness configuration is unavailable or unsafe."""


class WitnessOperationError(RuntimeError):
    """Raised with a stable message when the fixed Locate action fails."""


class WitnessResult(StrEnum):
    DISABLED = "DISABLED"
    SIGNAL_SENT = "SIGNAL_SENT"


@dataclass(frozen=True, repr=False)
class RoombaWitnessConfig:
    """In-memory configuration; secrets are deliberately excluded from repr."""

    enabled: bool = False
    host: str = ""
    device_id: str = field(default="", repr=False)
    local_password: str = field(default="", repr=False)
    device_model: str = EXPECTED_MODEL
    timeout_seconds: float = 8.0

    def __post_init__(self) -> None:
        if not self.enabled:
            return
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise WitnessConfigurationError("Physical-witness target is not a valid IPv4 address.") from exc
        if address.version != 4 or not any(address in network for network in _RFC1918_NETWORKS):
            raise WitnessConfigurationError("Physical-witness target must be a private RFC1918 address.")
        if self.device_model != EXPECTED_MODEL:
            raise WitnessConfigurationError("Physical-witness model does not match the approved device class.")
        if not self.device_id or not self.local_password:
            raise WitnessConfigurationError("Physical-witness local credentials are incomplete.")
        if not 1.0 <= self.timeout_seconds <= 20.0:
            raise WitnessConfigurationError("Physical-witness timeout is outside the safe range.")

    def __repr__(self) -> str:
        return (
            "RoombaWitnessConfig(enabled="
            f"{self.enabled!r}, device_model={self.device_model!r}, credentials='[REDACTED]')"
        )


class _LocateTransport(Protocol):
    def execute_locate(
        self,
        config: RoombaWitnessConfig,
        topic: str,
        payload: bytes,
    ) -> None: ...


class _PahoLocateTransport:
    """MQTT-over-TLS transport for one fixed, non-movement action."""

    def execute_locate(
        self,
        config: RoombaWitnessConfig,
        topic: str,
        payload: bytes,
    ) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise WitnessOperationError(
                "Physical-witness support requires the optional 'physical' dependency."
            ) from exc

        connected = False
        connection_accepted = False

        def on_connect(client: object, userdata: object, flags: object, reason_code: object, properties: object) -> None:
            del client, userdata, flags, properties
            nonlocal connection_accepted
            connection_accepted = reason_code == 0

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=config.device_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
            reconnect_on_failure=False,
        )
        client.username_pw_set(config.device_id, config.local_password)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        client.tls_set_context(context)
        client.tls_insecure_set(True)
        client.on_connect = on_connect
        client._connect_timeout = config.timeout_seconds

        try:
            client.connect(config.host, MQTT_TLS_PORT, keepalive=15)
            connected = True
            deadline = time.monotonic() + config.timeout_seconds
            while not connection_accepted and time.monotonic() < deadline:
                result = client.loop(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
                if result != mqtt.MQTT_ERR_SUCCESS:
                    raise WitnessOperationError("Physical-witness TLS MQTT connection failed.")
            if not connection_accepted:
                raise WitnessOperationError("Physical-witness TLS MQTT authentication timed out.")

            published = client.publish(topic, payload=payload, qos=0, retain=False)
            if published.rc != mqtt.MQTT_ERR_SUCCESS:
                raise WitnessOperationError("Physical-witness Locate signal was not accepted for sending.")
            client.loop(timeout=1.0)
        except WitnessOperationError:
            raise
        except Exception:
            raise WitnessOperationError("Physical-witness Locate signal could not be sent.") from None
        finally:
            if connected:
                try:
                    client.disconnect()
                    client.loop(timeout=0.2)
                except Exception:
                    pass


class RoombaLocateWitness:
    """Expose only a single fixed Locate action; disabled unless explicitly configured."""

    def __init__(
        self,
        config: RoombaWitnessConfig | None = None,
        *,
        transport: _LocateTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config or RoombaWitnessConfig()
        self._transport = transport or _PahoLocateTransport()
        self._clock = clock

    def locate_once(self) -> WitnessResult:
        if not self._config.enabled:
            return WitnessResult.DISABLED
        payload = json.dumps(
            {
                "command": LOCATE_COMMAND,
                "initiator": LOCATE_INITIATOR,
                "time": int(self._clock()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            self._transport.execute_locate(self._config, LOCATE_TOPIC, payload)
        except WitnessOperationError:
            raise
        except Exception:
            raise WitnessOperationError("Physical-witness Locate signal could not be sent.") from None
        return WitnessResult.SIGNAL_SENT


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise WitnessConfigurationError("The approved local credential file requires Windows DPAPI.")
    buffer = ctypes.create_string_buffer(data)
    source = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    destination = _DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(destination)
    ):
        raise WitnessConfigurationError("The approved local credential file could not be decrypted.")
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32.LocalFree(destination.pbData)


def load_local_witness_config(path: Path, runtime_root: Path) -> RoombaWitnessConfig:
    """Load the previously owner-authorized DPAPI file from ignored runtime storage."""

    try:
        resolved_path = path.resolve(strict=True)
        resolved_runtime = runtime_root.resolve(strict=True)
        if path.is_symlink() or not resolved_path.is_relative_to(resolved_runtime):
            raise WitnessConfigurationError("Physical-witness configuration is outside ignored runtime storage.")
        container = json.loads(resolved_path.read_text(encoding="utf-8"))
        if set(container) != {"format", "protected_b64"}:
            raise WitnessConfigurationError("Physical-witness credential container has an invalid structure.")
        if container["format"] != "windows-dpapi-current-user":
            raise WitnessConfigurationError("Physical-witness credential container has an unsupported format.")
        protected = base64.b64decode(container["protected_b64"], validate=True)
        document = json.loads(_dpapi_unprotect(protected).decode("utf-8"))
        if set(document) != {"blid", "password", "target"}:
            raise WitnessConfigurationError("Physical-witness decrypted configuration has an invalid structure.")
        return RoombaWitnessConfig(
            enabled=True,
            host=document["target"],
            device_id=document["blid"],
            local_password=document["password"],
        )
    except WitnessConfigurationError:
        raise
    except Exception:
        raise WitnessConfigurationError("Physical-witness local configuration could not be loaded.") from None
