"""Tests for the optional, default-off physical-output witness."""

from __future__ import annotations

import json
from pathlib import Path
import runpy
import socket

import pytest

from physical_witness.policy import WitnessAction, plan_physical_witness
from physical_witness.roomba import (
    LOCATE_COMMAND,
    LOCATE_INITIATOR,
    LOCATE_TOPIC,
    RoombaLocateWitness,
    RoombaWitnessConfig,
    WitnessOperationError,
    WitnessResult,
)
from scripts import roomba_witness
from verifier.models import EvidenceDocument, ExecutionRole, VerificationOutcome


ROOT = Path(__file__).resolve().parents[1]


class FakeTransport:
    def __init__(self, failure: Exception | None = None) -> None:
        self.calls: list[tuple[RoombaWitnessConfig, str, bytes]] = []
        self.failure = failure

    def execute_locate(self, config: RoombaWitnessConfig, topic: str, payload: bytes) -> None:
        self.calls.append((config, topic, payload))
        if self.failure is not None:
            raise self.failure


def load_demo_evidence() -> EvidenceDocument:
    path = ROOT / "evidence" / "demo-bundle" / "evidence.json"
    return EvidenceDocument.model_validate_json(path.read_bytes())


def enabled_config(password: str = "synthetic-test-password") -> RoombaWitnessConfig:
    return RoombaWitnessConfig(
        enabled=True,
        host="10.0.0.2",
        device_id="synthetic-test-device",
        local_password=password,
    )


def test_import_creates_zero_network_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("network activity during import")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    runpy.run_path(str(ROOT / "physical_witness" / "roomba.py"))


def test_dry_run_creates_zero_network_activity(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_connect(*args: object, **kwargs: object) -> None:
        raise AssertionError("dry run attempted network activity")

    monkeypatch.setattr(socket, "create_connection", fail_connect)
    result = roomba_witness.main(
        ["--bundle", "evidence/demo-bundle", "--dry-run"]
    )
    output = capsys.readouterr().out
    assert result == 0
    assert "VULNERABLE=WOULD_SIGNAL" in output
    assert "PATCHED=NO_COMMAND" in output
    assert "POSITIVE_CONTROL=WOULD_SIGNAL" in output


def test_default_mode_is_disabled() -> None:
    transport = FakeTransport()
    witness = RoombaLocateWitness(transport=transport)
    assert witness.locate_once() is WitnessResult.DISABLED
    assert transport.calls == []


def test_verified_policy_plans_only_vulnerable_and_positive_signals() -> None:
    plan = plan_physical_witness(load_demo_evidence())
    assert plan.eligible is True
    assert plan.action_for(ExecutionRole.VULNERABLE) is WitnessAction.SIGNAL
    assert plan.action_for(ExecutionRole.PATCHED) is WitnessAction.NO_COMMAND
    assert plan.action_for(ExecutionRole.POSITIVE_CONTROL) is WitnessAction.SIGNAL
    assert plan.signal_count == 2


def test_live_executor_never_publishes_for_patched_scenario() -> None:
    transport = FakeTransport()
    witness = RoombaLocateWitness(enabled_config(), transport=transport, clock=lambda: 1234.0)
    plan = plan_physical_witness(load_demo_evidence())
    slept: list[float] = []
    results = roomba_witness._execute_live_plan(
        plan,
        witness,
        sleeper=slept.append,
        monotonic=lambda: 0.0,
    )
    assert results == (
        "VULNERABLE=SIGNAL_SENT",
        "PATCHED=NO_COMMAND",
        "POSITIVE_CONTROL=SIGNAL_SENT",
    )
    assert len(transport.calls) == 2
    assert slept == [20.0]


def test_non_verified_outcome_plans_zero_signals() -> None:
    evidence = load_demo_evidence().model_copy(
        update={"verification_outcome": VerificationOutcome.PATCH_NOT_VERIFIED}
    )
    plan = plan_physical_witness(evidence)
    assert plan.eligible is False
    assert plan.signal_count == 0


def test_same_input_mismatch_plans_zero_signals() -> None:
    evidence = load_demo_evidence()
    executions = list(evidence.executions)
    patched_index = next(
        index for index, item in enumerate(executions) if item.role is ExecutionRole.PATCHED
    )
    patched = executions[patched_index]
    mismatched_package = patched.package.model_copy(update={"envelope_sha256": "0" * 64})
    executions[patched_index] = patched.model_copy(update={"package": mismatched_package})
    mismatched = evidence.model_copy(update={"executions": executions})
    plan = plan_physical_witness(mismatched)
    assert plan.eligible is False
    assert plan.signal_count == 0


def test_locate_once_uses_only_fixed_topic_and_payload() -> None:
    transport = FakeTransport()
    witness = RoombaLocateWitness(enabled_config(), transport=transport, clock=lambda: 1234.9)
    assert witness.locate_once() is WitnessResult.SIGNAL_SENT
    assert len(transport.calls) == 1
    _, topic, payload = transport.calls[0]
    assert topic == LOCATE_TOPIC == "cmd"
    assert json.loads(payload) == {
        "command": LOCATE_COMMAND,
        "initiator": LOCATE_INITIATOR,
        "time": 1234,
    }


def test_witness_exposes_no_generic_publish_method() -> None:
    public_names = {name for name in dir(RoombaLocateWitness) if not name.startswith("_")}
    assert public_names == {"locate_once"}


def test_exception_does_not_expose_credentials() -> None:
    secret = "do-not-expose-this-test-secret"
    transport = FakeTransport(RuntimeError(f"transport rejected {secret}"))
    witness = RoombaLocateWitness(enabled_config(secret), transport=transport)
    with pytest.raises(WitnessOperationError) as caught:
        witness.locate_once()
    assert secret not in str(caught.value)
    assert secret not in repr(enabled_config(secret))


def test_sanitized_proof_contains_no_private_identifiers() -> None:
    path = ROOT / "docs" / "evidence" / "roomba-locate-proof.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document) == {
        "cleaning_started",
        "core_evidence_bundle_member",
        "core_ota_target",
        "device_model",
        "firmware_changed",
        "limitation",
        "movement_observed",
        "observed_result",
        "role",
        "settings_changed",
        "test_type",
    }
    serialized = json.dumps(document).casefold()
    for forbidden in ("192.168.", "mac", "password", "blid", "mqtt", "certificate", "robotname"):
        assert forbidden not in serialized
