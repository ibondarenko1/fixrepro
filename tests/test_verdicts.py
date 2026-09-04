from __future__ import annotations

from verifier.models import (
    ExecutionRole,
    ObservedDecision,
    SecurityVerdict,
    VerificationOutcome,
)
from verifier.verdicts import calculate_verification_outcome

from .phase3_helpers import make_execution, state, verified_executions


def test_patch_verified_outcome() -> None:
    assert calculate_verification_outcome(verified_executions()) == VerificationOutcome.PATCH_VERIFIED


def test_patch_not_verified_when_patched_accepts_untrusted_package() -> None:
    executions = verified_executions()
    executions[1] = make_execution(
        ExecutionRole.PATCHED,
        decision=ObservedDecision.ACCEPTED,
        http_status=200,
        reason_code="CHECKSUM_ONLY_ACCEPTED",
        after=state("9.9.0-test", 1, "1" * 64),
    )
    assert executions[1].security_verdict == SecurityVerdict.FAIL
    assert calculate_verification_outcome(executions) == VerificationOutcome.PATCH_NOT_VERIFIED


def test_patch_not_verified_when_positive_control_fails() -> None:
    executions = verified_executions()
    executions[2] = make_execution(
        ExecutionRole.POSITIVE_CONTROL,
        decision=ObservedDecision.REJECTED,
        http_status=403,
        reason_code="UNTRUSTED_SIGNER",
        after=state(),
    )
    assert executions[2].security_verdict == SecurityVerdict.FAIL
    assert calculate_verification_outcome(executions) == VerificationOutcome.PATCH_NOT_VERIFIED


def test_inconclusive_when_vulnerable_baseline_does_not_reproduce() -> None:
    executions = verified_executions()
    executions[0] = make_execution(
        ExecutionRole.VULNERABLE,
        decision=ObservedDecision.REJECTED,
        http_status=403,
        reason_code="UNTRUSTED_SIGNER",
        after=state(),
    )
    assert calculate_verification_outcome(executions) == VerificationOutcome.INCONCLUSIVE


def test_inconclusive_when_same_input_hashes_differ() -> None:
    executions = verified_executions()
    executions[1] = make_execution(ExecutionRole.PATCHED, envelope_sha256="f" * 64)
    assert calculate_verification_outcome(executions) == VerificationOutcome.INCONCLUSIVE


def test_inconclusive_on_operational_error() -> None:
    executions = verified_executions()
    executions[1] = make_execution(
        ExecutionRole.PATCHED,
        decision=ObservedDecision.ERROR,
        http_status=502,
        reason_code="DEVICE_UNAVAILABLE",
    )
    assert executions[1].security_verdict == SecurityVerdict.INCONCLUSIVE
    assert calculate_verification_outcome(executions) == VerificationOutcome.INCONCLUSIVE


def test_exactly_one_execution_per_role_is_required() -> None:
    duplicate_roles = [
        make_execution(ExecutionRole.VULNERABLE),
        make_execution(ExecutionRole.VULNERABLE),
        make_execution(ExecutionRole.POSITIVE_CONTROL),
    ]
    assert calculate_verification_outcome(duplicate_roles) == VerificationOutcome.INCONCLUSIVE
