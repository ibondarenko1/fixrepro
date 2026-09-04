"""Pure deterministic verdict calculations for recorded observations."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from .models import (
    ExecutionEvidence,
    ExecutionRole,
    ObservedDecision,
    SecurityVerdict,
    VerificationOutcome,
)


INITIAL_VERSION = "1.0.0"
UNTRUSTED_VERSION = "9.9.0-test"
TRUSTED_VERSION = "1.1.0"


def _is_initial(execution: ExecutionEvidence) -> bool:
    before = execution.device_state_before
    return (
        before.firmware_version == INITIAL_VERSION
        and before.update_counter == 0
        and before.last_payload_sha256 is None
    )


def _is_unchanged(execution: ExecutionEvidence) -> bool:
    return execution.device_state_after == execution.device_state_before


def _is_applied(execution: ExecutionEvidence, version: str) -> bool:
    before = execution.device_state_before
    after = execution.device_state_after
    return (
        _is_initial(execution)
        and after.firmware_version == version
        and after.update_counter == before.update_counter + 1
        and after.last_payload_sha256 == execution.package.sha256
    )


def _response_is_coherent(execution: ExecutionEvidence) -> bool:
    response = execution.response
    if execution.observed_decision != response.decision:
        return False
    if execution.package.envelope_sha256 != execution.request.body_sha256:
        return False
    if response.decision == ObservedDecision.ACCEPTED:
        return response.http_status == 200 and (
            execution.device_state_after.update_counter
            == execution.device_state_before.update_counter + 1
        )
    if response.decision == ObservedDecision.REJECTED:
        return response.http_status in {400, 403} and _is_unchanged(execution)
    return False


def calculate_individual_verdict(execution: ExecutionEvidence) -> SecurityVerdict:
    """Derive one verdict without I/O, time, environment, or randomness."""

    if execution.observed_decision == ObservedDecision.ERROR:
        return SecurityVerdict.INCONCLUSIVE
    if not _is_initial(execution) or not _response_is_coherent(execution):
        return SecurityVerdict.INCONCLUSIVE

    if execution.role == ExecutionRole.VULNERABLE:
        if execution.observed_decision == ObservedDecision.ACCEPTED and _is_applied(
            execution, UNTRUSTED_VERSION
        ):
            return SecurityVerdict.FAIL
        if execution.observed_decision == ObservedDecision.REJECTED and _is_unchanged(execution):
            return SecurityVerdict.PASS
        return SecurityVerdict.INCONCLUSIVE

    if execution.role == ExecutionRole.PATCHED:
        if execution.observed_decision == ObservedDecision.REJECTED and _is_unchanged(execution):
            return SecurityVerdict.PASS
        if execution.observed_decision == ObservedDecision.ACCEPTED and _is_applied(
            execution, UNTRUSTED_VERSION
        ):
            return SecurityVerdict.FAIL
        return SecurityVerdict.INCONCLUSIVE

    if execution.role == ExecutionRole.POSITIVE_CONTROL:
        if execution.observed_decision == ObservedDecision.ACCEPTED and _is_applied(
            execution, TRUSTED_VERSION
        ):
            return SecurityVerdict.PASS
        if execution.observed_decision == ObservedDecision.REJECTED and _is_unchanged(execution):
            return SecurityVerdict.FAIL
        return SecurityVerdict.INCONCLUSIVE

    return SecurityVerdict.INCONCLUSIVE


def _baseline_reproduced(execution: ExecutionEvidence) -> bool:
    return (
        calculate_individual_verdict(execution) == SecurityVerdict.FAIL
        and execution.response.http_status == 200
        and execution.observed_decision == ObservedDecision.ACCEPTED
        and execution.response.reason_code == "CHECKSUM_ONLY_ACCEPTED"
        and _is_applied(execution, UNTRUSTED_VERSION)
    )


def _patched_rejected(execution: ExecutionEvidence) -> bool:
    return (
        calculate_individual_verdict(execution) == SecurityVerdict.PASS
        and execution.response.http_status == 403
        and execution.observed_decision == ObservedDecision.REJECTED
        and execution.response.reason_code == "UNTRUSTED_SIGNER"
        and _is_initial(execution)
        and _is_unchanged(execution)
    )


def _positive_control_passed(execution: ExecutionEvidence) -> bool:
    return (
        calculate_individual_verdict(execution) == SecurityVerdict.PASS
        and execution.response.http_status == 200
        and execution.observed_decision == ObservedDecision.ACCEPTED
        and execution.response.reason_code == "TRUSTED_SIGNATURE_ACCEPTED"
        and _is_applied(execution, TRUSTED_VERSION)
    )


def calculate_verification_outcome(
    executions: Sequence[ExecutionEvidence],
) -> VerificationOutcome:
    """Recompute the overall result from evidence instead of trusting a stored label."""

    roles = Counter(execution.role for execution in executions)
    if len(executions) != 3 or any(roles[role] != 1 for role in ExecutionRole):
        return VerificationOutcome.INCONCLUSIVE

    by_role = {execution.role: execution for execution in executions}
    vulnerable = by_role[ExecutionRole.VULNERABLE]
    patched = by_role[ExecutionRole.PATCHED]
    positive = by_role[ExecutionRole.POSITIVE_CONTROL]

    if any(
        execution.observed_decision == ObservedDecision.ERROR
        or calculate_individual_verdict(execution) == SecurityVerdict.INCONCLUSIVE
        for execution in executions
    ):
        return VerificationOutcome.INCONCLUSIVE

    if (
        vulnerable.package.envelope_sha256 != patched.package.envelope_sha256
        or vulnerable.request.body_sha256 != patched.request.body_sha256
        or vulnerable.package.envelope_sha256 != vulnerable.request.body_sha256
        or patched.package.envelope_sha256 != patched.request.body_sha256
    ):
        return VerificationOutcome.INCONCLUSIVE

    if not _baseline_reproduced(vulnerable):
        return VerificationOutcome.INCONCLUSIVE

    patched_pass = _patched_rejected(patched)
    positive_pass = _positive_control_passed(positive)
    if patched_pass and positive_pass:
        return VerificationOutcome.PATCH_VERIFIED

    if not _response_is_coherent(patched) or not _response_is_coherent(positive):
        return VerificationOutcome.INCONCLUSIVE
    return VerificationOutcome.PATCH_NOT_VERIFIED


def evidence_consistency_failures(executions: Sequence[ExecutionEvidence]) -> list[str]:
    """Return deterministic mismatches between stored and recomputed execution fields."""

    failures: list[str] = []
    expected_secure = {
        ExecutionRole.VULNERABLE: ObservedDecision.REJECTED,
        ExecutionRole.PATCHED: ObservedDecision.REJECTED,
        ExecutionRole.POSITIVE_CONTROL: ObservedDecision.ACCEPTED,
    }
    for execution in executions:
        calculated = calculate_individual_verdict(execution)
        if execution.security_verdict != calculated:
            failures.append(
                f"{execution.role} stored verdict {execution.security_verdict} "
                f"does not match recomputed verdict {calculated}"
            )
        if execution.secure_expected_decision != expected_secure[execution.role]:
            failures.append(f"{execution.role} has an incorrect secure expected decision")
        if execution.observed_decision != execution.response.decision:
            failures.append(f"{execution.role} observed and response decisions differ")
    return failures
