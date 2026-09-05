"""Deterministic policy for an optional physical-output witness."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from verifier.models import (
    EvidenceDocument,
    ExecutionRole,
    ObservedDecision,
    SecurityVerdict,
    VerificationOutcome,
)
from verifier.verdicts import calculate_verification_outcome


class WitnessAction(StrEnum):
    """The only physical-witness actions the policy can plan."""

    SIGNAL = "SIGNAL"
    NO_COMMAND = "NO_COMMAND"


@dataclass(frozen=True)
class ScenarioWitnessPlan:
    """One evidence role and its physical-witness action."""

    role: ExecutionRole
    action: WitnessAction


@dataclass(frozen=True)
class WitnessPlan:
    """A complete, bounded plan derived from strict evidence."""

    eligible: bool
    reason: str
    scenarios: tuple[ScenarioWitnessPlan, ...]

    @property
    def signal_count(self) -> int:
        return sum(item.action is WitnessAction.SIGNAL for item in self.scenarios)

    def action_for(self, role: ExecutionRole) -> WitnessAction:
        return next(item.action for item in self.scenarios if item.role is role)


def _no_command_plan(reason: str) -> WitnessPlan:
    return WitnessPlan(
        eligible=False,
        reason=reason,
        scenarios=tuple(
            ScenarioWitnessPlan(role=role, action=WitnessAction.NO_COMMAND)
            for role in ExecutionRole
        ),
    )


def plan_physical_witness(evidence: EvidenceDocument) -> WitnessPlan:
    """Plan at most two signals without changing the core security verdict."""

    if evidence.verification_outcome is not VerificationOutcome.PATCH_VERIFIED:
        return _no_command_plan("OVERALL_OUTCOME_NOT_PATCH_VERIFIED")
    if calculate_verification_outcome(evidence.executions) is not VerificationOutcome.PATCH_VERIFIED:
        return _no_command_plan("RECOMPUTED_OUTCOME_NOT_PATCH_VERIFIED")

    by_role = {execution.role: execution for execution in evidence.executions}
    vulnerable = by_role[ExecutionRole.VULNERABLE]
    patched = by_role[ExecutionRole.PATCHED]
    positive = by_role[ExecutionRole.POSITIVE_CONTROL]

    if vulnerable.package.envelope_sha256 != patched.package.envelope_sha256:
        return _no_command_plan("ENVELOPE_HASH_MISMATCH")
    if vulnerable.request.body_sha256 != patched.request.body_sha256:
        return _no_command_plan("REQUEST_HASH_MISMATCH")

    expected = (
        vulnerable.observed_decision is ObservedDecision.ACCEPTED
        and vulnerable.security_verdict is SecurityVerdict.FAIL
        and patched.observed_decision is ObservedDecision.REJECTED
        and patched.security_verdict is SecurityVerdict.PASS
        and positive.observed_decision is ObservedDecision.ACCEPTED
        and positive.security_verdict is SecurityVerdict.PASS
    )
    if not expected:
        return _no_command_plan("SCENARIO_CONTRACT_MISMATCH")

    plan = WitnessPlan(
        eligible=True,
        reason="PATCH_VERIFIED_WITNESS_PLAN",
        scenarios=(
            ScenarioWitnessPlan(ExecutionRole.VULNERABLE, WitnessAction.SIGNAL),
            ScenarioWitnessPlan(ExecutionRole.PATCHED, WitnessAction.NO_COMMAND),
            ScenarioWitnessPlan(ExecutionRole.POSITIVE_CONTROL, WitnessAction.SIGNAL),
        ),
    )
    if plan.signal_count > 2:
        return _no_command_plan("SIGNAL_LIMIT_EXCEEDED")
    return plan
