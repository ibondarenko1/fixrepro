"""Reusable three-scenario localhost verification orchestrator."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from fixrepro_core.artifacts import GeneratedArtifacts, generate_demo_artifacts
from fixrepro_core.config import (
    DEFAULT_DEVICE_URL,
    LOOPBACK_HOST,
    PATCHED_BUILD_ID,
    PATCHED_GATEWAY_PORT,
    VULNERABLE_BUILD_ID,
    VULNERABLE_GATEWAY_PORT,
)
from fixrepro_core.models import DeviceState, GatewayResponse
from fixrepro_core.package import DecodedPackage, parse_and_decode_package

from .bundle import (
    BundleError,
    artifact_record,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    publish_directory,
    verify_bundle,
    write_manifest,
)
from .evidence import (
    load_test_case,
    new_execution_id,
    new_verification_id,
    utc_timestamp,
    write_evidence,
)
from .models import (
    DeviceStateEvidence,
    EvidenceDocument,
    ExecutionEvidence,
    ExecutionRole,
    ObservedDecision,
    PackageEvidence,
    RawScenarioRecord,
    RequestEvidence,
    ResponseEvidence,
    SecurityVerdict,
    SignerTrust,
    VerificationOutcome,
)
from .processes import ProcessError, ServiceProcess, assert_services_running, start_services, stop_services
from .report import write_report
from .verdicts import calculate_individual_verdict, calculate_verification_outcome


REQUEST_TIMEOUT_SECONDS = 3.0
UPDATE_PATH = "/api/v1/updates"


class VerificationError(RuntimeError):
    """An operational failure prevented a safely publishable result."""


@dataclass(frozen=True)
class ScenarioDefinition:
    role: ExecutionRole
    gateway_port: int
    build_id: str
    package_bytes: bytes
    package: DecodedPackage
    package_bundle_path: str
    signer_trust: SignerTrust
    secure_expected_decision: ObservedDecision


@dataclass(frozen=True)
class ScenarioCapture:
    definition: ScenarioDefinition
    execution_id: str
    started_at: str
    finished_at: str
    reset_confirmed: bool
    request: RequestEvidence
    response: ResponseEvidence
    gateway_response: dict[str, Any]
    device_state_before: DeviceStateEvidence
    device_state_after: DeviceStateEvidence


@dataclass(frozen=True)
class VerificationRunResult:
    verification_id: str
    outcome: VerificationOutcome
    bundle_path: Path
    bundle_relative_path: str
    manifest_sha256: str
    manifest_entry_count: int
    executions: tuple[ExecutionEvidence, ...]


def _device_state(value: DeviceState) -> DeviceStateEvidence:
    return DeviceStateEvidence(**value.model_dump(mode="python"))


def _parse_device_response(response: httpx.Response, operation: str) -> DeviceState:
    if response.status_code != 200:
        raise VerificationError(f"device {operation} returned HTTP {response.status_code}")
    try:
        return DeviceState.model_validate(response.json())
    except (ValueError, TypeError, ValidationError) as exc:
        raise VerificationError(f"device {operation} returned malformed state JSON") from exc


def _reset_device(client: httpx.Client) -> tuple[DeviceStateEvidence, bool]:
    try:
        response = client.post(f"{DEFAULT_DEVICE_URL}/api/v1/reset")
    except httpx.RequestError as exc:
        raise VerificationError(f"device reset request failed: {exc}") from exc
    state = _device_state(_parse_device_response(response, "reset"))
    confirmed = (
        state.firmware_version == "1.0.0"
        and state.update_counter == 0
        and state.last_payload_sha256 is None
    )
    return state, confirmed


def _read_device_state(client: httpx.Client) -> DeviceStateEvidence:
    try:
        response = client.get(f"{DEFAULT_DEVICE_URL}/api/v1/state")
    except httpx.RequestError as exc:
        raise VerificationError(f"device state request failed: {exc}") from exc
    return _device_state(_parse_device_response(response, "state"))


def _execute_scenario(
    client: httpx.Client,
    definition: ScenarioDefinition,
) -> ScenarioCapture:
    started_at = utc_timestamp()
    execution_id = new_execution_id(definition.role)
    before, reset_confirmed = _reset_device(client)
    request = RequestEvidence(
        method="POST",
        path=UPDATE_PATH,
        content_type="application/json",
        body_sha256=hashlib.sha256(definition.package_bytes).hexdigest(),
    )
    url = f"http://{LOOPBACK_HOST}:{definition.gateway_port}{UPDATE_PATH}"
    try:
        gateway_http_response = client.post(
            url,
            content=definition.package_bytes,
            headers={"content-type": "application/json"},
        )
    except httpx.RequestError as exc:
        raise VerificationError(f"{definition.role.value} gateway request failed: {exc}") from exc

    response_body_sha256 = hashlib.sha256(gateway_http_response.content).hexdigest()
    gateway_document: dict[str, Any]
    try:
        parsed = gateway_http_response.json()
        gateway = GatewayResponse.model_validate(parsed)
        gateway_document = gateway.model_dump(mode="json")
        decision = ObservedDecision(gateway.decision)
        reason_code = gateway.reason_code
    except (ValueError, TypeError, ValidationError):
        gateway_document = {"malformed_response": True}
        decision = ObservedDecision.ERROR
        reason_code = "MALFORMED_RESPONSE"

    after = _read_device_state(client)
    recorded_before = gateway_document.get("device_state_before")
    if recorded_before is not None and recorded_before != before.model_dump(mode="json"):
        decision = ObservedDecision.ERROR
        reason_code = "CONFLICTING_OBSERVATION"
    recorded_after = gateway_document.get("device_state_after")
    if recorded_after is not None and recorded_after != after.model_dump(mode="json"):
        decision = ObservedDecision.ERROR
        reason_code = "CONFLICTING_OBSERVATION"

    response = ResponseEvidence(
        http_status=gateway_http_response.status_code,
        decision=decision,
        reason_code=reason_code,
        body_sha256=response_body_sha256,
    )
    return ScenarioCapture(
        definition=definition,
        execution_id=execution_id,
        started_at=started_at,
        finished_at=utc_timestamp(),
        reset_confirmed=reset_confirmed,
        request=request,
        response=response,
        gateway_response=gateway_document,
        device_state_before=before,
        device_state_after=after,
    )


def _raw_path(role: ExecutionRole) -> str:
    return {
        ExecutionRole.VULNERABLE: "raw/vulnerable.json",
        ExecutionRole.PATCHED: "raw/patched.json",
        ExecutionRole.POSITIVE_CONTROL: "raw/positive-control.json",
    }[role]


def _write_raw_capture(bundle_root: Path, capture: ScenarioCapture) -> str:
    relative_path = _raw_path(capture.definition.role)
    record = RawScenarioRecord(
        execution_id=capture.execution_id,
        role=capture.definition.role,
        started_at=capture.started_at,
        finished_at=capture.finished_at,
        reset_confirmed=capture.reset_confirmed,
        request=capture.request,
        gateway_response=capture.gateway_response,
        device_state_before=capture.device_state_before,
        device_state_after=capture.device_state_after,
    )
    atomic_write_json(
        bundle_root / Path(*relative_path.split("/")),
        record.model_dump(mode="json"),
    )
    return relative_path


def _execution_from_capture(bundle_root: Path, capture: ScenarioCapture) -> ExecutionEvidence:
    raw_path = _write_raw_capture(bundle_root, capture)
    raw_artifact = artifact_record(bundle_root, raw_path, "application/json")
    package_manifest = capture.definition.package.envelope.manifest
    package = PackageEvidence(
        filename=capture.definition.package_bundle_path,
        sha256=package_manifest.payload_sha256,
        envelope_sha256=hashlib.sha256(capture.definition.package_bytes).hexdigest(),
        signer_fingerprint=capture.definition.package.envelope.signer_fingerprint,
        signer_trust=capture.definition.signer_trust,
    )
    initial = ExecutionEvidence(
        execution_id=capture.execution_id,
        role=capture.definition.role,
        build_id=capture.definition.build_id,
        started_at=capture.started_at,
        finished_at=capture.finished_at,
        package=package,
        request=capture.request,
        response=capture.response,
        device_state_before=capture.device_state_before,
        device_state_after=capture.device_state_after,
        secure_expected_decision=capture.definition.secure_expected_decision,
        observed_decision=capture.response.decision,
        security_verdict=SecurityVerdict.INCONCLUSIVE,
        artifacts=[raw_artifact],
    )
    verdict = calculate_individual_verdict(initial)
    return initial.model_copy(update={"security_verdict": verdict})


def _bundle_relative_path(repository_root: Path, destination: Path) -> str:
    return destination.resolve().relative_to(repository_root.resolve()).as_posix()


def resolve_output_directory(
    repository_root: Path,
    verification_id: str,
    output_argument: str | None,
) -> Path:
    if output_argument is None:
        candidate = repository_root / "evidence" / "runs" / verification_id
    else:
        raw = Path(output_argument)
        if raw.is_absolute() or ".." in raw.parts:
            raise BundleError("output directory must be a traversal-free repository-relative path")
        candidate = repository_root / raw

    resolved_repository = repository_root.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    evidence_root = (repository_root / "evidence").resolve()
    if resolved_candidate == resolved_repository or not resolved_candidate.is_relative_to(evidence_root):
        raise BundleError("output directory must be a child of the repository evidence directory")
    if resolved_candidate == evidence_root:
        raise BundleError("the evidence directory itself cannot be used as output")

    current = candidate
    while current.resolve(strict=False) != resolved_repository:
        if current.exists() and current.is_symlink():
            raise BundleError("output directory or one of its parents may not be a symlink")
        current = current.parent
    return resolved_candidate


class VerificationOrchestrator:
    def __init__(self, repository_root: Path) -> None:
        self.repository_root = repository_root.resolve()
        self.schema_path = self.repository_root / "schemas" / "evidence.schema.json"

    def _verify_existing_demo_before_replace(self, destination: Path, replace: bool) -> None:
        demo_path = (self.repository_root / "evidence" / "demo-bundle").resolve()
        if destination != demo_path or not destination.exists() or not replace:
            return
        previous = verify_bundle(
            destination,
            self.repository_root,
            self.schema_path,
        )
        if not previous.valid:
            details = "; ".join(previous.failures)
            raise BundleError(f"existing demo bundle failed pre-replacement verification: {details}")

    def run(
        self,
        *,
        output_argument: str | None = None,
        replace: bool = False,
    ) -> VerificationRunResult:
        verification_id = new_verification_id()
        created_at = utc_timestamp()
        destination = resolve_output_directory(
            self.repository_root,
            verification_id,
            output_argument,
        )
        if destination.exists() and not replace:
            raise BundleError(f"output directory already exists: {_bundle_relative_path(self.repository_root, destination)}")
        if destination.is_symlink():
            raise BundleError("output directory may not be a symlink")
        self._verify_existing_demo_before_replace(destination, replace)

        runtime_root = self.repository_root / ".runtime" / "verifications" / verification_id
        artifacts = generate_demo_artifacts(runtime_root)
        untrusted_package_bytes = artifacts.untrusted_package_path.read_bytes()
        trusted_package_bytes = artifacts.trusted_package_path.read_bytes()
        untrusted_package = parse_and_decode_package(untrusted_package_bytes)
        trusted_package = parse_and_decode_package(trusted_package_bytes)

        definitions = (
            ScenarioDefinition(
                ExecutionRole.VULNERABLE,
                VULNERABLE_GATEWAY_PORT,
                VULNERABLE_BUILD_ID,
                untrusted_package_bytes,
                untrusted_package,
                "packages/untrusted-update.json",
                SignerTrust.UNTRUSTED,
                ObservedDecision.REJECTED,
            ),
            ScenarioDefinition(
                ExecutionRole.PATCHED,
                PATCHED_GATEWAY_PORT,
                PATCHED_BUILD_ID,
                untrusted_package_bytes,
                untrusted_package,
                "packages/untrusted-update.json",
                SignerTrust.UNTRUSTED,
                ObservedDecision.REJECTED,
            ),
            ScenarioDefinition(
                ExecutionRole.POSITIVE_CONTROL,
                PATCHED_GATEWAY_PORT,
                PATCHED_BUILD_ID,
                trusted_package_bytes,
                trusted_package,
                "packages/trusted-update.json",
                SignerTrust.TRUSTED,
                ObservedDecision.ACCEPTED,
            ),
        )
        if definitions[0].package_bytes is not definitions[1].package_bytes:
            raise VerificationError("untrusted package byte array was not reused")

        services: list[ServiceProcess] = []
        captures: list[ScenarioCapture] = []
        try:
            services = start_services(
                self.repository_root,
                artifacts.logs_dir,
                artifacts.trusted_public_key_path,
            )
            with httpx.Client(
                timeout=REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                for definition in definitions:
                    assert_services_running(services)
                    captures.append(_execute_scenario(client, definition))
                assert_services_running(services)
        except ProcessError as exc:
            raise VerificationError(str(exc)) from exc
        finally:
            if services:
                try:
                    stop_services(services)
                except ProcessError as exc:
                    raise VerificationError(str(exc)) from exc

        staged = self.repository_root / ".runtime" / "bundles" / verification_id
        if staged.exists():
            raise BundleError("unexpected verification staging directory collision")
        staged.mkdir(parents=True)
        atomic_write_bytes(staged / "packages" / "untrusted-update.json", untrusted_package_bytes)
        atomic_write_bytes(staged / "packages" / "trusted-update.json", trusted_package_bytes)
        atomic_write_bytes(
            staged / "trust" / "trusted-public-key.pem",
            artifacts.trusted_public_key_path.read_bytes(),
        )

        executions = tuple(_execution_from_capture(staged, capture) for capture in captures)
        outcome = calculate_verification_outcome(executions)
        log_lines = [
            f"{created_at} verification {verification_id} started",
            *(
                f"{capture.finished_at} {capture.definition.role.value} completed "
                f"with {capture.response.decision.value}"
                for capture in captures
            ),
            f"{utc_timestamp()} verification outcome {outcome.value}",
        ]
        atomic_write_text(staged / "run.log", "\n".join(log_lines) + "\n")

        media_types = {
            "packages/untrusted-update.json": "application/json",
            "packages/trusted-update.json": "application/json",
            "raw/vulnerable.json": "application/json",
            "raw/patched.json": "application/json",
            "raw/positive-control.json": "application/json",
            "trust/trusted-public-key.pem": "application/x-pem-file",
            "run.log": "text/plain",
        }
        bundle_files = [
            artifact_record(staged, path, media_types[path])
            for path in sorted(media_types)
        ]
        evidence = EvidenceDocument(
            schema_version="1.1",
            verification_id=verification_id,
            created_at=created_at,
            test_case=load_test_case(self.repository_root),
            executions=list(executions),
            verification_outcome=outcome,
            bundle_files=bundle_files,
        )
        write_evidence(staged / "evidence.json", evidence, self.schema_path)
        relative_destination = _bundle_relative_path(self.repository_root, destination)
        write_report(staged / "report.html", evidence, relative_destination)
        manifest, manifest_sha256 = write_manifest(staged)

        staged_result = verify_bundle(staged, self.repository_root, self.schema_path)
        if not staged_result.valid:
            raise BundleError("generated bundle failed verification: " + "; ".join(staged_result.failures))
        publish_directory(staged, destination, replace=replace)
        final_result = verify_bundle(destination, self.repository_root, self.schema_path)
        if not final_result.valid:
            raise BundleError("published bundle failed verification: " + "; ".join(final_result.failures))
        if final_result.manifest_sha256 != manifest_sha256:
            raise BundleError("published bundle root digest changed during publication")

        return VerificationRunResult(
            verification_id=verification_id,
            outcome=outcome,
            bundle_path=destination,
            bundle_relative_path=relative_destination,
            manifest_sha256=manifest_sha256,
            manifest_entry_count=len(manifest.files),
            executions=executions,
        )
