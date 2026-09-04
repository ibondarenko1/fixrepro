from __future__ import annotations

import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.jobs import VerificationAlreadyRunningError, VerificationJobManager
from app.models import JobStatus
from app.presentation import BundleRegistry
from verifier.bundle import artifact_record, atomic_write_json, write_manifest
from verifier.evidence import write_evidence
from verifier.models import (
    DeviceStateEvidence,
    EvidenceDocument,
    ExecutionRole,
    ObservedDecision,
    RawScenarioRecord,
)
from verifier.orchestrator import VerificationError
from verifier.report import write_report
from verifier.verdicts import calculate_individual_verdict, calculate_verification_outcome

from .phase3_helpers import ROOT, build_valid_bundle


def job_repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    (repository / "schemas").mkdir(parents=True)
    shutil.copy2(ROOT / "schemas/evidence.schema.json", repository / "schemas")
    bundle = repository / "evidence/runs/fake-live-bundle"
    build_valid_bundle(bundle)
    return repository, bundle


def make_patch_not_verified(bundle: Path, repository: Path) -> None:
    evidence_path = bundle / "evidence.json"
    evidence = EvidenceDocument.model_validate_json(evidence_path.read_bytes())
    executions = list(evidence.executions)
    index = next(
        offset
        for offset, execution in enumerate(executions)
        if execution.role == ExecutionRole.PATCHED
    )
    patched = executions[index]
    after = DeviceStateEvidence(
        firmware_version="9.9.0-test",
        update_counter=1,
        last_payload_sha256=patched.package.sha256,
    )
    response = patched.response.model_copy(
        update={
            "http_status": 200,
            "decision": ObservedDecision.ACCEPTED,
            "reason_code": "CHECKSUM_ONLY_ACCEPTED",
        }
    )
    patched = patched.model_copy(
        update={
            "response": response,
            "observed_decision": ObservedDecision.ACCEPTED,
            "device_state_after": after,
        }
    )
    patched = patched.model_copy(
        update={"security_verdict": calculate_individual_verdict(patched)}
    )
    raw_path = bundle / "raw/patched.json"
    raw = RawScenarioRecord.model_validate_json(raw_path.read_bytes())
    gateway = dict(raw.gateway_response)
    gateway.update(
        {
            "decision": "ACCEPTED",
            "reason_code": "CHECKSUM_ONLY_ACCEPTED",
            "device_state_after": after.model_dump(mode="json"),
        }
    )
    raw = raw.model_copy(
        update={"gateway_response": gateway, "device_state_after": after}
    )
    atomic_write_json(raw_path, raw.model_dump(mode="json"))
    patched = patched.model_copy(
        update={
            "artifacts": [artifact_record(bundle, "raw/patched.json", "application/json")]
        }
    )
    executions[index] = patched
    bundle_files = [
        artifact_record(bundle, record.path, record.media_type)
        if record.path == "raw/patched.json"
        else record
        for record in evidence.bundle_files
    ]
    updated = evidence.model_copy(
        update={
            "executions": executions,
            "verification_outcome": calculate_verification_outcome(executions),
            "bundle_files": bundle_files,
        }
    )
    write_evidence(evidence_path, updated, repository / "schemas/evidence.schema.json")
    write_report(bundle / "report.html", updated, "evidence/runs/fake-live-bundle")
    write_manifest(bundle)


def wait_for_finished(manager: VerificationJobManager, job_id: str) -> JobStatus:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = manager.get_job(job_id)
        assert job is not None
        if job.status in {JobStatus.COMPLETED, JobStatus.FAILED}:
            return job.status
        time.sleep(0.02)
    raise AssertionError("fake verification job did not finish")


class ImmediateOrchestrator:
    def __init__(self, bundle: Path) -> None:
        self.bundle = bundle

    def run(self):  # type: ignore[no-untyped-def]
        return SimpleNamespace(bundle_path=self.bundle)


class BlockingOrchestrator(ImmediateOrchestrator):
    def __init__(self, bundle: Path, entered: threading.Event, release: threading.Event) -> None:
        super().__init__(bundle)
        self.entered = entered
        self.release = release

    def run(self):  # type: ignore[no-untyped-def]
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise VerificationError("test release timed out")
        return super().run()


class FailingOrchestrator:
    def run(self):  # type: ignore[no-untyped-def]
        raise VerificationError("sensitive internal test detail")


def test_job_manager_allows_only_one_active_job(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: BlockingOrchestrator(bundle, entered, release),
    )
    first = manager.start_job()
    assert entered.wait(timeout=2)
    with pytest.raises(VerificationAlreadyRunningError):
        manager.start_job()
    release.set()
    assert wait_for_finished(manager, first.job_id) == JobStatus.COMPLETED
    manager.shutdown()


def test_job_manager_allows_new_job_after_completion(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: ImmediateOrchestrator(bundle),
    )
    first = manager.start_job()
    assert wait_for_finished(manager, first.job_id) == JobStatus.COMPLETED
    second = manager.start_job()
    assert second.job_id != first.job_id
    assert wait_for_finished(manager, second.job_id) == JobStatus.COMPLETED
    manager.shutdown()


def test_job_manager_status_reads_are_thread_safe(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: BlockingOrchestrator(bundle, entered, release),
    )
    started = manager.start_job()
    assert entered.wait(timeout=2)
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: manager.get_job(started.job_id), range(40)))
    assert all(item is not None and item.status == JobStatus.RUNNING for item in statuses)
    release.set()
    assert wait_for_finished(manager, started.job_id) == JobStatus.COMPLETED
    manager.shutdown()


def test_job_manager_bounds_finished_history(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: ImmediateOrchestrator(bundle),
    )
    job_ids: list[str] = []
    for _ in range(11):
        job = manager.start_job()
        job_ids.append(job.job_id)
        assert wait_for_finished(manager, job.job_id) == JobStatus.COMPLETED
    assert manager.get_job(job_ids[0]) is None
    assert all(manager.get_job(job_id) is not None for job_id in job_ids[1:])
    manager.shutdown()


def test_operational_failure_becomes_safe_failed_state(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    (repository / "schemas").mkdir(parents=True)
    shutil.copy2(ROOT / "schemas/evidence.schema.json", repository / "schemas")
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        FailingOrchestrator,
    )
    started = manager.start_job()
    assert wait_for_finished(manager, started.job_id) == JobStatus.FAILED
    result = manager.get_job(started.job_id)
    assert result is not None
    assert result.error is not None
    assert result.error.code == "VERIFICATION_START_FAILED"
    assert "sensitive internal test detail" not in result.error.message
    assert result.result is None
    manager.shutdown()


def test_non_verified_deterministic_outcome_is_completed_not_failed(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    make_patch_not_verified(bundle, repository)
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: ImmediateOrchestrator(bundle),
    )
    started = manager.start_job()
    assert wait_for_finished(manager, started.job_id) == JobStatus.COMPLETED
    result = manager.get_job(started.job_id)
    assert result is not None and result.result is not None
    assert result.result.verification_outcome == "PATCH_NOT_VERIFIED"
    assert result.error is None
    manager.shutdown()


def test_shutdown_rejects_new_jobs(tmp_path: Path) -> None:
    repository, bundle = job_repository(tmp_path)
    manager = VerificationJobManager(
        repository,
        BundleRegistry(repository),
        lambda: ImmediateOrchestrator(bundle),
    )
    manager.shutdown()
    with pytest.raises(RuntimeError, match="shutting down"):
        manager.start_job()
