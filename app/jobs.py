"""Thread-safe, single-worker verification job management."""

from __future__ import annotations

import logging
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from verifier.bundle import BundleError
from verifier.evidence import utc_timestamp
from verifier.orchestrator import VerificationError, VerificationOrchestrator, VerificationRunResult

from .models import (
    BundlePresentation,
    JobStatus,
    JobStatusResponse,
    PresentationSource,
    PublicJobError,
    StartVerificationResponse,
)
from .presentation import BundleRegistry, PresentationError, present_bundle


LOGGER = logging.getLogger(__name__)
MAX_FINISHED_JOBS = 10


class OrchestratorProtocol(Protocol):
    def run(self) -> VerificationRunResult: ...


class VerificationAlreadyRunningError(RuntimeError):
    """A second job was requested while the worker is active."""


class VerificationManagerShuttingDownError(RuntimeError):
    """A job was requested after shutdown began."""


@dataclass
class _JobRecord:
    job_id: str
    status: JobStatus
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    result: BundlePresentation | None = None
    error: PublicJobError | None = None

    def public(self) -> JobStatusResponse:
        return JobStatusResponse(
            job_id=self.job_id,
            status=self.status,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            result=self.result,
            error=self.error,
        )


class VerificationJobManager:
    """Run at most one fixed orchestrator and retain a bounded in-memory history."""

    def __init__(
        self,
        repository_root: Path,
        bundle_registry: BundleRegistry | None = None,
        orchestrator_factory: Callable[[], OrchestratorProtocol] | None = None,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.bundle_registry = bundle_registry or BundleRegistry(self.repository_root)
        self._orchestrator_factory = orchestrator_factory or (
            lambda: VerificationOrchestrator(self.repository_root)
        )
        self._lock = threading.RLock()
        self._jobs: dict[str, _JobRecord] = {}
        self._active_job_id: str | None = None
        self._worker: threading.Thread | None = None
        self._shutting_down = False

    def start_job(self) -> StartVerificationResponse:
        with self._lock:
            if self._shutting_down:
                raise VerificationManagerShuttingDownError("job manager is shutting down")
            if self._active_job_id is not None:
                raise VerificationAlreadyRunningError("a verification job is already active")
            job_id = f"JOB-{secrets.token_hex(4)}"
            now = utc_timestamp()
            record = _JobRecord(
                job_id=job_id,
                status=JobStatus.RUNNING,
                created_at=now,
                started_at=now,
            )
            worker = threading.Thread(
                target=self._run_job,
                args=(job_id,),
                name=f"fixrepro-{job_id.lower()}",
                daemon=False,
            )
            self._jobs[job_id] = record
            self._active_job_id = job_id
            self._worker = worker
            try:
                worker.start()
            except RuntimeError:
                self._jobs.pop(job_id, None)
                self._active_job_id = None
                self._worker = None
                raise
        return StartVerificationResponse(
            job_id=job_id,
            status=JobStatus.RUNNING,
            status_url=f"/api/v1/verifications/{job_id}",
        )

    def get_job(self, job_id: str) -> JobStatusResponse | None:
        with self._lock:
            record = self._jobs.get(job_id)
            return None if record is None else record.public()

    def _run_job(self, job_id: str) -> None:
        try:
            run_result = self._orchestrator_factory().run()
            self.bundle_registry.register_live(job_id, run_result.bundle_path)
            presentation = present_bundle(
                self.repository_root,
                self.bundle_registry,
                job_id,
                PresentationSource.LIVE,
            )
        except (BundleError, VerificationError, PresentationError, OSError, ValueError) as exc:
            LOGGER.exception("Verification job %s failed during a known operation", job_id)
            self._finish_failed(
                job_id,
                "VERIFICATION_START_FAILED",
                "Deterministic verification could not be completed.",
            )
            return
        except Exception:
            LOGGER.exception("Verification job %s failed unexpectedly", job_id)
            self._finish_failed(
                job_id,
                "INTERNAL_ERROR",
                "Verification failed because of an internal operational error.",
            )
            return
        with self._lock:
            record = self._jobs[job_id]
            record.status = JobStatus.COMPLETED
            record.finished_at = utc_timestamp()
            record.result = presentation
            record.error = None
            self._active_job_id = None
            self._worker = None
            self._trim_finished_locked()

    def _finish_failed(self, job_id: str, code: str, message: str) -> None:
        with self._lock:
            record = self._jobs[job_id]
            record.status = JobStatus.FAILED
            record.finished_at = utc_timestamp()
            record.result = None
            record.error = PublicJobError(code=code, message=message)
            self._active_job_id = None
            self._worker = None
            self._trim_finished_locked()

    def _trim_finished_locked(self) -> None:
        finished = [
            job_id
            for job_id, record in self._jobs.items()
            if record.status in {JobStatus.COMPLETED, JobStatus.FAILED}
            and job_id != self._active_job_id
        ]
        while len(finished) > MAX_FINISHED_JOBS:
            oldest = finished.pop(0)
            self._jobs.pop(oldest, None)

    def shutdown(self, *, wait: bool = True) -> None:
        with self._lock:
            self._shutting_down = True
            worker = self._worker
        if wait and worker is not None and worker is not threading.current_thread():
            worker.join()
