from __future__ import annotations

import os
from pathlib import Path

import pytest

from verifier.bundle import BundleError
from verifier.orchestrator import resolve_output_directory


def test_output_path_is_repository_relative_and_under_evidence(tmp_path: Path) -> None:
    (tmp_path / "evidence").mkdir()
    resolved = resolve_output_directory(tmp_path, "FR-test", "evidence/demo-bundle")
    assert resolved == (tmp_path / "evidence/demo-bundle").resolve()


@pytest.mark.parametrize("argument", ["../outside", ".", "evidence"])
def test_output_path_rejects_unsafe_targets(tmp_path: Path, argument: str) -> None:
    (tmp_path / "evidence").mkdir()
    with pytest.raises(BundleError):
        resolve_output_directory(tmp_path, "FR-test", argument)


def test_output_path_rejects_absolute_path(tmp_path: Path) -> None:
    (tmp_path / "evidence").mkdir()
    with pytest.raises(BundleError):
        resolve_output_directory(tmp_path, "FR-test", str((tmp_path / "absolute").resolve()))


def test_output_path_rejects_symlink_parent_where_supported(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    real = evidence / "real"
    real.mkdir()
    linked = evidence / "linked"
    try:
        os.symlink(real, linked, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are not available on this host")
    with pytest.raises(BundleError):
        resolve_output_directory(tmp_path, "FR-test", "evidence/linked/bundle")
