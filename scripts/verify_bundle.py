#!/usr/bin/env python3
"""Independently verify a FixRepro tamper-evident evidence bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from verifier.bundle import verify_bundle


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_path")
    parser.add_argument("--allow-external", action="store_true")
    args = parser.parse_args()

    supplied = Path(args.bundle_path)
    bundle_path = supplied if supplied.is_absolute() else ROOT / supplied
    result = verify_bundle(
        bundle_path,
        ROOT,
        ROOT / "schemas" / "evidence.schema.json",
        allow_external=args.allow_external,
    )
    if not result.valid:
        print(f"BUNDLE_VERIFICATION_FAIL ({len(result.failures)} issue(s))", file=sys.stderr)
        for failure in result.failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("BUNDLE_VERIFICATION_PASS")
    print(f"VERIFICATION_OUTCOME={result.verification_outcome.value}")
    print(f"BUNDLE_MANIFEST_SHA256={result.manifest_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
