#!/usr/bin/env python3
"""Run deterministic FixRepro verification and publish a checked evidence bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from verifier.bundle import BundleError
from verifier.models import VerificationOutcome
from verifier.orchestrator import VerificationError, VerificationOrchestrator


ROOT = Path(__file__).resolve().parents[1]


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("repeat must be at least 1")
    return parsed


def outcome_exit_code(outcome: VerificationOutcome) -> int:
    return {
        VerificationOutcome.PATCH_VERIFIED: 0,
        VerificationOutcome.PATCH_NOT_VERIFIED: 2,
        VerificationOutcome.INCONCLUSIVE: 3,
    }[outcome]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=positive_integer, default=1)
    parser.add_argument("--output-dir")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    if args.repeat != 1 and args.output_dir is not None:
        parser.error("--repeat and --output-dir may not be combined")
    if args.replace and args.output_dir is None:
        parser.error("--replace requires --output-dir")

    orchestrator = VerificationOrchestrator(ROOT)
    results = []
    try:
        for index in range(1, args.repeat + 1):
            result = orchestrator.run(
                output_argument=args.output_dir,
                replace=args.replace,
            )
            results.append(result)
            if args.repeat > 1:
                print(f"RUN={index}")
                print(f"VERIFICATION_OUTCOME={result.outcome.value}")
                print(f"BUNDLE_PATH={result.bundle_relative_path}")
                print(f"BUNDLE_MANIFEST_SHA256={result.manifest_sha256}")
            if result.outcome != VerificationOutcome.PATCH_VERIFIED:
                return outcome_exit_code(result.outcome)
    except (BundleError, VerificationError, OSError, ValueError) as exc:
        print(f"VERIFICATION_ERROR={exc}", file=sys.stderr)
        return 1

    final = results[-1]
    if args.repeat > 1:
        print(f"SUCCESSFUL_RUNS={len(results)}")
        print("PHASE3_VERIFICATION_PASS")
    else:
        print(f"VERIFICATION_OUTCOME={final.outcome.value}")
        print(f"BUNDLE_PATH={final.bundle_relative_path}")
        print(f"BUNDLE_MANIFEST_SHA256={final.manifest_sha256}")
        print("PHASE3_VERIFICATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
