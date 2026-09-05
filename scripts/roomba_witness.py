#!/usr/bin/env python3
"""Plan or execute the optional Roomba s9+ physical-output witness."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time
from typing import Callable

from physical_witness.policy import WitnessAction, WitnessPlan, plan_physical_witness
from physical_witness.roomba import (
    RoombaLocateWitness,
    WitnessConfigurationError,
    WitnessOperationError,
    load_local_witness_config,
)
from verifier.bundle import verify_bundle
from verifier.models import EvidenceDocument, ExecutionRole


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "evidence.schema.json"
LOCAL_CONFIG_PATH = (
    ROOT
    / ".runtime"
    / "device-discovery"
    / "irobot-30"
    / "authorized-locate-test"
    / "credentials.dpapi.json"
)
LIVE_CONFIRMATION = "OWNER_AUTHORIZED_TWO_LOCATE_SIGNALS"
COOLDOWN_SECONDS = 20.0


def _load_verified_plan(bundle_path: Path) -> WitnessPlan:
    result = verify_bundle(bundle_path, ROOT, SCHEMA_PATH)
    if not result.valid:
        raise RuntimeError("The evidence bundle did not pass independent verification.")
    evidence = EvidenceDocument.model_validate_json((bundle_path / "evidence.json").read_bytes())
    return plan_physical_witness(evidence)


def _print_dry_run(plan: WitnessPlan) -> None:
    values = {
        WitnessAction.SIGNAL: "WOULD_SIGNAL",
        WitnessAction.NO_COMMAND: "NO_COMMAND",
    }
    for role in ExecutionRole:
        print(f"{role.value}={values[plan.action_for(role)]}")


def _execute_live_plan(
    plan: WitnessPlan,
    witness: RoombaLocateWitness,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[str, ...]:
    if not plan.eligible or plan.signal_count > 2:
        raise WitnessOperationError("Physical-witness plan is not eligible for live execution.")
    results: list[str] = []
    last_signal_at: float | None = None
    sent = 0
    for item in plan.scenarios:
        if item.action is WitnessAction.NO_COMMAND:
            results.append(f"{item.role.value}=NO_COMMAND")
            continue
        if sent >= 2:
            raise WitnessOperationError("Physical-witness signal limit would be exceeded.")
        if last_signal_at is not None:
            remaining = COOLDOWN_SECONDS - (monotonic() - last_signal_at)
            if remaining > 0:
                sleeper(remaining)
        witness.locate_once()
        sent += 1
        last_signal_at = monotonic()
        results.append(f"{item.role.value}=SIGNAL_SENT")
    return tuple(results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument(
        "--confirm",
        help=f"Live mode requires the exact phrase {LIVE_CONFIRMATION}",
    )
    args = parser.parse_args(argv)

    supplied = Path(args.bundle)
    bundle_path = supplied if supplied.is_absolute() else ROOT / supplied
    try:
        plan = _load_verified_plan(bundle_path)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"PHYSICAL_WITNESS_ERROR={exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        _print_dry_run(plan)
        if not plan.eligible:
            print(f"PHYSICAL_WITNESS_DISABLED={plan.reason}", file=sys.stderr)
            return 2
        print("PHYSICAL_WITNESS_DRY_RUN_PASS")
        return 0

    if args.confirm != LIVE_CONFIRMATION:
        print("PHYSICAL_WITNESS_ERROR=Exact owner confirmation is required.", file=sys.stderr)
        return 1
    if not plan.eligible:
        print(f"PHYSICAL_WITNESS_ERROR=No signal is permitted: {plan.reason}", file=sys.stderr)
        return 2

    try:
        config = load_local_witness_config(LOCAL_CONFIG_PATH, ROOT / ".runtime")
        witness = RoombaLocateWitness(config)
        for result in _execute_live_plan(plan, witness):
            print(result)
    except (WitnessConfigurationError, WitnessOperationError) as exc:
        print(f"PHYSICAL_WITNESS_ERROR={exc}", file=sys.stderr)
        return 1
    print("PHYSICAL_WITNESS_LIVE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
