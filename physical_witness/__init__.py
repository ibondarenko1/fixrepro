"""Optional physical-output witnesses for verified FixRepro results."""

from physical_witness.policy import WitnessAction, WitnessPlan, plan_physical_witness
from physical_witness.roomba import (
    RoombaLocateWitness,
    RoombaWitnessConfig,
    WitnessConfigurationError,
    WitnessOperationError,
    WitnessResult,
)

__all__ = [
    "RoombaLocateWitness",
    "RoombaWitnessConfig",
    "WitnessAction",
    "WitnessConfigurationError",
    "WitnessOperationError",
    "WitnessPlan",
    "WitnessResult",
    "plan_physical_witness",
]
