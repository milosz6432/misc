"""Helpers shared by reputation providers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from hunterintel.domain.evidence import Assurance, ObservationDraft, ReputationSignal


def half_life(amount: float, half: float) -> float:
    """Saturating 0..1 curve: every ``half`` units of evidence halve the remaining doubt.

    ``half_life(3, 3) == 0.5`` — three engines flagging an indicator is "50% of the way" to
    full strength; twelve is ~94%. Explainable, monotonic, and bounded.
    """
    if amount <= 0:
        return 0.0
    return 1.0 - 0.5 ** (amount / half)


def epoch_iso(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=UTC).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def reputation_observation(
    display_name: str, signal: ReputationSignal, **extra: Any
) -> ObservationDraft:
    return ObservationDraft(
        kind="reputation",
        title=f"Reputation — {display_name}",
        assurance=Assurance.PROVIDER_CLAIM,
        data={"signal": signal.model_dump(mode="json"), **extra},
        summary=signal.label,
    )


def clean_tags(values: list[Any], limit: int = 20) -> list[str]:
    out: list[str] = []
    for v in values:
        tag = str(v).strip().lower()[:64]
        if tag and tag not in out:
            out.append(tag)
        if len(out) >= limit:
            break
    return out
