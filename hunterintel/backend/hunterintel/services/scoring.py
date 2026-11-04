"""Explainable risk / confidence scoring and freshness (pure functions, no I/O).

Definitions
-----------
*Signal*      a normalised statement from one source: ``{verdict, strength, reliability}``.
*Weight*      ``strength × reliability × freshness_factor`` — how much a malicious-leaning
              signal moves the needle right now.
*Risk*        ``100 × (1 − Π(1 − weight_i))`` over malicious-leaning signals (noisy-OR),
              then combined the same way with a **capped** contribution from structural
              heuristics. Heuristics alone can never reach "suspicious".
*Confidence*  how sure we are of the verdict: ``100 × (1 − Π(1 − reliability_i·factor_i))``
              over independent sources that *agree* with it, ×0.7 if sources conflict.
              A source that merely has no record contributes nothing.
*Verdict*     ``malicious ≥70 · suspicious ≥40 · low_risk >0 · no_detections`` (a definitive
              clean signal and zero risk) ``· unknown`` (nothing to go on, or expired).

Absence of evidence is *never* reported as "clean".
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from hunterintel.domain.evidence import Assurance, ReputationSignal, RiskFlag, Severity

#: default indicator lifetimes (days) — IPs and URLs churn quickly, file hashes do not
TTL_DAYS: dict[str, int] = {
    "ip": 30,
    "url": 30,
    "domain": 90,
    "email": 180,
    "hash": 365,
    "certificate": 365,
    "asn": 365,
}

SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.05,
    Severity.MEDIUM: 0.12,
    Severity.HIGH: 0.20,
    Severity.CRITICAL: 0.30,
}
HEURISTIC_CAP = 0.30
MALICIOUS_AT = 70
SUSPICIOUS_AT = 40
CONFLICT_PENALTY = 0.7


class Freshness(StrEnum):
    FRESH = "fresh"  # < 25 % of TTL since last seen
    AGING = "aging"  # < 75 %
    STALE = "stale"  # < 100 %
    EXPIRED = "expired"


@dataclass(frozen=True)
class ObsView:
    """Just the fields scoring needs, so it can be tested without a database."""

    provider: str
    kind: str
    assurance: str
    data: dict[str, Any]
    last_seen: datetime
    first_seen: datetime | None = None


@dataclass
class Assessment:
    risk_score: int | None
    confidence: int
    verdict: str
    freshness: Freshness
    freshness_ratio: float
    expires_at: datetime
    breakdown: list[dict[str, Any]] = field(default_factory=list)
    risk_flags: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    conflict: bool = False
    explanation: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "freshness": self.freshness.value,
            "freshness_ratio": round(self.freshness_ratio, 3),
            "expires_at": self.expires_at.isoformat(),
            "breakdown": self.breakdown,
            "risk_flags": self.risk_flags,
            "sources": self.sources,
            "conflict": self.conflict,
            "explanation": self.explanation,
        }


def freshness_of(
    last_seen: datetime, ttl_days: int, now: datetime
) -> tuple[Freshness, float, datetime]:
    ttl = timedelta(days=max(ttl_days, 1))
    expires = last_seen + ttl
    ratio = max((now - last_seen) / ttl, 0.0)
    if ratio >= 1.0:
        state = Freshness.EXPIRED
    elif ratio >= 0.75:
        state = Freshness.STALE
    elif ratio >= 0.25:
        state = Freshness.AGING
    else:
        state = Freshness.FRESH
    return state, ratio, expires


def evidence_factor(ratio: float) -> float:
    """Full weight for the first quarter of the TTL, then linear decay to zero at expiry."""
    if ratio <= 0.25:
        return 1.0
    return max(0.0, (1.0 - ratio) / 0.75)


def _latest_per_source(observations: list[ObsView], kind: str) -> list[ObsView]:
    latest: dict[str, ObsView] = {}
    for o in observations:
        if o.kind == kind and (
            o.provider not in latest or o.last_seen >= latest[o.provider].last_seen
        ):
            latest[o.provider] = o
    return list(latest.values())


def noisy_or(weights: list[float]) -> float:
    return 1.0 - math.prod(1.0 - min(max(w, 0.0), 1.0) for w in weights)


def assess(
    *, last_seen: datetime, ttl_days: int, observations: list[ObsView], now: datetime
) -> Assessment:
    state, ratio, expires = freshness_of(last_seen, ttl_days, now)
    breakdown: list[dict[str, Any]] = []
    malicious_weights: list[float] = []
    malicious_rel: list[float] = []
    harmless_rel: list[float] = []
    sources: list[str] = []
    saw_any_signal = False

    for obs in _latest_per_source(observations, "reputation"):
        try:
            sig = ReputationSignal.model_validate(obs.data["signal"])
        except (KeyError, ValueError):
            continue
        saw_any_signal = True
        sources.append(obs.provider)
        sig_state, sig_ratio, _ = freshness_of(obs.last_seen, ttl_days, now)
        factor = evidence_factor(sig_ratio)
        leaning_bad = sig.verdict in ("malicious", "suspicious")
        weight = sig.strength * sig.reliability * factor if leaning_bad else 0.0
        if leaning_bad:
            malicious_weights.append(weight)
            if sig.definitive:
                malicious_rel.append(sig.reliability * factor * (0.5 + 0.5 * sig.strength))
        elif sig.verdict == "harmless" and sig.definitive:
            harmless_rel.append(sig.reliability * factor)
        breakdown.append(
            {
                "kind": "reputation",
                "source": obs.provider,
                "assurance": Assurance.PROVIDER_CLAIM.value,
                "verdict": sig.verdict,
                "label": sig.label,
                "strength": round(sig.strength, 3),
                "reliability": sig.reliability,
                "freshness": sig_state.value,
                "freshness_factor": round(factor, 3),
                "weight": round(weight, 3),
                "definitive": sig.definitive,
            }
        )

    # structural heuristics — labelled "inferred" and capped so they cannot convict alone
    flags: list[dict[str, Any]] = []
    flag_weights: list[float] = []
    seen_flags: set[tuple[str, str]] = set()
    for obs in _latest_per_source(observations, "risk_flags"):
        for raw in obs.data.get("flags", []):
            try:
                flag = RiskFlag.model_validate(raw)
            except ValueError:
                continue
            if (obs.provider, flag.id) in seen_flags:
                continue
            seen_flags.add((obs.provider, flag.id))
            weight = SEVERITY_WEIGHT[flag.severity] * evidence_factor(
                freshness_of(obs.last_seen, ttl_days, now)[1]
            )
            flag_weights.append(weight)
            flags.append(
                {
                    **flag.model_dump(mode="json"),
                    "source": obs.provider,
                    "assurance": Assurance.INFERRED.value,
                }
            )
            if weight > 0:
                breakdown.append(
                    {
                        "kind": "heuristic",
                        "source": obs.provider,
                        "assurance": Assurance.INFERRED.value,
                        "verdict": "suspicious",
                        "label": flag.title,
                        "strength": SEVERITY_WEIGHT[flag.severity],
                        "reliability": None,
                        "weight": round(weight, 3),
                        "definitive": False,
                    }
                )
    heuristic = min(noisy_or(flag_weights), HEURISTIC_CAP)
    reputation_risk = noisy_or(malicious_weights)
    risk = 1.0 - (1.0 - reputation_risk) * (1.0 - heuristic)
    risk_score = round(risk * 100)

    leaning_bad_overall = bool(malicious_weights) or heuristic > 0
    conflict = bool(malicious_rel) and bool(harmless_rel)
    if state is Freshness.EXPIRED:
        verdict, risk_score = "unknown", 0
        explanation = (
            f"Expired: not seen for {int(ratio * ttl_days)} days against a {ttl_days}-day lifetime, "
            "so no active assessment is made. Re-enrich to refresh."
        )
        confidence = 0
    else:
        if risk_score >= MALICIOUS_AT:
            verdict = "malicious"
        elif risk_score >= SUSPICIOUS_AT:
            verdict = "suspicious"
        elif risk_score > 0 and leaning_bad_overall:
            verdict = "low_risk"
        elif harmless_rel:
            verdict = "no_detections"
        else:
            verdict = "unknown"
        agreeing = (
            malicious_rel
            if verdict in ("malicious", "suspicious", "low_risk")
            else harmless_rel
            if verdict == "no_detections"
            else []
        )
        confidence = round(100 * noisy_or(agreeing) * (CONFLICT_PENALTY if conflict else 1.0))
        explanation = _explain(
            verdict, risk_score, reputation_risk, heuristic, conflict, saw_any_signal
        )

    return Assessment(
        risk_score=risk_score if (saw_any_signal or flags) else None,
        confidence=confidence,
        verdict=verdict,
        freshness=state,
        freshness_ratio=ratio,
        expires_at=expires,
        breakdown=breakdown,
        risk_flags=flags,
        sources=sorted(set(sources)),
        conflict=conflict,
        explanation=explanation,
    )


def _explain(
    verdict: str, score: int, reputation: float, heuristic: float, conflict: bool, saw_signal: bool
) -> str:
    if verdict == "unknown":
        return (
            "No reputation source returned a determination, so there is nothing to score. "
            "Unknown is not the same as safe."
            if not saw_signal
            else "Sources responded but none made a definitive determination."
        )
    parts = [f"Risk {score}/100"]
    if reputation > 0:
        parts.append(f"provider signals contribute {round(reputation * 100)}")
    if heuristic > 0:
        parts.append(
            f"inferred structural heuristics add up to {round(heuristic * 100)} (capped at {round(HEURISTIC_CAP * 100)})"
        )
    if verdict == "no_detections":
        parts = [
            "No detections: a definitive source reported nothing malicious — absence of detections, not proof of safety"
        ]
    if conflict:
        parts.append("sources disagree, which lowers confidence")
    return "; ".join(parts) + "."
