from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hunterintel.services.scoring import (
    HEURISTIC_CAP,
    Freshness,
    ObsView,
    assess,
    evidence_factor,
    freshness_of,
    noisy_or,
)

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def rep(
    provider: str,
    verdict: str,
    strength: float,
    reliability: float,
    *,
    age_days: float = 0,
    definitive: bool = True,
) -> ObsView:
    seen = NOW - timedelta(days=age_days)
    return ObsView(
        provider=provider,
        kind="reputation",
        assurance="provider_claim",
        last_seen=seen,
        first_seen=seen,
        data={
            "signal": {
                "source": provider,
                "verdict": verdict,
                "strength": strength,
                "reliability": reliability,
                "label": f"{provider} says {verdict}",
                "definitive": definitive,
            }
        },
    )


def flags(provider: str, *sev: str, age_days: float = 0) -> ObsView:
    return ObsView(
        provider=provider,
        kind="risk_flags",
        assurance="inferred",
        last_seen=NOW - timedelta(days=age_days),
        data={
            "flags": [
                {"id": f"f{i}", "severity": s, "title": f"flag {i}", "detail": "d"}
                for i, s in enumerate(sev)
            ]
        },
    )


def run(obs: list[ObsView], ttl: int = 90, last_seen_days: float = 0):  # noqa: ANN201
    return assess(
        last_seen=NOW - timedelta(days=last_seen_days), ttl_days=ttl, observations=obs, now=NOW
    )


def test_noisy_or_properties() -> None:
    assert noisy_or([]) == 0.0
    assert noisy_or([0.5]) == pytest.approx(0.5)
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)
    assert noisy_or([1.0, 0.3]) == 1.0
    assert 0.0 <= noisy_or([-1, 5]) <= 1.0  # inputs are clamped


def test_freshness_states_and_decay() -> None:
    day = lambda d: freshness_of(NOW - timedelta(days=d), 100, NOW)  # noqa: E731
    assert day(10)[0] is Freshness.FRESH and day(30)[0] is Freshness.AGING
    assert day(80)[0] is Freshness.STALE and day(100)[0] is Freshness.EXPIRED
    assert day(10)[2] == NOW - timedelta(days=10) + timedelta(days=100)
    assert evidence_factor(0.1) == 1.0 and evidence_factor(1.0) == 0.0
    assert evidence_factor(0.625) == pytest.approx(0.5)


def test_no_evidence_is_unknown_never_clean() -> None:
    a = run([])
    assert (a.verdict, a.risk_score, a.confidence) == ("unknown", None, 0)
    assert "not the same as safe" in a.explanation


def test_nothing_found_by_a_source_is_still_unknown() -> None:
    a = run([rep("virustotal", "unknown", 0.0, 0.85, definitive=False)])
    assert a.verdict == "unknown" and a.confidence == 0


def test_strong_agreement_between_independent_sources_is_malicious_with_high_confidence() -> None:
    a = run(
        [
            rep("virustotal", "malicious", 0.95, 0.85),
            rep("urlhaus", "malicious", 0.95, 0.9),
            rep("abuseipdb", "malicious", 0.9, 0.7),
        ]
    )
    assert a.verdict == "malicious" and a.risk_score and a.risk_score >= 95
    assert a.confidence >= 95 and sorted(a.sources) == ["abuseipdb", "urlhaus", "virustotal"]
    assert {b["source"] for b in a.breakdown} == set(a.sources)
    assert all(b["weight"] > 0 for b in a.breakdown)


def test_single_noisy_source_stays_low_confidence() -> None:
    a = run([rep("otx", "suspicious", 0.6, 0.45)])
    assert a.verdict == "low_risk"  # 0.6 × 0.45 = 27 → well under the suspicious line
    assert a.risk_score == 27 and a.confidence < 50


def test_clean_signal_gives_no_detections_not_clean() -> None:
    a = run([rep("virustotal", "harmless", 0.0, 0.85)])
    assert (a.verdict, a.risk_score) == ("no_detections", 0)
    assert a.confidence == 85 and "not proof of safety" in a.explanation


def test_conflicting_sources_reduce_confidence() -> None:
    agree = run([rep("virustotal", "malicious", 0.9, 0.85), rep("urlhaus", "malicious", 0.9, 0.9)])
    clash = run([rep("virustotal", "harmless", 0.0, 0.85), rep("urlhaus", "malicious", 0.9, 0.9)])
    assert clash.conflict and clash.verdict == "malicious"
    assert clash.confidence < agree.confidence and "disagree" in clash.explanation


def test_heuristics_alone_never_convict_and_are_capped() -> None:
    a = run([flags("local", "high", "high", "critical", "high")])
    assert a.verdict == "low_risk" and a.risk_score == round(HEURISTIC_CAP * 100)
    assert a.confidence == 0  # inferred signals never create confidence
    assert all(f["assurance"] == "inferred" for f in a.risk_flags)
    assert {b["kind"] for b in a.breakdown} == {"heuristic"}


def test_info_flags_do_not_move_risk() -> None:
    a = run([flags("rdap", "info")])
    assert a.risk_score == 0 and a.verdict == "unknown" and len(a.risk_flags) == 1


def test_heuristics_add_to_reputation_without_double_counting_confidence() -> None:
    base = run([rep("virustotal", "suspicious", 0.5, 0.85)])
    plus = run([rep("virustotal", "suspicious", 0.5, 0.85), flags("local", "medium")])
    assert plus.risk_score > base.risk_score and plus.confidence == base.confidence  # type: ignore[operator]


def test_old_evidence_decays_and_expired_indicators_are_not_assessed() -> None:
    fresh = run([rep("virustotal", "malicious", 0.95, 0.85, age_days=1)], ttl=30)
    aging = run([rep("virustotal", "malicious", 0.95, 0.85, age_days=15)], ttl=30)
    stale = run([rep("virustotal", "malicious", 0.95, 0.85, age_days=27)], ttl=30)
    assert fresh.risk_score > aging.risk_score > stale.risk_score  # type: ignore[operator]
    assert fresh.freshness is Freshness.FRESH
    expired = run(
        [rep("virustotal", "malicious", 0.95, 0.85, age_days=40)], ttl=30, last_seen_days=40
    )
    assert expired.freshness is Freshness.EXPIRED and expired.verdict == "unknown"
    assert expired.confidence == 0 and "Expired" in expired.explanation


def test_only_latest_observation_per_source_counts() -> None:
    old = rep("virustotal", "malicious", 0.95, 0.85, age_days=10)
    new = rep("virustotal", "harmless", 0.0, 0.85, age_days=0)
    a = run([old, new])
    assert (
        a.verdict == "no_detections"
        and len([b for b in a.breakdown if b["kind"] == "reputation"]) == 1
    )


def test_malformed_signal_is_ignored_not_fatal() -> None:
    bad = ObsView("x", "reputation", "provider_claim", {"signal": {"verdict": "malicious"}}, NOW)
    assert run([bad]).verdict == "unknown"
