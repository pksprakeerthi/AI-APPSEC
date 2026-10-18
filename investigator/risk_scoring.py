"""Transparent, deterministic risk scoring.

This is a teaching/prioritization heuristic. It is NOT CVSS, EPSS, SSVC or any official
industry standard. Missing inputs are never treated as "safe": they receive a neutral
value and are flagged so a human can fill the gap.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

WEIGHTS: Dict[str, float] = {
    "severity": 0.40,
    "exposure": 0.25,
    "exploit": 0.20,
    "criticality": 0.15,
}

UNKNOWN_FACTOR = 0.5  # neutral value for missing or unrecognised inputs

SEVERITY_FACTORS: Dict[str, float] = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
EXPOSURE_FACTORS: Dict[str, float] = {
    "internet-facing": 1.0,
    "partner-facing": 0.7,
    "internal": 0.4,
    "isolated": 0.2,
}
EXPLOIT_FACTORS: Dict[str, float] = {"actively-exploited": 1.0, "public-poc": 0.75, "none-known": 0.25}
CRITICALITY_FACTORS: Dict[str, float] = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}

FACTOR_TABLES = {
    "severity": ("Vulnerability severity", SEVERITY_FACTORS),
    "exposure": ("Application exposure", EXPOSURE_FACTORS),
    "exploit": ("Exploitability evidence", EXPLOIT_FACTORS),
    "criticality": ("Business criticality", CRITICALITY_FACTORS),
}

# (priority, minimum score, suggested action)
PRIORITY_THRESHOLDS: Tuple[Tuple[str, float, str], ...] = (
    ("P1", 80.0, "Fix first"),
    ("P2", 60.0, "Fix soon"),
    ("P3", 40.0, "Plan remediation"),
    ("P4", 0.0, "Monitor and review"),
)

_MISSING_TOKENS = {"", "unknown", "null", "n/a"}

FORMULA_TEXT = """
**Score (0-100)** = 100 × ( 0.40 × severity + 0.25 × exposure + 0.20 × exploit evidence + 0.15 × business criticality )

Each input is converted to a factor between 0 and 1 using the tables below.

* A **missing or unrecognised** input gets the neutral factor **0.5** and is flagged. Missing data is
  never treated as proof of safety, and it is never scored below a "known low" value by accident.
* "none-known" exploit evidence still carries a factor of 0.25 because *no known exploit* is not the same as
  *no exploit*.
* This is a simple prioritization heuristic for this project. It is **not** CVSS, EPSS, SSVC or any official
  industry standard.
"""


@dataclass(frozen=True)
class FactorResult:
    key: str
    name: str
    input_value: Optional[str]
    factor: float
    weight: float
    points: float
    known: bool
    note: str


@dataclass(frozen=True)
class RiskScore:
    score: float
    priority: str
    action: str
    factors: Tuple[FactorResult, ...]
    missing_factors: Tuple[str, ...]
    confidence: str  # data completeness: High / Medium / Low


def _normalize(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return None if text in _MISSING_TOKENS else text


def priority_for(score: float) -> Tuple[str, str]:
    for priority, minimum, action in PRIORITY_THRESHOLDS:
        if score >= minimum:
            return priority, action
    return PRIORITY_THRESHOLDS[-1][0], PRIORITY_THRESHOLDS[-1][2]


def _factor(key: str, raw: Optional[str]) -> FactorResult:
    name, table = FACTOR_TABLES[key]
    weight = WEIGHTS[key]
    normalized = _normalize(raw)
    if normalized is None:
        factor, known, note = UNKNOWN_FACTOR, False, "Not recorded: neutral value used (not treated as safe)."
    elif normalized in table:
        factor, known, note = table[normalized], True, "Recorded in graph."
    else:
        factor, known = UNKNOWN_FACTOR, False
        note = f"Unrecognised value {raw!r}: neutral value used."
    return FactorResult(
        key=key,
        name=name,
        input_value=normalized if known else (None if normalized is None else str(raw)),
        factor=factor,
        weight=weight,
        points=factor * weight * 100.0,
        known=known,
        note=note,
    )


def score_finding(
    severity: Optional[str],
    exposure: Optional[str],
    exploit_evidence: Optional[str],
    criticality: Optional[str],
) -> RiskScore:
    """Compute a transparent risk score from the four evidence inputs."""
    factors = (
        _factor("severity", severity),
        _factor("exposure", exposure),
        _factor("exploit", exploit_evidence),
        _factor("criticality", criticality),
    )
    score = round(sum(f.points for f in factors), 1)
    missing = tuple(f.key for f in factors if not f.known)
    confidence = "High" if not missing else ("Medium" if len(missing) == 1 else "Low")
    priority, action = priority_for(score)
    return RiskScore(
        score=score,
        priority=priority,
        action=action,
        factors=factors,
        missing_factors=missing,
        confidence=confidence,
    )
