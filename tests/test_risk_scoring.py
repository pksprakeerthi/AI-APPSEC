"""Tests for the transparent risk scoring (no database needed)."""
import pytest

from graph import schema
from investigator import risk_scoring
from investigator.risk_scoring import score_finding


def test_weights_sum_to_one():
    assert sum(risk_scoring.WEIGHTS.values()) == pytest.approx(1.0)


def test_factor_tables_match_schema_vocabulary():
    assert set(risk_scoring.SEVERITY_FACTORS) == set(schema.SEVERITIES)
    assert set(risk_scoring.EXPOSURE_FACTORS) == set(schema.EXPOSURE_LEVELS)
    assert set(risk_scoring.EXPLOIT_FACTORS) == set(schema.EXPLOIT_LEVELS)
    assert set(risk_scoring.CRITICALITY_FACTORS) == set(schema.CRITICALITY_LEVELS)


def test_maximum_inputs_give_100_and_p1():
    result = score_finding("critical", "internet-facing", "actively-exploited", "critical")
    assert result.score == pytest.approx(100.0)
    assert result.priority == "P1"
    assert result.confidence == "High"
    assert result.missing_factors == ()


def test_lowest_known_inputs_give_p4():
    result = score_finding("low", "isolated", "none-known", "low")
    assert 23.0 < result.score < 24.0
    assert result.priority == "P4"


def test_inputs_are_case_insensitive():
    assert score_finding("HIGH", "Internal", "PUBLIC-POC", "Medium").score == score_finding(
        "high", "internal", "public-poc", "medium"
    ).score


def test_missing_data_uses_neutral_value_and_is_flagged():
    result = score_finding("high", None, None, None)
    assert set(result.missing_factors) == {"exposure", "exploit", "criticality"}
    assert result.confidence == "Low"
    for factor in result.factors:
        if not factor.known:
            assert factor.factor == risk_scoring.UNKNOWN_FACTOR


def test_missing_data_is_not_scored_as_safe():
    unknown = score_finding("high", None, None, None).score
    known_low = score_finding("high", "isolated", "none-known", "low").score
    assert unknown > known_low


def test_unrecognised_value_is_treated_as_unknown():
    result = score_finding("catastrophic", "internal", "none-known", "low")
    assert "severity" in result.missing_factors
    assert result.factors[0].factor == risk_scoring.UNKNOWN_FACTOR


def test_higher_severity_never_lowers_score():
    scores = [score_finding(s, "internal", "none-known", "medium").score for s in ("low", "medium", "high", "critical")]
    assert scores == sorted(scores)


def test_all_unknown_is_neutral_midpoint():
    result = score_finding(None, None, None, None)
    assert result.score == pytest.approx(50.0)
    assert result.priority == "P3"
    assert result.confidence == "Low"


def test_priority_boundaries():
    assert risk_scoring.priority_for(80.0)[0] == "P1"
    assert risk_scoring.priority_for(79.9)[0] == "P2"
    assert risk_scoring.priority_for(60.0)[0] == "P2"
    assert risk_scoring.priority_for(40.0)[0] == "P3"
    assert risk_scoring.priority_for(39.9)[0] == "P4"
