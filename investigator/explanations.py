"""Deterministic, evidence-based explanations, plus an optional guarded LLM narrative.

Every sentence in the deterministic output is built from values read from the graph.
The optional LLM only rephrases a JSON bundle of those facts, and its output is rejected
if it introduces identifiers or version numbers that are not in that bundle.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from config import LLMSettings
from graph.queries import Exposure
from investigator.risk_scoring import RiskScore


def package_label(name: Optional[str], version: Optional[str]) -> str:
    name = name or "unknown-package"
    return f"{name}@{version}" if version else name


def relationship_path(e: Exposure) -> str:
    parts = [e.application_name, "-[HAS_COMPONENT]->", e.component_name]
    for pkg_id, name, version in e.chain:
        parts += ["-[DEPENDS_ON]->", package_label(name, version)]
    parts += ["-[HAS_VULNERABILITY]->", e.vulnerability_id]
    return " ".join(parts)


def dependency_description(e: Exposure) -> str:
    if e.is_direct:
        return f"Direct: component '{e.component_name}' depends on {package_label(e.package_name, e.package_version)} itself."
    via = " → ".join(package_label(n, v) for _, n, v in e.chain)
    return (
        f"Transitive ({e.hops} hop{'s' if e.hops > 1 else ''}): the component depends on "
        f"{package_label(e.chain[0][1], e.chain[0][2])}, which pulls in the vulnerable package. Chain: {via}."
    )


def why_it_matters(e: Exposure, score: RiskScore) -> str:
    sentences = [
        f"{e.vulnerability_id} (severity: {e.severity or 'not recorded'}) is recorded on "
        f"{package_label(e.package_name, e.package_version)}, which {e.application_name} reaches through "
        f"{e.component_name} ({'direct' if e.is_direct else 'transitive'} dependency)."
    ]
    exposure_text = {
        "internet-facing": "The application is recorded as internet-facing, so vulnerable code could be reachable by outsiders (reachability is not confirmed).",
        "partner-facing": "The application is recorded as partner-facing, so third parties may be able to interact with it.",
        "internal": "The application is recorded as internal-only, which narrows who can reach it but does not remove insider or lateral-movement risk.",
        "isolated": "The application is recorded as isolated, which lowers exposure but does not remove the vulnerable dependency.",
    }.get((e.app_exposure or "").lower())
    if exposure_text:
        sentences.append(exposure_text)
    exploit_text = {
        "actively-exploited": "The vulnerability is recorded as actively exploited, which makes remediation time-sensitive.",
        "public-poc": "A public proof-of-concept is recorded, which lowers the effort an attacker needs.",
        "none-known": "No known exploit is recorded; that is not proof that none exists.",
    }.get((e.exploit_evidence or "").lower())
    if exploit_text:
        sentences.append(exploit_text)
    if e.app_criticality:
        sentences.append(f"The application's business criticality is recorded as {e.app_criticality}.")
    sentences.append(
        f"Heuristic risk score: {score.score:.1f}/100 ({score.priority}: {score.action}); "
        f"data completeness: {score.confidence}."
    )
    return " ".join(sentences)


def evidence_items(e: Exposure) -> List[str]:
    items = [
        f"Graph path found in FalkorDB: {relationship_path(e)}",
        f"Vulnerability node {e.vulnerability_id} is attached to package node "
        f"{package_label(e.package_name, e.package_version)} via HAS_VULNERABILITY.",
    ]
    if e.severity:
        items.append(f"Severity recorded on the vulnerability node: {e.severity}.")
    if e.exploit_evidence:
        note = " (absence of a known exploit is not proof of safety)" if e.exploit_evidence == "none-known" else ""
        items.append(f"Exploit evidence recorded: {e.exploit_evidence}{note}.")
    if e.app_exposure:
        items.append(f"Application exposure recorded: {e.app_exposure}.")
    if e.app_criticality:
        items.append(f"Business criticality recorded: {e.app_criticality}.")
    if e.fixed_version:
        items.append(f"A fixed version is recorded in the dataset: {e.fixed_version}.")
    return items


_MISSING_TEXT = {
    "severity": "Vulnerability severity is not recorded; a neutral value was used in scoring.",
    "exposure": "Application exposure is not recorded; a neutral value was used, which does not imply the application is safe.",
    "exploit": "Exploit evidence is not recorded; a neutral value was used. No data is not evidence that no exploit exists.",
    "criticality": "Business criticality of the application is not recorded; a neutral value was used.",
}


def missing_information(e: Exposure, score: RiskScore) -> List[str]:
    items = [_MISSING_TEXT[key] for key in score.missing_factors]
    items.append(
        "Installed version versus the advisory's affected range: the graph stores the package version and "
        "a fixed version only, not a verified affected range."
    )
    items.append("Reachability: the graph holds no call-graph data showing whether the vulnerable code path is used.")
    items.append("Compensating controls (WAF rules, network segmentation, runtime protections) are not modelled.")
    if not e.fixed_version:
        items.append("No fixed version is recorded for this vulnerability.")
    return items


def next_steps(e: Exposure, score: RiskScore) -> List[str]:
    pkg = package_label(e.package_name, e.package_version)
    steps = [
        f"Confirm the installed version of {pkg} in '{e.component_name}' from its lockfile or SBOM, "
        "and compare it with the vendor advisory."
    ]
    if e.fixed_version:
        steps.append(f"Plan an upgrade to {e.fixed_version} or later (recorded in the dataset; verify with the vendor advisory).")
    else:
        steps.append("No fixed version is recorded: check the vendor advisory for a patch or a mitigation.")
    if not e.is_direct:
        direct = package_label(e.chain[0][1], e.chain[0][2])
        steps.append(
            f"Identify whether upgrading the direct dependency {direct} resolves the issue, "
            "or whether the transitive version can be overridden."
        )
    steps.append("Check whether the application actually calls the vulnerable functionality (reachability analysis).")
    if (e.exploit_evidence or "").lower() in ("actively-exploited", "public-poc"):
        steps.append("Treat as time-sensitive: review logs and WAF telemetry for exploitation attempts and consider temporary mitigations.")
    missing_meta = [k for k in score.missing_factors if k in ("exposure", "criticality")]
    if missing_meta:
        steps.append(f"Record the application's {' and '.join(missing_meta)} in the graph and re-run to refine the score.")
    if score.priority == "P1":
        steps.append("Assign an owner and agree a remediation deadline.")
    return steps


@dataclass(frozen=True)
class FindingExplanation:
    path: str
    dependency_type: str
    why_it_matters: str
    evidence: Tuple[str, ...]
    missing_information: Tuple[str, ...]
    next_steps: Tuple[str, ...]


def explain_finding(e: Exposure, score: RiskScore) -> FindingExplanation:
    return FindingExplanation(
        path=relationship_path(e),
        dependency_type=dependency_description(e),
        why_it_matters=why_it_matters(e, score),
        evidence=tuple(evidence_items(e)),
        missing_information=tuple(missing_information(e, score)),
        next_steps=tuple(next_steps(e, score)),
    )


# ---------------------------------------------------------------- optional LLM narrative

_ID_PATTERN = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|DEMO-VULN-\d+)\b")
_VERSION_PATTERN = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

LLM_SYSTEM_PROMPT = (
    "You are a security analyst assistant. Write a plain-language summary (maximum 150 words) of the "
    "investigation facts in the JSON provided by the user. Use ONLY facts present in that JSON. Never add "
    "vulnerability identifiers, package names, version numbers, affected ranges or evidence that are not in the "
    "JSON. If information is marked 'not recorded', say it is missing and never infer safety from missing data. "
    "Do not describe the risk score as an official standard."
)


def validate_llm_text(text: str, facts_json: str) -> bool:
    """Reject LLM output that introduces identifiers or version numbers absent from the facts."""
    for identifier in _ID_PATTERN.findall(text):
        if identifier not in facts_json:
            return False
    for version in _VERSION_PATTERN.findall(text):
        if version not in facts_json:
            return False
    return True


def generate_llm_summary(facts: Dict[str, Any], settings: LLMSettings) -> Tuple[Optional[str], Optional[str]]:
    """Return (text, warning). Text is None if the LLM is unavailable or its output was rejected."""
    if not settings.enabled:
        return None, "No ANTHROPIC_API_KEY configured; showing deterministic explanations only."
    try:
        import anthropic  # optional dependency
    except ImportError:
        return None, "The 'anthropic' package is not installed (pip install anthropic)."
    facts_json = json.dumps(facts, indent=2, default=str)
    try:
        client = anthropic.Anthropic(api_key=settings.api_key)
        response = client.messages.create(
            model=settings.model,
            max_tokens=500,
            system=LLM_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Investigation facts (JSON):\n{facts_json}"}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text").strip()
    except Exception as exc:  # noqa: BLE001
        return None, f"LLM request failed: {exc}"
    if not text:
        return None, "The LLM returned an empty response."
    if not validate_llm_text(text, facts_json):
        return None, "The LLM output mentioned identifiers or versions that are not in the graph evidence, so it was discarded."
    return text, None
