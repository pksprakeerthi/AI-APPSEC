"""Investigation workflow: query FalkorDB first, then score and explain.

Every report records the graph queries that were run, so the evidence trail is visible.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from graph import queries
from graph.queries import Exposure
from investigator import explanations, risk_scoring
from investigator.explanations import FindingExplanation, package_label
from investigator.risk_scoring import RiskScore

_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:@+\-]{1,128}$")
_COVERAGE_GAP = (
    "Coverage of the graph itself is unknown: applications or components not loaded, undeclared dependencies, "
    f"container base images and dependencies deeper than {queries.MAX_TRANSITIVE_HOPS} hops are not covered."
)


class InvestigationError(ValueError):
    """Raised for invalid investigation input."""


def clean_identifier(value: Optional[str], field_name: str = "identifier") -> str:
    if value is None or not str(value).strip():
        raise InvestigationError(f"{field_name} must not be empty.")
    text = str(value).strip()
    if not _ID_PATTERN.match(text):
        raise InvestigationError(
            f"{field_name} may only contain letters, digits and . _ : @ + - (max 128 characters)."
        )
    return text


@dataclass(frozen=True)
class Finding:
    exposure: Exposure
    score: RiskScore
    explanation: FindingExplanation


@dataclass
class InvestigationReport:
    subject_type: str  # "vulnerability" or "package"
    subject_id: str
    found: bool
    title: str
    summary: str
    subject: Optional[Dict[str, Optional[str]]] = None
    findings: List[Finding] = field(default_factory=list)
    related: List[Dict[str, Any]] = field(default_factory=list)
    queries_run: List[str] = field(default_factory=list)
    missing_information: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    @property
    def affected_applications(self) -> List[str]:
        return sorted({f.exposure.application_name for f in self.findings})

    @property
    def highest_score(self) -> Optional[float]:
        return max((f.score.score for f in self.findings), default=None)


@dataclass
class DashboardData:
    counts: Dict[str, int]
    severity_counts: Dict[str, int]
    findings: List[Finding]

    @property
    def is_empty(self) -> bool:
        return sum(self.counts.values()) == 0


def score_exposure(e: Exposure) -> RiskScore:
    return risk_scoring.score_finding(e.severity, e.app_exposure, e.exploit_evidence, e.app_criticality)


def build_findings(exposures: Sequence[Exposure]) -> List[Finding]:
    findings = []
    for e in exposures:
        score = score_exposure(e)
        findings.append(Finding(exposure=e, score=score, explanation=explanations.explain_finding(e, score)))
    findings.sort(key=lambda f: (-f.score.score, f.exposure.application_name, f.exposure.vulnerability_id))
    return findings


def _merge_unique(lists: Sequence[Sequence[str]]) -> List[str]:
    seen: List[str] = []
    for items in lists:
        for item in items:
            if item not in seen:
                seen.append(item)
    return seen


def _investigation_plan(findings: Sequence[Finding]) -> List[str]:
    top = findings[0]
    e = top.exposure
    plan = [
        f"Start with the highest-risk path: {e.application_name} → {e.component_name} "
        f"({package_label(e.package_name, e.package_version)}), score {top.score.score:.1f} ({top.score.priority}).",
        "Confirm installed versions from lockfiles or SBOMs for every affected component listed.",
    ]
    if any(not f.exposure.is_direct for f in findings):
        plan.append("For transitive paths, identify which direct dependency pulls in the vulnerable package and whether it can be upgraded or overridden.")
    if any(f.score.missing_factors for f in findings):
        plan.append("Fill in the missing application and vulnerability metadata, then re-run to refine the scores.")
    plan.append("Check reachability of the vulnerable code in each affected application.")
    return plan


def _no_exposure_gaps() -> List[str]:
    return [_COVERAGE_GAP]


def _no_exposure_steps() -> List[str]:
    return [
        "Cross-check with SBOMs, lockfiles and other scanners to confirm the graph is complete.",
        "Add any missing applications, components and dependencies to the graph and re-run.",
    ]


def investigate_vulnerability(graph, vulnerability_id: str) -> InvestigationReport:
    """Query the graph for a vulnerability, then build the evidence-based report."""
    vid = clean_identifier(vulnerability_id, "Vulnerability id")
    log: List[str] = []

    vuln = queries.get_vulnerability(graph, vid)
    log.append(f"get_vulnerability(id={vid!r})")
    if vuln is None:
        return InvestigationReport(
            subject_type="vulnerability", subject_id=vid, found=False, title=vid,
            summary=f"{vid} was not found in the graph. Nothing can be concluded about it.",
            queries_run=log,
        )

    packages = queries.get_vulnerable_packages(graph, vid)
    log.append(f"get_vulnerable_packages(vulnerability_id={vid!r})")
    exposures = queries.find_exposures(graph, vulnerability_id=vid)
    log.append(f"find_exposures(vulnerability_id={vid!r}, max_transitive_hops={queries.MAX_TRANSITIVE_HOPS})")

    findings = build_findings(exposures)
    title = f"{vid}: {vuln['title']}" if vuln.get("title") else vid
    apps = sorted({f.exposure.application_name for f in findings})

    if findings:
        top = findings[0]
        summary = (
            f"{vid} (severity: {vuln.get('severity') or 'not recorded'}) is attached to {len(packages)} package(s) "
            f"and reaches {len(apps)} application(s) through {len(findings)} dependency path(s). "
            f"Highest score: {top.score.score:.1f} ({top.score.priority}) on {top.exposure.application_name}."
        )
        missing = _merge_unique([f.explanation.missing_information for f in findings])
        steps = _investigation_plan(findings)
    else:
        if packages:
            summary = (
                f"{vid} is attached to {len(packages)} package(s), but no application in the graph depends on "
                "them within the searched depth. That is not evidence of safety; the graph may be incomplete."
            )
        else:
            summary = (
                f"{vid} exists in the graph but is not attached to any package, so no application exposure could be "
                "traced. That is not evidence of safety."
            )
        missing, steps = _no_exposure_gaps(), _no_exposure_steps()

    return InvestigationReport(
        subject_type="vulnerability", subject_id=vid, found=True, title=title, summary=summary,
        subject=vuln, findings=findings, related=list(packages), queries_run=log,
        missing_information=missing, next_steps=steps,
    )


def investigate_package(graph, package_id: str) -> InvestigationReport:
    """Query the graph for a package (and what it pulls in), then build the report."""
    pid = clean_identifier(package_id, "Package id")
    log: List[str] = []

    pkg = queries.get_package(graph, pid)
    log.append(f"get_package(id={pid!r})")
    if pkg is None:
        return InvestigationReport(
            subject_type="package", subject_id=pid, found=False, title=pid,
            summary=f"Package {pid} was not found in the graph. Nothing can be concluded about it.",
            queries_run=log,
        )

    title = package_label(pkg.get("name"), pkg.get("version"))
    links = queries.package_vulnerability_links(graph, pid)
    log.append(f"package_vulnerability_links(package_id={pid!r}, max_transitive_hops={queries.MAX_TRANSITIVE_HOPS})")

    exposures: List[Exposure] = []
    for vuln_id in sorted({link["vulnerability_id"] for link in links}):
        for e in queries.find_exposures(graph, vulnerability_id=vuln_id):
            log.append(f"find_exposures(vulnerability_id={vuln_id!r})")
            if e.involves_package(pid):
                exposures.append(e)
    findings = build_findings(exposures)

    if not links:
        summary = (
            f"No vulnerabilities are recorded for {title} or for the packages it depends on "
            f"(up to {queries.MAX_TRANSITIVE_HOPS} hops). This is not evidence of safety; the dataset may be incomplete."
        )
        missing, steps = _no_exposure_gaps(), _no_exposure_steps()
    else:
        own = sum(1 for link in links if link["hops"] == 0)
        inherited = len(links) - own
        apps = sorted({f.exposure.application_name for f in findings})
        summary = (
            f"{title} has {own} vulnerabilit{'y' if own == 1 else 'ies'} recorded directly and {inherited} through "
            f"packages it depends on. It is involved in {len(findings)} exposure path(s) across {len(apps)} application(s)."
        )
        if findings:
            missing = _merge_unique([f.explanation.missing_information for f in findings])
            steps = _investigation_plan(findings)
        else:
            missing, steps = _no_exposure_gaps(), _no_exposure_steps()

    return InvestigationReport(
        subject_type="package", subject_id=pid, found=True, title=title, summary=summary,
        subject=pkg, findings=findings, related=links, queries_run=log,
        missing_information=missing, next_steps=steps,
    )


def load_dashboard(graph) -> DashboardData:
    """Query FalkorDB for dashboard counts and scored findings."""
    counts = queries.count_nodes(graph)
    if sum(counts.values()) == 0:
        return DashboardData(counts=counts, severity_counts={}, findings=[])
    return DashboardData(
        counts=counts,
        severity_counts=queries.severity_counts(graph),
        findings=build_findings(queries.find_exposures(graph)),
    )


def report_to_facts(report: InvestigationReport, limit: int = 10) -> Dict[str, Any]:
    """Flatten a report into a JSON-safe fact bundle for the optional LLM narrative."""

    def recorded(value: Optional[str]) -> str:
        return value if value else "not recorded"

    findings = []
    for f in report.findings[:limit]:
        e = f.exposure
        findings.append(
            {
                "application": e.application_name,
                "component": e.component_name,
                "dependency_chain": [package_label(n, v) for _, n, v in e.chain],
                "dependency_type": "direct" if e.is_direct else f"transitive ({e.hops} hops)",
                "vulnerability_id": e.vulnerability_id,
                "severity": recorded(e.severity),
                "exploit_evidence": recorded(e.exploit_evidence),
                "application_exposure": recorded(e.app_exposure),
                "business_criticality": recorded(e.app_criticality),
                "fixed_version": recorded(e.fixed_version),
                "risk_score": f.score.score,
                "priority": f.score.priority,
                "missing_inputs": list(f.score.missing_factors),
            }
        )
    return {
        "subject_type": report.subject_type,
        "subject": report.title,
        "summary": report.summary,
        "findings": findings,
        "graph_queries_run": report.queries_run,
    }
