"""Validate and seed the illustrative sample dataset into FalkorDB.

Every write uses MERGE on the node id, so seeding repeatedly never creates duplicates.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import SAMPLE_DATA_PATH
from graph import schema


class SeedError(RuntimeError):
    """Raised when the dataset is invalid or seeding fails."""


@dataclass
class SeedSummary:
    applications: int = 0
    components: int = 0
    packages: int = 0
    vulnerabilities: int = 0
    component_package_links: int = 0
    package_package_links: int = 0
    package_vulnerability_links: int = 0
    warnings: List[str] = field(default_factory=list)


_SECTIONS = (
    "applications",
    "components",
    "packages",
    "vulnerabilities",
    "dependencies",
    "package_dependencies",
    "package_vulnerabilities",
)


def load_dataset(path: Path = SAMPLE_DATA_PATH) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise SeedError(f"Sample dataset not found at {path}.") from exc
    except json.JSONDecodeError as exc:
        raise SeedError(f"Sample dataset is not valid JSON: {exc}") from exc
    validate_dataset(data)
    return data


def _check_vocab(problems: List[str], record: Dict[str, Any], key: str, allowed) -> None:
    value = record.get(key)
    if value is not None and value not in allowed:
        problems.append(f"{record.get('id')}: {key}={value!r} not in {list(allowed)}")


def validate_dataset(data: Any) -> None:
    """Raise SeedError listing every problem found in the dataset."""
    problems: List[str] = []
    if not isinstance(data, dict):
        raise SeedError("Dataset must be a JSON object.")
    for section in _SECTIONS:
        if not isinstance(data.get(section), list):
            problems.append(f"Missing or invalid section: {section}")
    if problems:
        raise SeedError("; ".join(problems))

    ids: Dict[str, set] = {}
    for section in ("applications", "components", "packages", "vulnerabilities"):
        seen: set = set()
        for record in data[section]:
            rid = record.get("id") if isinstance(record, dict) else None
            if not isinstance(rid, str) or not rid.strip():
                problems.append(f"{section}: record without a valid id: {record!r}")
                continue
            if rid in seen:
                problems.append(f"{section}: duplicate id {rid}")
            seen.add(rid)
        ids[section] = seen

    for record in data["applications"]:
        _check_vocab(problems, record, "exposure", schema.EXPOSURE_LEVELS)
        _check_vocab(problems, record, "criticality", schema.CRITICALITY_LEVELS)
    for record in data["vulnerabilities"]:
        _check_vocab(problems, record, "severity", schema.SEVERITIES)
        _check_vocab(problems, record, "exploit_evidence", schema.EXPLOIT_LEVELS)
    for record in data["components"]:
        if record.get("application_id") not in ids["applications"]:
            problems.append(f"{record.get('id')}: unknown application_id {record.get('application_id')!r}")
    for link in data["dependencies"]:
        if link.get("component_id") not in ids["components"]:
            problems.append(f"dependency references unknown component {link.get('component_id')!r}")
        if link.get("package_id") not in ids["packages"]:
            problems.append(f"dependency references unknown package {link.get('package_id')!r}")
    for link in data["package_dependencies"]:
        for key in ("from_package_id", "to_package_id"):
            if link.get(key) not in ids["packages"]:
                problems.append(f"package_dependency references unknown package {link.get(key)!r}")
    for link in data["package_vulnerabilities"]:
        if link.get("package_id") not in ids["packages"]:
            problems.append(f"package_vulnerability references unknown package {link.get('package_id')!r}")
        if link.get("vulnerability_id") not in ids["vulnerabilities"]:
            problems.append(
                f"package_vulnerability references unknown vulnerability {link.get('vulnerability_id')!r}"
            )
    if problems:
        raise SeedError("Dataset validation failed: " + "; ".join(problems))


_APPLICATION_CYPHER = """
MERGE (a:Application {id: $id})
SET a.name = $name, a.exposure = $exposure, a.criticality = $criticality,
    a.owner = $owner, a.description = $description, a.sample = true
"""

_COMPONENT_CYPHER = """
MERGE (c:Component {id: $id})
SET c.name = $name, c.kind = $kind, c.sample = true
"""

_PACKAGE_CYPHER = """
MERGE (p:Package {id: $id})
SET p.name = $name, p.version = $version, p.ecosystem = $ecosystem, p.sample = true
"""

_VULNERABILITY_CYPHER = """
MERGE (v:Vulnerability {id: $id})
SET v.title = $title, v.severity = $severity, v.exploit_evidence = $exploit_evidence,
    v.fixed_version = $fixed_version, v.description = $description,
    v.source = 'illustrative-sample', v.sample = true
"""

_HAS_COMPONENT_CYPHER = """
MATCH (a:Application {id: $application_id}), (c:Component {id: $component_id})
MERGE (a)-[:HAS_COMPONENT]->(c)
"""

_COMPONENT_DEPENDS_CYPHER = """
MATCH (c:Component {id: $component_id}), (p:Package {id: $package_id})
MERGE (c)-[:DEPENDS_ON]->(p)
"""

_PACKAGE_DEPENDS_CYPHER = """
MATCH (a:Package {id: $from_id}), (b:Package {id: $to_id})
MERGE (a)-[:DEPENDS_ON]->(b)
"""

_HAS_VULNERABILITY_CYPHER = """
MATCH (p:Package {id: $package_id}), (v:Vulnerability {id: $vulnerability_id})
MERGE (p)-[:HAS_VULNERABILITY]->(v)
"""


def seed_graph(graph, data: Optional[Dict[str, Any]] = None) -> SeedSummary:
    """Write the dataset into FalkorDB. Safe to run repeatedly."""
    dataset = data if data is not None else load_dataset()
    validate_dataset(dataset)
    summary = SeedSummary()
    try:
        summary.warnings = schema.ensure_schema(graph)

        for app in dataset["applications"]:
            graph.query(
                _APPLICATION_CYPHER,
                {
                    "id": app["id"],
                    "name": app.get("name"),
                    "exposure": app.get("exposure"),
                    "criticality": app.get("criticality"),
                    "owner": app.get("owner"),
                    "description": app.get("description"),
                },
            )
            summary.applications += 1

        for comp in dataset["components"]:
            graph.query(
                _COMPONENT_CYPHER,
                {"id": comp["id"], "name": comp.get("name"), "kind": comp.get("kind")},
            )
            graph.query(
                _HAS_COMPONENT_CYPHER,
                {"application_id": comp["application_id"], "component_id": comp["id"]},
            )
            summary.components += 1

        for pkg in dataset["packages"]:
            graph.query(
                _PACKAGE_CYPHER,
                {
                    "id": pkg["id"],
                    "name": pkg.get("name"),
                    "version": pkg.get("version"),
                    "ecosystem": pkg.get("ecosystem"),
                },
            )
            summary.packages += 1

        for vuln in dataset["vulnerabilities"]:
            graph.query(
                _VULNERABILITY_CYPHER,
                {
                    "id": vuln["id"],
                    "title": vuln.get("title"),
                    "severity": vuln.get("severity"),
                    "exploit_evidence": vuln.get("exploit_evidence"),
                    "fixed_version": vuln.get("fixed_version"),
                    "description": vuln.get("description"),
                },
            )
            summary.vulnerabilities += 1

        for link in dataset["dependencies"]:
            graph.query(
                _COMPONENT_DEPENDS_CYPHER,
                {"component_id": link["component_id"], "package_id": link["package_id"]},
            )
            summary.component_package_links += 1

        for link in dataset["package_dependencies"]:
            graph.query(
                _PACKAGE_DEPENDS_CYPHER,
                {"from_id": link["from_package_id"], "to_id": link["to_package_id"]},
            )
            summary.package_package_links += 1

        for link in dataset["package_vulnerabilities"]:
            graph.query(
                _HAS_VULNERABILITY_CYPHER,
                {"package_id": link["package_id"], "vulnerability_id": link["vulnerability_id"]},
            )
            summary.package_vulnerability_links += 1
    except SeedError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SeedError(f"Seeding failed part-way ({exc}). It is safe to retry.") from exc
    return summary


def clear_sample_data(graph) -> None:
    """Delete only nodes created by the sample seed (sample = true)."""
    try:
        graph.query("MATCH (n {sample: true}) DETACH DELETE n")
    except Exception as exc:  # noqa: BLE001
        raise SeedError(f"Could not delete sample data: {exc}") from exc
