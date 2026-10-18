"""All Cypher used by the application.

Rules followed here:
* Values always travel as query parameters ($name).
* The only text interpolated into Cypher comes from constants: labels checked against an
  allowlist, and hop counts checked against a fixed integer range.
* No user-supplied Cypher is ever executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from graph import schema

MAX_TRANSITIVE_HOPS = 2  # direct (0 extra hops), plus up to 2 package-to-package hops


class QueryError(RuntimeError):
    """Raised when FalkorDB fails to run a query."""


def run_query(graph, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[list]:
    """Run a read-only query and return result rows."""
    try:
        result = graph.ro_query(cypher, params or {})
    except Exception as exc:  # noqa: BLE001
        if "empty key" in str(exc).lower():
            return []  # the graph does not exist yet (nothing seeded)
        raise QueryError(f"FalkorDB query failed: {exc}") from exc
    return result.result_set


def _scalar(rows: List[list], default: int = 0) -> int:
    return int(rows[0][0]) if rows and rows[0] and rows[0][0] is not None else default


def _validate_label(label: str) -> str:
    if label not in schema.NODE_LABELS:
        raise ValueError(f"Unknown node label: {label!r}")
    return label


@dataclass(frozen=True)
class Exposure:
    """One path: Application -> Component -> Package (-> Package...) -> Vulnerability."""

    application_id: str
    application_name: str
    app_exposure: Optional[str]
    app_criticality: Optional[str]
    component_id: str
    component_name: str
    vulnerability_id: str
    vulnerability_title: Optional[str]
    severity: Optional[str]
    exploit_evidence: Optional[str]
    fixed_version: Optional[str]
    chain: Tuple[Tuple[str, str, str], ...]  # (package id, name, version): direct ... vulnerable

    @property
    def hops(self) -> int:
        return len(self.chain) - 1

    @property
    def is_direct(self) -> bool:
        return self.hops == 0

    @property
    def package_id(self) -> str:
        return self.chain[-1][0]

    @property
    def package_name(self) -> str:
        return self.chain[-1][1]

    @property
    def package_version(self) -> str:
        return self.chain[-1][2]

    def involves_package(self, package_id: str) -> bool:
        return any(item[0] == package_id for item in self.chain)


# ---------------------------------------------------------------- counts / lists

def count_nodes(graph) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for label in schema.NODE_LABELS:
        counts[label] = _scalar(run_query(graph, f"MATCH (n:{label}) RETURN count(n)"))
    return counts


def severity_counts(graph) -> Dict[str, int]:
    rows = run_query(graph, "MATCH (v:Vulnerability) RETURN v.severity, count(v)")
    result: Dict[str, int] = {}
    for severity, count in rows:
        key = severity if severity else "unknown"
        result[key] = result.get(key, 0) + int(count)
    return result


def list_vulnerabilities(graph) -> List[Dict[str, Optional[str]]]:
    rows = run_query(graph, "MATCH (v:Vulnerability) RETURN v.id, v.title, v.severity ORDER BY v.id")
    return [{"id": r[0], "title": r[1], "severity": r[2]} for r in rows]


def list_packages(graph) -> List[Dict[str, Optional[str]]]:
    rows = run_query(
        graph, "MATCH (p:Package) RETURN p.id, p.name, p.version, p.ecosystem ORDER BY p.name, p.version"
    )
    return [{"id": r[0], "name": r[1], "version": r[2], "ecosystem": r[3]} for r in rows]


def get_vulnerability(graph, vulnerability_id: str) -> Optional[Dict[str, Optional[str]]]:
    rows = run_query(
        graph,
        "MATCH (v:Vulnerability {id: $id}) "
        "RETURN v.id, v.title, v.severity, v.exploit_evidence, v.fixed_version, v.description",
        {"id": vulnerability_id},
    )
    if not rows:
        return None
    r = rows[0]
    return {
        "id": r[0],
        "title": r[1],
        "severity": r[2],
        "exploit_evidence": r[3],
        "fixed_version": r[4],
        "description": r[5],
    }


def get_package(graph, package_id: str) -> Optional[Dict[str, Optional[str]]]:
    rows = run_query(
        graph,
        "MATCH (p:Package {id: $id}) RETURN p.id, p.name, p.version, p.ecosystem",
        {"id": package_id},
    )
    if not rows:
        return None
    r = rows[0]
    return {"id": r[0], "name": r[1], "version": r[2], "ecosystem": r[3]}


def get_vulnerable_packages(graph, vulnerability_id: str) -> List[Dict[str, Optional[str]]]:
    rows = run_query(
        graph,
        "MATCH (p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability {id: $id}) "
        "RETURN p.id, p.name, p.version ORDER BY p.name",
        {"id": vulnerability_id},
    )
    return [{"id": r[0], "name": r[1], "version": r[2]} for r in rows]


# ---------------------------------------------------------------- exposure paths

_EXPOSURE_FIXED_COLUMNS = 11


def _exposure_query(hops: int, vulnerability_id: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    """Build the exposure query for a fixed number of package-to-package hops."""
    if not isinstance(hops, int) or isinstance(hops, bool) or not 0 <= hops <= MAX_TRANSITIVE_HOPS:
        raise ValueError(f"hops must be an integer between 0 and {MAX_TRANSITIVE_HOPS}")
    pattern = "(a:Application)-[:HAS_COMPONENT]->(c:Component)-[:DEPENDS_ON]->(p0:Package)"
    for i in range(1, hops + 1):
        pattern += f"-[:DEPENDS_ON]->(p{i}:Package)"
    pattern += "-[:HAS_VULNERABILITY]->(v:Vulnerability)"

    where = ""
    params: Dict[str, Any] = {}
    if vulnerability_id is not None:
        where = " WHERE v.id = $vulnerability_id"
        params["vulnerability_id"] = vulnerability_id

    returns = [
        "a.id", "a.name", "a.exposure", "a.criticality",
        "c.id", "c.name",
        "v.id", "v.title", "v.severity", "v.exploit_evidence", "v.fixed_version",
    ]
    for i in range(hops + 1):
        returns += [f"p{i}.id", f"p{i}.name", f"p{i}.version"]
    return f"MATCH {pattern}{where} RETURN {', '.join(returns)}", params


def _row_to_exposure(row: list, hops: int) -> Exposure:
    chain = []
    for i in range(hops + 1):
        base = _EXPOSURE_FIXED_COLUMNS + 3 * i
        chain.append((str(row[base]), str(row[base + 1] or ""), str(row[base + 2] or "")))
    return Exposure(
        application_id=row[0],
        application_name=row[1] or row[0],
        app_exposure=row[2],
        app_criticality=row[3],
        component_id=row[4],
        component_name=row[5] or row[4],
        vulnerability_id=row[6],
        vulnerability_title=row[7],
        severity=row[8],
        exploit_evidence=row[9],
        fixed_version=row[10],
        chain=tuple(chain),
    )


def find_exposures(graph, vulnerability_id: Optional[str] = None) -> List[Exposure]:
    """Find every Application->...->Vulnerability path (direct and transitive)."""
    best: Dict[Tuple[str, str, str, str], Exposure] = {}
    for hops in range(MAX_TRANSITIVE_HOPS + 1):
        cypher, params = _exposure_query(hops, vulnerability_id)
        for row in run_query(graph, cypher, params):
            exposure = _row_to_exposure(row, hops)
            key = (exposure.application_id, exposure.component_id, exposure.vulnerability_id, exposure.package_id)
            if key not in best:  # shortest path wins because hops ascend
                best[key] = exposure
    return sorted(
        best.values(),
        key=lambda e: (e.hops, e.application_name, e.component_name, e.vulnerability_id),
    )


def package_vulnerability_links(graph, package_id: str) -> List[Dict[str, Any]]:
    """Vulnerabilities on a package itself (hops=0) or on packages it depends on."""
    links: List[Dict[str, Any]] = []
    for hops in range(MAX_TRANSITIVE_HOPS + 1):
        pattern = "(p:Package {id: $package_id})"
        for i in range(1, hops + 1):
            pattern += f"-[:DEPENDS_ON]->(q{i}:Package)"
        last = "p" if hops == 0 else f"q{hops}"
        cypher = (
            f"MATCH {pattern}-[:HAS_VULNERABILITY]->(v:Vulnerability) "
            f"RETURN v.id, v.title, v.severity, {last}.id, {last}.name, {last}.version"
        )
        for r in run_query(graph, cypher, {"package_id": package_id}):
            links.append(
                {
                    "vulnerability_id": r[0],
                    "title": r[1],
                    "severity": r[2],
                    "package_id": r[3],
                    "package_name": r[4],
                    "package_version": r[5],
                    "hops": hops,
                }
            )
    return links


# ---------------------------------------------------------------- graph elements

NodeMap = Dict[str, Dict[str, Optional[str]]]
EdgeList = List[Tuple[str, str, str]]


def node_key(label: str, node_id: str) -> str:
    return f"{label}:{node_id}"


def get_graph_elements(graph) -> Tuple[NodeMap, EdgeList]:
    """Return all nodes and edges for the visualization."""
    nodes: NodeMap = {}
    for label in schema.NODE_LABELS:
        rows = run_query(
            graph,
            f"MATCH (n:{label}) RETURN n.id, coalesce(n.name, n.title), "
            "n.severity, n.exposure, n.criticality, n.version",
        )
        for r in rows:
            nodes[node_key(label, r[0])] = {
                "label": label, "id": r[0], "name": r[1],
                "severity": r[2], "exposure": r[3], "criticality": r[4], "version": r[5],
            }
    edges: EdgeList = []
    for src, rel, dst in schema.RELATIONSHIPS:
        rows = run_query(graph, f"MATCH (s:{src})-[:{rel}]->(t:{dst}) RETURN s.id, t.id")
        for s_id, t_id in rows:
            edges.append((node_key(src, s_id), rel, node_key(dst, t_id)))
    return nodes, edges


def elements_from_exposures(exposures: Sequence[Exposure]) -> Tuple[NodeMap, EdgeList]:
    """Build a focused subgraph from exposure paths (pure function, no database access)."""
    nodes: NodeMap = {}
    edges: set = set()
    for e in exposures:
        app = node_key("Application", e.application_id)
        comp = node_key("Component", e.component_id)
        vuln = node_key("Vulnerability", e.vulnerability_id)
        nodes[app] = {"label": "Application", "id": e.application_id, "name": e.application_name,
                      "exposure": e.app_exposure, "criticality": e.app_criticality}
        nodes[comp] = {"label": "Component", "id": e.component_id, "name": e.component_name}
        nodes[vuln] = {"label": "Vulnerability", "id": e.vulnerability_id,
                       "name": e.vulnerability_title, "severity": e.severity}
        edges.add((app, schema.REL_HAS_COMPONENT, comp))
        previous = comp
        for pkg_id, pkg_name, pkg_version in e.chain:
            pkg = node_key("Package", pkg_id)
            nodes[pkg] = {"label": "Package", "id": pkg_id, "name": pkg_name, "version": pkg_version}
            edges.add((previous, schema.REL_DEPENDS_ON, pkg))
            previous = pkg
        edges.add((previous, schema.REL_HAS_VULNERABILITY, vuln))
    return nodes, sorted(edges)


# ---------------------------------------------------------------- node inspection

def list_node_ids(graph, label: str) -> List[Dict[str, Optional[str]]]:
    label = _validate_label(label)
    rows = run_query(graph, f"MATCH (n:{label}) RETURN n.id, coalesce(n.name, n.title) ORDER BY n.id")
    return [{"id": r[0], "name": r[1]} for r in rows]


def get_node(graph, label: str, node_id: str) -> Optional[Dict[str, Any]]:
    label = _validate_label(label)
    rows = run_query(graph, f"MATCH (n:{label} {{id: $id}}) RETURN n", {"id": node_id})
    if not rows:
        return None
    return dict(rows[0][0].properties)


def get_node_relationships(graph, label: str, node_id: str) -> List[Dict[str, Optional[str]]]:
    label = _validate_label(label)
    found: List[Dict[str, Optional[str]]] = []
    for src, rel, dst in schema.RELATIONSHIPS:
        if src == label:
            rows = run_query(
                graph,
                f"MATCH (n:{src} {{id: $id}})-[:{rel}]->(m:{dst}) RETURN m.id, coalesce(m.name, m.title)",
                {"id": node_id},
            )
            found += [{"direction": "outgoing", "relationship": rel, "label": dst, "id": r[0], "name": r[1]}
                      for r in rows]
        if dst == label:
            rows = run_query(
                graph,
                f"MATCH (m:{src})-[:{rel}]->(n:{dst} {{id: $id}}) RETURN m.id, coalesce(m.name, m.title)",
                {"id": node_id},
            )
            found += [{"direction": "incoming", "relationship": rel, "label": src, "id": r[0], "name": r[1]}
                      for r in rows]
    return found
