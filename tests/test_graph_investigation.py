"""Investigation tests.

Most tests replace the query functions with canned data, so they check the investigation
logic (query first, score, explain, never claim safety) without a database. The final
tests are integration tests that run against a real FalkorDB and are skipped when none is
reachable. They use a separate graph, never your main one.
"""
import copy
import dataclasses
import os

import pytest

from config import load_falkor_settings
from graph import queries, seed_data
from graph.queries import Exposure
from investigator import explanations, graph_context
from investigator.graph_context import InvestigationError

VULN = {
    "id": "DEMO-VULN-900", "title": "Illustrative test flaw", "severity": "high",
    "exploit_evidence": "public-poc", "fixed_version": "2.0.0", "description": "test",
}


def make_exposure(**overrides):
    base = dict(
        application_id="app-a", application_name="App A", app_exposure="internet-facing",
        app_criticality="critical", component_id="comp-a", component_name="Comp A",
        vulnerability_id="DEMO-VULN-900", vulnerability_title="Illustrative test flaw",
        severity="high", exploit_evidence="public-poc", fixed_version="2.0.0",
        chain=(("pkg-x", "lib-x", "1.0.0"),),
    )
    base.update(overrides)
    return Exposure(**base)


@pytest.fixture
def fake_queries(monkeypatch):
    calls = []
    state = {"exposures": [], "packages": [{"id": "pkg-x", "name": "lib-x", "version": "1.0.0"}], "links": []}

    def get_vulnerability(graph, vid):
        calls.append("get_vulnerability")
        return dict(VULN) if vid == VULN["id"] else None

    def get_vulnerable_packages(graph, vid):
        calls.append("get_vulnerable_packages")
        return state["packages"]

    def find_exposures(graph, vulnerability_id=None):
        calls.append("find_exposures")
        return state["exposures"]

    def get_package(graph, pid):
        calls.append("get_package")
        return {"id": pid, "name": "lib-a", "version": "1.0.0", "ecosystem": "pypi"} if pid == "pkg-a" else None

    def package_vulnerability_links(graph, pid):
        calls.append("package_vulnerability_links")
        return state["links"]

    monkeypatch.setattr(queries, "get_vulnerability", get_vulnerability)
    monkeypatch.setattr(queries, "get_vulnerable_packages", get_vulnerable_packages)
    monkeypatch.setattr(queries, "find_exposures", find_exposures)
    monkeypatch.setattr(queries, "get_package", get_package)
    monkeypatch.setattr(queries, "package_vulnerability_links", package_vulnerability_links)
    return calls, state


def test_report_queries_graph_before_building_findings(fake_queries):
    calls, state = fake_queries
    state["exposures"] = [
        make_exposure(application_id="app-b", application_name="App B", app_exposure="internal", app_criticality="low"),
        make_exposure(),
    ]
    report = graph_context.investigate_vulnerability(object(), "DEMO-VULN-900")
    assert calls[:3] == ["get_vulnerability", "get_vulnerable_packages", "find_exposures"]
    assert report.queries_run and len(report.queries_run) == 3
    assert report.found
    scores = [f.score.score for f in report.findings]
    assert scores == sorted(scores, reverse=True)
    assert report.findings[0].exposure.application_id == "app-a"


def test_direct_and_transitive_are_distinguished(fake_queries):
    _, state = fake_queries
    state["exposures"] = [
        make_exposure(),
        make_exposure(application_id="app-c", application_name="App C",
                      chain=(("pkg-y", "lib-y", "3.0.0"), ("pkg-x", "lib-x", "1.0.0"))),
    ]
    report = graph_context.investigate_vulnerability(object(), "DEMO-VULN-900")
    kinds = {f.exposure.application_id: f.explanation.dependency_type for f in report.findings}
    assert kinds["app-a"].startswith("Direct")
    assert kinds["app-c"].startswith("Transitive")
    assert "lib-y@3.0.0" in kinds["app-c"]


def test_unknown_vulnerability_is_reported_as_not_found(fake_queries):
    report = graph_context.investigate_vulnerability(object(), "DEMO-VULN-404")
    assert report.found is False
    assert report.findings == []
    assert "not found" in report.summary.lower()


def test_no_exposure_is_not_claimed_as_safe(fake_queries):
    report = graph_context.investigate_vulnerability(object(), "DEMO-VULN-900")
    assert report.findings == []
    assert "not evidence of safety" in report.summary.lower()
    assert report.missing_information and report.next_steps


def test_missing_exposure_is_flagged_not_assumed_safe(fake_queries):
    _, state = fake_queries
    state["exposures"] = [make_exposure(app_exposure=None)]
    finding = graph_context.investigate_vulnerability(object(), "DEMO-VULN-900").findings[0]
    assert "exposure" in finding.score.missing_factors
    assert any("exposure" in item.lower() for item in finding.explanation.missing_information)
    assert finding.score.confidence == "Medium"


def test_invalid_identifiers_are_rejected(fake_queries):
    for bad in ("", "   ", "x; MATCH (n) DETACH DELETE n", "a" * 200):
        with pytest.raises(InvestigationError):
            graph_context.investigate_vulnerability(object(), bad)
        with pytest.raises(InvestigationError):
            graph_context.investigate_package(object(), bad)


def test_package_report_only_includes_paths_through_that_package(fake_queries):
    _, state = fake_queries
    state["links"] = [{"vulnerability_id": "DEMO-VULN-900", "title": "t", "severity": "high",
                       "package_id": "pkg-b", "package_name": "lib-b", "package_version": "1.0.0", "hops": 1}]
    through = make_exposure(chain=(("pkg-a", "lib-a", "1.0.0"), ("pkg-b", "lib-b", "1.0.0")))
    unrelated = make_exposure(application_id="app-z", application_name="App Z",
                              chain=(("pkg-q", "lib-q", "1.0.0"), ("pkg-b", "lib-b", "1.0.0")))
    state["exposures"] = [through, unrelated]
    report = graph_context.investigate_package(object(), "pkg-a")
    assert [f.exposure.application_id for f in report.findings] == ["app-a"]


def test_package_without_links_is_not_claimed_safe(fake_queries):
    report = graph_context.investigate_package(object(), "pkg-a")
    assert "not evidence of safety" in report.summary.lower()


def test_llm_output_with_invented_identifiers_is_rejected():
    facts = '{"vulnerability_id": "DEMO-VULN-900", "risk_score": 88.5}'
    assert explanations.validate_llm_text("DEMO-VULN-900 scores 88.5 in this dataset.", facts)
    assert not explanations.validate_llm_text("This is CVE-2099-12345, a real issue.", facts)
    assert not explanations.validate_llm_text("It affects versions 9.9.9 and earlier.", facts)


def test_exposure_query_uses_parameters_and_validates_hops():
    cypher, params = queries._exposure_query(1, "DEMO-VULN-001")
    assert "$vulnerability_id" in cypher
    assert "DEMO-VULN-001" not in cypher
    assert params == {"vulnerability_id": "DEMO-VULN-001"}
    for bad in (-1, queries.MAX_TRANSITIVE_HOPS + 1, "1", True):
        with pytest.raises(ValueError):
            queries._exposure_query(bad)


def test_node_label_allowlist_blocks_injection():
    with pytest.raises(ValueError):
        queries.get_node(None, "Application) DETACH DELETE n //", "x")
    with pytest.raises(ValueError):
        queries.list_node_ids(None, "Anything")


def test_sample_dataset_is_valid_and_clearly_illustrative():
    data = seed_data.load_dataset()
    assert all(v["id"].startswith("DEMO-VULN-") for v in data["vulnerabilities"])
    assert "illustrative" in data["dataset_label"].lower()


def test_dataset_validation_catches_broken_references():
    data = copy.deepcopy(seed_data.load_dataset())
    data["dependencies"].append({"component_id": "comp-portal-api", "package_id": "pkg-does-not-exist"})
    with pytest.raises(seed_data.SeedError):
        seed_data.validate_dataset(data)


# ----------------------------------------------------------------- integration (real FalkorDB)

@pytest.fixture(scope="module")
def live_graph():
    try:
        from graph.connection import connect

        base = load_falkor_settings()
        test_name = os.getenv("FALKORDB_TEST_GRAPH", "appsec_investigator_test")
        if test_name == base.graph_name:
            pytest.skip("FALKORDB_TEST_GRAPH must differ from FALKORDB_GRAPH to protect your data.")
        connection = connect(dataclasses.replace(base, graph_name=test_name))
    except pytest.skip.Exception:
        raise
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"FalkorDB not available: {exc}")
    yield connection.graph
    try:
        connection.graph.delete()
    except Exception:  # noqa: BLE001
        pass


def _edge_count(graph):
    return queries.run_query(graph, "MATCH ()-[r]->() RETURN count(r)")[0][0]


def test_seeding_twice_creates_no_duplicates(live_graph):
    data = seed_data.load_dataset()
    seed_data.seed_graph(live_graph, data)
    nodes_first, edges_first = queries.count_nodes(live_graph), _edge_count(live_graph)
    seed_data.seed_graph(live_graph, data)
    assert queries.count_nodes(live_graph) == nodes_first
    assert _edge_count(live_graph) == edges_first
    assert nodes_first["Application"] == len(data["applications"])
    assert nodes_first["Vulnerability"] == len(data["vulnerabilities"])


def test_end_to_end_investigation_against_falkordb(live_graph):
    seed_data.seed_graph(live_graph)
    report = graph_context.investigate_vulnerability(live_graph, "DEMO-VULN-001")
    assert report.found
    paths = {(f.exposure.application_id, f.exposure.hops) for f in report.findings}
    assert paths == {("app-portal", 0), ("app-payments", 1)}
    assert report.queries_run


def test_missing_application_exposure_is_visible_end_to_end(live_graph):
    seed_data.seed_graph(live_graph)
    report = graph_context.investigate_vulnerability(live_graph, "DEMO-VULN-006")
    legacy = [f for f in report.findings if f.exposure.application_id == "app-legacy"]
    assert legacy and "exposure" in legacy[0].score.missing_factors
