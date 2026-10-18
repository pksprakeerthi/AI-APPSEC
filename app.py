"""Streamlit entry point: AI Application Security Risk Investigator."""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import config
from graph import queries, schema
from graph.connection import GraphConnectionError, connect
from graph.queries import QueryError
from graph.seed_data import SeedError, clear_sample_data, seed_graph
from graph.visualize import LEGEND, render_graph_html
from investigator import explanations, graph_context, risk_scoring
from investigator.explanations import package_label
from investigator.graph_context import Finding, InvestigationError, InvestigationReport

st.set_page_config(page_title="AppSec Risk Investigator", page_icon="🛡️", layout="wide")

PAGES = ["Dashboard", "Investigate", "Graph explorer", "Risk scoring method"]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "unknown": "⚪"}
PRIORITY_ICON = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "🟢"}

CUSTOM_CSS = """
<style>
.block-container {padding-top: 2rem;}
.hero {background: linear-gradient(90deg, #111827 0%, #1e3a5f 100%); padding: 1.1rem 1.4rem;
       border-radius: 10px; margin-bottom: 1rem; border: 1px solid #1f2937;}
.hero h2 {margin: 0; color: #f3f4f6;}
.hero p {margin: 0.2rem 0 0 0; color: #93c5fd;}
</style>
"""


# ------------------------------------------------------------------ connection

def get_connection_state() -> Dict[str, Any]:
    """Connect once per session; a failed attempt stays visible until the user retries."""
    if "conn" not in st.session_state:
        try:
            settings = config.load_falkor_settings()
            connection = connect(settings)
            st.session_state["conn"] = {"connection": connection, "error": None, "settings": settings}
        except (config.ConfigError, GraphConnectionError) as exc:
            st.session_state["conn"] = {"connection": None, "error": str(exc), "settings": None}
    return st.session_state["conn"]


def retry_connection() -> None:
    st.session_state.pop("conn", None)
    st.rerun()


# ------------------------------------------------------------------ helpers

def _bullets(items: Sequence[str]) -> None:
    st.markdown("\n".join(f"- {item}" for item in items))


def _numbered(items: Sequence[str]) -> None:
    st.markdown("\n".join(f"{i}. {item}" for i, item in enumerate(items, start=1)))


def _display(value: Any, default: str = "not recorded") -> str:
    return str(value) if value else default


def findings_dataframe(findings: Sequence[Finding]) -> pd.DataFrame:
    rows = []
    for f in findings:
        e = f.exposure
        rows.append(
            {
                "Priority": f"{PRIORITY_ICON.get(f.score.priority, '')} {f.score.priority}",
                "Score": f.score.score,
                "Application": e.application_name,
                "Component": e.component_name,
                "Package": package_label(e.package_name, e.package_version),
                "Vulnerability": e.vulnerability_id,
                "Severity": f"{SEVERITY_ICON.get((e.severity or 'unknown').lower(), '⚪')} {_display(e.severity, 'unknown')}",
                "Dependency": "direct" if e.is_direct else f"transitive ({e.hops})",
                "Data completeness": f.score.confidence,
            }
        )
    return pd.DataFrame(rows)


def render_empty_state() -> None:
    st.info(
        "The graph is empty. Click **Seed sample data** in the sidebar to load the illustrative dataset into "
        "FalkorDB, or load your own records."
    )


def render_graph(nodes, edges, height: int = 560) -> None:
    if not nodes:
        st.info("There is nothing to draw yet.")
        return
    components.html(render_graph_html(nodes, edges, height_px=height), height=height + 20, scrolling=False)
    st.caption(LEGEND)


# ------------------------------------------------------------------ sidebar

def render_sidebar(state: Dict[str, Any]) -> str:
    st.sidebar.title("🛡️ AppSec Investigator")
    st.sidebar.caption(config.APP_TAGLINE)

    connection = state["connection"]
    if connection is not None:
        s = connection.settings
        st.sidebar.success(f"FalkorDB connected\n\n{s.host}:{s.port} · graph '{s.graph_name}'")
    else:
        st.sidebar.error("FalkorDB unavailable")
    if st.sidebar.button("Retry connection"):
        retry_connection()

    page = st.sidebar.radio("Navigate", PAGES, key="nav_page")

    if connection is not None:
        st.sidebar.divider()
        st.sidebar.markdown("**Sample data**")
        st.sidebar.caption("Illustrative, fictional records. Seeding is safe to repeat.")
        if st.sidebar.button("Seed sample data"):
            try:
                summary = seed_graph(connection.graph)
                st.sidebar.success(
                    f"Seeded {summary.applications} applications, {summary.components} components, "
                    f"{summary.packages} packages, {summary.vulnerabilities} vulnerabilities."
                )
                for warning in summary.warnings:
                    st.sidebar.warning(warning)
            except SeedError as exc:
                st.sidebar.error(str(exc))
        with st.sidebar.expander("Danger zone"):
            confirmed = st.checkbox("I understand this deletes the sample nodes", key="confirm_clear")
            if st.button("Delete sample data", disabled=not confirmed):
                try:
                    clear_sample_data(connection.graph)
                    st.success("Sample data deleted.")
                except SeedError as exc:
                    st.error(str(exc))
    return page


def render_connection_problem(state: Dict[str, Any]) -> None:
    st.error(f"Cannot use FalkorDB: {state['error']}")
    st.markdown(
        "**What you can do**\n"
        "1. Start FalkorDB locally: `docker run -p 6379:6379 -p 3000:3000 -it --rm falkordb/falkordb:latest`\n"
        "2. Or create a FalkorDB Cloud instance and put its host, port, username and password in `.env`.\n"
        "3. Press **Retry connection** in the sidebar.\n\n"
        "The app does not fall back to fake data, because that would hide the problem."
    )
    if st.button("Retry connection", key="retry_main"):
        retry_connection()


# ------------------------------------------------------------------ dashboard

def render_dashboard(graph) -> None:
    data = graph_context.load_dashboard(graph)
    if data.is_empty:
        render_empty_state()
        return

    cols = st.columns(4)
    for col, (title, key) in zip(
        cols,
        [("Applications", "Application"), ("Components", "Component"),
         ("Packages", "Package"), ("Vulnerabilities", "Vulnerability")],
    ):
        col.metric(title, data.counts.get(key, 0))

    st.subheader("Vulnerabilities by severity")
    present = [s for s in SEVERITY_ORDER if s in data.severity_counts]
    if present:
        left, right = st.columns([1, 2])
        with left:
            for severity in present:
                st.metric(f"{SEVERITY_ICON[severity]} {severity.title()}", data.severity_counts[severity])
        with right:
            chart = pd.DataFrame({"count": [data.severity_counts[s] for s in present]}, index=present)
            st.bar_chart(chart)
    else:
        st.info("No vulnerabilities in the graph yet.")

    st.subheader("Highest-priority findings")
    if not data.findings:
        st.info(
            "No application in the graph currently reaches a vulnerable package. That is not proof of safety: "
            "the graph only knows what has been loaded into it."
        )
        return
    limit = st.slider("Findings to show", min_value=5, max_value=50, value=10, step=5, key="dash_limit")
    st.dataframe(findings_dataframe(data.findings[:limit]), hide_index=True)
    st.caption(
        "Scores come from a transparent heuristic (see 'Risk scoring method'). Rows with lower data completeness "
        "used neutral values for missing inputs; that is not evidence of safety."
    )


# ------------------------------------------------------------------ investigation

def render_finding(finding: Finding) -> None:
    e, score, x = finding.exposure, finding.score, finding.explanation
    left, right = st.columns([2, 1])
    with left:
        st.markdown("**Relationship path**")
        st.code(x.path, language=None)
        st.markdown(f"**Dependency type:** {x.dependency_type}")
        st.markdown("**Why it matters**")
        st.write(x.why_it_matters)
        st.markdown("**Evidence from the graph**")
        _bullets(x.evidence)
    with right:
        st.metric("Risk score", f"{score.score:.1f} / 100")
        st.markdown(f"**Priority {score.priority}**: {score.action}")
        st.markdown(f"**Data completeness:** {score.confidence}")
        st.markdown("**Missing information**")
        _bullets(x.missing_information)
    st.markdown("**Recommended next steps**")
    _numbered(x.next_steps)
    breakdown = pd.DataFrame(
        [
            {
                "Factor": f.name,
                "Input": f.input_value or "not recorded",
                "Factor value": f.factor,
                "Weight": f.weight,
                "Points": round(f.points, 1),
                "Note": f.note,
            }
            for f in score.factors
        ]
    )
    st.dataframe(breakdown, hide_index=True)


def render_llm_section(report: InvestigationReport) -> None:
    llm = config.load_llm_settings()
    if not llm.enabled:
        st.caption("Optional AI narrative is off (no ANTHROPIC_API_KEY). Deterministic explanations are shown below.")
        return
    state_key = f"llm_{report.subject_type}_{report.subject_id}"
    if st.button("Generate optional AI narrative", key=f"btn_{state_key}"):
        with st.spinner("Asking the LLM to summarise the graph evidence..."):
            st.session_state[state_key] = explanations.generate_llm_summary(
                graph_context.report_to_facts(report), llm
            )
    if state_key in st.session_state:
        text, warning = st.session_state[state_key]
        if text:
            st.markdown("**AI narrative (rephrases the evidence below; verify against the findings)**")
            st.write(text)
        if warning:
            st.warning(warning)


def render_report(report: InvestigationReport) -> None:
    with st.expander("Graph queries executed before this report was written"):
        st.code("\n".join(report.queries_run), language=None)
    if not report.found:
        st.warning(report.summary)
        return

    st.markdown(f"### {report.title}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Affected applications", len(report.affected_applications))
    c2.metric("Exposure paths", len(report.findings))
    top = report.highest_score
    c3.metric("Highest risk score", f"{top:.1f}" if top is not None else "n/a")
    st.info(report.summary)
    render_llm_section(report)

    if report.findings:
        st.markdown("#### Findings (highest risk first)")
        for finding in report.findings:
            e = finding.exposure
            label = (
                f"{PRIORITY_ICON.get(finding.score.priority, '')} {finding.score.priority} · "
                f"{finding.score.score:.1f} · {e.application_name} → {e.component_name} · "
                f"{package_label(e.package_name, e.package_version)} · "
                f"{'direct' if e.is_direct else 'transitive'} · {e.vulnerability_id}"
            )
            with st.expander(label):
                render_finding(finding)
        st.markdown("#### Investigation graph")
        nodes, edges = queries.elements_from_exposures([f.exposure for f in report.findings])
        render_graph(nodes, edges, height=480)

    st.markdown("#### What information is missing")
    _bullets(report.missing_information)
    st.markdown("#### What to investigate next")
    _numbered(report.next_steps)


def render_investigate(graph) -> None:
    st.subheader("AI security investigation")
    st.caption("The investigator queries FalkorDB first, then scores and explains only what the graph returned.")
    mode = st.radio("Investigate a", ["Vulnerability", "Package"], horizontal=True, key="inv_mode")

    if mode == "Vulnerability":
        items = queries.list_vulnerabilities(graph)
        if not items:
            render_empty_state()
            return
        labels = {
            i["id"]: f"{i['id']} · {i['title'] or 'untitled'} [{i['severity'] or 'unknown'}]" for i in items
        }
    else:
        items = queries.list_packages(graph)
        if not items:
            render_empty_state()
            return
        labels = {i["id"]: f"{package_label(i['name'], i['version'])} ({i['ecosystem'] or 'unknown ecosystem'})" for i in items}

    selected = st.selectbox(
        f"Select a {mode.lower()}", options=list(labels), format_func=lambda key: labels[key], key=f"inv_select_{mode}"
    )
    try:
        if mode == "Vulnerability":
            report = graph_context.investigate_vulnerability(graph, selected)
        else:
            report = graph_context.investigate_package(graph, selected)
    except InvestigationError as exc:
        st.error(str(exc))
        return
    render_report(report)


# ------------------------------------------------------------------ graph explorer

def render_graph_explorer(graph) -> None:
    st.subheader("Graph explorer")
    counts = queries.count_nodes(graph)
    if sum(counts.values()) == 0:
        render_empty_state()
        return

    scope = st.radio("Show", ["Entire graph", "One vulnerability"], horizontal=True, key="gx_scope")
    if scope == "Entire graph":
        nodes, edges = queries.get_graph_elements(graph)
    else:
        vulns = queries.list_vulnerabilities(graph)
        if not vulns:
            st.info("No vulnerabilities in the graph yet.")
            return
        labels = {v["id"]: f"{v['id']} · {v['title'] or 'untitled'}" for v in vulns}
        chosen = st.selectbox("Vulnerability", options=list(labels), format_func=lambda k: labels[k], key="gx_vuln")
        exposures = queries.find_exposures(graph, vulnerability_id=chosen)
        if not exposures:
            st.info("No application reaches this vulnerability in the graph.")
            return
        nodes, edges = queries.elements_from_exposures(exposures)
    render_graph(nodes, edges)

    st.markdown("#### Inspect a node")
    label = st.selectbox("Node type", list(schema.NODE_LABELS), key="gx_label")
    choices = queries.list_node_ids(graph, label)
    if not choices:
        st.info(f"No {label} nodes yet.")
        return
    names = {c["id"]: f"{c['id']} · {c['name'] or ''}".strip(" ·") for c in choices}
    node_id = st.selectbox("Node", options=list(names), format_func=lambda k: names[k], key=f"gx_node_{label}")
    properties = queries.get_node(graph, label, node_id)
    if properties is None:
        st.warning("That node no longer exists.")
        return
    st.markdown("**Properties**")
    st.dataframe(
        pd.DataFrame([{"Property": k, "Value": str(v)} for k, v in sorted(properties.items())]), hide_index=True
    )
    relationships = queries.get_node_relationships(graph, label, node_id)
    st.markdown("**Relationships**")
    if relationships:
        st.dataframe(pd.DataFrame(relationships), hide_index=True)
    else:
        st.caption("This node has no relationships in the graph.")


# ------------------------------------------------------------------ scoring method

def render_scoring_method() -> None:
    st.subheader("Risk scoring method")
    st.markdown(risk_scoring.FORMULA_TEXT)
    st.markdown("**Weights**")
    st.dataframe(
        pd.DataFrame([{"Factor": risk_scoring.FACTOR_TABLES[k][0], "Weight": w} for k, w in risk_scoring.WEIGHTS.items()]),
        hide_index=True,
    )
    for key, (name, table) in risk_scoring.FACTOR_TABLES.items():
        st.markdown(f"**{name}**")
        st.dataframe(pd.DataFrame([{"Value": v, "Factor": f} for v, f in table.items()]), hide_index=True)
    st.markdown("**Priority bands**")
    st.dataframe(
        pd.DataFrame([{"Priority": p, "Minimum score": m, "Suggested action": a} for p, m, a in risk_scoring.PRIORITY_THRESHOLDS]),
        hide_index=True,
    )


# ------------------------------------------------------------------ main

def main() -> None:
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    state = get_connection_state()
    page = render_sidebar(state)
    st.markdown(
        f"<div class='hero'><h2>🛡️ {config.APP_TITLE}</h2><p>{config.APP_TAGLINE}</p></div>",
        unsafe_allow_html=True,
    )
    if state["connection"] is None:
        render_connection_problem(state)
        return

    graph = state["connection"].graph
    try:
        if page == "Dashboard":
            render_dashboard(graph)
        elif page == "Investigate":
            render_investigate(graph)
        elif page == "Graph explorer":
            render_graph_explorer(graph)
        else:
            render_scoring_method()
    except QueryError as exc:
        st.error(f"The database query failed: {exc}")
        st.caption("FalkorDB may have stopped or the connection dropped. Use Retry connection in the sidebar.")


main()
