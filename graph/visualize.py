"""Graph visualization using pyvis, embedded in Streamlit as an HTML component."""
from __future__ import annotations

import json
from typing import Dict, Optional, Sequence, Tuple

from pyvis.network import Network

NODE_STYLE = {
    "Application": {"color": "#4f8ef7", "shape": "box"},
    "Component": {"color": "#a78bfa", "shape": "ellipse"},
    "Package": {"color": "#34d399", "shape": "dot"},
    "Vulnerability": {"color": "#9ca3af", "shape": "diamond"},
}
SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
}
LEGEND = (
    "Blue box = Application · Purple oval = Component · Green dot = Package · "
    "Diamond = Vulnerability (red critical, orange high, yellow medium, green low, grey unknown). "
    "Hover a node or edge for details."
)

_OPTIONS = {
    "physics": {
        "solver": "forceAtlas2Based",
        "stabilization": {"iterations": 150},
    },
    "edges": {
        "font": {"size": 9, "color": "#9aa4b2", "strokeWidth": 0},
        "smooth": {"type": "dynamic"},
        "color": {"color": "#6b7280"},
    },
    "nodes": {"font": {"color": "#e6edf3", "size": 13}},
    "interaction": {"hover": True, "tooltipDelay": 100},
}


def _short(text: Optional[str], limit: int = 28) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _tooltip(meta: Dict[str, Optional[str]]) -> str:
    lines = [f"{meta.get('label')}: {meta.get('id')}"]
    for key in ("name", "version", "severity", "exposure", "criticality"):
        value = meta.get(key)
        if value:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)


def render_graph_html(
    nodes: Dict[str, Dict[str, Optional[str]]],
    edges: Sequence[Tuple[str, str, str]],
    height_px: int = 560,
) -> str:
    """Return a self-contained HTML page for the given nodes and edges."""
    net = Network(
        height=f"{height_px}px",
        width="100%",
        directed=True,
        bgcolor="#0e1117",
        font_color="#e6edf3",
        cdn_resources="in_line",
    )
    for key, meta in nodes.items():
        label = meta.get("label") or "Package"
        style = NODE_STYLE.get(label, NODE_STYLE["Package"])
        color = style["color"]
        if label == "Vulnerability":
            color = SEVERITY_COLORS.get((meta.get("severity") or "").lower(), "#9ca3af")
        shown = meta.get("id") if label == "Vulnerability" else meta.get("name") or meta.get("id")
        if label == "Package" and meta.get("version"):
            shown = f"{meta.get('name')}@{meta.get('version')}"
        net.add_node(
            key,
            label=_short(str(shown)),
            title=_tooltip(meta),
            color=color,
            shape=style["shape"],
            size=16,
        )
    for source, relationship, target in edges:
        if source in nodes and target in nodes:
            net.add_edge(source, target, label=relationship, title=relationship, arrows="to")
    net.set_options(json.dumps(_OPTIONS))
    return net.generate_html()
