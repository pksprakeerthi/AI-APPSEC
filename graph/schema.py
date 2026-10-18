"""Graph schema: labels, relationships, allowed vocabularies and indexes.

FalkorDB is schemaless, so this module is the single source of truth for what the
application expects to find in the graph.
"""
from __future__ import annotations

from typing import List

NODE_LABELS = ("Application", "Component", "Package", "Vulnerability")

REL_HAS_COMPONENT = "HAS_COMPONENT"
REL_DEPENDS_ON = "DEPENDS_ON"
REL_HAS_VULNERABILITY = "HAS_VULNERABILITY"

# (source label, relationship type, target label)
RELATIONSHIPS = (
    ("Application", REL_HAS_COMPONENT, "Component"),
    ("Component", REL_DEPENDS_ON, "Package"),
    ("Package", REL_DEPENDS_ON, "Package"),
    ("Package", REL_HAS_VULNERABILITY, "Vulnerability"),
)

SEVERITIES = ("critical", "high", "medium", "low")
EXPOSURE_LEVELS = ("internet-facing", "partner-facing", "internal", "isolated")
EXPLOIT_LEVELS = ("actively-exploited", "public-poc", "none-known")
CRITICALITY_LEVELS = ("critical", "high", "medium", "low")

INDEX_STATEMENTS = tuple(f"CREATE INDEX FOR (n:{label}) ON (n.id)" for label in NODE_LABELS)

SCHEMA_SUMMARY = """
(Application)-[:HAS_COMPONENT]->(Component)
(Component)-[:DEPENDS_ON]->(Package)        direct dependency
(Package)-[:DEPENDS_ON]->(Package)          transitive dependency
(Package)-[:HAS_VULNERABILITY]->(Vulnerability)
"""


def ensure_schema(graph) -> List[str]:
    """Create id indexes. Returns warnings; an index that already exists is not a problem."""
    warnings: List[str] = []
    for statement in INDEX_STATEMENTS:
        try:
            graph.query(statement)
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            if "already" in message.lower():
                continue
            warnings.append(f"Index statement failed ({statement}): {message}")
    return warnings
