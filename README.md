# AI Application Security Risk Investigator

**Connect the risks. Trace the evidence. Prioritize what matters.**

A Streamlit app backed by a FalkorDB knowledge graph. It traces
`Application → Component → Package → Vulnerability` paths with Cypher, scores each path with a
transparent heuristic, and explains every finding using only evidence read from the graph.
Built for Graph Hacks 2026.

> All sample data is fictional. Vulnerability IDs (`DEMO-VULN-xxx`) and packages are invented
> and do not describe real CVEs or real software.

## Graph model

```
(Application)-[:HAS_COMPONENT]->(Component)
(Component)-[:DEPENDS_ON]->(Package)          direct dependency
(Package)-[:DEPENDS_ON]->(Package)            transitive dependency
(Package)-[:HAS_VULNERABILITY]->(Vulnerability)
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env
```

Start FalkorDB (Docker):

```bash
docker run -p 6379:6379 -p 3000:3000 -it --rm falkordb/falkordb:latest
```

No Docker? Create a FalkorDB Cloud instance and copy its host, port, username and password
into `.env` (try `FALKORDB_SSL=true` if the plain connection is refused). Never commit `.env`.

Run:

```bash
streamlit run app.py
```

Click **Seed sample data** in the sidebar (safe to repeat).

## Configuration

See `.env.example`. Variables: `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_USERNAME`,
`FALKORDB_PASSWORD`, `FALKORDB_SSL`, `FALKORDB_GRAPH`, optional `ANTHROPIC_API_KEY` and `LLM_MODEL`.

## Optional LLM narrative

Works fully without it. To enable: `pip install anthropic` and set `ANTHROPIC_API_KEY`.
The LLM receives only a JSON bundle of graph facts, and its output is discarded if it adds
vulnerability IDs or version numbers that are not in that bundle.

## Tests

```bash
pytest
```

Unit tests need no database. Integration tests use a separate graph
(`FALKORDB_TEST_GRAPH`) and skip automatically if FalkorDB is unreachable.

## Risk score

`100 × (0.40 severity + 0.25 exposure + 0.20 exploit evidence + 0.15 business criticality)`.
Missing inputs get a neutral 0.5 and are flagged; they are never treated as safe.
This is a project heuristic, **not** CVSS, EPSS, SSVC or any industry standard.

## Known limitations

- Dependencies are followed up to 2 package-to-package hops.
- The graph stores a fixed version, not verified affected version ranges.
- No reachability, call-graph, or compensating-control data.
- Sample data is fictional; there is no importer for real SBOMs or scanner output yet.
- Graph nodes are inspected through a selector below the graph, not by clicking.
- There is no authentication or multi-user support.
