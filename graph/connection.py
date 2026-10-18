"""FalkorDB connection handling with readable error messages."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from falkordb import FalkorDB

from config import FalkorSettings


class GraphConnectionError(RuntimeError):
    """Raised when the FalkorDB server cannot be reached or rejects us."""


@dataclass(frozen=True)
class Connection:
    client: Any
    graph: Any
    settings: FalkorSettings


def describe_error(exc: Exception, settings: FalkorSettings) -> str:
    """Turn a low-level exception into advice a student can act on."""
    target = f"{settings.host}:{settings.port}"
    name = type(exc).__name__
    text = str(exc)
    lowered = text.lower()

    if (
        name == "AuthenticationError"
        or "authentication" in lowered
        or "wrongpass" in lowered
        or "invalid username-password" in lowered
        or "noauth" in lowered
    ):
        return (
            f"FalkorDB at {target} rejected the credentials. "
            "Check FALKORDB_USERNAME and FALKORDB_PASSWORD in your .env file."
        )
    if "ssl" in lowered or "certificate" in lowered or "wrong version number" in lowered:
        return (
            f"TLS/SSL problem while connecting to {target} ({text}). "
            "FalkorDB Cloud usually needs FALKORDB_SSL=true; a local Docker server needs false."
        )
    if (
        name in ("ConnectionError", "TimeoutError")
        or "connection refused" in lowered
        or "timed out" in lowered
        or "getaddrinfo" in lowered
        or "name or service not known" in lowered
        or "connecting to" in lowered
    ):
        return (
            f"Could not reach FalkorDB at {target}. If you use Docker, check the container "
            "is running (docker ps). If you use FalkorDB Cloud, check host and port in .env."
        )
    return f"Unexpected error while connecting to FalkorDB at {target}: {name}: {text}"


def connect(settings: FalkorSettings) -> Connection:
    """Open a FalkorDB connection and verify it responds."""
    try:
        client = FalkorDB(
            host=settings.host,
            port=settings.port,
            username=settings.username,
            password=settings.password,
            ssl=settings.ssl,
            socket_connect_timeout=5,
        )
        client.list_graphs()  # forces a round trip so failures surface now
        graph = client.select_graph(settings.graph_name)
    except Exception as exc:  # noqa: BLE001 - we convert every failure to one clear error
        raise GraphConnectionError(describe_error(exc, settings)) from exc
    return Connection(client=client, graph=graph, settings=settings)
