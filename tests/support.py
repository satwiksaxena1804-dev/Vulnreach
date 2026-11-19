from __future__ import annotations

from pathlib import Path
from typing import Any

from vulnreach.callgraph import build_call_graph
from vulnreach.model import Advisory, Dependency
from vulnreach.reachability import analyze
from vulnreach.resolution import resolve_project
from vulnreach.scanner import scan_project

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
DEMO_APP = EXAMPLES / "demo_app"
DEMO_ADVISORIES = EXAMPLES / "advisories"


def make_dependency(
    name: str = "lib",
    version: str | None = "1.0.0",
    *,
    import_names: tuple[str, ...] | None = None,
    direct: bool = True,
    via: tuple[str, ...] = (),
) -> Dependency:
    return Dependency(
        name=name,
        raw_name=name,
        specifier=f"=={version}" if version else "",
        version=version,
        version_source="pinned" if version else "unknown",
        import_names=import_names or (name.replace("-", "_"),),
        direct=direct,
        via=via,
    )


def make_advisory(
    advisory_id: str = "TEST-2026-0001",
    package: str = "lib",
    symbols: tuple[str, ...] = ("lib.danger",),
    *,
    severity: str = "HIGH",
    query_mode: str = "offline",
    introduced: str = "0",
    fixed: str = "2.0.0",
) -> Advisory:
    affected: tuple[dict[str, Any], ...] = (
        {
            "package": {"ecosystem": "PyPI", "name": package},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": introduced}, {"fixed": fixed}],
                }
            ],
        },
    )
    return Advisory(
        id=advisory_id,
        package=package,
        package_raw=package,
        summary=f"Synthetic advisory {advisory_id}",
        severity=severity,
        symbols=symbols,
        symbol_source="advisory" if symbols else None,
        affected=affected,
        query_mode=query_mode,
    )


def run_graph(root: Path):
    parsed = scan_project(root)
    output, index = resolve_project(parsed.info, parsed.trees)
    graph = build_call_graph(parsed.info, parsed.trees, output, index)
    return parsed, output, index, graph


def run_analysis(
    root: Path,
    advisories: list[Advisory],
    dependencies: list[Dependency] | None = None,
):
    parsed, output, index, graph = run_graph(root)
    if dependencies is None:
        dependencies = [make_dependency() for _ in advisories]
    return (
        analyze(
            parsed.info,
            graph,
            dependencies,
            advisories,
            advisory_source="offline",
        ),
        graph,
        output,
    )


def edge_kinds(graph, source: str, target: str) -> list[str]:
    return [edge.kind.value for edge in graph.adjacency.get(source, []) if edge.target == target]
