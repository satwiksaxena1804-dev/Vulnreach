"""Call graph construction, entry-point selection and path search."""

from __future__ import annotations

import json
import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .model import (
    CallStats,
    Edge,
    EdgeKind,
    EntryPoint,
    Gap,
    GapKind,
    Hop,
    Location,
    NodeKind,
    PathEvidence,
    ProjectInfo,
)
from .resolution import SymbolIndex

HANDLER_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "websocket",
    "task",
    "command",
    "callback",
    "receiver",
    "api_view",
}


@dataclass
class GraphNode:
    """A node in the call graph."""

    id: str
    kind: NodeKind
    label: str
    location: Location | None = None
    module: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "label": self.label,
            "location": self.location.to_dict() if self.location else None,
            "module": self.module,
        }


@dataclass
class CallGraph:
    """A directed graph with evidence-carrying edges."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    adjacency: dict[str, list[Edge]] = field(default_factory=dict)
    reverse: dict[str, list[Edge]] = field(default_factory=dict)
    roots: list[EntryPoint] = field(default_factory=list)
    stats: CallStats = field(default_factory=CallStats)
    per_caller: dict[str, CallStats] = field(default_factory=dict)
    gaps: list[Gap] = field(default_factory=list)
    import_uses: dict[str, set[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    # ------------------------------------------------------------- building
    def add_node(self, node: GraphNode) -> None:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            self.adjacency.setdefault(node.id, [])
            self.reverse.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        self.adjacency.setdefault(edge.source, [])
        self.reverse.setdefault(edge.target, [])
        bucket = self.adjacency.setdefault(edge.source, [])
        key = (
            edge.target,
            edge.kind,
            edge.location.path if edge.location else "",
            edge.location.line if edge.location else 0,
            edge.expression,
        )
        for existing in bucket:
            existing_key = (
                existing.target,
                existing.kind,
                existing.location.path if existing.location else "",
                existing.location.line if existing.location else 0,
                existing.expression,
            )
            if existing_key == key:
                return
        bucket.append(edge)
        self.reverse.setdefault(edge.target, []).append(edge)

    # --------------------------------------------------------------- paths
    def reachable_from_roots(self) -> tuple[set[str], dict[str, Edge]]:
        """Breadth-first search over all edge kinds from every entry point."""
        roots = [entry.node_id for entry in self.roots]
        return self._bfs(roots)

    def _bfs(self, starts: list[str]) -> tuple[set[str], dict[str, Edge]]:
        seen: set[str] = set(starts)
        predecessor: dict[str, Edge] = {}
        queue: deque[str] = deque(starts)
        while queue:
            current = queue.popleft()
            for edge in self.adjacency.get(current, []):
                if edge.target in seen:
                    continue
                seen.add(edge.target)
                predecessor[edge.target] = edge
                queue.append(edge.target)
        return seen, predecessor

    def path_to(self, target: str, predecessor: dict[str, Edge]) -> PathEvidence | None:
        if target not in predecessor:
            return None
        hops: list[Hop] = []
        current = target
        guard = 0
        while current in predecessor and guard < 10_000:
            edge = predecessor[current]
            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)
            hops.append(
                Hop(
                    source=edge.source,
                    target=edge.target,
                    source_label=source_node.label if source_node else edge.source,
                    target_label=target_node.label if target_node else edge.target,
                    kind=edge.kind,
                    location=edge.location,
                    expression=edge.expression,
                    uncertain=edge.uncertain,
                )
            )
            current = edge.source
            guard += 1
        hops.reverse()
        return PathEvidence(hops=hops) if hops else None

    def paths_to(
        self,
        targets: set[str],
        limit: int = 3,
        *,
        reachable: set[str] | None = None,
        predecessor: dict[str, Edge] | None = None,
    ) -> list[PathEvidence]:
        if reachable is None or predecessor is None:
            reachable, predecessor = self.reachable_from_roots()
        paths = [
            path
            for target in targets
            if target in reachable and (path := self.path_to(target, predecessor)) is not None
        ]
        paths.sort(key=lambda path: path.length)
        return paths[:limit]

    def external_nodes(self) -> Iterator[GraphNode]:
        for node in self.nodes.values():
            if node.kind is NodeKind.EXTERNAL:
                yield node

    def external_nodes_for(self, import_names: tuple[str, ...]) -> set[str]:
        roots = set(import_names)
        return {node.id for node in self.external_nodes() if (node.label.split(".")[0] in roots)}

    def get_node(self, node_id: str) -> GraphNode | None:
        return self.nodes.get(node_id)

    def stats_for(self, node_ids: set[str]) -> CallStats:
        total = CallStats()
        for node_id in node_ids:
            stats = self.per_caller.get(node_id)
            if stats:
                total.merge(stats)
        return total

    # ------------------------------------------------------------ exports
    def to_dict(self) -> dict:
        return {
            "entry_points": [entry.to_dict() for entry in self.roots],
            "nodes": [node.to_dict() for node in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind.value,
                    "location": edge.location.to_dict() if edge.location else None,
                    "expression": edge.expression,
                    "uncertain": edge.uncertain,
                }
                for source in sorted(self.adjacency)
                for edge in self.adjacency[source]
            ],
            "statistics": self.stats.to_dict(),
        }

    def to_dot(self) -> str:
        colors = {
            NodeKind.MODULE: "#dbeafe",
            NodeKind.FUNCTION: "#dcfce7",
            NodeKind.EXTERNAL: "#fee2e2",
        }
        lines = ["digraph vulnreach {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
        for node in sorted(self.nodes.values(), key=lambda item: item.id):
            label = node.label.replace('"', '\\"')
            color = colors.get(node.kind, "#ffffff")
            lines.append(
                f'  "{node.id}" [label="{label}", fillcolor="{color}", style="filled,rounded"];'
            )
        for source in sorted(self.adjacency):
            for edge in self.adjacency[source]:
                style = "dashed" if edge.kind is not EdgeKind.CALL else "solid"
                color = "#b91c1c" if edge.kind is EdgeKind.REFERENCE else "#334155"
                lines.append(
                    f'  "{edge.source}" -> "{edge.target}" '
                    f'[style={style}, color="{color}", label="{edge.kind.value}"];'
                )
        lines.append("}")
        return "\n".join(lines) + "\n"

    def write_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8", newline="\n")

    def write_dot(self, path: Path) -> None:
        path.write_text(self.to_dot(), encoding="utf-8", newline="\n")


@dataclass
class GraphBuildResult:
    graph: CallGraph
    index: SymbolIndex


def build_call_graph(project: ProjectInfo, trees: dict, output, index: SymbolIndex) -> CallGraph:
    """Assemble nodes, edges, entry points and uncertainty gaps."""
    graph = CallGraph(stats=output.stats, per_caller=dict(output.per_caller))
    graph.gaps.extend(output.gaps)
    graph.import_uses = {root: set(callers) for root, callers in output.import_uses.items()}
    graph.warnings.extend(project.warnings)

    module_nodes: dict[str, str] = {}
    for module in project.modules:
        node = GraphNode(
            id=module.node_id,
            kind=NodeKind.MODULE,
            label=f"{module.name} (module)",
            location=Location(path=module.path, line=1),
            module=module.name,
        )
        graph.add_node(node)
        module_nodes[module.name] = node.id

    for function in index.functions.values():
        graph.add_node(
            GraphNode(
                id=function.node_id,
                kind=NodeKind.FUNCTION,
                label=function.display,
                location=function.location,
                module=function.module,
            )
        )

    for edge in output.edges:
        if edge.target.startswith("ext:"):
            graph.add_node(
                GraphNode(
                    id=edge.target,
                    kind=NodeKind.EXTERNAL,
                    label=edge.target.removeprefix("ext:"),
                )
            )
        elif edge.target.startswith("fn:"):
            if edge.target in index.functions:
                info = index.functions[edge.target]
                graph.add_node(
                    GraphNode(
                        id=info.node_id,
                        kind=NodeKind.FUNCTION,
                        label=info.display,
                        location=info.location,
                        module=info.module,
                    )
                )
        graph.add_edge(edge)

    _select_entry_points(graph, project, index, output)

    parse_errors = project.parse_errors
    if parse_errors:
        graph.warnings.append(
            f"{len(parse_errors)} module(s) could not be parsed and were excluded from the graph"
        )
    return graph


def _select_entry_points(
    graph: CallGraph, project: ProjectInfo, index: SymbolIndex, output
) -> None:
    entries: list[EntryPoint] = []
    seen: set[str] = set()

    def add(node_id: str, kind: str, label: str, location: Location | None = None) -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        entries.append(EntryPoint(node_id=node_id, label=label, kind=kind, location=location))

    modules = {module.name: module for module in project.modules}

    for module_name in project.entry_modules:
        module = modules.get(module_name)
        if module is not None:
            add(module.node_id, "declared", f"{module.name} (module)", Location(module.path, 1))

    for script_name, target in project.console_scripts:
        module_name, _, function_name = target.partition(":")
        module = modules.get(module_name)
        if module is None:
            continue
        function = next(
            (
                item
                for item in module.functions
                if item.qualname == function_name and item.is_module_level
            ),
            None,
        )
        if function is not None:
            add(
                function.node_id,
                "console_script",
                f"{script_name} -> {function.display}",
                function.location,
            )
        else:
            add(
                module.node_id,
                "console_script",
                f"{script_name} -> {module.name}",
                Location(module.path, 1),
            )

    imported_modules = {
        edge.target
        for source in graph.adjacency
        for edge in graph.adjacency[source]
        if edge.kind is EdgeKind.IMPORT and edge.target.startswith("mod:")
    }
    for module in project.modules:
        if module.parse_error is not None:
            continue
        if module.has_main_guard:
            add(module.node_id, "main_guard", f"{module.name} (__main__)", Location(module.path, 1))
        elif module.node_id not in imported_modules:
            add(module.node_id, "top_level", f"{module.name} (module)", Location(module.path, 1))

    for function in index.functions.values():
        decorator_names = {_decorator_leaf(item) for item in function.decorators}
        matched = decorator_names & HANDLER_DECORATORS
        if matched:
            add(
                function.node_id,
                "handler",
                f"{function.display} (@{sorted(matched)[0]})",
                function.location,
            )

    if not entries:
        graph.gaps.append(
            Gap(
                kind=GapKind.NO_ENTRY_POINTS,
                caller_id="",
                module="",
                location=Location(path="", line=0),
                detail="no entry points were identified; every module was treated as a root",
            )
        )
        for module in project.modules:
            add(module.node_id, "fallback", f"{module.name} (module)", Location(module.path, 1))

    graph.roots = sorted(entries, key=lambda entry: (entry.kind, entry.label))


def _decorator_leaf(text: str) -> str:
    head = text.split("(", 1)[0].strip()
    return re.split(r"\.", head)[-1] if head else ""
