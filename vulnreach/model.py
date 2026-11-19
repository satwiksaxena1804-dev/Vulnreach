"""Core data model shared by every stage of the analysis pipeline.

The model is deliberately plain data: parsing produces :class:`ModuleInfo`
records, resolution produces a graph over the node identifiers defined here, and
reports serialise findings without depending on the analysis machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class EdgeKind(StrEnum):
    """How one node can lead to another."""

    CALL = "call"
    REFERENCE = "reference"
    IMPORT = "import"


class NodeKind(StrEnum):
    MODULE = "module"
    FUNCTION = "function"
    EXTERNAL = "external"


class Verdict(StrEnum):
    """The reachability conclusion for one advisory/dependency pair."""

    REACHABLE = "reachable"
    NOT_REACHABLE = "not_reachable"
    UNCERTAIN = "uncertain"


class GapKind(StrEnum):
    """Categories of missing knowledge that reduce confidence."""

    UNRESOLVED_CALL = "unresolved_call"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    STAR_IMPORT = "star_import"
    DYNAMIC_IMPORT = "dynamic_import"
    DYNAMIC_CODE = "dynamic_code"
    PARSE_ERROR = "parse_error"
    UNRESOLVED_IMPORT = "unresolved_import"
    NO_ENTRY_POINTS = "no_entry_points"


@dataclass(frozen=True, slots=True)
class Location:
    """A source location relative to the scanned project root."""

    path: str
    line: int
    column: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "column": self.column}

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True, slots=True)
class ImportRef:
    """An import statement as written in the source file."""

    module: str
    name: str | None
    alias: str
    level: int
    location: Location
    is_star: bool = False


@dataclass(frozen=True, slots=True)
class FunctionInfo:
    """A function or method discovered in the project."""

    node_id: str
    module: str
    name: str
    qualname: str
    location: Location
    class_qualname: str | None = None
    decorators: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()
    has_varargs: bool = False
    has_kwargs: bool = False
    is_async: bool = False
    is_module_level: bool = True

    @property
    def display(self) -> str:
        return f"{self.module}.{self.qualname}"


@dataclass(frozen=True, slots=True)
class ClassInfo:
    """A class discovered in the project."""

    class_id: str
    module: str
    name: str
    qualname: str
    location: Location
    bases: tuple[str, ...] = ()
    decorators: tuple[str, ...] = ()
    enclosing_function: str | None = None


@dataclass
class ModuleInfo:
    """Structural information about one Python module."""

    name: str
    path: str
    node_id: str
    is_package: bool
    imports: list[ImportRef] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    has_main_guard: bool = False
    line_count: int = 0
    parse_error: str | None = None


@dataclass
class ProjectInfo:
    """Metadata and parsed modules for the scanned project."""

    root: Path
    name: str
    version: str | None
    modules: list[ModuleInfo]
    warnings: list[str] = field(default_factory=list)
    console_scripts: list[tuple[str, str]] = field(default_factory=list)
    entry_modules: tuple[str, ...] = ()

    @property
    def module_map(self) -> dict[str, ModuleInfo]:
        return {module.name: module for module in self.modules}

    @property
    def source_files(self) -> int:
        return len(self.modules)

    @property
    def parse_errors(self) -> list[ModuleInfo]:
        return [module for module in self.modules if module.parse_error]


@dataclass(frozen=True, slots=True)
class Dependency:
    """A declared or installed Python distribution."""

    name: str
    raw_name: str
    specifier: str
    version: str | None
    version_source: str
    import_names: tuple[str, ...]
    direct: bool
    depth: int = 0
    via: tuple[str, ...] = ()
    extras: tuple[str, ...] = ()
    marker: str | None = None
    source: str = "requirements.txt"

    @property
    def display(self) -> str:
        return f"{self.name}=={self.version}" if self.version else self.name


@dataclass
class Advisory:
    """A vulnerability advisory normalised from OSV data."""

    id: str
    package: str
    package_raw: str
    summary: str
    details: str = ""
    aliases: tuple[str, ...] = ()
    severity: str = "UNKNOWN"
    cvss_vector: str | None = None
    published: str | None = None
    modified: str | None = None
    url: str | None = None
    symbols: tuple[str, ...] = ()
    symbol_source: str | None = None
    fixed_versions: tuple[str, ...] = ()
    affected: tuple[dict[str, Any], ...] = field(default_factory=tuple, repr=False)
    query_mode: str = "offline"
    database_specific: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def identifiers(self) -> tuple[str, ...]:
        return (self.id, *self.aliases)

    @property
    def severity_rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}.get(
            self.severity.upper(), 0
        )


@dataclass(frozen=True, slots=True)
class Gap:
    """A place where the analysis could not see the full program."""

    kind: GapKind
    caller_id: str
    module: str
    location: Location
    detail: str


@dataclass(frozen=True, slots=True)
class Edge:
    """A directed edge in the call graph."""

    source: str
    target: str
    kind: EdgeKind
    location: Location | None = None
    expression: str | None = None
    uncertain: bool = False


@dataclass(frozen=True, slots=True)
class Hop:
    """A rendered, evidence-carrying edge on a path."""

    source: str
    target: str
    source_label: str
    target_label: str
    kind: EdgeKind
    location: Location | None
    expression: str | None
    uncertain: bool = False


@dataclass
class PathEvidence:
    """One call path from an entry point to a vulnerable symbol."""

    hops: list[Hop]

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def is_confirmed(self) -> bool:
        return all(hop.kind is not EdgeKind.REFERENCE and not hop.uncertain for hop in self.hops)

    @property
    def nodes(self) -> list[tuple[str, str]]:
        if not self.hops:
            return []
        nodes = [(self.hops[0].source, self.hops[0].source_label)]
        nodes.extend((hop.target, hop.target_label) for hop in self.hops)
        return nodes

    def describe(self) -> str:
        return " -> ".join(label for _, label in self.nodes)


@dataclass(frozen=True, slots=True)
class Rationale:
    """A machine-readable explanation for a verdict component."""

    code: str
    message: str


@dataclass
class Finding:
    """The result of analysing one advisory against one dependency."""

    advisory: Advisory
    dependency: Dependency
    verdict: Verdict
    confidence: float
    rationale: list[Rationale]
    paths: list[PathEvidence] = field(default_factory=list)
    matched_symbols: tuple[str, ...] = ()
    vulnerable_symbols: tuple[str, ...] = ()
    uncertainty: list[Gap] = field(default_factory=list)
    affected_status: str = "affected"

    @property
    def id(self) -> str:
        return f"{self.advisory.id}:{self.dependency.name}"


@dataclass
class CallStats:
    """Call-resolution counters, globally or for one node."""

    total: int = 0
    project: int = 0
    external: int = 0
    stdlib: int = 0
    builtin: int = 0
    unresolved: int = 0
    references: int = 0

    def merge(self, other: CallStats) -> None:
        self.total += other.total
        self.project += other.project
        self.external += other.external
        self.stdlib += other.stdlib
        self.builtin += other.builtin
        self.unresolved += other.unresolved
        self.references += other.references

    @property
    def resolved(self) -> int:
        return self.project + self.external + self.stdlib + self.builtin

    @property
    def coverage(self) -> float:
        return self.resolved / self.total if self.total else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.total,
            "resolved": self.resolved,
            "project_calls": self.project,
            "external_calls": self.external,
            "stdlib_calls": self.stdlib,
            "builtin_calls": self.builtin,
            "unresolved_calls": self.unresolved,
            "references": self.references,
            "resolution_coverage": round(self.coverage, 3),
        }


@dataclass
class EntryPoint:
    """A node from which execution is assumed to start."""

    node_id: str
    label: str
    kind: str
    location: Location | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "kind": self.kind,
            "location": self.location.to_dict() if self.location else None,
        }


@dataclass
class AnalysisMetrics:
    """Aggregate statistics describing how complete the analysis was."""

    modules_scanned: int = 0
    modules_failed: int = 0
    total_calls: int = 0
    resolved_calls: int = 0
    resolution_coverage: float = 1.0
    reachable_resolution_coverage: float = 1.0
    dynamic_gaps: int = 0
    entry_points: int = 0
    dependencies: int = 0
    advisories_considered: int = 0
    advisories_excluded: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "modules_scanned": self.modules_scanned,
            "modules_failed": self.modules_failed,
            "calls": self.total_calls,
            "resolved_calls": self.resolved_calls,
            "resolution_coverage": round(self.resolution_coverage, 3),
            "reachable_resolution_coverage": round(self.reachable_resolution_coverage, 3),
            "dynamic_gaps": self.dynamic_gaps,
            "entry_points": self.entry_points,
            "dependencies": self.dependencies,
            "advisories_considered": self.advisories_considered,
            "advisories_excluded": self.advisories_excluded,
        }
