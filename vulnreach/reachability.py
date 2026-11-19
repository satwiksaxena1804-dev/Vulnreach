"""Reachability analysis and evidence construction.

The engine answers one question per advisory/dependency pair: can application
code reach the advisory's vulnerable symbol?  It never asks a model, and it
never treats "no path found" as unconditional proof.  Every verdict carries
paths, confidence, rationale codes and the specific gaps that limited it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .callgraph import CallGraph
from .model import (
    Advisory,
    AnalysisMetrics,
    CallStats,
    Dependency,
    EntryPoint,
    Finding,
    Gap,
    GapKind,
    PathEvidence,
    ProjectInfo,
    Rationale,
    Verdict,
)
from .symbols import SymbolPattern, build_patterns, matched_symbols
from .versions import advisory_affects_version, next_fixed_version

LIMITATIONS = [
    (
        "Reachability is evaluated at the application-to-dependency call boundary. "
        "Control flow inside third-party packages is not modelled, so a package "
        "function that internally calls a vulnerable helper may be reported as "
        "not reachable with reduced confidence."
    ),
    (
        "Dynamic imports, getattr-based dispatch, monkeypatching and exec/eval are "
        "reported as uncertainty. They are never silently followed or assumed safe."
    ),
    (
        "Entry points are inferred statically from __main__ guards, console scripts, "
        "web/task handler decorators and modules that nothing else imports."
    ),
    (
        "Dependency versions come from the installed environment when it satisfies "
        "the declared specifier, otherwise from exact pins. Unpinned, uninstalled "
        "packages produce an uncertain affectedness result."
    ),
]

_GLOBAL_GAP_KINDS = {
    GapKind.DYNAMIC_CODE,
    GapKind.DYNAMIC_DISPATCH,
    GapKind.UNRESOLVED_CALL,
}


@dataclass
class AnalysisResult:
    """The complete output of one scan."""

    project: ProjectInfo
    dependencies: list[Dependency]
    advisories: list[Advisory]
    findings: list[Finding]
    entry_points: list[EntryPoint]
    graph_stats: CallStats
    metrics: AnalysisMetrics
    gaps: list[Gap]
    warnings: list[str] = field(default_factory=list)
    advisory_source: str = "osv"
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))

    @property
    def summary(self) -> dict[str, int]:
        counts = {
            Verdict.REACHABLE.value: 0,
            Verdict.NOT_REACHABLE.value: 0,
            Verdict.UNCERTAIN.value: 0,
        }
        for finding in self.findings:
            counts[finding.verdict.value] += 1
        counts["total"] = len(self.findings)
        counts["advisories_excluded"] = self.metrics.advisories_excluded
        return counts

    def by_verdict(self, verdict: Verdict) -> list[Finding]:
        return [finding for finding in self.findings if finding.verdict is verdict]


def analyze(
    project: ProjectInfo,
    graph: CallGraph,
    dependencies: list[Dependency],
    advisories: list[Advisory],
    *,
    advisory_source: str,
    warnings: Iterable[str] = (),
) -> AnalysisResult:
    """Match advisories to dependencies and decide reachability."""
    dependency_by_name = {dependency.name: dependency for dependency in dependencies}
    package_map = _dependency_package_map(dependencies)
    reachable, predecessor = graph.reachable_from_roots()
    reachable_stats = graph.stats_for(reachable)
    all_gaps = list(graph.gaps)
    reachable_gaps = [
        gap
        for gap in all_gaps
        if gap.kind is GapKind.PARSE_ERROR or gap.caller_id in reachable or not gap.caller_id
    ]
    global_dynamic = [gap for gap in reachable_gaps if gap.kind in _GLOBAL_GAP_KINDS]
    parse_errors = [gap for gap in all_gaps if gap.kind is GapKind.PARSE_ERROR]

    findings: list[Finding] = []
    excluded = 0
    considered = 0

    for advisory in advisories:
        dependency = dependency_by_name.get(advisory.package)
        if dependency is None:
            dependency = package_map.get(advisory.package)
        if dependency is None:
            continue

        considered += 1
        status = advisory_affects_version(advisory, dependency.version)
        if status is False:
            excluded += 1
            continue

        finding = _analyze_one(
            advisory,
            dependency,
            graph,
            reachable,
            predecessor,
            reachable_stats,
            reachable_gaps,
            global_dynamic,
            parse_errors,
            version_unknown=status is None or dependency.version is None,
        )
        findings.append(finding)

    findings.sort(
        key=lambda finding: (
            {Verdict.REACHABLE: 0, Verdict.UNCERTAIN: 1, Verdict.NOT_REACHABLE: 2}[finding.verdict],
            -finding.advisory.severity_rank,
            finding.advisory.id,
        )
    )

    metrics = AnalysisMetrics(
        modules_scanned=len(project.modules),
        modules_failed=len(project.parse_errors),
        total_calls=graph.stats.total,
        resolved_calls=graph.stats.resolved,
        resolution_coverage=graph.stats.coverage,
        reachable_resolution_coverage=reachable_stats.coverage,
        dynamic_gaps=len(global_dynamic),
        entry_points=len(graph.roots),
        dependencies=len(dependencies),
        advisories_considered=considered,
        advisories_excluded=excluded,
    )

    limitations = list(LIMITATIONS)
    symbol_less = [finding for finding in findings if not finding.advisory.symbols]
    if symbol_less:
        limitations.append(
            f"{len(symbol_less)} advisory finding(s) had no function-level symbol data; "
            "those verdicts are uncertain by construction."
        )
    if project.parse_errors:
        limitations.append(
            f"{len(project.parse_errors)} module(s) failed to parse; "
            "paths through them are invisible."
        )

    warnings_list = list(warnings) + list(graph.warnings)
    if not dependencies:
        warnings_list.append("no dependencies were discovered; reachability has nothing to check")

    return AnalysisResult(
        project=project,
        dependencies=dependencies,
        advisories=advisories,
        findings=findings,
        entry_points=graph.roots,
        graph_stats=graph.stats,
        metrics=metrics,
        gaps=all_gaps,
        warnings=warnings_list,
        advisory_source=advisory_source,
        limitations=limitations,
    )


def _dependency_package_map(dependencies: list[Dependency]) -> dict[str, Dependency]:
    mapping: dict[str, Dependency] = {}
    for dependency in dependencies:
        mapping.setdefault(dependency.name, dependency)
        for name in dependency.import_names:
            mapping.setdefault(name.split(".")[0], dependency)
    return mapping


def _analyze_one(
    advisory: Advisory,
    dependency: Dependency,
    graph: CallGraph,
    reachable: set[str],
    predecessor,
    reachable_stats: CallStats,
    reachable_gaps: list[Gap],
    global_dynamic: list[Gap],
    parse_errors: list[Gap],
    *,
    version_unknown: bool,
) -> Finding:
    roots = {name.split(".")[0] for name in dependency.import_names}
    package_nodes = graph.external_nodes_for(dependency.import_names)
    package_reachable = package_nodes & reachable
    package_imported = _package_imported(graph, roots, reachable)
    relevant_gaps = _relevant_gaps(reachable_gaps, roots)

    rationale: list[Rationale] = []
    uncertainty: list[Gap] = []

    patterns = build_patterns(advisory.symbols, dependency.import_names)
    target_nodes = {
        node.id
        for node in graph.external_nodes()
        if any(pattern.matches(node.label) for pattern in patterns)
    }
    paths = (
        graph.paths_to(target_nodes, limit=3, reachable=reachable, predecessor=predecessor)
        if target_nodes
        else []
    )
    confirmed = [path for path in paths if path.is_confirmed]
    matched = _matched_symbols_for_paths(patterns, paths)

    if version_unknown:
        rationale.append(
            Rationale(
                "version_unknown",
                "The installed/declared version of "
                f"{dependency.name} could not be determined, so affectedness is unproven.",
            )
        )
        rationale.append(
            Rationale(
                "call_boundary_evidence",
                _boundary_message(package_reachable, package_imported, dependency),
            )
        )
        evidence_paths = paths or _package_paths(
            graph, package_nodes, limit=1, reachable=reachable, predecessor=predecessor
        )
        uncertainty.extend(relevant_gaps[:5])
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=0.3,
            rationale=rationale,
            paths=evidence_paths,
            matched_symbols=matched,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
            affected_status="unknown",
        )

    if not advisory.symbols:
        only_call_paths = (
            graph.paths_to(
                package_reachable,
                limit=1,
                reachable=reachable,
                predecessor=predecessor,
            )
            if package_reachable
            else []
        )
        uncertainty.extend(relevant_gaps[:5])
        if dependency.direct is False and not package_imported:
            rationale.append(
                Rationale(
                    "transitive_dependency",
                    f"{dependency.name} is pulled in by "
                    f"{', '.join(dependency.via) or 'another dependency'}; the parent package may "
                    "call the vulnerable code internally.",
                )
            )
            return Finding(
                advisory=advisory,
                dependency=dependency,
                verdict=Verdict.UNCERTAIN,
                confidence=0.3,
                rationale=rationale,
                paths=only_call_paths,
                vulnerable_symbols=advisory.symbols,
                uncertainty=uncertainty,
            )
        rationale.append(
            Rationale(
                "symbol_data_unavailable",
                f"The advisory for {dependency.name} does not identify vulnerable "
                "functions, so reachability cannot be decided from the call graph.",
            )
        )
        rationale.append(
            Rationale(
                "package_usage",
                _boundary_message(package_reachable, package_imported, dependency),
            )
        )
        confidence = 0.45 if package_reachable else 0.4 if package_imported else 0.35
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=confidence,
            rationale=rationale,
            paths=only_call_paths,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    if advisory.symbol_source == "fix_commit_candidate":
        rationale.append(
            Rationale(
                "fix_commit_symbol_candidates",
                "The candidate functions were inferred from a referenced fix commit. "
                "A changed function is not necessarily vulnerable, so review this mapping "
                "before treating the path as confirmed.",
            )
        )
        uncertainty.extend(relevant_gaps[:5])
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=0.65 if paths else 0.4,
            rationale=rationale,
            paths=paths[:3],
            matched_symbols=matched,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    if confirmed:
        best = confirmed[0]
        rationale.append(
            Rationale(
                "vulnerable_symbol_reached",
                f"Application code calls {best.hops[-1].target_label}, which the advisory "
                "marks as vulnerable.",
            )
        )
        rationale.append(
            Rationale(
                "confirmed_call_path",
                f"{len(confirmed)} confirmed path(s) reach the vulnerable symbol "
                "through resolved calls and imports only.",
            )
        )
        confidence = 0.9 + (0.03 if len(best.hops) <= 2 else 0.0)
        confidence = min(0.95, confidence)
        if global_dynamic:
            rationale.append(
                Rationale(
                    "dynamic_code_present",
                    f"{len(global_dynamic)} dynamic construct(s) exist in reachable code; "
                    "they do not invalidate a directly observed call path.",
                )
            )
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.REACHABLE,
            confidence=round(confidence, 2),
            rationale=rationale,
            paths=confirmed[:3],
            matched_symbols=matched,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    if paths:
        rationale.append(
            Rationale(
                "reference_only_path",
                "The vulnerable symbol is referenced by application code, but only through "
                "a value/reference edge. It may be invoked indirectly.",
            )
        )
        uncertainty.extend(relevant_gaps[:5])
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=0.5,
            rationale=rationale,
            paths=paths[:3],
            matched_symbols=matched,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    if relevant_gaps:
        rationale.append(
            Rationale(
                "dynamic_access_to_package",
                "No static path reaches the vulnerable symbol, but dynamic access to "
                f"{dependency.name} was observed in reachable code.",
            )
        )
        uncertainty.extend(relevant_gaps[:5])
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=0.45,
            rationale=rationale,
            paths=_package_paths(
                graph,
                package_nodes,
                limit=1,
                reachable=reachable,
                predecessor=predecessor,
            ),
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    if dependency.direct is False and not package_imported:
        rationale.append(
            Rationale(
                "transitive_dependency",
                f"{dependency.name} is a transitive dependency of "
                f"{', '.join(dependency.via) or 'another package'}; application code does not "
                "import it, but its parent may call it internally.",
            )
        )
        return Finding(
            advisory=advisory,
            dependency=dependency,
            verdict=Verdict.UNCERTAIN,
            confidence=0.3,
            rationale=rationale,
            vulnerable_symbols=advisory.symbols,
            uncertainty=uncertainty,
        )

    rationale.append(
        Rationale(
            "no_path_to_symbol",
            f"No confirmed call path from an entry point reaches {', '.join(advisory.symbols)}.",
        )
    )
    if package_reachable or package_imported:
        rationale.append(
            Rationale(
                "package_used_but_symbol_not_called",
                f"{dependency.name} is used by the application, but not through the "
                "vulnerable symbol. Dependency-internal calls are outside the analysis boundary.",
            )
        )
    else:
        rationale.append(
            Rationale(
                "package_not_imported",
                f"No reachable module imports or calls {dependency.name}.",
            )
        )

    confidence = 0.9
    confidence -= 0.25 * (1.0 - reachable_stats.coverage)
    if package_reachable or package_imported:
        confidence -= 0.08
    if global_dynamic:
        confidence -= 0.08
    if parse_errors:
        confidence -= 0.08
    if dependency.direct is False:
        confidence -= 0.05
    confidence = max(0.3, min(0.9, confidence))
    if global_dynamic:
        rationale.append(
            Rationale(
                "dynamic_code_present",
                f"{len(global_dynamic)} dynamic call site(s) in reachable code could hide an "
                "indirect invocation.",
            )
        )

    return Finding(
        advisory=advisory,
        dependency=dependency,
        verdict=Verdict.NOT_REACHABLE,
        confidence=round(confidence, 2),
        rationale=rationale,
        paths=[],
        matched_symbols=matched,
        vulnerable_symbols=advisory.symbols,
        uncertainty=uncertainty,
    )


def _matched_symbols_for_paths(
    patterns: list[SymbolPattern], paths: list[PathEvidence]
) -> tuple[str, ...]:
    matched: list[str] = []
    for path in paths:
        if not path.hops:
            continue
        for symbol in matched_symbols(patterns, path.hops[-1].target_label):
            if symbol not in matched:
                matched.append(symbol)
    return tuple(matched)


def _package_imported(graph: CallGraph, roots: set[str], reachable: set[str]) -> bool:
    callers: set[str] = set()
    for root in roots:
        callers |= graph.import_uses.get(root, set())
    return bool(callers & reachable)


def _relevant_gaps(gaps: list[Gap], roots: set[str]) -> list[Gap]:
    relevant: list[Gap] = []
    for gap in gaps:
        root = gap.detail.split(".")[0]
        if gap.kind in {GapKind.STAR_IMPORT, GapKind.DYNAMIC_IMPORT} and root in roots:
            relevant.append(gap)
        elif gap.kind in {GapKind.DYNAMIC_CODE, GapKind.DYNAMIC_DISPATCH}:
            relevant.append(gap)
        elif gap.kind in {GapKind.UNRESOLVED_CALL, GapKind.UNRESOLVED_IMPORT, GapKind.PARSE_ERROR}:
            # These gaps can hide a path the resolver could not name. Treating
            # absence of a graph path as proof would be unsafe.
            relevant.append(gap)
    return relevant


def _package_paths(
    graph: CallGraph,
    package_nodes: set[str],
    *,
    limit: int,
    reachable: set[str],
    predecessor,
) -> list[PathEvidence]:
    if not package_nodes:
        return []
    return graph.paths_to(package_nodes, limit=limit, reachable=reachable, predecessor=predecessor)


def _boundary_message(
    package_reachable: set[str], package_imported: bool, dependency: Dependency
) -> str:
    if package_reachable:
        return (
            f"Application code calls into {dependency.name} at "
            f"{len(package_reachable)} call site(s)."
        )
    if package_imported:
        return f"{dependency.name} is imported by reachable application code."
    return f"{dependency.name} is installed/declared but not imported by the application."


def remediation_hint(finding: Finding) -> str | None:
    """Return a concrete upgrade hint for a finding, when one exists."""
    fixed = next_fixed_version(finding.advisory, finding.dependency.version)
    if fixed:
        return f"Upgrade {finding.dependency.name} to {fixed} or later."
    return None
