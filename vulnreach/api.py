"""Programmatic entry point for a complete VulnReach analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .callgraph import build_call_graph
from .dependencies import collect_dependencies
from .model import ProjectInfo
from .osv import AdvisoryClient
from .reachability import AnalysisResult, analyze
from .resolution import resolve_project
from .scanner import scan_project
from .symbols import SymbolDatabase, enrich_advisory


@dataclass
class ScanConfig:
    """Options for one analysis run."""

    root: Path
    include_tests: bool = False
    excludes: tuple[str, ...] = ()
    entry_modules: tuple[str, ...] = ()
    include_dev: bool = False
    offline: bool = False
    advisory_dirs: tuple[Path, ...] = ()
    symbol_files: tuple[Path, ...] = ()
    cache_dir: Path | None = None
    no_cache: bool = False
    timeout: float = 20.0
    extra_warnings: list[str] = field(default_factory=list)


def analyze_project(config: ScanConfig) -> AnalysisResult:
    """Run scanning, dependency resolution, advisories and reachability."""
    parsed = scan_project(
        config.root,
        include_tests=config.include_tests,
        excludes=config.excludes,
        entry_modules=config.entry_modules,
    )
    project: ProjectInfo = parsed.info

    dependency_set = collect_dependencies(project.root, include_dev=config.include_dev)
    output, index = resolve_project(project, parsed.trees)
    graph = build_call_graph(project, parsed.trees, output, index)

    warnings = [
        *project.warnings,
        *dependency_set.warnings,
        *config.extra_warnings,
    ]

    if dependency_set.dependencies:
        cache_dir = config.cache_dir
        if cache_dir is None and not config.no_cache:
            cache_dir = project.root / ".vulnreach" / "cache"
        client = AdvisoryClient(
            cache_dir=cache_dir,
            offline_dirs=config.advisory_dirs,
            offline=config.offline,
            use_cache=not config.no_cache,
            timeout=config.timeout,
        )
        query = client.query_all(dependency_set.dependencies)
        advisories = query.advisories
        warnings.extend(query.warnings)
        advisory_source = query.source
    else:
        advisories = []
        advisory_source = "offline" if config.offline else "osv"

    symbol_database = SymbolDatabase.load(config.symbol_files)
    advisories = [enrich_advisory(advisory, symbol_database) for advisory in advisories]

    return analyze(
        project,
        graph,
        dependency_set.dependencies,
        advisories,
        advisory_source=advisory_source,
        warnings=warnings,
    )
