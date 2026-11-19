"""Machine-readable JSON report generation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..model import Finding, Gap, Hop, PathEvidence
from ..reachability import AnalysisResult, remediation_hint

SCHEMA_VERSION = "1.0"


def build_report(result: AnalysisResult, *, generated_at: str | None = None) -> dict[str, Any]:
    """Build the JSON report payload."""
    timestamp = generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "vulnreach", "version": __version__},
        "generated_at": timestamp,
        "project": {
            "name": result.project.name,
            "version": result.project.version,
            "root": str(result.project.root),
            "modules_scanned": result.metrics.modules_scanned,
            "modules_failed": result.metrics.modules_failed,
            "entry_points": [entry.to_dict() for entry in result.entry_points],
        },
        "analysis": {
            "advisory_source": result.advisory_source,
            "graph": result.graph_stats.to_dict(),
            "metrics": result.metrics.to_dict(),
            "gaps": [_gap_to_dict(gap) for gap in result.gaps],
            "warnings": list(result.warnings),
            "limitations": list(result.limitations),
        },
        "dependencies": [
            {
                "name": dependency.name,
                "version": dependency.version,
                "version_source": dependency.version_source,
                "specifier": dependency.specifier,
                "direct": dependency.direct,
                "depth": dependency.depth,
                "via": list(dependency.via),
                "import_names": list(dependency.import_names),
                "source": dependency.source,
            }
            for dependency in result.dependencies
        ],
        "findings": [_finding_to_dict(finding) for finding in result.findings],
        "summary": result.summary,
    }


def write_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "verdict": finding.verdict.value,
        "confidence": finding.confidence,
        "affected_status": finding.affected_status,
        "advisory": {
            "id": finding.advisory.id,
            "aliases": list(finding.advisory.aliases),
            "summary": finding.advisory.summary,
            "details": finding.advisory.details,
            "severity": finding.advisory.severity,
            "cvss_vector": finding.advisory.cvss_vector,
            "published": finding.advisory.published,
            "modified": finding.advisory.modified,
            "url": finding.advisory.url,
            "fixed_versions": list(finding.advisory.fixed_versions),
            "symbol_source": finding.advisory.symbol_source,
        },
        "dependency": {
            "name": finding.dependency.name,
            "version": finding.dependency.version,
            "direct": finding.dependency.direct,
            "via": list(finding.dependency.via),
        },
        "vulnerable_symbols": list(finding.vulnerable_symbols),
        "matched_symbols": list(finding.matched_symbols),
        "rationale": [
            {"code": rationale.code, "message": rationale.message}
            for rationale in finding.rationale
        ],
        "paths": [_path_to_dict(path) for path in finding.paths],
        "uncertainty": [_gap_to_dict(gap) for gap in finding.uncertainty],
        "remediation": remediation_hint(finding),
    }


def _path_to_dict(path: PathEvidence) -> dict[str, Any]:
    return {
        "length": path.length,
        "confirmed": path.is_confirmed,
        "nodes": [
            {
                "id": node_id,
                "label": label,
                "kind": node_id.split(":", 1)[0] if ":" in node_id else "unknown",
            }
            for node_id, label in path.nodes
        ],
        "hops": [_hop_to_dict(hop) for hop in path.hops],
    }


def _hop_to_dict(hop: Hop) -> dict[str, Any]:
    return {
        "from": hop.source,
        "to": hop.target,
        "from_label": hop.source_label,
        "to_label": hop.target_label,
        "kind": hop.kind.value,
        "location": hop.location.to_dict() if hop.location else None,
        "expression": hop.expression,
        "uncertain": hop.uncertain,
    }


def _gap_to_dict(gap: Gap) -> dict[str, Any]:
    return {
        "kind": gap.kind.value,
        "module": gap.module,
        "caller_id": gap.caller_id,
        "location": gap.location.to_dict(),
        "detail": gap.detail,
    }
