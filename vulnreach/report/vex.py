"""OpenVEX 0.2.0 report generation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from .. import __version__
from ..model import Finding, Verdict
from ..reachability import AnalysisResult, remediation_hint

VEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


def build_vex(result: AnalysisResult, *, generated_at: str | None = None) -> dict[str, Any]:
    """Build an OpenVEX document for the scan result."""
    timestamp = generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    product = _purl("generic", result.project.name, result.project.version)

    statements: list[dict[str, Any]] = []
    for finding in result.findings:
        statements.append(_statement(finding, product))

    return {
        "@context": VEX_CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "VulnReach",
        "timestamp": timestamp,
        "version": 1,
        "tooling": f"vulnreach {__version__}",
        "statements": statements,
    }


def _statement(finding: Finding, product: str) -> dict[str, Any]:
    advisory = finding.advisory
    status, justification, notes = _status_for(finding)

    statement: dict[str, Any] = {
        "vulnerability": {
            "name": advisory.id,
            "description": advisory.summary,
            "aliases": [alias for alias in advisory.aliases if alias != advisory.id],
        },
        "products": [
            {
                "@id": product,
                "subcomponents": [
                    {"@id": _purl("pypi", finding.dependency.name, finding.dependency.version)}
                ],
            }
        ],
        "status": status,
    }
    if advisory.url:
        statement["vulnerability"]["@id"] = advisory.url
    if justification:
        statement["justification"] = justification
    if status == "not_affected":
        statement["impact_statement"] = (
            "No call path from an application entry point reaches the vulnerable "
            "symbol in the analysed application."
        )
    if status == "affected":
        hint = remediation_hint(finding)
        statement["action_statement"] = hint or (
            "Remove the vulnerable call, or upgrade the dependency to a fixed release."
        )
    statement["status_notes"] = notes
    statement["vulnerability"]["description"] = advisory.summary or advisory.details[:500]
    return statement


def _status_for(finding: Finding) -> tuple[str, str | None, str]:
    evidence = "; ".join(
        f"{rationale.code}: {rationale.message}" for rationale in finding.rationale
    )
    confidence = f"confidence {finding.confidence:.2f}"
    if finding.verdict is Verdict.REACHABLE:
        return "affected", None, f"{confidence}. {evidence}"
    if finding.verdict is Verdict.UNCERTAIN:
        return (
            "under_investigation",
            None,
            f"{confidence}. Insufficient evidence for a definitive status. {evidence}",
        )
    return (
        "not_affected",
        "vulnerable_code_not_in_execute_path",
        f"{confidence}. {evidence}",
    )


def _purl(kind: str, name: str, version: str | None) -> str:
    safe_name = quote(name.strip().lower().replace("_", "-"), safe="-.")
    purl = f"pkg:{kind}/{safe_name}"
    if version:
        purl += f"@{quote(version, safe='.-+')}"
    return purl
