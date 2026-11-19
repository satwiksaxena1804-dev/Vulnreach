from __future__ import annotations

import json

from support import DEMO_ADVISORIES, DEMO_APP

from vulnreach.api import ScanConfig, analyze_project
from vulnreach.report.json_report import build_report
from vulnreach.report.markdown import render_markdown
from vulnreach.report.vex import VEX_CONTEXT, build_vex


def demo_result():
    return analyze_project(
        ScanConfig(
            root=DEMO_APP,
            offline=True,
            advisory_dirs=(DEMO_ADVISORIES,),
            no_cache=True,
        )
    )


def test_json_report_shape():
    report = build_report(demo_result(), generated_at="2026-01-01T00:00:00Z")
    assert report["schema_version"] == "1.0"
    assert report["tool"]["name"] == "vulnreach"
    assert report["generated_at"] == "2026-01-01T00:00:00Z"
    assert report["summary"]["reachable"] == 1
    assert report["summary"]["uncertain"] == 1
    assert report["summary"]["not_reachable"] == 3
    assert len(report["findings"]) == 5
    assert len(report["dependencies"]) == 4

    reachable = next(item for item in report["findings"] if item["verdict"] == "reachable")
    assert reachable["advisory"]["id"] == "VULNREACH-DEMO-0001"
    assert reachable["paths"][0]["confirmed"] is True
    assert reachable["paths"][0]["hops"][-1]["to"] == "ext:demo_http_client.fetch"
    assert reachable["remediation"].startswith("Upgrade")
    assert reachable["rationale"]


def test_markdown_report_contains_evidence():
    text = render_markdown(demo_result())
    assert "# VulnReach report" in text
    assert "## Summary" in text
    assert "VULNREACH-DEMO-0001" in text
    assert "REACHABLE" in text
    assert "Evidence path" in text
    assert "app.fetch_status" in text
    assert "## Limitations" in text


def test_vex_document_is_valid_openvex():
    vex = build_vex(demo_result(), generated_at="2026-01-01T00:00:00Z")
    assert vex["@context"] == VEX_CONTEXT
    assert vex["author"] == "VulnReach"
    assert vex["version"] == 1
    assert vex["timestamp"] == "2026-01-01T00:00:00Z"
    assert "_meta" not in vex
    assert len(vex["statements"]) == 5

    by_id = {statement["vulnerability"]["name"]: statement for statement in vex["statements"]}
    affected = by_id["VULNREACH-DEMO-0001"]
    assert affected["status"] == "affected"
    assert affected["products"][0]["@id"] == "pkg:generic/demo-app"
    assert affected["products"][0]["subcomponents"][0]["@id"] == "pkg:pypi/demo-http-client@1.4.2"
    assert affected["action_statement"]

    not_affected = by_id["VULNREACH-DEMO-0002"]
    assert not_affected["status"] == "not_affected"
    assert not_affected["justification"] == "vulnerable_code_not_in_execute_path"
    assert not_affected["impact_statement"]

    uncertain = by_id["VULNREACH-DEMO-0003"]
    assert uncertain["status"] == "under_investigation"
    assert "Insufficient evidence" in uncertain["status_notes"]


def test_vex_uses_cve_alias():
    vex = build_vex(demo_result(), generated_at="2026-01-01T00:00:00Z")
    statement = next(
        item for item in vex["statements"] if item["vulnerability"]["name"] == "VULNREACH-DEMO-0002"
    )
    assert "CVE-2099-0002" in statement["vulnerability"]["aliases"]


def test_json_is_serialisable():
    report = build_report(demo_result())
    text = json.dumps(report)
    assert '"findings"' in text
