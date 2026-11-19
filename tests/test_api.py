from __future__ import annotations

from support import DEMO_ADVISORIES, DEMO_APP

from vulnreach.api import ScanConfig, analyze_project


def test_demo_end_to_end():
    result = analyze_project(
        ScanConfig(
            root=DEMO_APP,
            offline=True,
            advisory_dirs=(DEMO_ADVISORIES,),
            no_cache=True,
        )
    )
    assert result.advisory_source == "offline"
    assert result.summary["reachable"] == 1
    assert result.summary["uncertain"] == 1
    assert result.summary["not_reachable"] == 3
    assert result.metrics.resolution_coverage == 1.0
    assert result.metrics.entry_points == 1
    assert len(result.dependencies) == 4

    finding = result.findings[0]
    assert finding.advisory.id == "VULNREACH-DEMO-0001"
    assert finding.paths[0].describe().endswith("demo_http_client.fetch")
