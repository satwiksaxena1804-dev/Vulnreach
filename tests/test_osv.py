from __future__ import annotations

import json
from pathlib import Path

import pytest
from support import DEMO_ADVISORIES, make_dependency

from vulnreach.errors import AdvisorySourceError
from vulnreach.osv import AdvisoryClient, advisory_from_osv, load_offline_database


def test_offline_database_loads_demo_records():
    database = load_offline_database([DEMO_ADVISORIES])
    assert len(database.advisories) == 5
    first = next(item for item in database.advisories if item.id == "VULNREACH-DEMO-0001")
    assert first.package == "demo-http-client"
    assert first.symbols == ("demo_http_client.fetch", "demo_http_client.client.fetch")
    assert first.fixed_versions == ("1.5.0",)
    assert first.severity == "HIGH"


def test_offline_queries_filter_by_version():
    client = AdvisoryClient(offline=True, offline_dirs=(DEMO_ADVISORIES,))
    affected = client.query_all([make_dependency("demo-http-client", "1.4.2")])
    ids = {advisory.id for advisory in affected.advisories}
    assert {"VULNREACH-DEMO-0001", "VULNREACH-DEMO-0004"} <= ids

    fixed = client.query_all([make_dependency("demo-http-client", "1.5.0")])
    assert fixed.advisories == []


def test_offline_without_sources_raises(tmp_path: Path):
    client = AdvisoryClient(offline=True, cache_dir=tmp_path / "missing")
    with pytest.raises(AdvisorySourceError):
        client.query_all([make_dependency()])


def test_advisory_parsing_without_symbols():
    data = {
        "id": "GHSA-xxxx",
        "aliases": ["CVE-2026-1"],
        "summary": "broken thing",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Demo_Pkg"}, "ranges": []}],
        "database_specific": {"severity": "moderate"},
        "references": [{"url": "https://example.test/advisory"}],
    }
    advisory = advisory_from_osv(data)
    assert advisory is not None
    assert advisory.package == "demo-pkg"
    assert advisory.package_raw == "Demo_Pkg"
    assert advisory.symbols == ()
    assert advisory.severity == "MODERATE"
    assert advisory.url == "https://example.test/advisory"
    assert advisory.aliases == ("CVE-2026-1",)


def test_non_pypi_entries_are_ignored():
    data = {
        "id": "OSV-1",
        "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}, "ranges": []}],
    }
    advisory = advisory_from_osv(data)
    assert advisory is not None
    assert advisory.package == ""


def test_cache_round_trip(tmp_path: Path):
    client = AdvisoryClient(cache_dir=tmp_path, timeout=1)
    payload = {
        "vulns": [
            {
                "id": "TEST-1",
                "summary": "cached",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "lib"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    calls = {"count": 0}

    def fake_post(body: bytes):
        calls["count"] += 1
        return payload

    client._post = fake_post  # type: ignore[method-assign]
    first = client.query_all([make_dependency()])
    second = client.query_all([make_dependency()])
    assert calls["count"] == 1
    assert first.advisories[0].id == "TEST-1"
    assert second.advisories[0].id == "TEST-1"


def test_network_failure_without_cache_raises(tmp_path: Path):
    client = AdvisoryClient(cache_dir=tmp_path / "cache", retries=0, timeout=0.01)

    def fail(_body: bytes):
        raise AdvisorySourceError("network down")

    client._post = fail  # type: ignore[method-assign]
    with pytest.raises(AdvisorySourceError):
        client.query_all([make_dependency()])


def test_offline_database_reads_directories_of_lists(tmp_path: Path):
    path = tmp_path / "list.json"
    path.write_text(
        json.dumps(
            [
                {
                    "id": "A-1",
                    "affected": [{"package": {"ecosystem": "PyPI", "name": "lib"}, "ranges": []}],
                }
            ]
        ),
        encoding="utf-8",
    )
    database = load_offline_database([tmp_path])
    assert [advisory.id for advisory in database.advisories] == ["A-1"]
