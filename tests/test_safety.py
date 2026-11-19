"""Safety behaviours: missing advisory data must never look like a clean scan."""

from __future__ import annotations

import pytest
from support import make_dependency

from vulnreach.errors import AdvisorySourceError
from vulnreach.osv import AdvisoryClient, load_offline_database


def test_missing_advisory_directory_raises(tmp_path):
    with pytest.raises(AdvisorySourceError):
        load_offline_database([tmp_path / "does-not-exist"])


def test_empty_offline_directory_warns_but_returns(tmp_path):
    database = load_offline_database([tmp_path])
    assert database.advisories == []
    assert database.warnings == []


def test_offline_scan_with_wrong_directory_never_returns_clean(tmp_path):
    client = AdvisoryClient(
        offline=True,
        offline_dirs=(tmp_path / "wrong",),
        cache_dir=tmp_path / "cache",
    )
    with pytest.raises(AdvisorySourceError):
        client.query_all([make_dependency()])


def test_unknown_version_advisory_is_kept(tmp_path):
    path = tmp_path / "advisory.json"
    path.write_text(
        """
        {
          "id": "TEST-X",
          "summary": "x",
          "affected": [
            {"package": {"ecosystem": "PyPI", "name": "lib"},
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}
          ]
        }
        """,
        encoding="utf-8",
    )
    client = AdvisoryClient(offline=True, offline_dirs=(tmp_path,))
    result = client.query_all([make_dependency(version=None)])
    assert [advisory.id for advisory in result.advisories] == ["TEST-X"]
