from __future__ import annotations

from vulnreach.model import Advisory
from vulnreach.versions import (
    advisory_affects_version,
    fixed_versions_for,
    next_fixed_version,
    parse_version,
)


def advisory(ranges, *, query_mode="offline") -> Advisory:
    return Advisory(
        id="TEST-1",
        package="lib",
        package_raw="lib",
        summary="test",
        affected=(
            {
                "package": {"ecosystem": "PyPI", "name": "lib"},
                "ranges": ranges,
            },
        ),
        query_mode=query_mode,
    )


def test_range_events_semantics():
    item = advisory(
        [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}]}]
    )
    assert advisory_affects_version(item, "1.0.0") is True
    assert advisory_affects_version(item, "1.4.9") is True
    assert advisory_affects_version(item, "1.5.0") is False
    assert advisory_affects_version(item, "0.9.0") is False


def test_last_affected_and_multiple_ranges():
    item = advisory(
        [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "1.0"}, {"last_affected": "1.2"}],
            },
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.1"}]},
        ]
    )
    assert advisory_affects_version(item, "1.2") is True
    assert advisory_affects_version(item, "1.3") is False
    assert advisory_affects_version(item, "2.0.5") is True
    assert advisory_affects_version(item, "2.1") is False


def test_non_pep440_and_git_ranges_are_unknown():
    git_only = advisory([{"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}])
    assert advisory_affects_version(git_only, "1.0.0") is None

    broken = advisory(
        [{"type": "ECOSYSTEM", "events": [{"introduced": "not-a-version"}, {"fixed": "2.0"}]}]
    )
    assert advisory_affects_version(broken, "1.0.0") is None


def test_missing_version_or_affected_data_is_unknown():
    item = advisory([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}])
    assert advisory_affects_version(item, None) is None
    empty = Advisory(id="X", package="p", package_raw="p", summary="s")
    assert advisory_affects_version(empty, "1.0") is None


def test_version_queries_are_trusted():
    item = advisory([], query_mode="version")
    assert advisory_affects_version(item, "1.0.0") is True


def test_fixed_versions_and_next_fix():
    item = advisory(
        [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "1.2.0"}, {"fixed": "1.3.0"}],
            }
        ]
    )
    assert fixed_versions_for(item) == ("1.2.0", "1.3.0")
    assert next_fixed_version(item, "1.1.0") == "1.2.0"
    assert next_fixed_version(item, "1.2.0") == "1.3.0"
    assert next_fixed_version(item, "9.0") is None


def test_parse_version():
    assert str(parse_version("1.0.0")) == "1.0.0"
    assert parse_version("") is None
    assert parse_version("not-a-version") is None
