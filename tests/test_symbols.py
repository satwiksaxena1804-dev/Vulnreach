from __future__ import annotations

import json

import pytest

from vulnreach.errors import SymbolDataError
from vulnreach.model import Advisory
from vulnreach.symbols import (
    SymbolDatabase,
    build_patterns,
    enrich_advisory,
    matched_symbols,
)


def advisory(identifier="GHSA-test", package="lib", symbols=()) -> Advisory:
    return Advisory(
        id=identifier,
        package=package,
        package_raw=package,
        summary="test",
        symbols=tuple(symbols),
    )


def test_patterns_add_package_prefix():
    patterns = build_patterns(("danger",), ("lib",))
    assert patterns[0].matches("lib.danger")
    assert not patterns[0].matches("other.danger")


def test_class_and_method_prefix_match():
    patterns = build_patterns(("lib.Client.danger",), ("lib",))
    assert patterns[0].matches("lib.Client.danger")
    assert patterns[0].matches("lib.Client.danger.deep")
    assert not patterns[0].matches("lib.Client.safe")


def test_module_wildcard():
    patterns = build_patterns(("lib.*",), ("lib",))
    assert patterns[0].matches("lib.danger")
    assert not patterns[0].matches("libsafe.danger")


def test_duplicate_symbols_are_collapsed():
    patterns = build_patterns(("lib.danger", "lib.danger"), ("lib",))
    assert len(patterns) == 1
    assert matched_symbols(patterns, "lib.danger") == ["lib.danger"]


def test_curated_database_merges_and_validates_package(tmp_path):
    path = tmp_path / "symbols.json"
    path.write_text(
        json.dumps(
            {
                "advisories": {
                    "GHSA-test": {"package": "lib", "symbols": ["lib.danger"]},
                    "GHSA-other": {"package": "other", "symbols": ["other.boom"]},
                }
            }
        ),
        encoding="utf-8",
    )
    database = SymbolDatabase.load((path,), include_bundled=False)
    enriched = enrich_advisory(advisory(), database)
    assert enriched.symbols == ("lib.danger",)
    assert enriched.symbol_source == "curated"

    wrong_package = enrich_advisory(advisory("GHSA-other"), database)
    assert wrong_package.symbols == ()


def test_advisory_symbols_are_not_overridden(tmp_path):
    path = tmp_path / "symbols.json"
    path.write_text(
        json.dumps({"advisories": {"GHSA-test": {"symbols": ["curated"]}}}),
        encoding="utf-8",
    )
    database = SymbolDatabase.load((path,), include_bundled=False)
    original = advisory(symbols=("advisory",))
    assert enrich_advisory(original, database).symbols == ("advisory",)


def test_malformed_database_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(SymbolDataError):
        SymbolDatabase.load((path,), include_bundled=False)

    path.write_text(json.dumps({"advisories": {"x": {"symbols": "nope"}}}), encoding="utf-8")
    with pytest.raises(SymbolDataError):
        SymbolDatabase.load((path,), include_bundled=False)
