"""Vulnerable-symbol extraction, curation and matching.

Symbol data can come from the advisory itself (``database_specific`` or the OSV
``ecosystem_specific.imports`` shape) or from a curated symbol database.  An
advisory without symbol data is a first-class outcome: the analyzer reports
uncertainty rather than assuming reachability.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .errors import SymbolDataError
from .model import Advisory


@dataclass(frozen=True)
class SymbolPattern:
    """A normalised vulnerable symbol pattern."""

    raw: str
    paths: tuple[str, ...]
    module_wide: bool = False

    def matches(self, path: str) -> bool:
        for candidate in self.paths:
            if candidate.endswith(".*"):
                prefix = candidate[:-1]
                if path == candidate[:-2] or path.startswith(prefix):
                    return True
            elif path == candidate or path.startswith(f"{candidate}."):
                return True
        return False


@dataclass
class SymbolDatabase:
    """Curated advisory-to-symbol mappings."""

    entries: dict[str, dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.entries is None:
            self.entries = {}

    @classmethod
    def load(cls, paths: tuple[Path, ...] = (), *, include_bundled: bool = True) -> SymbolDatabase:
        database = cls()
        if include_bundled:
            try:
                bundled = resources.files("vulnreach.data").joinpath("known-symbols.json")
                database._merge(json.loads(bundled.read_text(encoding="utf-8")), "bundled")
            except (FileNotFoundError, ModuleNotFoundError, json.JSONDecodeError):
                pass
        for path in paths:
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise SymbolDataError(f"cannot read symbol database {path}: {exc}") from exc
            database._merge(data, str(path))
        return database

    def _merge(self, data: object, source: str) -> None:
        if not isinstance(data, dict):
            raise SymbolDataError(f"{source}: symbol database must be a JSON object")
        advisories = data.get("advisories")
        if not isinstance(advisories, dict):
            raise SymbolDataError(f"{source}: missing 'advisories' object")
        for advisory_id, entry in advisories.items():
            if not isinstance(entry, dict):
                raise SymbolDataError(f"{source}: entry {advisory_id} must be an object")
            symbols = entry.get("symbols")
            if not isinstance(symbols, list) or not all(isinstance(s, str) for s in symbols):
                raise SymbolDataError(f"{source}: entry {advisory_id} needs a 'symbols' list")
            self.entries.setdefault(str(advisory_id), entry)

    def symbols_for(self, advisory: Advisory) -> tuple[tuple[str, ...], str | None]:
        """Return curated symbols for an advisory and their source label."""
        for identifier in advisory.identifiers:
            entry = self.entries.get(identifier)
            if entry is None:
                continue
            package = entry.get("package")
            from packaging.utils import canonicalize_name

            if isinstance(package, str) and canonicalize_name(package) != advisory.package:
                continue
            symbols = tuple(entry.get("symbols") or ())
            if symbols:
                return symbols, "curated"
        return (), None


def enrich_advisory(advisory: Advisory, database: SymbolDatabase) -> Advisory:
    """Attach curated symbols to an advisory when it has none of its own."""
    if advisory.symbols:
        return advisory
    symbols, source = database.symbols_for(advisory)
    if not symbols:
        return advisory
    advisory.symbols = symbols
    advisory.symbol_source = source
    return advisory


def build_patterns(symbols: tuple[str, ...], import_names: tuple[str, ...]) -> list[SymbolPattern]:
    """Normalise advisory symbols into matchable dotted paths."""
    names = {name for name in import_names if name}
    patterns: list[SymbolPattern] = []
    seen: set[str] = set()

    for raw in symbols:
        cleaned = raw.strip().strip("`").strip().replace("::", ".").replace(":", ".")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        candidates = {cleaned}
        root = cleaned.split(".")[0]
        if root not in names:
            for name in names:
                candidates.add(f"{name}.{cleaned}")
        wildcard = cleaned.endswith(".*") or cleaned in names
        patterns.append(
            SymbolPattern(
                raw=cleaned,
                paths=tuple(sorted(candidates)),
                module_wide=wildcard,
            )
        )
    return patterns


def matched_symbols(patterns: list[SymbolPattern], path: str) -> list[str]:
    """Return the raw patterns that match one external call path."""
    return [pattern.raw for pattern in patterns if pattern.matches(path)]
