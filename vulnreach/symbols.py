"""Vulnerable-symbol extraction, curation and matching.

Symbol data can come from the advisory itself (``database_specific`` or the OSV
``ecosystem_specific.imports`` shape) or from a curated symbol database.  An
advisory without symbol data is a first-class outcome: the analyzer reports
uncertainty rather than assuming reachability.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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


_FUNCTION_DEF = re.compile(r"(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_MAX_FIX_PATCH_BYTES = 2_000_000


def symbols_from_fix_patch(patch: str, import_names: tuple[str, ...]) -> tuple[str, ...]:
    """Return function names surrounding changed hunks in a GitHub patch.

    These are candidates only: a changed function is not necessarily the
    vulnerable function, so the caller must not treat this as authoritative.
    """
    candidates: list[str] = []
    file_path: str | None = None
    current_function: str | None = None
    hunk_changed = False

    def save_candidate() -> None:
        if not file_path or not current_function or not hunk_changed:
            return
        module = _module_in_import_roots(file_path, import_names)
        if module:
            symbol = f"{module}.{current_function}"
            if symbol not in candidates:
                candidates.append(symbol)

    for line in patch.splitlines():
        if line.startswith("diff --git "):
            save_candidate()
            file_path = _patch_file_path(line)
            current_function = None
            hunk_changed = False
        elif line.startswith("@@"):
            save_candidate()
            current_function = _function_name(line.split("@@", 2)[-1])
            hunk_changed = False
        elif line.startswith(("+++", "---")):
            continue
        elif line.startswith(("+", "-")):
            hunk_changed = True
            changed_function = _function_name(line[1:])
            if changed_function:
                current_function = changed_function
        elif line.startswith(" "):
            context_function = _function_name(line[1:])
            if context_function:
                current_function = context_function

    save_candidate()
    return tuple(candidates)


def infer_fix_commit_symbols(
    advisory: Advisory,
    import_names: tuple[str, ...],
    *,
    cache_dir: Path | None = None,
    allow_network: bool = True,
    timeout: float = 4.0,
) -> tuple[str, ...]:
    """Infer review candidates from referenced GitHub fix commits.

    The patch is parsed as text and never executed. Cached results are keyed by
    commit URL and package import names. A network failure returns no candidates.
    """
    for fix_url in advisory.fix_urls:
        patch_url = _github_patch_url(fix_url)
        if patch_url is None:
            continue
        cache_path = _fix_symbol_cache_path(cache_dir, patch_url, import_names)
        if cache_path and cache_path.is_file():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                symbols = cached.get("symbols") if isinstance(cached, dict) else None
                if isinstance(symbols, list) and all(isinstance(item, str) for item in symbols):
                    if symbols:
                        return tuple(symbols)
                    continue
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                pass
        if not allow_network:
            continue
        try:
            request = Request(patch_url, headers={"User-Agent": "vulnreach/0.1.0"})
            with urlopen(request, timeout=timeout) as response:
                raw_patch = response.read(_MAX_FIX_PATCH_BYTES + 1)
            if len(raw_patch) > _MAX_FIX_PATCH_BYTES:
                continue
            patch = raw_patch.decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError, OSError):
            continue

        candidates = symbols_from_fix_patch(patch, import_names)
        if cache_path:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(
                    json.dumps({"symbols": list(candidates)}), encoding="utf-8", newline="\n"
                )
            except OSError:
                pass
        if candidates:
            return candidates
    return ()


def _function_name(text: str) -> str | None:
    match = _FUNCTION_DEF.search(text)
    return match.group(1) if match else None


def _patch_file_path(diff_header: str) -> str | None:
    match = re.match(r"diff --git a/(.+?) b/(.+)$", diff_header)
    if not match:
        return None
    target = match.group(2)
    if target == "/dev/null":
        target = match.group(1)
    return target if target.endswith(".py") else None


def _module_in_import_roots(path: str, import_names: tuple[str, ...]) -> str | None:
    parts = path.split("/")
    filename = parts[-1]
    if not filename.endswith(".py"):
        return None
    if filename == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = filename[:-3]
    roots = set(import_names)
    root_index = next((index for index, part in enumerate(parts) if part in roots), None)
    if root_index is None:
        return None
    module_parts = [part for part in parts[root_index:] if part.isidentifier()]
    return ".".join(module_parts) if module_parts else None


def _github_patch_url(fix_url: str) -> str | None:
    parsed = urlparse(fix_url)
    parts = [part for part in parsed.path.split("/") if part]
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != "github.com"
        or len(parts) < 4
        or parts[2] != "commit"
    ):
        return None
    owner, repository, _commit, revision = parts[:4]
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in (owner, repository, revision)):
        return None
    return f"https://github.com/{owner}/{repository}/commit/{revision}.patch"


def _fix_symbol_cache_path(
    cache_dir: Path | None, patch_url: str, import_names: tuple[str, ...]
) -> Path | None:
    if cache_dir is None:
        return None
    cache_key = hashlib.sha256(
        (patch_url + "\0" + "\0".join(sorted(import_names))).encode("utf-8")
    ).hexdigest()
    return cache_dir / "fix-symbols" / f"{cache_key}.json"


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
