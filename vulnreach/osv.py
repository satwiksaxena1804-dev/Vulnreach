"""OSV.dev advisory ingestion with an offline database and on-disk cache.

Online queries use the public OSV API.  When ``offline`` is set, or when the
network fails, VulnReach can fall back to a directory of OSV JSON files and to
previously cached responses.  Advisory data is never invented: if no source can
answer, the scan fails loudly instead of reporting a clean result.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from .errors import AdvisorySourceError
from .model import Advisory, Dependency
from .versions import advisory_affects_version, fixed_versions_for

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CACHE_TTL_SECONDS = 24 * 60 * 60
USER_AGENT = "vulnreach/0.1.0 (+https://github.com/example/vulnreach)"


@dataclass
class AdvisoryQueryResult:
    """Advisories returned for a dependency set."""

    advisories: list[Advisory] = field(default_factory=list)
    source: str = "osv"
    warnings: list[str] = field(default_factory=list)


@dataclass
class OfflineDatabase:
    """A local collection of OSV records."""

    advisories: list[Advisory] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class AdvisoryClient:
    """Fetches advisories for dependencies from OSV, cache or local files."""

    def __init__(
        self,
        *,
        cache_dir: Path | None = None,
        offline_dirs: Iterable[Path] = (),
        offline: bool = False,
        use_cache: bool = True,
        timeout: float = 20.0,
        retries: int = 2,
    ) -> None:
        self.cache_dir = cache_dir
        self.offline_dirs = tuple(Path(path) for path in offline_dirs)
        self.offline = offline
        self.use_cache = use_cache
        self.timeout = timeout
        self.retries = retries
        self._offline_db: OfflineDatabase | None = None

    # ------------------------------------------------------------------ API
    def query_all(self, dependencies: list[Dependency]) -> AdvisoryQueryResult:
        result = AdvisoryQueryResult()
        if self.offline:
            result.source = "offline"
            if not self.offline_dirs and not self._cache_available():
                raise AdvisorySourceError(
                    "offline mode needs advisory data: pass --advisories DIR "
                    "or run once online to populate the cache"
                )
            database = self._offline_database()
            result.warnings.extend(database.warnings)
            for dependency in dependencies:
                result.advisories.extend(self._from_offline(dependency, database))
            if self._cache_available() and self.cache_dir is not None:
                for dependency in dependencies:
                    result.advisories.extend(self._from_cache(dependency, allow_stale=True))
            result.advisories = _deduplicate(result.advisories)
            result.advisories.sort(key=_advisory_sort_key)
            return result

        failures: list[str] = []
        stale_used: list[str] = []

        def fetch(dependency: Dependency) -> list[Advisory]:
            try:
                return self._online(dependency)
            except AdvisorySourceError as exc:
                cached = self._from_cache(dependency, allow_stale=True)
                if cached:
                    stale_used.append(f"{dependency.name}: {exc} (using cached advisories)")
                    return cached
                failures.append(f"{dependency.name}: {exc}")
                return []

        workers = min(8, max(1, len(dependencies)))
        if dependencies:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for advisories in pool.map(fetch, dependencies):
                    result.advisories.extend(advisories)

        if failures:
            raise AdvisorySourceError("advisory lookup failed for: " + "; ".join(sorted(failures)))

        result.source = "osv"
        result.warnings.extend(stale_used)
        if any("cached" in warning for warning in stale_used):
            result.source = "osv+cache"
        result.advisories = _deduplicate(result.advisories)
        result.advisories.sort(key=_advisory_sort_key)
        return result

    # -------------------------------------------------------------- online
    def _online(self, dependency: Dependency) -> list[Advisory]:
        payload: dict[str, Any] = {
            "package": {"name": dependency.raw_name or dependency.name, "ecosystem": "PyPI"}
        }
        mode = "package"
        if dependency.version:
            payload["version"] = dependency.version
            mode = "version"

        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        cached = self._read_cache(body)
        if cached is not None:
            return _parse_payload(cached, dependency, query_mode=mode)

        response = self._post(body)
        self._write_cache(body, response)
        return _parse_payload(response, dependency, query_mode=mode)

    def _post(self, body: bytes) -> dict[str, Any]:
        request = urllib.request.Request(
            OSV_QUERY_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                parsed = json.loads(raw.decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise AdvisorySourceError("OSV returned an unexpected response")
                return parsed
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AdvisorySourceError(f"OSV returned invalid JSON: {exc}") from exc
        raise AdvisorySourceError(f"OSV request failed: {last_error}")

    # --------------------------------------------------------------- cache
    def _cache_path(self, body: bytes) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(body).hexdigest()[:32]
        return self.cache_dir / f"{digest}.json"

    def _read_cache(self, body: bytes) -> dict[str, Any] | None:
        if not self.use_cache:
            return None
        path = self._cache_path(body)
        if path is None or not path.is_file():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        fetched = float(record.get("fetched_at", 0))
        if time.time() - fetched > CACHE_TTL_SECONDS:
            return None
        payload = record.get("payload")
        return payload if isinstance(payload, dict) else None

    def _write_cache(self, body: bytes, payload: dict[str, Any]) -> None:
        path = self._cache_path(body)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            record = {"fetched_at": time.time(), "payload": payload}
            path.write_text(json.dumps(record), encoding="utf-8", newline="\n")
        except OSError:
            # A read-only cache directory must not break the scan.
            return

    def _cache_available(self) -> bool:
        return self.cache_dir is not None and self.cache_dir.is_dir()

    def _from_cache(self, dependency: Dependency, *, allow_stale: bool) -> list[Advisory]:
        if self.cache_dir is None or not self.cache_dir.is_dir():
            return []
        for version in (dependency.version, None):
            payload: dict[str, Any] = {
                "package": {"name": dependency.raw_name or dependency.name, "ecosystem": "PyPI"}
            }
            mode = "package"
            if version:
                payload["version"] = version
                mode = "version"
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            path = self._cache_path(body)
            if path is None or not path.is_file():
                continue
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (
                not allow_stale
                and time.time() - float(record.get("fetched_at", 0)) > CACHE_TTL_SECONDS
            ):
                continue
            data = record.get("payload")
            if isinstance(data, dict):
                return _parse_payload(data, dependency, query_mode=mode)
        return []

    # ------------------------------------------------------------- offline
    def _offline_database(self) -> OfflineDatabase:
        if self._offline_db is None:
            self._offline_db = load_offline_database(self.offline_dirs)
        return self._offline_db

    def _from_offline(self, dependency: Dependency, database: OfflineDatabase) -> list[Advisory]:
        matches: list[Advisory] = []
        for advisory in database.advisories:
            if advisory.package != dependency.name:
                continue
            status = advisory_affects_version(advisory, dependency.version)
            if status is False:
                continue
            matches.append(advisory)
        return matches


def load_offline_database(directories: Iterable[Path]) -> OfflineDatabase:
    """Load every ``*.json`` OSV record from the given directories."""
    database = OfflineDatabase()
    seen: set[str] = set()
    requested = [Path(directory) for directory in directories]
    readable = [directory for directory in requested if directory.is_dir()]
    if requested and not readable:
        raise AdvisorySourceError(
            "none of the advisory directories exist: "
            + ", ".join(str(directory) for directory in requested)
        )
    for directory in requested:
        if not directory.is_dir():
            database.warnings.append(f"advisory directory does not exist: {directory}")
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                database.warnings.append(f"cannot read advisory {path.name}: {exc}")
                continue
            records: list[Any]
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict) and isinstance(data.get("vulns"), list):
                records = data["vulns"]
            else:
                records = [data]
            for record in records:
                if not isinstance(record, dict):
                    database.warnings.append(f"ignoring malformed advisory in {path.name}")
                    continue
                advisory = advisory_from_osv(record, query_mode="offline")
                if advisory is None:
                    continue
                key = f"{advisory.id}:{advisory.package}"
                if key in seen:
                    continue
                seen.add(key)
                database.advisories.append(advisory)
    database.advisories.sort(key=_advisory_sort_key)
    return database


def advisory_from_osv(data: dict[str, Any], *, query_mode: str = "package") -> Advisory | None:
    """Normalise one OSV record into an :class:`Advisory`."""
    advisory_id = str(data.get("id") or "").strip()
    if not advisory_id:
        return None

    affected_entries = data.get("affected") or []
    if not isinstance(affected_entries, list):
        affected_entries = []
    package_name = ""
    package_raw = ""
    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            continue
        if str(package.get("ecosystem", "")).lower() != "pypi":
            continue
        package_raw = str(package.get("name") or "")
        if package_raw:
            package_name = canonicalize_name(package_raw)
            break

    database_specific = data.get("database_specific") or {}
    if not isinstance(database_specific, dict):
        database_specific = {}

    severity = "UNKNOWN"
    cvss_vector: str | None = None
    for item in data.get("severity") or []:
        if isinstance(item, dict) and isinstance(item.get("score"), str):
            cvss_vector = item["score"]
            break
    raw_severity = database_specific.get("severity")
    if isinstance(raw_severity, str) and raw_severity.strip():
        severity = raw_severity.strip().upper()

    aliases_raw = data.get("aliases") or []
    aliases = tuple(str(alias) for alias in aliases_raw if alias)
    symbols = _extract_symbols(data, affected_entries)

    url: str | None = None
    for reference in data.get("references") or []:
        if isinstance(reference, dict) and isinstance(reference.get("url"), str):
            url = reference["url"]
            break

    advisory = Advisory(
        id=advisory_id,
        package=package_name,
        package_raw=package_raw,
        summary=str(data.get("summary") or data.get("details") or "").strip(),
        details=str(data.get("details") or ""),
        aliases=aliases,
        severity=severity,
        cvss_vector=cvss_vector,
        published=str(data.get("published")) if data.get("published") else None,
        modified=str(data.get("modified")) if data.get("modified") else None,
        url=url,
        symbols=symbols,
        symbol_source="advisory" if symbols else None,
        affected=tuple(entry for entry in affected_entries if isinstance(entry, dict)),
        query_mode=query_mode,
        database_specific=database_specific,
    )
    advisory.fixed_versions = fixed_versions_for(advisory)
    return advisory


def _extract_symbols(data: dict[str, Any], affected_entries: list[Any]) -> tuple[str, ...]:
    symbols: list[str] = []
    top_level = data.get("database_specific") or {}
    if isinstance(top_level, dict):
        symbols.extend(_string_list(top_level.get("vulnreach_symbols")))
    for entry in affected_entries:
        if not isinstance(entry, dict):
            continue
        ecosystem_specific = entry.get("ecosystem_specific") or {}
        if isinstance(ecosystem_specific, dict):
            imports = ecosystem_specific.get("imports") or []
            if isinstance(imports, list):
                for item in imports:
                    if isinstance(item, dict):
                        symbols.extend(_string_list(item.get("symbols")))
        database_specific = entry.get("database_specific") or {}
        if isinstance(database_specific, dict):
            symbols.extend(_string_list(database_specific.get("vulnreach_symbols")))
    cleaned: list[str] = []
    for symbol in symbols:
        text = symbol.strip().strip("`").strip()
        if text and text not in cleaned:
            cleaned.append(text)
    return tuple(cleaned)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _parse_payload(
    payload: dict[str, Any], dependency: Dependency, *, query_mode: str
) -> list[Advisory]:
    advisories: list[Advisory] = []
    for record in payload.get("vulns") or []:
        if not isinstance(record, dict):
            continue
        advisory = advisory_from_osv(record, query_mode=query_mode)
        if advisory is None:
            continue
        if advisory.package and advisory.package != dependency.name:
            # The API can return advisories for related packages; keep only ours.
            continue
        if not advisory.package:
            advisory.package = dependency.name
            advisory.package_raw = dependency.raw_name
        advisories.append(advisory)
    return advisories


def _deduplicate(advisories: Iterable[Advisory]) -> list[Advisory]:
    unique: dict[tuple[str, str], Advisory] = {}
    for advisory in advisories:
        key = (advisory.id, advisory.package)
        if key not in unique:
            unique[key] = advisory
    return list(unique.values())


def _advisory_sort_key(advisory: Advisory) -> tuple:
    return (advisory.package, -advisory.severity_rank, advisory.id)
