"""OSV affected-range evaluation using PEP 440 versions.

OSV models affect as an ordered list of range events (``introduced``,
``fixed``, ``last_affected``, ``limit``) or an explicit list of versions.
This module turns those records into a three-valued answer:

* ``True``  - the version is affected,
* ``False`` - the version is not affected,
* ``None``  - the data cannot prove either way (unknown ecosystem, GIT ranges,
  unparsable versions).
"""

from __future__ import annotations

from typing import Any

from packaging.version import InvalidVersion, Version

from .model import Advisory


def parse_version(value: str | None) -> Version | None:
    """Parse a PEP 440 version, returning ``None`` when it is invalid."""
    if not value:
        return None
    text = str(value).strip()
    # OSV uses "0" to mean "from the beginning of time".
    if text == "0":
        return Version("0")
    try:
        return Version(text)
    except InvalidVersion:
        return None


def _event_intervals(
    events: list[dict[str, Any]],
) -> tuple[list[tuple[Any, Version | None, str]], bool]:
    """Translate ordered OSV events into ``(introduced, bound, kind)`` tuples.

    The second element of the return value is ``True`` when at least one event
    version was present but unparsable, which makes the interval set unknown.
    """
    intervals: list[tuple[Any, Version | None, str]] = []
    unknown = False
    opened = False
    introduced: Any = None

    for event in events:
        if not isinstance(event, dict):
            unknown = True
            continue
        if "introduced" in event:
            raw = event["introduced"]
            introduced = Version("0") if raw == "0" else parse_version(raw)
            if introduced is None:
                unknown = True
            opened = True
        elif "fixed" in event or "last_affected" in event or "limit" in event:
            kind = (
                "fixed"
                if "fixed" in event
                else "last_affected"
                if "last_affected" in event
                else "limit"
            )
            raw = event.get(kind)
            bound = parse_version(raw)
            if bound is None:
                unknown = True
            if opened:
                intervals.append((introduced, bound, kind))
                opened = False

    if opened:
        intervals.append((introduced, None, "open"))
    return intervals, unknown


def _range_affects(version: Version, range_obj: dict[str, Any]) -> bool | None:
    range_type = str(range_obj.get("type", "")).upper()
    if range_type == "GIT":
        return None
    if range_type not in {"ECOSYSTEM", "SEMVER", ""}:
        return None
    events = range_obj.get("events") or []
    if not isinstance(events, list) or not events:
        return None

    intervals, unknown = _event_intervals(events)
    if unknown and not intervals:
        return None

    for introduced, bound, kind in intervals:
        if introduced is None:
            continue
        if version < introduced:
            continue
        if bound is None:
            return True
        if kind == "fixed" and version < bound:
            return True
        if kind == "last_affected" and version <= bound:
            return True
        if kind == "limit" and version < bound:
            return True

    return None if unknown else False


def entry_affects_version(entry: dict[str, Any], version: Version) -> bool | None:
    """Evaluate one ``affected`` entry for a concrete version."""
    results: list[bool | None] = []

    for range_obj in entry.get("ranges") or []:
        if isinstance(range_obj, dict):
            results.append(_range_affects(version, range_obj))

    explicit = entry.get("versions") or []
    if isinstance(explicit, list) and explicit:
        listed = False
        for item in explicit:
            parsed = parse_version(str(item))
            if parsed is not None and parsed == version:
                listed = True
                break
            if parsed is None and str(item).strip() == str(version):
                listed = True
                break
        results.append(listed)

    if not results:
        return None
    if any(result is True for result in results):
        return True
    if any(result is None for result in results):
        return None
    return False


def advisory_affects_version(advisory: Advisory, version: str | None) -> bool | None:
    """Return whether ``advisory`` affects ``version``.

    ``None`` means the advisory data is insufficient to decide (for example a
    GIT-only range or an unknown installed version).
    """
    parsed = parse_version(version)
    if parsed is None:
        return None
    if not advisory.affected:
        return None
    if advisory.query_mode == "version":
        # The OSV API already filtered by the exact version.
        return True

    results = [
        entry_affects_version(entry, parsed)
        for entry in advisory.affected
        if isinstance(entry, dict)
    ]
    if any(result is True for result in results):
        return True
    if any(result is None for result in results):
        return None
    return False


def fixed_versions_for(advisory: Advisory) -> tuple[str, ...]:
    """Extract fixed versions from all affected ranges."""
    found: list[str] = []
    for entry in advisory.affected:
        if not isinstance(entry, dict):
            continue
        for range_obj in entry.get("ranges") or []:
            if not isinstance(range_obj, dict):
                continue
            if str(range_obj.get("type", "")).upper() == "GIT":
                continue
            for event in range_obj.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    found.append(event["fixed"])

    unique = sorted({value for value in found}, key=_sort_key)
    return tuple(unique)


def next_fixed_version(advisory: Advisory, current: str | None) -> str | None:
    """Return the smallest fixed version greater than ``current``."""
    current_version = parse_version(current)
    for value in fixed_versions_for(advisory):
        parsed = parse_version(value)
        if parsed is None:
            continue
        if current_version is None or parsed > current_version:
            return value
    return None


def _sort_key(value: str) -> tuple[int, Version | str]:
    parsed = parse_version(value)
    return (0, parsed) if parsed is not None else (1, value)
