"""Dependency and package identification.

VulnReach reads declared dependencies from ``pyproject.toml`` and requirements
files, resolves the version that is actually installed when available, and maps
distribution names to the top-level modules they provide.  The mapping is what
lets the call graph attribute a call such as ``yaml.load`` to the ``pyyaml``
distribution.
"""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.markers import InvalidMarker
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .model import Dependency

MAX_TRANSITIVE_DEPTH = 3
MAX_TRANSITIVE_COUNT = 300

# Distributions whose import name cannot be derived mechanically.
KNOWN_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "beautifulsoup4": ("bs4",),
    "django-rest-framework": ("rest_framework",),
    "google-api-python-client": ("googleapiclient",),
    "mysql-connector-python": ("mysql",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "pillow": ("PIL",),
    "protobuf": ("google",),
    "pyjwt": ("jwt",),
    "pyopenssl": ("OpenSSL",),
    "pyserial": ("serial",),
    "python-dateutil": ("dateutil",),
    "python-dotenv": ("dotenv",),
    "pyyaml": ("yaml",),
    "ruamel-yaml": ("ruamel",),
    "scikit-learn": ("sklearn",),
    "setuptools": ("setuptools", "pkg_resources"),
    "sqlalchemy": ("sqlalchemy",),
    "typing-extensions": ("typing_extensions",),
    "zope-interface": ("zope",),
}


@dataclass
class DependencySet:
    """Resolved dependencies plus non-fatal manifest warnings."""

    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def by_name(self) -> dict[str, Dependency]:
        return {dependency.name: dependency for dependency in self.dependencies}

    def import_map(self) -> dict[str, Dependency]:
        """Map top-level import names to dependencies."""
        mapping: dict[str, Dependency] = {}
        for dependency in self.dependencies:
            for name in dependency.import_names:
                mapping.setdefault(name, dependency)
        return mapping


@dataclass
class _Declared:
    requirement: Requirement
    source: str


def collect_dependencies(root: Path, *, include_dev: bool = False) -> DependencySet:
    """Collect direct and (when installed) transitive dependencies."""
    result = DependencySet()
    declared = _declared_requirements(root, include_dev=include_dev, result=result)

    seen: dict[str, _Declared] = {}
    for item in declared:
        name = canonicalize_name(item.requirement.name)
        if name in seen:
            if str(seen[name].requirement.specifier) != str(item.requirement.specifier):
                result.warnings.append(
                    f"dependency '{name}' declared more than once with different specifiers; "
                    f"using {item.requirement.specifier or 'no specifier'}"
                )
            continue
        seen[name] = item

    for name, item in seen.items():
        dependency = _direct_dependency(name, item, result.warnings)
        result.dependencies.append(dependency)

    results_sources = sorted({item.source for item in declared})
    result.sources = results_sources

    _add_transitive(result, start_dependencies=list(result.dependencies))
    result.dependencies.sort(key=lambda dep: (not dep.direct, dep.depth, dep.name))
    return result


def parse_requirement_string(text: str) -> Requirement | None:
    """Parse a PEP 508 requirement, returning ``None`` when invalid."""
    text = text.strip()
    if not text:
        return None
    try:
        return Requirement(text)
    except InvalidRequirement:
        return None


def _declared_requirements(
    root: Path, *, include_dev: bool, result: DependencySet
) -> list[_Declared]:
    declared: list[_Declared] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"cannot read pyproject.toml dependencies: {exc}")
            data = {}

        project = data.get("project") or {}
        groups = [("project.dependencies", project.get("dependencies") or [])]
        if include_dev:
            for group, values in (project.get("optional-dependencies") or {}).items():
                if group.lower() in {"dev", "test", "tests", "testing"}:
                    groups.append((f"project.optional-dependencies.{group}", values))
        for source, values in groups:
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                requirement = parse_requirement_string(value)
                if requirement is None:
                    result.warnings.append(f"cannot parse requirement '{value}' in {source}")
                elif _marker_applies(requirement, result, source):
                    declared.append(_Declared(requirement=requirement, source=source))

        poetry = (data.get("tool") or {}).get("poetry") or {}
        poetry_deps = poetry.get("dependencies") or {}
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                text = _poetry_requirement(name, spec)
                requirement = parse_requirement_string(text)
                if requirement is not None:
                    declared.append(
                        _Declared(requirement=requirement, source="tool.poetry.dependencies")
                    )

    requirement_files = [root / "requirements.txt"]
    if include_dev:
        requirement_files.extend([root / "requirements-dev.txt", root / "requirements" / "dev.txt"])
    for path in requirement_files:
        if path.is_file():
            declared.extend(_read_requirements_file(path, result, seen=set()))

    if not declared and not requirement_files[0].is_file() and not pyproject.is_file():
        result.warnings.append(
            "no dependency manifest found (looked for pyproject.toml and requirements.txt)"
        )
    return declared


def _read_requirements_file(
    path: Path, result: DependencySet, *, seen: set[Path]
) -> list[_Declared]:
    path = path.resolve()
    if path in seen:
        result.warnings.append(f"recursive requirements include ignored: {path.name}")
        return []
    seen.add(path)

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.warnings.append(f"cannot read {path.name}: {exc}")
        return []

    source = path.name
    declared: list[_Declared] = []
    logical_lines = _logical_lines(text)

    for line in logical_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-"):
            if stripped.startswith(("-r ", "--requirement ")):
                target = stripped.split(None, 1)[1].strip()
                included = (path.parent / target).resolve()
                if included.is_file():
                    declared.extend(_read_requirements_file(included, result, seen=seen))
                else:
                    result.warnings.append(
                        f"{source}: included requirements file not found: {target}"
                    )
            elif stripped.startswith(("-e ", "--editable ")):
                result.warnings.append(f"{source}: editable requirement skipped: {stripped}")
            # Other pip options do not describe a package requirement.
            continue

        requirement = parse_requirement_string(_strip_inline_comment(stripped))
        if requirement is None:
            result.warnings.append(f"{source}: ignoring unparsable requirement '{stripped}'")
            continue
        if _marker_applies(requirement, result, source):
            declared.append(_Declared(requirement=requirement, source=source))
    return declared


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        lines.append(current + line)
        current = ""
    if current:
        lines.append(current)
    return lines


def _strip_inline_comment(line: str) -> str:
    # PEP 508 URLs may contain '#', but an inline comment is preceded by whitespace.
    match = re.search(r"\s+#", line)
    if match:
        return line[: match.start()].strip()
    return line.strip()


def _marker_applies(requirement: Requirement, result: DependencySet, source: str) -> bool:
    if requirement.marker is None:
        return True
    try:
        return bool(requirement.marker.evaluate())
    except (InvalidMarker, KeyError, ValueError) as exc:
        result.warnings.append(f"{source}: cannot evaluate marker for '{requirement.name}': {exc}")
        return True


def _poetry_requirement(name: str, spec: object) -> str:
    if isinstance(spec, str):
        return name if spec in {"*", ""} else f"{name}{spec}"
    if isinstance(spec, dict):
        version = spec.get("version")
        extras = spec.get("extras") or []
        suffix = f"[{','.join(str(extra) for extra in extras)}]" if extras else ""
        if isinstance(version, str) and version not in {"*", ""}:
            return f"{name}{suffix}{version}"
        return f"{name}{suffix}"
    return name


def _direct_dependency(name: str, item: _Declared, warnings: list[str]) -> Dependency:
    requirement = item.requirement
    installed = _installed_version(name)
    pinned = next(
        (
            spec.version
            for spec in requirement.specifier
            if spec.operator == "==" and "*" not in spec.version
        ),
        None,
    )
    source = "unknown"
    version: str | None = None

    if installed and (not pinned or requirement.specifier.contains(installed, prereleases=True)):
        version, source = installed, "installed"
    elif pinned:
        version, source = pinned, "pinned"
        if installed and installed != pinned:
            warnings.append(
                f"{name}: installed version {installed} does not satisfy the pinned "
                f"specifier =={pinned}; analysing the pinned version"
            )
    elif installed:
        version, source = installed, "installed (specifier not satisfied)"
        warnings.append(
            f"{name}: installed version {installed} does not satisfy "
            f"'{requirement.specifier or 'any'}'; analysing the installed version"
        )
    else:
        warnings.append(
            f"{name}: version could not be determined (not installed and not pinned); "
            "affectedness will be reported as uncertain"
        )

    return Dependency(
        name=name,
        raw_name=requirement.name,
        specifier=str(requirement.specifier),
        version=version,
        version_source=source,
        import_names=_import_names(name),
        direct=True,
        depth=0,
        via=(),
        extras=tuple(sorted(requirement.extras)),
        marker=str(requirement.marker) if requirement.marker else None,
        source=item.source,
    )


def _add_transitive(result: DependencySet, *, start_dependencies: list[Dependency]) -> None:
    known = {dependency.name for dependency in result.dependencies}
    queue: list[tuple[Dependency, int]] = [(dependency, 0) for dependency in start_dependencies]
    added = 0

    while queue and added < MAX_TRANSITIVE_COUNT:
        parent, depth = queue.pop(0)
        if depth >= MAX_TRANSITIVE_DEPTH:
            continue
        for requirement in _installed_requires(parent.name):
            name = canonicalize_name(requirement.name)
            if name in known:
                continue
            installed = _installed_version(name)
            if installed is None:
                continue
            dependency = Dependency(
                name=name,
                raw_name=requirement.name,
                specifier=str(requirement.specifier),
                version=installed,
                version_source="installed (transitive)",
                import_names=_import_names(name),
                direct=False,
                depth=depth + 1,
                via=(parent.name,),
                extras=tuple(sorted(requirement.extras)),
                marker=None,
                source=f"metadata of {parent.name}",
            )
            known.add(name)
            result.dependencies.append(dependency)
            queue.append((dependency, depth + 1))
            added += 1

    if added >= MAX_TRANSITIVE_COUNT:
        result.warnings.append(
            f"transitive dependency walk stopped after {MAX_TRANSITIVE_COUNT} packages"
        )


def _installed_requires(name: str) -> list[Requirement]:
    try:
        raw = importlib.metadata.requires(name)
    except importlib.metadata.PackageNotFoundError:
        return []
    requirements: list[Requirement] = []
    for text in raw or []:
        requirement = parse_requirement_string(text)
        if requirement is None:
            continue
        # Do not pull in optional extras of a dependency.
        if requirement.marker is not None:
            try:
                if not requirement.marker.evaluate({"extra": ""}):
                    continue
            except (InvalidMarker, KeyError, ValueError):
                continue
        requirements.append(requirement)
    return requirements


def _installed_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return None


def _import_names(name: str) -> tuple[str, ...]:
    names: set[str] = set(KNOWN_IMPORT_NAMES.get(name, ()))
    mechanical = name.replace("-", "_")
    if mechanical.isidentifier():
        names.add(mechanical)
    compact = name.replace("-", "")
    if compact.isidentifier():
        names.add(compact)

    try:
        distribution = importlib.metadata.distribution(name)
    except (importlib.metadata.PackageNotFoundError, ValueError):
        distribution = None

    if distribution is not None:
        top_level = distribution.read_text("top_level.txt")
        if top_level:
            for line in top_level.splitlines():
                candidate = line.strip().replace("/", ".")
                if candidate and candidate.isidentifier():
                    names.add(candidate)
        else:
            record = distribution.read_text("RECORD") or ""
            for line in record.splitlines():
                path = line.split(",", 1)[0]
                if not path or path.startswith(".."):
                    continue
                first = path.split("/", 1)[0]
                if first.endswith((".dist-info", ".data", ".egg-info")):
                    continue
                stem = first[:-3] if first.endswith(".py") else first
                if stem.isidentifier() and stem not in {"__pycache__", "bin", "scripts"}:
                    names.add(stem)
    return tuple(sorted(names))
