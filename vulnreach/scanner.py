"""Project discovery and structural AST parsing.

This module is responsible for finding the Python files that make up a project,
deriving importable module names from the directory layout, and collecting the
static structure (imports, functions, classes, ``__main__`` guards) that later
stages consume.  It does not resolve names or build the call graph.
"""

from __future__ import annotations

import ast
import fnmatch
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ScanError
from .model import ClassInfo, FunctionInfo, ImportRef, Location, ModuleInfo, ProjectInfo

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".freebuff",
    ".codebuff",
    "node_modules",
    "build",
    "dist",
    "site-packages",
    ".idea",
    ".vscode",
}

TEST_DIR_NAMES = {"test", "tests", "testing"}
TEST_FILE_PATTERNS = ("test_*.py", "*_test.py", "conftest.py")

MAX_SOURCE_BYTES = 2_000_000


@dataclass
class ParsedProject:
    """A scanned project plus the ASTs kept for the resolution stage."""

    info: ProjectInfo
    trees: dict[str, ast.Module]


def scan_project(
    root: Path,
    *,
    include_tests: bool = False,
    excludes: tuple[str, ...] = (),
    entry_modules: tuple[str, ...] = (),
) -> ParsedProject:
    """Scan ``root`` and return its modules and ASTs.

    Args:
        root: Directory to analyse.
        include_tests: Include ``tests/`` directories and test modules.
        excludes: Additional glob patterns (matched against the POSIX relative
            path) to skip.
        entry_modules: Module names the caller declared as entry points.

    Raises:
        ScanError: if the root is not a directory or no Python files are found.
    """
    root = root.resolve()
    if not root.is_dir():
        raise ScanError(f"project path is not a directory: {root}")

    name, version, scripts, warnings = read_project_metadata(root)
    files = discover_python_files(root, include_tests=include_tests, excludes=excludes)

    if not files:
        raise ScanError(
            f"no Python files found under {root} "
            "(check --exclude patterns and whether the project is empty)"
        )

    modules: list[ModuleInfo] = []
    trees: dict[str, ast.Module] = {}
    seen: dict[str, str] = {}

    for path in files:
        module_name, is_package = module_name_for(root, path)
        if module_name in seen:
            warnings.append(
                f"duplicate module name '{module_name}' for {path}; "
                f"keeping the first occurrence ({seen[module_name]})"
            )
            continue
        seen[module_name] = _relative(path, root)

        info, tree = parse_module(module_name, path, root, is_package=is_package)
        modules.append(info)
        if tree is not None:
            trees[module_name] = tree

    modules.sort(key=lambda module: module.name)
    scanned_names = {module.name for module in modules}
    declared: list[str] = []
    for module in entry_modules:
        if module in scanned_names:
            declared.append(module)
        else:
            warnings.append(f"--entry-module '{module}' does not match any scanned module")

    project = ProjectInfo(
        root=root,
        name=name,
        version=version,
        modules=modules,
        warnings=warnings,
        console_scripts=scripts,
        entry_modules=tuple(declared),
    )
    return ParsedProject(info=project, trees=trees)


def discover_python_files(
    root: Path, *, include_tests: bool = False, excludes: tuple[str, ...] = ()
) -> list[Path]:
    """Return Python files under ``root`` that should be analysed."""
    found: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        try:
            relative = path.relative_to(root)
        except ValueError:  # pragma: no cover - rglob cannot escape root
            continue
        parts = relative.parts[:-1]
        if any(part in DEFAULT_EXCLUDED_DIRS for part in parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        posix = relative.as_posix()
        if any(fnmatch.fnmatch(posix, pattern) for pattern in excludes):
            continue
        if not include_tests:
            if any(part in TEST_DIR_NAMES for part in parts):
                continue
            if any(fnmatch.fnmatch(path.name, pattern) for pattern in TEST_FILE_PATTERNS):
                continue
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                continue
        except OSError:
            continue
        found.append(path)
    return found


def module_name_for(root: Path, path: Path) -> tuple[str, bool]:
    """Derive an importable module name from a file's location.

    The walk stops at the first directory without ``__init__.py``, which
    naturally supports both flat layouts and ``src/`` layouts without special
    casing.
    """
    is_package = path.name == "__init__.py"
    parts: list[str] = [] if is_package else [path.stem]
    parent = path.parent

    while parent != root and (parent / "__init__.py").is_file():
        parts.insert(0, parent.name)
        parent = parent.parent

    if parent == root and (root / "__init__.py").is_file():
        parts.insert(0, root.name)

    return ".".join(parts) or root.name, is_package


def parse_module(
    module_name: str, path: Path, root: Path, *, is_package: bool
) -> tuple[ModuleInfo, ast.Module | None]:
    """Parse one file into structural metadata."""
    location_path = _relative(path, root)
    info = ModuleInfo(
        name=module_name,
        path=location_path,
        node_id=f"mod:{module_name}",
        is_package=is_package,
    )

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        info.parse_error = f"cannot read file: {exc}"
        return info, None

    info.line_count = source.count("\n") + (1 if source and not source.endswith("\n") else 0)

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        info.parse_error = f"syntax error at line {exc.lineno}: {exc.msg}"
        return info, None

    collector = _StructureCollector(module_name, location_path)
    collector.collect(tree.body)
    info.functions = collector.functions
    info.classes = collector.classes
    info.imports = _collect_module_imports(tree, location_path)
    info.has_main_guard = _has_main_guard(tree)
    return info, tree


def read_project_metadata(
    root: Path,
) -> tuple[str, str | None, list[tuple[str, str]], list[str]]:
    """Read name, version and console scripts from ``pyproject.toml``."""
    name = root.name
    version: str | None = None
    scripts: list[tuple[str, str]] = []
    warnings: list[str] = []

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            warnings.append(f"cannot read pyproject.toml: {exc}")
            return name, version, scripts, warnings

        project = data.get("project") or {}
        poetry = (data.get("tool") or {}).get("poetry") or {}
        metadata = project or poetry
        if isinstance(metadata.get("name"), str):
            name = metadata["name"]
        if isinstance(metadata.get("version"), str):
            version = metadata["version"]

        raw_scripts: dict[str, object] = {}
        if isinstance(project.get("scripts"), dict):
            raw_scripts.update(project["scripts"])
        if isinstance(poetry.get("scripts"), dict):
            raw_scripts.update(poetry["scripts"])
        for script_name, target in raw_scripts.items():
            if not isinstance(target, str):
                continue
            module, _, function = target.partition(":")
            scripts.append((script_name, f"{module}:{function or 'main'}"))
    return name, version, scripts, warnings


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover
        return path.as_posix()


class _StructureCollector:
    """Collect functions and classes, including nested definitions."""

    def __init__(self, module: str, path: str) -> None:
        self.module = module
        self.path = path
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []

    def collect(self, body: list[ast.stmt]) -> None:
        self._walk(
            body,
            prefix="",
            class_qualname=None,
            enclosing_function=None,
            in_function_body=False,
        )

    def _walk(
        self,
        body: list[ast.stmt],
        *,
        prefix: str,
        class_qualname: str | None,
        enclosing_function: str | None,
        in_function_body: bool,
    ) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{prefix}{node.name}"
                is_method = class_qualname is not None and prefix == f"{class_qualname}."
                self.functions.append(
                    FunctionInfo(
                        node_id=f"fn:{self.module}:{qualname}",
                        module=self.module,
                        name=node.name,
                        qualname=qualname,
                        location=self._location(node),
                        class_qualname=class_qualname if is_method else None,
                        decorators=tuple(_decorator_text(d) for d in node.decorator_list),
                        parameters=_parameters(node.args),
                        has_varargs=node.args.vararg is not None,
                        has_kwargs=node.args.kwarg is not None,
                        is_async=isinstance(node, ast.AsyncFunctionDef),
                        is_module_level=(class_qualname is None and not in_function_body),
                    )
                )
                self._walk(
                    node.body,
                    prefix=f"{qualname}.<locals>.",
                    class_qualname=None,
                    enclosing_function=qualname,
                    in_function_body=True,
                )
            elif isinstance(node, ast.ClassDef):
                qualname = f"{prefix}{node.name}"
                self.classes.append(
                    ClassInfo(
                        class_id=f"cls:{self.module}:{qualname}",
                        module=self.module,
                        name=node.name,
                        qualname=qualname,
                        location=self._location(node),
                        bases=tuple(_base_text(base) for base in node.bases),
                        decorators=tuple(_decorator_text(d) for d in node.decorator_list),
                        enclosing_function=enclosing_function,
                    )
                )
                self._walk(
                    node.body,
                    prefix=f"{qualname}.",
                    class_qualname=qualname,
                    enclosing_function=enclosing_function,
                    in_function_body=in_function_body,
                )
            else:
                for child_body in _child_statement_bodies(node):
                    self._walk(
                        child_body,
                        prefix=prefix,
                        class_qualname=class_qualname,
                        enclosing_function=enclosing_function,
                        in_function_body=in_function_body,
                    )

    def _location(self, node: ast.AST) -> Location:
        return Location(
            path=self.path,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
        )


def _child_statement_bodies(node: ast.stmt) -> list[list[ast.stmt]]:
    bodies: list[list[ast.stmt]] = []
    for attribute in ("body", "orelse", "finalbody"):
        value = getattr(node, attribute, None)
        if isinstance(value, list) and all(isinstance(item, ast.stmt) for item in value):
            bodies.append(value)
    for handler in getattr(node, "handlers", []) or []:
        if isinstance(handler, ast.ExceptHandler):
            bodies.append(handler.body)
    for case in getattr(node, "cases", []) or []:
        body = getattr(case, "body", None)
        if isinstance(body, list):
            bodies.append(body)
    return bodies


class _ImportCollector(ast.NodeVisitor):
    """Collect imports that execute at module import time."""

    def __init__(self) -> None:
        self.imports: list[ImportRef] = []
        self._path = ""

    def collect(self, tree: ast.Module, path: str) -> list[ImportRef]:
        self._path = path
        for node in tree.body:
            self.visit(node)
        return self.imports

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self.imports.append(
                ImportRef(
                    module=alias.name,
                    name=None,
                    alias=alias.asname or alias.name.split(".")[0],
                    level=0,
                    location=self._loc(node),
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            self.imports.append(
                ImportRef(
                    module=module,
                    name=None if alias.name == "*" else alias.name,
                    alias=alias.asname or alias.name,
                    level=node.level,
                    location=self._loc(node),
                    is_star=alias.name == "*",
                )
            )

    def _loc(self, node: ast.AST) -> Location:
        return Location(
            path=self._path,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
        )


def _collect_module_imports(tree: ast.Module, path: str) -> list[ImportRef]:
    collector = _ImportCollector()
    return collector.collect(tree, path)


def _has_main_guard(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.If):
            text = ast.unparse(node.test)
            if "__name__" in text and "__main__" in text:
                return True
    return False


def _parameters(args: ast.arguments) -> tuple[str, ...]:
    names = [arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return tuple(names)


def _decorator_text(node: ast.expr) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - ast.unparse is reliable on parsed trees
        return "<decorator>"


def _base_text(node: ast.expr) -> str:
    if isinstance(node, ast.Subscript):
        return ast.unparse(node.value)
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover
        return "<base>"


def stdlib_module_names() -> frozenset[str]:
    """Return the stdlib module roots for the running interpreter."""
    names = getattr(sys, "stdlib_module_names", frozenset())
    return frozenset(names)
