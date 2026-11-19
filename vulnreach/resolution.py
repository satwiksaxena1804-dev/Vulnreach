"""Name resolution, call extraction and scope-aware binding.

The resolver is deliberately conservative.  It understands module imports,
aliases, nested functions, classes, methods, inheritance, ``self`` attributes and
``super()`` calls.  Anything it cannot prove becomes a :class:`Gap` and lowers
confidence instead of silently guessing.
"""

from __future__ import annotations

import ast
import builtins
from collections import defaultdict
from dataclasses import dataclass, field

from .model import (
    CallStats,
    Edge,
    EdgeKind,
    FunctionInfo,
    Gap,
    GapKind,
    Location,
    ModuleInfo,
    ProjectInfo,
)
from .scanner import stdlib_module_names

BUILTIN_NAMES = frozenset(dir(builtins))
STDLIB_ROOTS = stdlib_module_names()

DYNAMIC_CODE_NAMES = {"eval", "exec", "compile", "globals", "locals", "vars"}
DYNAMIC_DISPATCH_NAMES = {"getattr", "setattr", "delattr"}
IMPORT_MODULES = {"importlib", "__import__", "import_module"}


class BindingKind:
    """String constants describing what a name refers to."""

    PROJECT_FUNCTION = "project_function"
    PROJECT_CLASS = "project_class"
    MODULE = "module"
    EXTERNAL_MODULE = "external_module"
    EXTERNAL = "external"
    VALUE = "value"
    SUPER = "super"


@dataclass(frozen=True, slots=True)
class Binding:
    kind: str
    target: str
    uncertain: bool = False
    detail: str | None = None


@dataclass
class Scope:
    """A lexical scope with a parent chain and star-import fallbacks."""

    module: str
    caller_id: str
    bindings: dict[str, Binding] = field(default_factory=dict)
    parent: Scope | None = None
    star_imports: list[str] = field(default_factory=list)
    globals: set[str] = field(default_factory=set)
    class_id: str | None = None

    def lookup(self, name: str) -> Binding | None:
        scope: Scope | None = self
        while scope is not None:
            if name in scope.bindings:
                return scope.bindings[name]
            scope = scope.parent
        return None


@dataclass
class ResolutionOutput:
    """Everything produced by walking the project's module bodies."""

    edges: list[Edge] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    stats: CallStats = field(default_factory=CallStats)
    per_caller: dict[str, CallStats] = field(default_factory=lambda: defaultdict(CallStats))
    import_uses: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


class SymbolIndex:
    """Project-wide bindings for modules, classes and functions."""

    def __init__(self, project: ProjectInfo, trees: dict[str, ast.Module]) -> None:
        self.project = project
        self.trees = trees
        self.modules: dict[str, ModuleInfo] = {
            module.name: module for module in project.modules if module.parse_error is None
        }
        self.module_names = set(self.modules)
        self.project_roots = {name.split(".")[0] for name in self.module_names}

        self.functions: dict[str, FunctionInfo] = {}
        self.classes: dict[str, ClassInfoRecord] = {}
        self.module_defs: dict[str, dict[str, Binding]] = defaultdict(dict)
        self.module_bindings: dict[str, dict[str, Binding]] = defaultdict(dict)
        self.class_methods: dict[str, dict[str, str]] = defaultdict(dict)
        self.class_bases: dict[str, tuple[Binding, ...]] = {}
        self.class_attributes: dict[str, dict[str, Binding]] = defaultdict(dict)
        self.star_imports: dict[str, list[str]] = defaultdict(list)
        self.function_ast: dict[str, ast.AST] = {}
        self.class_ids: dict[tuple[str, str], str] = {}
        self.import_edges: list[Edge] = []
        self.import_uses: dict[str, set[str]] = defaultdict(set)
        self.gaps: list[Gap] = []
        self._build()

    # ------------------------------------------------------------------ build
    def _build(self) -> None:
        for module in self.modules.values():
            for function in module.functions:
                self.functions[function.node_id] = function
                if function.is_module_level:
                    self.module_defs[module.name][function.name] = Binding(
                        BindingKind.PROJECT_FUNCTION, function.node_id
                    )
            for class_info in module.classes:
                self.classes[class_info.class_id] = ClassInfoRecord(
                    class_id=class_info.class_id,
                    module=class_info.module,
                    qualname=class_info.qualname,
                    location=class_info.location,
                    bases=class_info.bases,
                )
                self.class_ids[(class_info.module, class_info.qualname)] = class_info.class_id
                if class_info.enclosing_function is None and "." not in class_info.qualname:
                    self.module_defs[module.name][class_info.name] = Binding(
                        BindingKind.PROJECT_CLASS, class_info.class_id
                    )

        self._index_ast_nodes()
        self._build_method_maps()

        for module in self.modules.values():
            for ref in module.imports:
                self._bind_import(module, ref, module.node_id, top_level=True)
            self._bind_module_assignments(module)

        self._resolve_class_bases()
        self._collect_class_attributes()

    def _index_ast_nodes(self) -> None:
        """Map function node ids to their AST nodes using scanner naming rules."""
        for module_name, tree in self.trees.items():
            self._walk_ast(
                tree.body, module_name, prefix="", class_qualname=None, in_function=False
            )

    def _walk_ast(
        self,
        body: list[ast.stmt],
        module_name: str,
        *,
        prefix: str,
        class_qualname: str | None,
        in_function: bool,
    ) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{prefix}{node.name}"
                node_id = f"fn:{module_name}:{qualname}"
                self.function_ast[node_id] = node
                self._walk_ast(
                    node.body,
                    module_name,
                    prefix=f"{qualname}.<locals>.",
                    class_qualname=None,
                    in_function=True,
                )
            elif isinstance(node, ast.ClassDef):
                qualname = f"{prefix}{node.name}"
                self._walk_ast(
                    node.body,
                    module_name,
                    prefix=f"{qualname}.",
                    class_qualname=qualname,
                    in_function=in_function,
                )
            else:
                for attribute in ("body", "orelse", "finalbody"):
                    value = getattr(node, attribute, None)
                    if isinstance(value, list) and all(isinstance(v, ast.stmt) for v in value):
                        self._walk_ast(
                            value,
                            module_name,
                            prefix=prefix,
                            class_qualname=class_qualname,
                            in_function=in_function,
                        )
                for handler in getattr(node, "handlers", []) or []:
                    if isinstance(handler, ast.ExceptHandler):
                        self._walk_ast(
                            handler.body,
                            module_name,
                            prefix=prefix,
                            class_qualname=class_qualname,
                            in_function=in_function,
                        )

    def _build_method_maps(self) -> None:
        for function in self.functions.values():
            if function.class_qualname is None:
                continue
            class_id = self.class_ids.get((function.module, function.class_qualname))
            if class_id is None:
                continue
            self.class_methods[class_id][function.name] = function.node_id

    # ------------------------------------------------------------- imports
    def absolute_module(self, module_name: str, ref) -> str | None:
        if ref.level == 0:
            return ref.module or None
        module = self.modules.get(module_name)
        package = (
            module_name
            if module is not None and module.is_package
            else module_name.rpartition(".")[0]
        )
        if not package:
            return None
        parts = package.split(".")
        up = ref.level - 1
        if up > 0:
            parts = parts[:-up] if up < len(parts) else []
        base = ".".join(parts)
        if ref.module:
            return f"{base}.{ref.module}" if base else ref.module
        return base or None

    def _is_project_package(self, path: str) -> bool:
        return path in self.modules or any(
            name.startswith(f"{path}.") for name in self.module_names
        )

    def _module_binding(self, path: str) -> Binding:
        if self._is_project_package(path):
            return Binding(BindingKind.MODULE, path)
        return Binding(BindingKind.EXTERNAL_MODULE, path)

    def _bind_import(
        self, module: ModuleInfo, ref, caller_id: str, *, top_level: bool = False
    ) -> Binding | None:
        absolute = self.absolute_module(module.name, ref)
        if absolute is None:
            return None

        binding: Binding | None = None
        if ref.is_star:
            if absolute not in self.star_imports[module.name]:
                self.star_imports[module.name].append(absolute)
            self._record_import(module, absolute, caller_id, ref.location, star=True)
            return None

        if ref.name is None:
            first = absolute.split(".")[0]
            # ``import a.b`` binds ``a``; ``import a.b as c`` binds ``c`` to ``a.b``.
            target = absolute if ref.alias != first else first
            binding = self._module_binding(target)
        else:
            if absolute in self.modules or self._is_project_package(absolute):
                candidate = self.module_defs.get(absolute, {}).get(ref.name)
                if candidate is not None:
                    binding = candidate
                else:
                    submodule = f"{absolute}.{ref.name}"
                    binding = (
                        Binding(BindingKind.MODULE, submodule)
                        if self._is_project_package(submodule)
                        else None
                    )
            else:
                binding = Binding(BindingKind.EXTERNAL, f"{absolute}.{ref.name}")

        if binding is not None and top_level:
            self.module_bindings[module.name][ref.alias] = binding
        self._record_import(module, absolute, caller_id, ref.location, star=False)
        if (
            binding is not None
            and binding.kind == BindingKind.MODULE
            and binding.target in self.modules
            and binding.target != absolute
        ):
            self._record_import(
                module, binding.target, caller_id, ref.location, star=False, record_use=False
            )
        return binding

    def _record_import(
        self,
        module: ModuleInfo,
        absolute: str,
        caller_id: str,
        location: Location,
        *,
        star: bool,
        record_use: bool = True,
    ) -> None:
        if absolute in self.modules:
            self.import_edges.append(
                Edge(
                    source=caller_id,
                    target=self.modules[absolute].node_id,
                    kind=EdgeKind.IMPORT,
                    location=location,
                    expression=absolute,
                )
            )
        root = absolute.split(".")[0]
        if record_use and root and root not in self.project_roots and root not in STDLIB_ROOTS:
            self.import_uses[root].add(caller_id)
        if star:
            self.gaps.append(
                Gap(
                    kind=GapKind.STAR_IMPORT,
                    caller_id=caller_id,
                    module=module.name,
                    location=location,
                    detail=absolute,
                )
            )

    def resolve_import(self, module_name: str, ref) -> tuple[Binding | None, str | None]:
        module = self.modules[module_name]
        binding = self._bind_import(module, ref, module.node_id)
        return binding, self.absolute_module(module_name, ref)

    # --------------------------------------------------------- assignments
    def _bind_module_assignments(self, module: ModuleInfo) -> None:
        tree = self.trees.get(module.name)
        if tree is None:
            return
        for node in _iter_module_statements(tree.body):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    binding = self._simple_expr_binding(module.name, node.value)
                    if binding is not None:
                        self.module_bindings[module.name][target.id] = binding
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is not None:
                    binding = self._simple_expr_binding(module.name, node.value)
                    if binding is not None:
                        self.module_bindings[module.name][node.target.id] = binding

    def _simple_expr_binding(self, module_name: str, node: ast.expr | None) -> Binding | None:
        if node is None:
            return None
        resolver = Resolver(self)
        scope = Scope(
            module=module_name,
            caller_id=f"mod:{module_name}",
            bindings=self.module_bindings[module_name],
        )
        binding = resolver.resolve(node, scope)
        if binding is None:
            return None
        if isinstance(node, ast.Call) and binding.kind == BindingKind.PROJECT_FUNCTION:
            return Binding(BindingKind.VALUE, "")
        return binding

    # --------------------------------------------------------------- bases
    def _resolve_class_bases(self) -> None:
        for class_id, record in self.classes.items():
            bindings: list[Binding] = []
            for base_text in record.bases:
                binding = self._resolve_dotted_text(record.module, base_text)
                if binding is not None:
                    bindings.append(binding)
            self.class_bases[class_id] = tuple(bindings)

    def _resolve_dotted_text(self, module_name: str, text: str) -> Binding | None:
        parts = [part.strip() for part in text.split(".") if part.strip()]
        if not parts:
            return None
        if parts[0] in BUILTIN_NAMES and parts[0] not in self.module_bindings[module_name]:
            return None
        binding = self.module_bindings[module_name].get(parts[0])
        if binding is None:
            binding = self.module_defs[module_name].get(parts[0])
        if binding is None:
            return None
        resolver = Resolver(self)
        for part in parts[1:]:
            binding = resolver.attribute(binding, part)
            if binding is None:
                return None
        return binding

    # ---------------------------------------------------- self attributes
    def _collect_class_attributes(self) -> None:
        resolver = Resolver(self)
        for class_id, record in self.classes.items():
            for method_id in self.class_methods[class_id].values():
                tree = self.function_ast.get(method_id)
                if tree is None:
                    continue
                scope = Scope(
                    module=record.module,
                    caller_id=method_id,
                    bindings=dict(self.module_bindings[record.module]),
                    class_id=class_id,
                )
                self_binding = Binding(BindingKind.PROJECT_CLASS, class_id)
                scope.bindings["self"] = self_binding
                scope.bindings["cls"] = self_binding
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                        continue
                    target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                    value = node.value
                    if (
                        value is not None
                        and isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id in {"self", "cls"}
                    ):
                        binding = resolver.resolve(value, scope)
                        if binding is not None and binding.kind in {
                            BindingKind.PROJECT_CLASS,
                            BindingKind.EXTERNAL,
                            BindingKind.MODULE,
                            BindingKind.EXTERNAL_MODULE,
                        }:
                            self.class_attributes[class_id][target.attr] = binding


@dataclass(frozen=True, slots=True)
class ClassInfoRecord:
    class_id: str
    module: str
    qualname: str
    location: Location
    bases: tuple[str, ...]


class Resolver:
    """Resolve AST expressions against the symbol index."""

    def __init__(self, index: SymbolIndex) -> None:
        self.index = index

    def resolve(self, node: ast.expr, scope: Scope) -> Binding | None:
        if isinstance(node, ast.Name):
            return scope.lookup(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope)
            if base is None:
                return None
            return self.attribute(base, node.attr)
        if isinstance(node, ast.Call):
            return self._call_value(node, scope)
        if isinstance(node, (ast.Subscript, ast.Await, ast.Starred)):
            return self.resolve(node.value, scope)
        return None

    def _call_value(self, node: ast.Call, scope: Scope) -> Binding | None:
        if isinstance(node.func, ast.Name) and node.func.id == "super" and scope.class_id:
            return Binding(BindingKind.SUPER, scope.class_id)
        binding = self.resolve(node.func, scope)
        if binding is None:
            return None
        if binding.kind == BindingKind.PROJECT_CLASS:
            return binding
        return Binding(BindingKind.VALUE, "")

    def attribute(self, base: Binding, name: str) -> Binding | None:
        if base.kind == BindingKind.MODULE:
            target = f"{base.target}.{name}"
            if self.index._is_project_package(target):
                return Binding(BindingKind.MODULE, target)
            candidate = self.index.module_defs.get(base.target, {}).get(name)
            if candidate is not None:
                return candidate
            return None
        if base.kind in {BindingKind.EXTERNAL_MODULE, BindingKind.EXTERNAL}:
            if not base.target:
                return None
            return Binding(
                BindingKind.EXTERNAL,
                f"{base.target}.{name}",
                uncertain=base.uncertain,
                detail=base.detail,
            )
        if base.kind == BindingKind.PROJECT_CLASS:
            return self.find_method(base.target, name) or self.index.class_attributes.get(
                base.target, {}
            ).get(name)
        if base.kind == BindingKind.SUPER:
            return self.find_in_bases(base.target, name)
        return None

    def find_method(
        self, class_id: str, name: str, _seen: set[str] | None = None
    ) -> Binding | None:
        seen = _seen or set()
        if class_id in seen:
            return None
        seen.add(class_id)
        method = self.index.class_methods.get(class_id, {}).get(name)
        if method is not None:
            return Binding(BindingKind.PROJECT_FUNCTION, method)
        for base in self.index.class_bases.get(class_id, ()):
            if base.kind == BindingKind.PROJECT_CLASS:
                found = self.find_method(base.target, name, seen)
                if found is not None:
                    return found
            elif base.kind in {BindingKind.EXTERNAL, BindingKind.EXTERNAL_MODULE}:
                return Binding(BindingKind.EXTERNAL, f"{base.target}.{name}", uncertain=True)
        return None

    def find_in_bases(
        self, class_id: str, name: str, _seen: set[str] | None = None
    ) -> Binding | None:
        """Resolve a ``super()`` attribute, skipping the current class."""
        seen = _seen or set()
        if class_id in seen:
            return None
        seen.add(class_id)
        for base in self.index.class_bases.get(class_id, ()):
            if base.kind == BindingKind.PROJECT_CLASS:
                found = self.find_method(base.target, name, seen)
                if found is not None:
                    return found
            elif base.kind in {BindingKind.EXTERNAL, BindingKind.EXTERNAL_MODULE}:
                return Binding(BindingKind.EXTERNAL, f"{base.target}.{name}", uncertain=True)
        return None

    def init_method(self, class_id: str) -> Binding | None:
        return self.find_method(class_id, "__init__")

    def star_binding(self, name: str, scope: Scope) -> Binding | None:
        scope_chain: list[Scope] = []
        current: Scope | None = scope
        while current is not None:
            scope_chain.append(current)
            current = current.parent
        for scoped in scope_chain:
            for star in reversed(scoped.star_imports):
                if star in self.index.modules:
                    candidate = self.index.module_defs.get(star, {}).get(name)
                    if candidate is not None:
                        return Binding(
                            candidate.kind,
                            candidate.target,
                            uncertain=True,
                            detail=f"star import from {star}",
                        )
                elif star.split(".")[0] not in STDLIB_ROOTS:
                    return Binding(
                        BindingKind.EXTERNAL,
                        f"{star}.{name}",
                        uncertain=True,
                        detail=f"star import from {star}",
                    )
        return None


# ---------------------------------------------------------------------------
# Body walker
# ---------------------------------------------------------------------------


@dataclass
class _WalkContext:
    module: ModuleInfo
    prefix: str
    class_qualname: str | None
    class_id: str | None
    in_function_body: bool


class Walker:
    """Walk a module body, recording call and reference edges."""

    def __init__(
        self,
        index: SymbolIndex,
        resolver: Resolver,
        output: ResolutionOutput,
        module: ModuleInfo,
        scope: Scope,
        context: _WalkContext,
    ) -> None:
        self.index = index
        self.resolver = resolver
        self.output = output
        self.module = module
        self.scope = scope
        self.context = context
        self.path = module.path
        self._suppress_references = 0

    # ------------------------------------------------------------ utilities
    def _loc(self, node: ast.AST) -> Location:
        return Location(
            path=self.path,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
        )

    def _stats(self) -> CallStats:
        return self.output.per_caller[self.scope.caller_id]

    def _add_edge(
        self,
        target: str,
        kind: EdgeKind,
        node: ast.AST,
        *,
        expression: str | None = None,
        uncertain: bool = False,
    ) -> None:
        self._edge_at(target, kind, self._loc(node), expression=expression, uncertain=uncertain)

    def _edge_at(
        self,
        target: str,
        kind: EdgeKind,
        location: Location,
        *,
        expression: str | None = None,
        uncertain: bool = False,
    ) -> None:
        if not target:
            return
        self.output.edges.append(
            Edge(
                source=self.scope.caller_id,
                target=target,
                kind=kind,
                location=location,
                expression=expression,
                uncertain=uncertain,
            )
        )

    def _gap(self, kind: GapKind, node: ast.AST | Location, detail: str) -> None:
        location = node if isinstance(node, Location) else self._loc(node)
        self.output.gaps.append(
            Gap(
                kind=kind,
                caller_id=self.scope.caller_id,
                module=self.module.name,
                location=location,
                detail=detail[:300],
            )
        )

    def _expression_text(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)[:200]
        except Exception:  # pragma: no cover
            return "<expression>"

    # ---------------------------------------------------------------- walk
    def walk(self, body: list[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)

    def visit(self, node: ast.AST | None) -> None:
        if node is None:
            return
        method = getattr(self, f"visit_{type(node).__name__}", None)
        if method is not None:
            method(node)
        else:
            self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    # ---------------------------------------------------------- definitions
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._handle_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._handle_function(node)

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]:
            self.visit(default)

        qualname = f"{self.context.prefix}{node.name}"
        is_method = (
            self.context.class_qualname is not None
            and self.context.prefix == f"{self.context.class_qualname}."
        )
        class_id = self.context.class_id if is_method else None
        caller_id = f"fn:{self.module.name}:{qualname}"

        parent_scope = self.scope
        if is_method and self.scope.parent is not None:
            parent_scope = self.scope.parent

        child = Scope(
            module=self.module.name,
            caller_id=caller_id,
            bindings={},
            parent=parent_scope,
            class_id=class_id,
        )
        for parameter in _all_parameters(node.args):
            child.bindings[parameter] = Binding(BindingKind.VALUE, "")
        if is_method and class_id:
            instance = Binding(BindingKind.PROJECT_CLASS, class_id)
            for name in ("self", "cls"):
                if name in child.bindings:
                    child.bindings[name] = instance

        self._precollect(node.body, child, prefix=f"{qualname}.<locals>.")
        walker = Walker(
            self.index,
            self.resolver,
            self.output,
            self.module,
            child,
            _WalkContext(
                module=self.module,
                prefix=f"{qualname}.<locals>.",
                class_qualname=None,
                class_id=None,
                in_function_body=True,
            ),
        )
        walker.walk(node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        qualname = f"{self.context.prefix}{node.name}"
        class_id = self.index.class_ids.get((self.module.name, qualname))
        body_scope = Scope(
            module=self.module.name,
            caller_id=self.scope.caller_id,
            bindings={},
            parent=self.scope,
            class_id=class_id,
        )
        body_scope.star_imports = list(self.scope.star_imports)
        walker = Walker(
            self.index,
            self.resolver,
            self.output,
            self.module,
            body_scope,
            _WalkContext(
                module=self.module,
                prefix=f"{qualname}.",
                class_qualname=qualname,
                class_id=class_id,
                in_function_body=self.context.in_function_body,
            ),
        )
        walker.walk(node.body)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        child = Scope(
            module=self.module.name,
            caller_id=self.scope.caller_id,
            bindings={name: Binding(BindingKind.VALUE, "") for name in _all_parameters(node.args)},
            parent=self.scope,
            class_id=self.scope.class_id,
        )
        child.star_imports = list(self.scope.star_imports)
        walker = Walker(
            self.index,
            self.resolver,
            self.output,
            self.module,
            child,
            self.context,
        )
        walker.visit(node.body)

    # ------------------------------------------------------------- imports
    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            ref = _import_ref(alias.name, None, alias.asname, 0, self._loc(node))
            self._import(ref)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for alias in node.names:
            ref = _import_ref(
                module,
                None if alias.name == "*" else alias.name,
                alias.asname or alias.name,
                node.level,
                self._loc(node),
                is_star=alias.name == "*",
            )
            self._import(ref)

    def _import(self, ref) -> None:
        absolute = self.index.absolute_module(self.module.name, ref)
        if absolute is None:
            return
        if absolute in self.index.modules:
            self._edge_at(
                self.index.modules[absolute].node_id,
                EdgeKind.IMPORT,
                ref.location,
                expression=absolute,
            )
        root = absolute.split(".")[0]
        if root and root not in self.index.project_roots and root not in STDLIB_ROOTS:
            self.output.import_uses[root].add(self.scope.caller_id)
        if ref.is_star:
            if absolute not in self.scope.star_imports:
                self.scope.star_imports.append(absolute)
            self._gap(GapKind.STAR_IMPORT, ref.location, absolute)

    # ----------------------------------------------------------- bindings
    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            self.visit(node.value)
            if isinstance(node.target, ast.Name):
                self._bind_name(node.target.id, node.value)
        # Annotations are intentionally not walked: they are not executed calls.

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self.visit(node.value)
        self._bind_target(node.target, None)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self.visit(node.iter)
        self._bind_target(node.target, None)
        self.walk(node.body)
        self.walk(node.orelse)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self.visit_For(node)  # type: ignore[arg-type]

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars, None)
        self.walk(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:  # noqa: N802
        self.visit_With(node)  # type: ignore[arg-type]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.name:
            self.scope.bindings[node.name] = Binding(BindingKind.VALUE, "")
        self.walk(node.body)

    def visit_Global(self, node: ast.Global) -> None:  # noqa: N802
        self.scope.globals.update(node.names)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        self.visit(node.value)
        self._bind_target(node.target, node.value)

    def _bind_target(self, target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, ast.Name):
            self._bind_name(target.id, value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, None)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, None)
        elif isinstance(target, ast.Attribute):
            self._bind_attribute(target, value)

    def _bind_name(self, name: str, value: ast.expr | None) -> None:
        if name in self.scope.globals:
            return
        binding = self._value_binding(value) if value is not None else None
        self.scope.bindings[name] = binding or Binding(BindingKind.VALUE, "")

    def _bind_attribute(self, target: ast.Attribute, value: ast.expr | None) -> None:
        if not isinstance(target.value, ast.Name) or target.value.id not in {"self", "cls"}:
            return
        if self.context.class_id is None:
            return
        binding = self._value_binding(value)
        if binding is not None and binding.kind in {
            BindingKind.PROJECT_CLASS,
            BindingKind.EXTERNAL,
            BindingKind.MODULE,
            BindingKind.EXTERNAL_MODULE,
        }:
            self.index.class_attributes[self.context.class_id][target.attr] = binding

    def _value_binding(self, value: ast.expr | None) -> Binding | None:
        if value is None:
            return None
        if isinstance(value, ast.Name):
            return self.scope.lookup(value.id)
        if isinstance(value, ast.Attribute):
            return self.resolver.resolve(value, self.scope)
        if isinstance(value, ast.Call):
            func = self.resolver.resolve(value.func, self.scope)
            if func is None:
                return None
            if func.kind == BindingKind.PROJECT_CLASS:
                return Binding(BindingKind.PROJECT_CLASS, func.target)
            if func.kind == BindingKind.EXTERNAL:
                leaf = func.target.rsplit(".", 1)[-1]
                if leaf[:1].isupper():
                    # Heuristic: CamelCase callables are constructors.  This makes
                    # ``session = requests.Session(); session.get(...)`` resolve.
                    return Binding(BindingKind.EXTERNAL, func.target, uncertain=True)
                return Binding(BindingKind.VALUE, "")
        return None

    # --------------------------------------------------------------- calls
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        text = self._expression_text(node.func)
        self._handle_special_call(node, text)

        binding = self.resolver.resolve(node.func, self.scope)
        recorded = False

        if binding is not None:
            if binding.kind == BindingKind.PROJECT_FUNCTION:
                self._record_call(
                    binding.target, node, text, BindingKind.PROJECT_FUNCTION, binding.uncertain
                )
                recorded = True
            elif binding.kind == BindingKind.PROJECT_CLASS:
                init = self.resolver.init_method(binding.target)
                if init is None:
                    self._stats().project += 1
                    self._stats().total += 1
                elif init.kind == BindingKind.PROJECT_FUNCTION:
                    self._record_call(
                        init.target, node, text, BindingKind.PROJECT_FUNCTION, init.uncertain
                    )
                elif init.kind == BindingKind.EXTERNAL:
                    self._record_call(init.target, node, text, BindingKind.EXTERNAL, True)
                recorded = True
            elif binding.kind == BindingKind.EXTERNAL:
                target = binding.target
                root = target.split(".")[0]
                stats = self._stats()
                stats.total += 1
                if root in STDLIB_ROOTS or root == "__future__":
                    stats.stdlib += 1
                else:
                    stats.external += 1
                    self._add_edge(
                        f"ext:{target}",
                        EdgeKind.CALL,
                        node,
                        expression=text,
                        uncertain=binding.uncertain,
                    )
                recorded = True
            elif binding.kind == BindingKind.SUPER:
                recorded = True
            elif binding.kind in {BindingKind.MODULE, BindingKind.EXTERNAL_MODULE}:
                self._gap(GapKind.UNRESOLVED_CALL, node, f"calling module '{binding.target}'")
                recorded = True

        if not recorded and isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "super":
                recorded = True
            elif name in BUILTIN_NAMES:
                self._stats().builtin += 1
                self._stats().total += 1
                recorded = True
                if name in DYNAMIC_CODE_NAMES or name in DYNAMIC_DISPATCH_NAMES:
                    self._gap(GapKind.DYNAMIC_CODE, node, f"{name}() in reachable code")
            else:
                star = self.resolver.star_binding(name, self.scope)
                if star is not None and star.kind == BindingKind.EXTERNAL:
                    self._record_call(star.target, node, text, BindingKind.EXTERNAL, True)
                    recorded = True

        if not recorded:
            stats = self._stats()
            stats.total += 1
            stats.unresolved += 1
            binding_kind = binding.kind if binding is not None else None
            if binding_kind == BindingKind.VALUE:
                self._gap(
                    GapKind.DYNAMIC_DISPATCH,
                    node,
                    f"call through a value: {text}",
                )
            else:
                self._gap(GapKind.UNRESOLVED_CALL, node, text)

        # Visit arguments (references and nested calls) and the callee expression
        # for nested calls such as factory().run().
        self._suppress_references += 1
        try:
            self.visit(node.func)
        finally:
            self._suppress_references -= 1
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def _handle_special_call(self, node: ast.Call, text: str) -> None:
        name = text.rsplit(".", 1)[-1]
        if name in IMPORT_MODULES and text in {
            "__import__",
            "importlib.import_module",
            "import_module",
        }:
            module: str | None = None
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                module = node.args[0].value
            if module:
                self._gap(GapKind.DYNAMIC_IMPORT, node, module)
                root = module.split(".")[0]
                if root not in STDLIB_ROOTS and root not in self.index.project_roots:
                    self.output.import_uses[root].add(self.scope.caller_id)
            else:
                self._gap(GapKind.DYNAMIC_IMPORT, node, f"dynamic module name in {text}()")

    def _record_call(
        self, target: str, node: ast.AST, text: str, kind: str, uncertain: bool
    ) -> None:
        stats = self._stats()
        stats.total += 1
        if kind == BindingKind.PROJECT_FUNCTION:
            stats.project += 1
        else:
            stats.external += 1
            target = f"ext:{target}"
        self._add_edge(target, EdgeKind.CALL, node, expression=text, uncertain=uncertain)

    # ----------------------------------------------------------- references
    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if self._suppress_references or not isinstance(node.ctx, ast.Load):
            return
        if node.id in BUILTIN_NAMES and self.scope.lookup(node.id) is None:
            return
        binding = self.scope.lookup(node.id)
        self._record_reference(binding, node, node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if not self._suppress_references and isinstance(node.ctx, ast.Load):
            binding = self.resolver.resolve(node, self.scope)
            self._record_reference(binding, node, self._expression_text(node))
        self._suppress_references += 1
        try:
            self.visit(node.value)
        finally:
            self._suppress_references -= 1

    def _record_reference(self, binding: Binding | None, node: ast.AST, text: str) -> None:
        if binding is None:
            return
        if binding.kind == BindingKind.PROJECT_FUNCTION:
            self._stats().references += 1
            self._add_edge(binding.target, EdgeKind.REFERENCE, node, expression=text)
        elif binding.kind == BindingKind.EXTERNAL:
            root = binding.target.split(".")[0]
            if root in STDLIB_ROOTS or root == "__future__" or not root:
                return
            self._stats().references += 1
            self._add_edge(
                f"ext:{binding.target}",
                EdgeKind.REFERENCE,
                node,
                expression=text,
                uncertain=True,
            )

    # ---------------------------------------------------------- precollect
    def _precollect(self, body: list[ast.stmt], scope: Scope, *, prefix: str) -> None:
        for statement in body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{prefix}{statement.name}"
                scope.bindings[statement.name] = Binding(
                    BindingKind.PROJECT_FUNCTION, f"fn:{self.module.name}:{qualname}"
                )
            elif isinstance(statement, ast.ClassDef):
                qualname = f"{prefix}{statement.name}"
                class_id = self.index.class_ids.get((self.module.name, qualname), "")
                scope.bindings[statement.name] = Binding(
                    BindingKind.PROJECT_CLASS, class_id or qualname
                )
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    ref = _import_ref(alias.name, None, alias.asname, 0, self._loc(statement))
                    self._bind_local_import(scope, ref)
            elif isinstance(statement, ast.ImportFrom):
                for alias in statement.names:
                    ref = _import_ref(
                        statement.module or "",
                        None if alias.name == "*" else alias.name,
                        alias.asname or alias.name,
                        statement.level,
                        self._loc(statement),
                        is_star=alias.name == "*",
                    )
                    self._bind_local_import(scope, ref)
            elif isinstance(statement, ast.Global):
                scope.globals.update(statement.names)
            else:
                for attribute in ("body", "orelse", "finalbody"):
                    value = getattr(statement, attribute, None)
                    if isinstance(value, list) and all(isinstance(v, ast.stmt) for v in value):
                        self._precollect(value, scope, prefix=prefix)
                for handler in getattr(statement, "handlers", []) or []:
                    if isinstance(handler, ast.ExceptHandler):
                        self._precollect(handler.body, scope, prefix=prefix)

    def _bind_local_import(self, scope: Scope, ref) -> None:
        absolute = self.index.absolute_module(self.module.name, ref)
        if absolute is None:
            return
        if ref.is_star:
            if absolute not in scope.star_imports:
                scope.star_imports.append(absolute)
            return
        if ref.name is None:
            first = absolute.split(".")[0]
            target = absolute if ref.alias != first else first
            scope.bindings[ref.alias] = self.index._module_binding(target)
            return
        if absolute in self.index.modules or self.index._is_project_package(absolute):
            candidate = self.index.module_defs.get(absolute, {}).get(ref.name)
            if candidate is not None:
                scope.bindings[ref.alias] = candidate
                return
            submodule = f"{absolute}.{ref.name}"
            if self.index._is_project_package(submodule):
                scope.bindings[ref.alias] = Binding(BindingKind.MODULE, submodule)
                return
            scope.bindings[ref.alias] = Binding(BindingKind.VALUE, "")
            return
        scope.bindings[ref.alias] = Binding(BindingKind.EXTERNAL, f"{absolute}.{ref.name}")


def _import_ref(
    module: str,
    name: str | None,
    alias: str,
    level: int,
    location: Location,
    *,
    is_star: bool = False,
):
    from .model import ImportRef

    return ImportRef(
        module=module,
        name=name,
        alias=alias or name or module.split(".")[0],
        level=level,
        location=location,
        is_star=is_star,
    )


def _all_parameters(args: ast.arguments) -> list[str]:
    names = [arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return names


def _iter_module_statements(body: list[ast.stmt]):
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield statement
        for attribute in ("body", "orelse", "finalbody"):
            value = getattr(statement, attribute, None)
            if isinstance(value, list) and all(isinstance(v, ast.stmt) for v in value):
                yield from _iter_module_statements(value)
        for handler in getattr(statement, "handlers", []) or []:
            if isinstance(handler, ast.ExceptHandler):
                yield from _iter_module_statements(handler.body)


def resolve_project(
    project: ProjectInfo, trees: dict[str, ast.Module]
) -> tuple[ResolutionOutput, SymbolIndex]:
    """Resolve every module body and return edges, gaps and statistics."""
    index = SymbolIndex(project, trees)
    resolver = Resolver(index)
    output = ResolutionOutput()
    output.edges.extend(index.import_edges)
    output.gaps.extend(index.gaps)
    for root, callers in index.import_uses.items():
        output.import_uses[root].update(callers)

    for module in project.modules:
        tree = trees.get(module.name)
        if module.parse_error is not None or tree is None:
            output.gaps.append(
                Gap(
                    kind=GapKind.PARSE_ERROR,
                    caller_id=module.node_id,
                    module=module.name,
                    location=Location(path=module.path, line=1),
                    detail=module.parse_error,
                )
            )
            continue

        scope = Scope(
            module=module.name,
            caller_id=module.node_id,
            bindings={**index.module_defs[module.name], **index.module_bindings[module.name]},
            star_imports=list(index.star_imports[module.name]),
        )
        walker = Walker(
            index,
            resolver,
            output,
            module,
            scope,
            _WalkContext(
                module=module,
                prefix="",
                class_qualname=None,
                class_id=None,
                in_function_body=False,
            ),
        )
        walker.walk(tree.body)

    for stats in output.per_caller.values():
        output.stats.merge(stats)
    return output, index
