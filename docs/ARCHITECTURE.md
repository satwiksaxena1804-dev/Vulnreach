# Architecture

VulnReach is a pipeline of small, separately testable stages. Each stage has one
job and produces plain data that the next stage consumes.

```
project files
    │  scanner.py         discovery, module names, classes/functions/imports
    ▼
ParsedProject (ModuleInfo + ASTs)
    │  resolution.py      scope-aware binding, call/reference/import edges, gaps
    ▼
ResolutionOutput (edges, gaps, call stats, import usage)
    │  callgraph.py       nodes, entry points, BFS path reconstruction
    ▼
CallGraph
    │  osv.py              advisories for dependency versions
    │  symbols.py          vulnerable symbol patterns
    ▼
reachability.py           verdict + confidence + rationale per advisory
    │
    ▼
report/                   console · JSON · Markdown · OpenVEX
```

The optional `ai/explain.py` stage sits **beside** this pipeline. It reads a
finished finding and produces prose only.

---

## 1. Scanner (`vulnreach/scanner.py`)

**Discovery.** Walks `*.py` under the project root, skipping virtualenvs, VCS
directories, caches, build output, and (by default) tests. Extra exclusions are
glob patterns matched against the POSIX relative path.

**Module naming.** Starting at the file's directory, the scanner walks upward
while `__init__.py` exists and prepends directory names. This yields importable
names for flat, package and `src/` layouts without a hard-coded `src` special
case. Files whose names are not importable identifiers are kept but their imports
will not resolve; this is visible as unresolved names.

**Structure.** A recursive statement walker records:

- `FunctionInfo` for functions, async functions, methods and nested functions
  (qualnames follow `__qualname__`, including `<locals>`),
- `ClassInfo` for classes at any nesting level, with raw base expressions,
- module-level imports (imports inside functions belong to those scopes),
- `if __name__ == "__main__"` guards,
- decorators and parameter lists for entry-point inference.

**Metadata.** `pyproject.toml` supplies the project name, version and console
scripts. A syntax error is recorded on the module and becomes a `parse_error`
gap; it never aborts the scan.

## 2. Resolution (`vulnreach/resolution.py`)

This is the core of the static analysis. It builds a project-wide `SymbolIndex`
and walks every module body with a lexical `Scope` chain.

### Symbol index

- **Functions/classes** are registered under `fn:<module>:<qualname>` and
  `cls:<module>:<qualname>`.
- **Module bindings** contain imports, module-level functions/classes and simple
  module-level assignments (`client = HttpClient()`, aliases).
- **Relative imports** are converted to absolute module names using the package
  depth rules from Python's import system.
- **Class bases** are resolved against module bindings, producing project class
  references or external dotted references.
- **`self.attr` types** are collected from assignments such as
  `self.session = requests.Session()` so method calls through instance attributes
  resolve.

### Binding kinds

| Kind | Meaning |
| --- | --- |
| `project_function` | a function node in the scanned project |
| `project_class` | a project class (used for methods and constructors) |
| `module` | an importable project module |
| `external_module` | a module outside the project |
| `external` | a symbol outside the project (`yaml.load`, `requests.Session`) |
| `value` | a parameter/local whose type is unknown |
| `super` | `super()` inside a method, resolved against class bases |

### Resolution rules

- **Name:** local scope → enclosing function scopes → module scope → builtin.
- **Attribute:** project module attributes resolve to project functions/classes
  or submodules; external attributes extend the dotted path; project class
  attributes resolve through the class and its bases (depth-first, cycle-safe);
  `super()` starts at the bases, skipping the current class.
- **Call:** a project class resolves to `__init__` (or the external base's
  `__init__` when the class does not define one); an external callable produces an
  external call edge; a call through a `value` produces a dynamic-dispatch gap.
- **Instantiation heuristic:** the result of calling a CamelCase external callable
  is treated as an instance of that type, allowing `requests.Session().get(...)`.
  This is a heuristic and is recorded as uncertain.

### Edges

| Edge | Meaning | Counts as reachability? |
| --- | --- | --- |
| `call` | a resolved function call | yes |
| `import` | module import-time execution | yes |
| `reference` | a function/class used as a value (callback) | only as uncertainty |

Each edge stores source, target, source location and the original expression.
External nodes are prefixed `ext:`, project modules `mod:`, project functions
`fn:`.

### Gaps

Uncertainty is data, not an exception:

- `unresolved_call` — a call target the resolver cannot name,
- `dynamic_dispatch` — a call through a parameter/local,
- `star_import` — `from x import *`,
- `dynamic_import` — `importlib.import_module` / `__import__`,
- `dynamic_code` — `exec`, `eval`, `getattr`, etc.,
- `parse_error` — a file that could not be parsed,
- `no_entry_points` — no roots could be inferred.

## 3. Call graph (`vulnreach/callgraph.py`)

Nodes are modules, project functions and external symbols. The graph keeps both
forward and reverse adjacency; edges are de-duplicated by target, kind and
location.

**Entry points** are inferred from:

1. `--entry-module` declarations,
2. console scripts from `pyproject.toml`,
3. modules with a `__main__` guard,
4. modules that nothing else imports (entry scripts),
5. functions decorated with known handler decorators (`route`, `get`, `post`,
   `task`, `command`, `receiver`, `api_view`, …).

If nothing is found, every module becomes a root and a `no_entry_points` gap is
recorded. Roots are listed in every report.

**Paths.** A single breadth-first search from all roots produces a predecessor
map. The shortest evidence path to each matched vulnerable symbol is
reconstructed with labels, locations and edge kinds. Reference edges and edges
flagged uncertain mark a path as *not confirmed*.

## 4. Advisories (`vulnreach/osv.py`)

Three sources, selected explicitly:

- **OSV API** (`POST /v1/query`) with `{package, ecosystem: PyPI, version}`.
  Responses are cached for 24 hours under `.vulnreach/cache` (configurable).
- **Cache**, used when the API fails. Stale cache use is reported as a warning.
- **Offline directories** of OSV JSON records (single object, list, or
  `{"vulns": [...]}` envelope).

Online results are parsed into `Advisory` records: id, aliases, summary, severity,
CVSS vector, fixed versions, references, affected ranges and any symbol data. An
advisory that does not apply to the resolved version is excluded and counted.

Version matching (`versions.py`) implements OSV range semantics with PEP 440
versions: `introduced`, `fixed` (exclusive), `last_affected` (inclusive),
`limit`, explicit version lists and open-ended ranges. GIT ranges and unparsable
versions yield *unknown*, never *not affected*.

**Failure policy:** if every source fails for a package, the scan raises
`AdvisorySourceError`. This prevents a network failure from looking like a clean
result.

## 5. Vulnerable symbols (`vulnreach/symbols.py`)

Symbols are read from:

1. `database_specific.vulnreach_symbols` (top-level or per affected entry),
2. `affected[].ecosystem_specific.imports[].symbols` (the OSV symbol shape),
3. a curated database (`--symbols-file` or the bundled, initially empty
   `data/known-symbols.json`).

Patterns are normalised against the dependency's known import names. A symbol can
be an exact function (`yaml.load`), a class prefix (`yaml.Loader`, which also
matches `yaml.Loader.__init__`), or a module wildcard (`yaml.*`). See
[ADVISORY-SYMBOLS.md](ADVISORY-SYMBOLS.md).

## 6. Reachability (`vulnreach/reachability.py`)

For each advisory/dependency pair:

1. Resolve the dependency and decide whether the version is affected
   (`True` / `False` / unknown).
2. Build symbol patterns and find matching external graph nodes.
3. Reuse the BFS predecessor map to collect up to three shortest paths.
4. Classify the paths (confirmed vs reference-only).
5. Gather gaps relevant to this package:
   star/dynamic imports of the package, and dynamic code anywhere in reachable
   code.
6. Decide a verdict and compute confidence.

### Decision table

| Version affected | Symbols known | Evidence | Verdict |
| --- | --- | --- | --- |
| unknown | any | any | **uncertain** (`version_unknown`) |
| yes | yes | confirmed path | **reachable** |
| yes | yes | reference-only path | **uncertain** (`reference_only_path`) |
| yes | yes | import/dynamic access | **uncertain** (`dynamic_access_to_package`) |
| yes | yes | no path, package used | **not reachable**, confidence reduced |
| yes | yes | no path, package unused | **not reachable**, high confidence |
| yes | no | call into package | **uncertain** (`symbol_data_unavailable`) |
| yes | no | imported but no call | **uncertain** (import-time effects unknown) |
| yes | no | not imported, transitive | **uncertain** (`transitive_dependency`) |
| no | any | any | excluded, no finding |

### Confidence

Reachable:

```
min(0.95, 0.90 + 0.03 if path length <= 2 else 0)
```

Not reachable:

```
0.90
- 0.25 * (1 - reachable_call_resolution_coverage)
- 0.08 if the package is imported or called
- 0.08 if dynamic code exists in reachable code
- 0.08 if any module failed to parse
- 0.05 if the dependency is transitive
clamped to [0.30, 0.90]
```

Uncertain: 0.30–0.50 depending on the reason; never inflated to look decisive.

Rationale codes are stable API: `vulnerable_symbol_reached`,
`confirmed_call_path`, `reference_only_path`, `no_path_to_symbol`,
`package_used_but_symbol_not_called`, `package_not_imported`,
`symbol_data_unavailable`, `version_unknown`, `dynamic_access_to_package`,
`transitive_dependency`, `dynamic_code_present`.

## 7. Reports (`vulnreach/report/`)

- **JSON** — schema version 1.0, tool/project metadata, analysis metrics and gaps,
  dependency inventory, findings with rationale, paths and uncertainty.
- **Markdown** — summary table, per-finding evidence paths, remediation,
  limitations and warnings.
- **OpenVEX** — one statement per finding, product PURL for the application,
  dependency subcomponent PURL, statuses `affected` / `not_affected` /
  `under_investigation`, justification
  `vulnerable_code_not_in_execute_path` for not-affected findings.
- **Console** — compact, colourised when attached to a terminal.

## Design choices

- **No NetworkX in the runtime path.** A dict-backed adjacency list gives O(1)
  reverse lookups, deterministic ordering, path reconstruction with full evidence,
  and no dependency. DOT export covers visualisation.
- **No web framework.** The CLI is the product; JSON is the integration surface.
- **Stdlib HTTP.** One dependency (`packaging`) keeps installation trivial and
  supply-chain surface small.
- **Deterministic analysis.** Same source + same advisory set = same verdicts and
  confidence. Timestamps and VEX ids are the only varying fields.

## Extension points

- `--symbols-file` for curated vulnerable functions.
- `--advisories` for OSV mirrors or bespoke advisory sets.
- `vulnreach graph --format json` for downstream visualisation or graph queries.
- `ScanConfig` / `analyze()` for embedding in another Python tool.
- Future: scanning installed dependency sources to model interprocedural flows
  inside third-party packages.
