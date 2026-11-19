# VulnReach

**Evidence-based Python vulnerability reachability analysis.**

Most dependency scanners answer: *"is a vulnerable package installed?"*
VulnReach answers a harder question:

> **Is this application actually capable of reaching the vulnerable code, and what is the evidence?**

It builds a call graph from your Python source, resolves imports and names across
modules, maps declared dependencies to import names, ingests advisories from
[OSV.dev](https://osv.dev), and reports one of three verdicts per finding:

| Verdict | Meaning |
| --- | --- |
| **Reachable** | A confirmed call path from an application entry point reaches a symbol the advisory marks as vulnerable. |
| **Not reachable** | No such path exists in the analysed program, with confidence and explicit caveats. |
| **Uncertain** | The evidence is insufficient: missing symbol data, unresolved version, dynamic dispatch, star imports, or a transitive dependency. |

Every verdict ships with the evidence: the exact path, file/line locations, the
advisory, the dependency version, confidence, and the specific analysis gaps that
limited it. Reports are available as console output, JSON, Markdown and
[OpenVEX](https://openvex.dev) 0.2.0.

The LLM never decides reachability. An optional explanation command can narrate
evidence produced by the deterministic engine, and it cannot change a verdict.

---

## Why this exists

A raw SCA alert on a transitive YAML parser is often noise: the vulnerable
deserialisation function may never be called. Conversely, a pinned dependency
with a vulnerable helper can be genuinely exploitable from a request handler.
Reachability turns a dependency inventory into an argument about *this program*.

VulnReach is deliberately conservative:

- It does not guess. Unresolved calls, `getattr`, `exec`, dynamic imports and
  star imports become **evidence gaps**, not silent assumptions.
- It does not invent symbol data. If an advisory has no function-level
  information, the finding is **uncertain**, not "safe".
- It fails loudly when advisory data cannot be fetched. A network outage never
  becomes a clean security report.

## Installation

Requires Python 3.11+ and one runtime dependency (`packaging`).

```bash
git clone https://github.com/example/vulnreach.git
cd vulnreach
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e .
```

## Quick start: the offline demo

The repository ships a small application and a **synthetic** advisory set so the
analysis can be demonstrated without network access:

```bash
vulnreach scan examples/demo_app \
  --offline --advisories examples/advisories \
  --format console,json,markdown,vex \
  --output-dir reports
```

Expected outcome:

```
REACHABLE (1)
HIGH  VULNREACH-DEMO-0001  demo-http-client 1.4.2  confidence 0.90
  demo-http-client fetch() follows attacker-controlled URLs without validation
  path:
    app (module)
      -> app.main  app.py:30  [call]
      -> app.fetch_status  app.py:24  [call]
      -> demo_http_client.fetch  app.py:19  [call]
  fix: Upgrade demo-http-client to 1.5.0 or later.

UNCERTAIN (1)   # advisory has no function-level symbol data
NOT REACHABLE (3)
  demo-yaml    load() is never called (only safe_load and a dead function)
  demo-http-client  stream() is never called
  demo-crypto  the package is never imported
```

The demo advisory IDs (`VULNREACH-DEMO-*`) are fictional and live in
`examples/advisories`. They exist to exercise the engine and are not security
claims about any real package.

### Desktop interface

For a guided interface, choose a project folder, scan it, review findings and
save a JSON report from the app:

```bash
vulnreach gui
```

Online scans use OSV and need internet access. Select offline mode in the app to
use a local advisory cache. A clean result means no matching advisory was found;
it does not prove that a project is vulnerability-free.

## Real usage

For small offline examples covering reachable, not reachable and uncertain
results, see [examples/test_projects](examples/test_projects/README.md).

```bash
# Query OSV.dev for the versions in your environment
vulnreach scan .

# CI: produce every report and fail the build on reachable findings
vulnreach scan . \
  --format console,json,markdown,vex \
  --output-dir vulnreach-out \
  --fail-on reachable

# Only direct dependencies? Dev/test requirements too?
vulnreach scan . --include-dev

# Advisory mirror / air-gapped pipeline
vulnreach scan . --offline --advisories /srv/osv-mirror
```

### What gets scanned

- `pyproject.toml` (`[project].dependencies`, Poetry dependencies, console scripts)
- `requirements.txt` and recursive `-r` includes
- `requirements-dev.txt` with `--include-dev`
- installed distribution metadata for versions and transitive dependencies
- Python sources, excluding `.venv`, caches, build output and tests by default
  (`--include-tests` includes them)

### Verdict semantics in practice

- **Reachable** requires a path made only of resolved calls/imports. Reference-only
  paths (a function passed as a callback) are **uncertain**.
- **Not reachable** does not mean "exploit is impossible". It means the analysed
  program contains no statically visible call to the vulnerable symbol. The report
  states the confidence and the analysis boundary.
- **Uncertain** is a first-class result. It is the correct answer when the
  advisory has no symbols, the version is unpinned and not installed, the package
  is only transitively present, or dynamic constructs hide the call.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the decision table and the
confidence formula, and [docs/ADVISORY-SYMBOLS.md](docs/ADVISORY-SYMBOLS.md) for
symbol coverage.

## CLI reference

```
vulnreach scan [PATH]
  --offline                 no network; use --advisories and/or the cache
  --advisories DIR          directory of OSV JSON records (repeatable)
  --symbols-file FILE       curated advisory-to-symbol database (repeatable)
  --cache-dir DIR           OSV response cache (default: <project>/.vulnreach/cache)
  --no-cache                disable cache reads and writes
  --timeout SECONDS         OSV request timeout (default 20)
  --include-tests           include tests/ and test_*.py
  --exclude GLOB            exclude a relative path glob (repeatable)
  --entry-module MODULE     force a module to be an entry point (repeatable)
  --include-dev             include development/test dependencies
  --format LIST             console, json, markdown, vex (default: console)
  --output FILE             output file (single format only)
  --output-dir DIR          directory for file formats (default: .vulnreach)
  --fail-on LEVEL           never | reachable | uncertain | any (default: reachable)
  --no-color                disable ANSI colour
  --quiet                   suppress console output

vulnreach graph [PATH] --format dot|json --output FILE
vulnreach explain REPORT.json [--finding ID] [--ai] [--format text|json]
vulnreach version
```

Exit codes: `0` success, `1` gate failed (`--fail-on`), `2` error. A failed
advisory lookup is an error, never an empty report.

## Reports

- **Console** — grouped by verdict, evidence path, rationale, remediation.
- **JSON** — stable `schema_version: "1.0"` payload with analysis metrics, gaps,
  dependencies, findings and paths, suitable for dashboards.
- **Markdown** — for pull request comments and audit notes.
- **OpenVEX 0.2.0** — `affected`, `not_affected` (with
  `vulnerable_code_not_in_execute_path`) and `under_investigation` statements.
  The product is the application; dependencies are subcomponents with PyPI PURLs.

## GitHub integration

`.github/workflows/vulnreach.yml` scans on every push and pull request, uploads all
report formats as artifacts, updates a single PR comment
(`scripts/post_pr_comment.py`), and fails the job when a reachable finding is
present. `.github/workflows/ci.yml` runs ruff and the test suite on Python
3.11–3.13.

## Architecture at a glance

```
scanner.py      file discovery, module naming, AST structure
     │
resolution.py   scope-aware name binding, call/reference/import edges, gaps
     │
callgraph.py    graph assembly, entry points, BFS evidence paths
     │
osv.py          OSV API + cache + offline OSV directory
symbols.py      advisory/curated vulnerable symbols
     │
reachability.py verdict, confidence, rationale, uncertainty
     │
report/         console · JSON · Markdown · OpenVEX
```

- No AI in the analysis path.
- No NetworkX dependency: the graph is a dict-based adjacency list with reverse
  edges and evidence-rich BFS. `vulnreach graph --format dot` exports for
  visualisation.
- The optional AI command is isolated in `vulnreach/ai/explain.py`, receives only
  already-computed evidence, and its output is stored separately from the verdict.

## Optional AI explanations

```bash
export VULNREACH_LLM_BASE_URL=https://your-openai-compatible-endpoint/v1
export VULNREACH_LLM_MODEL=your-open-weight-model
export VULNREACH_LLM_API_KEY=...   # keep out of source control

vulnreach explain reports/vulnreach-report.json \
  --finding VULNREACH-DEMO-0001 --ai
```

The model receives the finding's evidence and must return
`{"summary", "evidence", "next_steps"}`. Any verdict-like field it returns is
ignored; the printed verdict and confidence still come from the report. Without
configuration, the command prints a deterministic explanation.

## Known limitations

- **Dependency internals are not modelled.** Reachability is decided at the
  application→dependency call boundary. If `lib.fetch()` internally calls a
  vulnerable `lib._request()`, and the app only calls `fetch()`, the advisory must
  name `fetch` for the path to be found. Confidence is reduced when the package is
  used but the vulnerable symbol is not called.
- **Symbol data is sparse in the ecosystem.** OSV records for PyPI rarely list
  vulnerable functions. VulnReach reports those as uncertain and accepts curated
  mappings (`--symbols-file`).
- **Reflection is not resolved.** `getattr`, `exec`, dynamic imports and star
  imports are reported as gaps. They lower confidence and can turn a would-be
  "not reachable" into "uncertain".
- **Entry points are inferred.** `__main__` guards, console scripts, handler
  decorators and modules nothing imports are used as roots. Use `--entry-module`
  when the inference misses your server entry point.
- **Tests are excluded by default** because test-only reachability is usually not
  production risk. `--include-tests` changes that.

## Development

```bash
pip install -e ".[dev]"
ruff format .
ruff check .
pytest
```

The suite currently contains 83 tests covering parsing, name resolution, call
graphs, dependency parsing, OSV offline ingestion, range evaluation, symbol
matching, all three verdicts, OpenVEX output, JSON/Markdown reports, safety
failure modes, CLI exit codes, and AI guardrails. Live OSV calls are exercised
manually, not in CI, so the suite is deterministic and offline.

## Roadmap

| Phase | Status |
| --- | --- |
| 1. Scanner and AST parser | done |
| 2. Function identification and call graph | done |
| 3. Dependency and package identification | done |
| 4. Advisory ingestion (OSV, cache, offline) | done |
| 5. Vulnerable function identification (advisory + curated symbols) | done |
| 6. Reachability analysis with evidence and uncertainty | done |
| 7. OpenVEX, JSON and Markdown reports | done |
| 8. CLI, tests, GitHub Action | done |
| 9. AI-assisted explanations and PR interaction | explanation command done; automated PR investigation is future work |
| 10. Dependency-source interprocedural analysis | future work |

## License

MIT. See [LICENSE](LICENSE).
