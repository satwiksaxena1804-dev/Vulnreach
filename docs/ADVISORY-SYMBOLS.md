# Advisory symbol coverage

Reachability needs to know *which functions in a package are vulnerable*. That
information is unevenly available:

- OSV records for PyPI usually identify affected **versions**, not symbols.
- Some records carry symbols in `affected[].ecosystem_specific.imports[].symbols`.
- Some records (and teams) maintain curated mappings.
- Many records have nothing at all.

VulnReach treats missing symbol data as **uncertainty**, never as safety. This
document explains the supported formats and how to add mappings.

## Where symbols come from

For each advisory, in order:

1. **The advisory itself** — `database_specific.vulnreach_symbols` at the top
   level or inside an `affected` entry, and
   `affected[].ecosystem_specific.imports[].symbols`.
2. **Curated databases** — `--symbols-file FILE` and the bundled
   `vulnreach/data/known-symbols.json`.
3. **Nothing** — the finding becomes `uncertain` with
   `symbol_data_unavailable`.

When the advisory has no symbols but includes a GitHub `FIX` commit reference,
VulnReach may extract changed Python function names as **review candidates**.
Candidates are not authoritative vulnerable-symbol data: findings based on them
remain `uncertain`, even when a static path is found. Review the patch and add a
validated mapping to a curated symbols file if you want a definitive verdict.

Advisory-provided symbols are never overridden by curated data.

## Symbol syntax

Symbols are dotted Python paths inside the distribution:

| Symbol | Matches |
| --- | --- |
| `yaml.load` | exactly `yaml.load` |
| `load` | `load`, and `yaml.load` when the package imports as `yaml` |
| `yaml.Loader` | `yaml.Loader`, plus any method below it (`yaml.Loader.__init__`) |
| `yaml.*` | any call into the `yaml` module |
| `pkg.mod:Class.method` | `pkg.mod.Class.method` (`:`/`::` are normalised to `.`) |

Matching is performed against the external call/reference path recorded by the
resolver, not against source text. A symbol that is never present in the graph
cannot produce a reachable verdict.

## Advisory JSON example

```json
{
  "id": "GHSA-example-0000",
  "summary": "Unsafe deserialisation",
  "affected": [
    {
      "package": {"ecosystem": "PyPI", "name": "example-yaml"},
      "ranges": [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.0"}]}
      ],
      "database_specific": {
        "vulnreach_symbols": ["example_yaml.load", "example_yaml.UnsafeLoader"]
      }
    }
  ]
}
```

## Curated database format

```json
{
  "schema_version": 1,
  "advisories": {
    "CVE-2020-0000": {
      "package": "example-yaml",
      "symbols": ["example_yaml.load"],
      "notes": "Optional human context; ignored by the analyzer."
    },
    "GHSA-abcd-efgh-ijkl": {
      "symbols": ["example_yaml.unsafe_load"]
    }
  }
}
```

- Entries are looked up by advisory id and then by any alias (including CVE ids).
- `package` is optional. When present it must match the advisory's PyPI package
  after PEP 503 normalisation; otherwise the entry is ignored for that advisory.
- A malformed file is a hard error (`SymbolDataError`) so that a typo cannot
  silently disable symbol coverage.

Run with:

```bash
vulnreach scan . --symbols-file security/vulnreach-symbols.json
```

## Writing good mappings

- Map the **public entry points** an application can call. If a package's
  `fetch()` wraps an internal vulnerable function, include `pkg.fetch` unless the
  advisory explicitly limits exploitation to the internal path.
- Prefer functions and classes over module wildcards. Wildcards produce reachable
  verdicts for any call into the module and reduce evidential precision.
- Include constructors (`pkg.Loader`) when unsafe behaviour happens during
  instantiation.
- Record the source of the mapping in a `notes` field or next to the file in
  version control; reviewers must be able to audit it.
- Keep mappings version-scoped. A CVE that affects 1.x may not apply to 2.x, and
  the advisory's affected ranges are still authoritative.

## OSV symbol extraction caveat

`ecosystem_specific.imports[].symbols` is primarily a Go-ecosystem shape. Some
PyPI advisories adopt it; VulnReach supports it but does not assume it is
complete. Curated data is usually required for Python.

## Why the bundled database is empty

Fabricating mappings would produce confident-looking but unsupported verdicts.
The bundled file exists so the loader and schema are exercised; real mappings
belong in a repository's own security data with review and provenance.

## Future work

- Pull symbol data from language-specific advisory feeds and package SBOMs.
- Analyse installed dependency source to follow calls inside a package.
- Support module-level symbol scopes for advisories that describe behaviour
  without function names.
