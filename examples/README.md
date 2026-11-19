# Demonstration fixtures

`demo_app/` is a small application used by the README and the end-to-end tests.
It is designed to exercise every verdict:

| Code | Result |
| --- | --- |
| `app.fetch_status` calls `demo_http_client.fetch` | **reachable** (synthetic advisory 0001) |
| `support.metrics.load_unsafe` calls `demo_yaml.load`, but nothing calls `load_unsafe` | **not reachable** (0002) |
| `app.main` calls `demo_logging.log_event`, advisory has no symbols | **uncertain** (0003) |
| `demo_http_client.stream` is never called | **not reachable** (0004) |
| `demo-crypto` is declared but never imported | **not reachable** (0005) |

## Important

The advisories in `advisories/` are **synthetic fixtures**, not real security
data. The package names do not exist on PyPI and the advisory ids
(`VULNREACH-DEMO-*`) are fictional. They exist so the engine can be demonstrated
offline and tested deterministically.

For real data, run without `--offline` against a project with real dependencies;
VulnReach queries OSV.dev.

These fixtures are synthetic and are not a benchmark on public repositories or
the organizers' hidden fixture set. Treat them as a demonstration of expected
behavior, then hand-check results on public Python projects before making
accuracy claims.

## Run it

```bash
vulnreach scan examples/demo_app \
  --offline --advisories examples/advisories \
  --format console,json,markdown,vex \
  --output-dir reports
```
