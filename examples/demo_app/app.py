"""VulnReach demonstration application.

This module is intentionally small: it exercises a reachable dependency call, a
safe call, a dependency with no symbol-level advisory data, and a function that
is defined but never invoked.
"""

from __future__ import annotations

import demo_yaml
from demo_http_client import fetch
from demo_logging import log_event
from support import metrics


def fetch_status(url: str) -> str:
    log_event("fetch_status", url)
    response = fetch(url)
    return response.text


def main() -> None:
    print(fetch_status("https://example.com"))
    print(demo_yaml.safe_load("ok: true"))
    metrics.record("boot")


if __name__ == "__main__":
    main()
