#!/usr/bin/env python3
"""Create or update a single VulnReach comment on the current pull request.

Best-effort: a missing token, a fork PR without write permission, or a GitHub
outage prints a warning and exits 0 so the reachability gate result stays the
primary CI signal.  The comment is identifiable by a hidden marker and is updated
in place on later runs instead of creating duplicates.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

MARKER = "<!-- vulnreach-report -->"
MAX_COMMENT_BYTES = 60_000


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: post_pr_comment.py REPORT.md", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()
    if not token or not repository or not event_path:
        print(
            "VulnReach: GITHUB_TOKEN, GITHUB_REPOSITORY or GITHUB_EVENT_PATH "
            "missing; skipping comment"
        )
        return 0

    try:
        with open(event_path, encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"VulnReach: cannot read GitHub event payload: {exc}", file=sys.stderr)
        return 0

    pull_request = event.get("pull_request") or {}
    number = pull_request.get("number")
    if not number:
        print("VulnReach: not a pull request event; skipping comment")
        return 0

    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            report = handle.read()
    except OSError as exc:
        print(f"VulnReach: cannot read report: {exc}", file=sys.stderr)
        return 0

    body = f"{MARKER}\n{report}"
    if len(body.encode("utf-8")) > MAX_COMMENT_BYTES:
        body = body.encode("utf-8")[:MAX_COMMENT_BYTES].decode("utf-8", "ignore")
        body += "\n\n_Report truncated. See the workflow artifact for the full report._"

    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    comments_url = f"{base}/repos/{repository}/issues/{number}/comments"

    try:
        existing = _request("GET", f"{comments_url}?per_page=100", token)
    except RuntimeError as exc:
        print(f"VulnReach: cannot list PR comments: {exc}", file=sys.stderr)
        return 0

    for comment in existing if isinstance(existing, list) else []:
        if isinstance(comment, dict) and MARKER in str(comment.get("body", "")):
            try:
                _request(
                    "PATCH",
                    f"{base}/repos/{repository}/issues/comments/{comment['id']}",
                    token,
                    {"body": body},
                )
                print("VulnReach: updated pull request comment")
            except RuntimeError as exc:
                print(f"VulnReach: cannot update PR comment: {exc}", file=sys.stderr)
            return 0

    try:
        _request("POST", comments_url, token, {"body": body})
        print("VulnReach: created pull request comment")
    except RuntimeError as exc:
        print(f"VulnReach: cannot create PR comment: {exc}", file=sys.stderr)
    return 0


def _request(method: str, url: str, token: str, payload: dict | None = None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "vulnreach-action",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(str(exc)) from exc
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


if __name__ == "__main__":
    sys.exit(main())
