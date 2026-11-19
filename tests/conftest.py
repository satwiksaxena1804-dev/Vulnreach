from __future__ import annotations

from pathlib import Path

import pytest

from vulnreach.callgraph import build_call_graph
from vulnreach.resolution import resolve_project
from vulnreach.scanner import scan_project


@pytest.fixture
def project_factory(tmp_path: Path):
    """Create a project directory from a mapping of file paths to contents."""

    counter = {"value": 0}

    def build(files: dict[str, str]) -> Path:
        counter["value"] += 1
        root = tmp_path / f"project{counter['value']}"
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return root

    return build


@pytest.fixture
def graph_for():
    """Build a call graph for a project root."""

    def build(root: Path):
        parsed = scan_project(root)
        output, index = resolve_project(parsed.info, parsed.trees)
        graph = build_call_graph(parsed.info, parsed.trees, output, index)
        return parsed, output, index, graph

    return build
