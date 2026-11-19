"""Code that is imported but never executed by the demo application."""

from __future__ import annotations

import demo_yaml


def load_unsafe(document: str):
    """Call a function that is vulnerable in the installed version."""

    return demo_yaml.load(document)


def record(name: str) -> None:
    print(name)
