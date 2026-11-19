"""Optional AI-assisted explanations.

The model explains evidence produced by the deterministic analysis engine. It
never decides a verdict and has no ability to change one.
"""

from __future__ import annotations

from .explain import Explanation, explain_finding

__all__ = ["Explanation", "explain_finding"]
