"""VulnReach: evidence-based Python vulnerability reachability analysis.

The public API is intentionally small.  Most users should use the command line
interface (``vulnreach scan``); programmatic users start with
:func:`vulnreach.api.analyze`.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
