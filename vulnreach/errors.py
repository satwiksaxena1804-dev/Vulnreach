"""Exception types used across VulnReach."""

from __future__ import annotations


class VulnReachError(Exception):
    """Base class for expected, user-facing errors."""


class ScanError(VulnReachError):
    """The project could not be scanned."""


class DependencyError(VulnReachError):
    """A dependency manifest could not be read."""


class AdvisorySourceError(VulnReachError):
    """Advisory data could not be obtained."""


class SymbolDataError(VulnReachError):
    """A symbol database file is malformed."""


class LLMError(VulnReachError):
    """The optional explanation model could not be called."""
