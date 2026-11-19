"""Terminal rendering with optional ANSI colour."""

from __future__ import annotations

import os
import sys

from .. import __version__
from ..model import Finding, Verdict
from ..reachability import AnalysisResult, remediation_hint

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
CYAN = "\x1b[36m"


def use_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def render_console(result: AnalysisResult, *, color: bool = True) -> str:
    """Render a compact terminal report."""
    style = _Style(color)
    summary = result.summary
    lines: list[str] = [
        f"{style.bold('VulnReach')} {__version__}  "
        f"{style.dim('evidence-based Python reachability')}",
        "",
        f"{style.bold(result.project.name)}"
        + (f" {result.project.version}" if result.project.version else ""),
        style.dim(f"root: {result.project.root}"),
        (
            f"{result.metrics.modules_scanned} modules · "
            f"{len(result.dependencies)} dependencies · "
            f"{result.metrics.total_calls} calls "
            f"({result.metrics.resolution_coverage:.0%} resolved) · "
            f"{result.metrics.entry_points} entry point(s)"
        ),
        (
            f"advisories: {result.metrics.advisories_considered} considered, "
            f"{result.metrics.advisories_excluded} excluded by version"
        ),
        "",
    ]

    if result.findings:
        for verdict in (Verdict.REACHABLE, Verdict.UNCERTAIN, Verdict.NOT_REACHABLE):
            group = result.by_verdict(verdict)
            if not group:
                continue
            lines.append(style.heading(_verdict_title(verdict, len(group)), verdict))
            for finding in group:
                lines.extend(_finding_lines(finding, style))
                lines.append("")
    else:
        lines.extend(
            [
                style.green("No advisory findings."),
                style.dim(
                    "No advisories affected the resolved dependency versions "
                    "(or no dependencies were discovered)."
                ),
                "",
            ]
        )

    counts = (
        f"{summary['reachable']} reachable · {summary['uncertain']} uncertain · "
        f"{summary['not_reachable']} not reachable"
    )
    lines.append(style.bold(f"Summary: {counts}"))
    if result.metrics.dynamic_gaps:
        lines.append(
            style.dim(
                f"{result.metrics.dynamic_gaps} dynamic construct(s) in reachable code "
                "reduce confidence where relevant."
            )
        )
    for warning in sorted(set(result.warnings))[:5]:
        lines.append(style.yellow(f"warning: {warning}"))
    lines.append("")
    return "\n".join(lines)


def _finding_lines(finding: Finding, style: _Style) -> list[str]:
    advisory = finding.advisory
    severity = advisory.severity.upper()
    header = (
        f"{style.dim(severity.ljust(8))} {style.bold(advisory.id)}  "
        f"{finding.dependency.name} {finding.dependency.version or '(unknown)'}  "
        f"{style.dim(f'confidence {finding.confidence:.2f}')}"
    )
    lines = [header, f"  {advisory.summary or 'No summary provided.'}"]
    if advisory.aliases:
        lines.append(style.dim(f"  aliases: {', '.join(advisory.aliases)}"))

    if finding.paths:
        first = finding.paths[0]
        label = "path" if first.is_confirmed else "reference-only path"
        lines.append(style.dim(f"  {label}:"))
        for index, (_, node_label) in enumerate(first.nodes):
            if index == 0:
                lines.append(f"    {style.cyan(node_label)}")
            else:
                hop = first.hops[index - 1]
                location = f"  {style.dim(str(hop.location))}" if hop.location else ""
                kind = "reference" if hop.kind.value == "reference" else hop.kind.value
                lines.append(
                    f"      -> {style.cyan(node_label)}{location}  {style.dim(f'[{kind}]')}"
                )
    else:
        lines.append(style.dim("  no call path from an entry point"))

    for rationale in finding.rationale[:2]:
        lines.append(f"  {style.dim('why:')} {rationale.message}")

    if finding.uncertainty:
        gap = finding.uncertainty[0]
        lines.append(
            f"  {style.yellow('uncertainty:')} {gap.kind.value} at {gap.location} ({gap.detail})"
        )

    hint = remediation_hint(finding)
    if hint:
        lines.append(f"  {style.bold('fix:')} {hint}")
    return lines


def _verdict_title(verdict: Verdict, count: int) -> str:
    title = {
        Verdict.REACHABLE: "REACHABLE",
        Verdict.UNCERTAIN: "UNCERTAIN",
        Verdict.NOT_REACHABLE: "NOT REACHABLE",
    }[verdict]
    return f"{title} ({count})"


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap(text, BOLD)

    def dim(self, text: str) -> str:
        return self._wrap(text, DIM)

    def green(self, text: str) -> str:
        return self._wrap(text, GREEN)

    def yellow(self, text: str) -> str:
        return self._wrap(text, YELLOW)

    def cyan(self, text: str) -> str:
        return self._wrap(text, CYAN)

    def heading(self, text: str, verdict: Verdict) -> str:
        code = {
            Verdict.REACHABLE: RED,
            Verdict.UNCERTAIN: YELLOW,
            Verdict.NOT_REACHABLE: GREEN,
        }[verdict]
        return self._wrap(text, f"{BOLD}{code}")
