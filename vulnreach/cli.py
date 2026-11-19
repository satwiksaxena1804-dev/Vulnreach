"""Command line interface for VulnReach."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ai.explain import explain_finding
from .api import ScanConfig, analyze_project
from .callgraph import build_call_graph
from .errors import VulnReachError
from .model import Verdict
from .report.console import render_console, use_color
from .report.json_report import build_report, write_report
from .report.markdown import render_markdown
from .report.vex import build_vex
from .resolution import resolve_project
from .scanner import scan_project

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

FILE_FORMATS = {
    "json": "vulnreach-report.json",
    "markdown": "vulnreach-report.md",
    "vex": "vulnreach.vex.json",
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except VulnReachError as exc:
        print(f"vulnreach: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        print("vulnreach: interrupted", file=sys.stderr)
        return 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnreach",
        description=(
            "Evidence-based Python vulnerability reachability analysis. "
            "Verdicts come from static call-graph evidence, never from a language model."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vulnreach {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="analyse a project and report findings")
    scan.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    _add_scan_options(scan)
    scan.add_argument(
        "--format",
        default="console",
        help="comma-separated output formats: console, json, markdown, vex (default: console)",
    )
    scan.add_argument("--output", type=Path, help="output file (single file format only)")
    scan.add_argument(
        "--output-dir",
        type=Path,
        help="directory for file formats (default: .vulnreach)",
    )
    scan.add_argument(
        "--fail-on",
        choices=["never", "reachable", "uncertain", "any"],
        default="reachable",
        help="exit 1 when this condition is met (default: reachable)",
    )
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    scan.add_argument("--quiet", action="store_true", help="suppress console output")
    scan.set_defaults(func=_cmd_scan)

    graph = subparsers.add_parser("graph", help="export the call graph as DOT or JSON")
    graph.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    graph.add_argument("--format", choices=["dot", "json"], default="dot")
    graph.add_argument("--output", type=Path, help="write to a file instead of stdout")
    graph.add_argument("--include-tests", action="store_true")
    graph.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    graph.add_argument("--entry-module", action="append", default=[], metavar="MODULE")
    graph.set_defaults(func=_cmd_graph)

    explain = subparsers.add_parser("explain", help="explain a finding from a JSON report")
    explain.add_argument("report", type=Path, help="JSON report produced by 'vulnreach scan'")
    explain.add_argument("--finding", help="finding id or id prefix (default: first finding)")
    explain.add_argument("--ai", action="store_true", help="use the configured LLM endpoint")
    explain.add_argument("--format", choices=["text", "json"], default="text")
    explain.set_defaults(func=_cmd_explain)

    version = subparsers.add_parser("version", help="print the version")
    version.set_defaults(func=lambda _args: _print_version())

    gui = subparsers.add_parser("gui", help="open the beginner-friendly desktop interface")
    gui.set_defaults(func=lambda _args: _launch_gui())
    return parser


def _launch_gui() -> int:
    from .gui import launch_gui

    return launch_gui()


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--offline",
        action="store_true",
        help="do not use the network; requires --advisories or a populated cache",
    )
    parser.add_argument(
        "--advisories",
        action="append",
        default=[],
        metavar="DIR",
        help="directory of OSV JSON advisories (repeatable)",
    )
    parser.add_argument(
        "--symbols-file",
        action="append",
        default=[],
        metavar="FILE",
        help="curated advisory-to-symbol JSON database (repeatable)",
    )
    parser.add_argument("--cache-dir", type=Path, help="OSV response cache directory")
    parser.add_argument(
        "--no-cache", action="store_true", help="do not read or write cached advisories"
    )
    parser.add_argument(
        "--timeout", type=float, default=20.0, help="OSV request timeout in seconds (default: 20)"
    )
    parser.add_argument("--include-tests", action="store_true", help="include test files")
    parser.add_argument(
        "--exclude", action="append", default=[], metavar="GLOB", help="exclude a path glob"
    )
    parser.add_argument(
        "--entry-module",
        action="append",
        default=[],
        metavar="MODULE",
        help="treat a module as an entry point (repeatable)",
    )
    parser.add_argument(
        "--include-dev", action="store_true", help="include development/test dependencies"
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    formats = _parse_formats(args.format)
    if args.output and len([fmt for fmt in formats if fmt != "console"]) > 1:
        raise VulnReachError("--output can only be used with a single file format")

    result = analyze_project(
        ScanConfig(
            root=Path(args.path),
            include_tests=args.include_tests,
            excludes=tuple(args.exclude),
            entry_modules=tuple(args.entry_module),
            include_dev=args.include_dev,
            offline=args.offline,
            advisory_dirs=tuple(Path(path) for path in args.advisories),
            symbol_files=tuple(Path(path) for path in args.symbols_file),
            cache_dir=Path(args.cache_dir) if args.cache_dir else None,
            no_cache=args.no_cache,
            timeout=args.timeout,
        )
    )

    if "console" in formats and not args.quiet:
        print(render_console(result, color=use_color(args.no_color)))

    file_formats = [fmt for fmt in formats if fmt != "console"]
    if file_formats:
        output_dir = Path(args.output_dir) if args.output_dir else Path(".vulnreach")
        for fmt in file_formats:
            path = Path(args.output) if args.output else output_dir / FILE_FORMATS[fmt]
            _write_format(result, fmt, path)
            if "console" in formats and not args.quiet:
                print(f"Wrote {fmt} report to {path}")

    return _gate(result, args.fail_on)


def _cmd_graph(args: argparse.Namespace) -> int:
    parsed = scan_project(
        Path(args.path),
        include_tests=args.include_tests,
        excludes=tuple(args.exclude),
        entry_modules=tuple(args.entry_module),
    )
    output, index = resolve_project(parsed.info, parsed.trees)
    graph = build_call_graph(parsed.info, parsed.trees, output, index)
    if args.format == "dot":
        content = graph.to_dot()
    else:
        content = json.dumps(graph.to_dict(), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8", newline="\n")
        print(f"Wrote call graph to {args.output}")
    else:
        print(content, end="")
    return EXIT_OK


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VulnReachError(f"cannot read report {args.report}: {exc}") from exc

    findings = report.get("findings") or []
    if not findings:
        print("No findings in this report.", file=sys.stderr)
        return EXIT_OK

    selected = None
    if args.finding:
        matches = [
            finding
            for finding in findings
            if str(finding.get("id", "")) == args.finding
            or str(finding.get("id", "")).startswith(args.finding)
        ]
        if not matches:
            raise VulnReachError(f"finding not found: {args.finding}")
        if len(matches) > 1:
            raise VulnReachError(
                f"finding id prefix is ambiguous: {', '.join(m.get('id', '') for m in matches)}"
            )
        selected = matches[0]
    else:
        selected = findings[0]

    explanation = explain_finding(selected, use_ai=args.ai)
    if args.format == "json":
        print(json.dumps(explanation.to_dict(), indent=2))
    else:
        print(explanation.render())
    return EXIT_OK


def _print_version() -> int:
    print(f"vulnreach {__version__}")
    return EXIT_OK


def _parse_formats(text: str) -> list[str]:
    formats: list[str] = []
    for raw in text.split(","):
        fmt = raw.strip().lower()
        if not fmt:
            continue
        if fmt not in {"console", "json", "markdown", "vex"}:
            raise VulnReachError(
                f"unknown format '{fmt}' (choose from console, json, markdown, vex)"
            )
        if fmt not in formats:
            formats.append(fmt)
    if not formats:
        raise VulnReachError("at least one output format is required")
    return formats


def _write_format(result, fmt: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        write_report(build_report(result), path)
    elif fmt == "markdown":
        path.write_text(render_markdown(result), encoding="utf-8", newline="\n")
    elif fmt == "vex":
        path.write_text(
            json.dumps(build_vex(result), indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    else:  # pragma: no cover - validated earlier
        raise VulnReachError(f"cannot write format '{fmt}'")


def _gate(result, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    reachable = result.by_verdict(Verdict.REACHABLE)
    uncertain = result.by_verdict(Verdict.UNCERTAIN)
    if fail_on == "reachable" and reachable:
        return EXIT_GATE_FAILED
    if fail_on == "uncertain" and (reachable or uncertain):
        return EXIT_GATE_FAILED
    if fail_on == "any" and result.findings:
        return EXIT_GATE_FAILED
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
