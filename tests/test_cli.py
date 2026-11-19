from __future__ import annotations

import json

from support import DEMO_ADVISORIES, DEMO_APP

from vulnreach.cli import EXIT_ERROR, EXIT_GATE_FAILED, EXIT_OK, main


def offline_args(*extra: str) -> list[str]:
    return [
        "scan",
        str(DEMO_APP),
        "--offline",
        "--advisories",
        str(DEMO_ADVISORIES),
        "--no-cache",
        *extra,
    ]


def test_scan_writes_json_and_exits_zero(tmp_path, capsys):
    output = tmp_path / "report.json"
    code = main(offline_args("--format", "json", "--output", str(output), "--fail-on", "never"))
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert captured.out == ""
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["summary"]["reachable"] == 1


def test_scan_gate_fails_on_reachable(capsys):
    code = main(offline_args("--fail-on", "reachable", "--quiet"))
    capsys.readouterr()
    assert code == EXIT_GATE_FAILED


def test_scan_multiple_formats(tmp_path, capsys):
    code = main(
        offline_args(
            "--format",
            "console,json,markdown,vex",
            "--output-dir",
            str(tmp_path),
            "--fail-on",
            "never",
            "--no-color",
        )
    )
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "Wrote json report" in captured.out
    assert (tmp_path / "vulnreach-report.json").is_file()
    assert (tmp_path / "vulnreach-report.md").is_file()
    assert (tmp_path / "vulnreach.vex.json").is_file()


def test_invalid_format_returns_error(capsys):
    code = main(offline_args("--format", "xml"))
    captured = capsys.readouterr()
    assert code == EXIT_ERROR
    assert "unknown format" in captured.err


def test_output_with_multiple_formats_is_rejected(tmp_path, capsys):
    code = main(
        offline_args(
            "--format",
            "json,markdown",
            "--output",
            str(tmp_path / "x.json"),
            "--fail-on",
            "never",
        )
    )
    assert code == EXIT_ERROR
    assert "--output" in capsys.readouterr().err


def test_graph_exports_json(capsys):
    code = main(["graph", str(DEMO_APP), "--format", "json"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    payload = json.loads(captured.out)
    assert payload["nodes"]
    assert any(edge["target"] == "ext:demo_http_client.fetch" for edge in payload["edges"])


def test_graph_exports_dot(tmp_path, capsys):
    output = tmp_path / "graph.dot"
    code = main(["graph", str(DEMO_APP), "--format", "dot", "--output", str(output)])
    assert code == EXIT_OK
    assert output.read_text(encoding="utf-8").startswith("digraph vulnreach")


def test_explain_finding(tmp_path, capsys):
    report = tmp_path / "report.json"
    main(offline_args("--format", "json", "--output", str(report), "--fail-on", "never"))
    capsys.readouterr()

    code = main(["explain", str(report), "--finding", "VULNREACH-DEMO-0001"])
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "REACHABLE" in captured.out
    assert "app.fetch_status" in captured.out


def test_explain_unknown_finding(tmp_path, capsys):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": []}), encoding="utf-8")
    code = main(["explain", str(report)])
    assert code == EXIT_OK
    assert "No findings" in capsys.readouterr().err


def test_version(capsys):
    assert main(["version"]) == EXIT_OK
    assert "vulnreach 0.1.0" in capsys.readouterr().out
