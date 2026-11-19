from __future__ import annotations

from support import make_advisory, make_dependency, run_analysis

from vulnreach.model import Verdict


def reachable_project(project_factory):
    return project_factory(
        {
            "app.py": (
                "import lib\n"
                "def wrapper():\n"
                "    lib.danger()\n"
                "def main():\n"
                "    wrapper()\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )


def test_direct_call_is_reachable_with_evidence(project_factory):
    result, _, _ = run_analysis(
        reachable_project(project_factory),
        [make_advisory()],
        [make_dependency()],
    )
    finding = result.findings[0]
    assert finding.verdict is Verdict.REACHABLE
    assert finding.confidence >= 0.9
    assert finding.paths and finding.paths[0].is_confirmed
    assert [label for _, label in finding.paths[0].nodes][-1] == "lib.danger"
    assert finding.paths[0].hops[0].location is not None


def test_uncalled_function_is_not_reachable(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import lib\n"
                "def unused():\n"
                "    lib.danger()\n"
                "def main():\n"
                "    print('hi')\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.NOT_REACHABLE
    assert finding.confidence >= 0.7
    assert not finding.paths
    assert any(item.code == "no_path_to_symbol" for item in finding.rationale)


def test_unresolved_reachable_call_prevents_not_reachable(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import lib\n"
                "def main():\n"
                "    unknown_dispatch()\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert any(gap.kind.value == "unresolved_call" for gap in finding.uncertainty)


def test_parse_error_prevents_not_reachable(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import lib\n"
                "def main():\n"
                "    print('running')\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "broken.py": "def hidden(:\n    lib.danger()\n",
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert any(gap.kind.value == "parse_error" for gap in finding.uncertainty)


def test_package_not_imported_is_not_reachable(project_factory):
    root = project_factory({"app.py": "def main():\n    pass\n"})
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.NOT_REACHABLE
    assert any(item.code == "package_not_imported" for item in finding.rationale)


def test_reference_only_is_uncertain(project_factory):
    root = project_factory(
        {
            "app.py": (
                "from lib import danger\n"
                "def register(callback):\n"
                "    return callback\n"
                "def main():\n"
                "    register(danger)\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert finding.paths and not finding.paths[0].is_confirmed
    assert any(item.code == "reference_only_path" for item in finding.rationale)


def test_symbol_less_advisory_is_uncertain(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import lib\n"
                "def main():\n"
                "    lib.anything()\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory(symbols=())], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert any(item.code == "symbol_data_unavailable" for item in finding.rationale)
    assert finding.paths


def test_unknown_version_is_uncertain(project_factory):
    result, _, _ = run_analysis(
        reachable_project(project_factory),
        [make_advisory()],
        [make_dependency(version=None)],
    )
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert finding.affected_status == "unknown"
    assert any(item.code == "version_unknown" for item in finding.rationale)


def test_unaffected_version_is_excluded(project_factory):
    result, _, _ = run_analysis(
        reachable_project(project_factory),
        [make_advisory()],
        [make_dependency(version="2.0.0")],
    )
    assert result.findings == []
    assert result.summary["advisories_excluded"] == 1


def test_fix_commit_candidates_are_never_reported_as_confirmed(project_factory):
    advisory = make_advisory()
    advisory.symbol_source = "fix_commit_candidate"
    result, _, _ = run_analysis(
        reachable_project(project_factory), [advisory], [make_dependency()]
    )
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert finding.paths and finding.paths[0].is_confirmed
    assert any(item.code == "fix_commit_symbol_candidates" for item in finding.rationale)


def test_dynamic_import_produces_uncertainty(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import importlib\n"
                "def main():\n"
                "    importlib.import_module('lib')\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert any(item.code == "dynamic_access_to_package" for item in finding.rationale)


def test_star_import_path_is_uncertain(project_factory):
    root = project_factory(
        {
            "app.py": (
                "from lib import *\n"
                "def main():\n"
                "    danger()\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            )
        }
    )
    result, _, _ = run_analysis(root, [make_advisory()], [make_dependency()])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert finding.paths and not finding.paths[0].is_confirmed


def test_transitive_dependency_without_import_is_uncertain(project_factory):
    root = project_factory({"app.py": "def main():\n    pass\n"})
    dependency = make_dependency(direct=False, via=("parent-lib",))
    result, _, _ = run_analysis(root, [make_advisory()], [dependency])
    finding = result.findings[0]
    assert finding.verdict is Verdict.UNCERTAIN
    assert any(item.code == "transitive_dependency" for item in finding.rationale)


def test_summary_and_ordering(project_factory):
    result, _, _ = run_analysis(
        reachable_project(project_factory),
        [
            make_advisory("TEST-1", severity="LOW"),
            make_advisory("TEST-2", severity="CRITICAL"),
        ],
        [make_dependency()],
    )
    assert result.summary["reachable"] == 2
    assert [finding.advisory.id for finding in result.findings] == ["TEST-2", "TEST-1"]
