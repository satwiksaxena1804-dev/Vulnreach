from __future__ import annotations

from support import run_graph

from vulnreach.model import EdgeKind, GapKind


def test_project_calls_are_resolved(project_factory):
    root = project_factory(
        {
            "app.py": (
                "def helper():\n    return 1\n\n"
                "def main():\n    helper()\n\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, _, _, graph = run_graph(root)
    assert "call" in [
        e.kind.value for e in graph.adjacency["fn:app:main"] if e.target == "fn:app:helper"
    ]
    roots = {entry.node_id for entry in graph.roots}
    assert "mod:app" in roots


def test_relative_imports_and_aliases(project_factory):
    root = project_factory(
        {
            "pkg/__init__.py": "",
            "pkg/util.py": "def helper():\n    return 1\n",
            "pkg/app.py": (
                "from .util import helper as h\n"
                "def main():\n    h()\n"
                "if __name__ == '__main__':\n    main()\n"
            ),
        }
    )
    _, _, _, graph = run_graph(root)
    call_edges = [
        edge for edge in graph.adjacency["fn:pkg.app:main"] if edge.target == "fn:pkg.util:helper"
    ]
    assert call_edges and call_edges[0].kind is EdgeKind.CALL
    assert "import" in [
        e.kind.value for e in graph.adjacency["mod:pkg.app"] if e.target == "mod:pkg.util"
    ]


def test_self_methods_are_resolved(project_factory):
    root = project_factory(
        {
            "app.py": (
                "class Service:\n"
                "    def run(self):\n"
                "        self.step()\n"
                "    def step(self):\n"
                "        pass\n\n"
                "def main():\n"
                "    Service().run()\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, _, _, graph = run_graph(root)
    run_id = "fn:app:Service.run"
    assert any(edge.target == "fn:app:Service.step" for edge in graph.adjacency[run_id])
    assert any(edge.target == run_id for edge in graph.adjacency["fn:app:main"])


def test_super_resolves_to_base_method(project_factory):
    root = project_factory(
        {
            "app.py": (
                "class Base:\n"
                "    def run(self):\n"
                "        pass\n"
                "class Child(Base):\n"
                "    def run(self):\n"
                "        super().run()\n"
                "def main():\n"
                "    Child().run()\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, _, _, graph = run_graph(root)
    targets = [edge.target for edge in graph.adjacency["fn:app:Child.run"]]
    assert "fn:app:Base.run" in targets
    assert "fn:app:Child.run" not in targets


def test_external_star_import_is_uncertain(project_factory):
    root = project_factory(
        {
            "app.py": (
                "from lib import *\n"
                "def main():\n    danger()\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, output, _, graph = run_graph(root)
    edges = [e for e in graph.adjacency["fn:app:main"] if e.target == "ext:lib.danger"]
    assert edges and edges[0].uncertain is True
    assert any(gap.kind is GapKind.STAR_IMPORT for gap in output.gaps)


def test_dynamic_import_records_gap(project_factory):
    root = project_factory(
        {
            "app.py": (
                "import importlib\n"
                "def main():\n    importlib.import_module('lib')\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, output, _, _ = run_graph(root)
    gaps = [gap for gap in output.gaps if gap.kind is GapKind.DYNAMIC_IMPORT]
    assert gaps and gaps[0].detail == "lib"
    assert "lib" in output.import_uses


def test_callback_reference_edge(project_factory):
    root = project_factory(
        {
            "app.py": (
                "from lib import danger\n"
                "def register(callback):\n    callback()\n"
                "def main():\n    register(danger)\n"
                "if __name__ == '__main__':\n    main()\n"
            )
        }
    )
    _, _, _, graph = run_graph(root)
    references = [
        edge for edge in graph.adjacency["fn:app:main"] if edge.target == "ext:lib.danger"
    ]
    assert references and references[0].kind is EdgeKind.REFERENCE
    assert any(gap.kind is GapKind.DYNAMIC_DISPATCH for gap in graph.gaps)


def test_value_call_is_reported_as_dynamic_dispatch(project_factory):
    root = project_factory(
        {
            "app.py": (
                "def main(callback):\n    callback()\nif __name__ == '__main__':\n    main(None)\n"
            )
        }
    )
    _, output, _, _ = run_graph(root)
    assert any(gap.kind is GapKind.DYNAMIC_DISPATCH for gap in output.gaps)


def test_handler_decorator_becomes_entry_point(project_factory):
    root = project_factory(
        {
            "app.py": (
                "def route(path):\n"
                "    def wrap(fn):\n"
                "        return fn\n"
                "    return wrap\n\n"
                "@route('/x')\n"
                "def handler():\n"
                "    pass\n"
            )
        }
    )
    _, _, _, graph = run_graph(root)
    kinds = {(entry.kind, entry.node_id) for entry in graph.roots}
    assert ("handler", "fn:app:handler") in kinds


def test_module_level_call_attributed_to_module(project_factory):
    root = project_factory({"app.py": ("def boot():\n    pass\nboot()\n")})
    _, output, _, graph = run_graph(root)
    assert any(edge.target == "fn:app:boot" for edge in graph.adjacency["mod:app"])
    assert output.stats.project >= 1


def test_parse_error_module_adds_gap(project_factory):
    root = project_factory({"broken.py": "def nope(:\n", "app.py": "x = 1\n"})
    _, output, _, graph = run_graph(root)
    assert any(gap.kind is GapKind.PARSE_ERROR for gap in output.gaps)
    assert any("could not be parsed" in warning for warning in graph.warnings)
