from __future__ import annotations

from pathlib import Path

from vulnreach.scanner import scan_project


def test_flat_and_package_module_names(project_factory):
    root = project_factory(
        {
            "app.py": "print('hi')\n",
            "pkg/__init__.py": "",
            "pkg/mod.py": "x = 1\n",
            "src/lib/__init__.py": "",
            "src/lib/core.py": "y = 2\n",
        }
    )
    parsed = scan_project(root)
    names = {module.name for module in parsed.info.modules}
    assert names == {"app", "pkg", "pkg.mod", "lib", "lib.core"}


def test_tests_are_excluded_by_default(project_factory):
    root = project_factory(
        {
            "app.py": "x = 1\n",
            "tests/__init__.py": "",
            "tests/test_app.py": "def test_x(): pass\n",
            "conftest.py": "",
        }
    )
    parsed = scan_project(root)
    assert [module.name for module in parsed.info.modules] == ["app"]

    parsed_all = scan_project(root, include_tests=True)
    assert {"app", "tests.test_app", "conftest"} <= {m.name for m in parsed_all.info.modules}


def test_syntax_errors_are_recorded_not_raised(project_factory):
    root = project_factory({"broken.py": "def oops(:\n", "ok.py": "x = 1\n"})
    parsed = scan_project(root)
    broken = next(module for module in parsed.info.modules if module.name == "broken")
    assert broken.parse_error is not None
    assert "syntax error" in broken.parse_error.lower()
    assert "broken" not in parsed.trees


def test_function_and_class_structure(project_factory):
    root = project_factory(
        {
            "app.py": (
                "class Outer:\n"
                "    class Inner:\n"
                "        def method(self):\n"
                "            def nested():\n"
                "                pass\n"
                "            return nested\n"
            )
        }
    )
    parsed = scan_project(root)
    module = parsed.info.modules[0]
    qualnames = {function.qualname for function in module.functions}
    assert "Outer.Inner.method" in qualnames
    assert "Outer.Inner.method.<locals>.nested" in qualnames
    method = next(f for f in module.functions if f.qualname == "Outer.Inner.method")
    assert method.class_qualname == "Outer.Inner"
    assert method.is_module_level is False


def test_main_guard_and_pyproject_metadata(project_factory):
    root = project_factory(
        {
            "pyproject.toml": (
                '[project]\nname = "demo-tool"\nversion = "1.2.3"\n'
                '[project.scripts]\ndemo = "app:main"\n'
            ),
            "app.py": ("def main():\n    pass\n\nif __name__ == '__main__':\n    main()\n"),
        }
    )
    parsed = scan_project(root)
    module = parsed.info.modules[0]
    assert module.has_main_guard is True
    assert parsed.info.name == "demo-tool"
    assert parsed.info.version == "1.2.3"
    assert parsed.info.console_scripts == [("demo", "app:main")]


def test_module_level_imports_only(project_factory):
    root = project_factory({"app.py": ("import os\ndef f():\n    import json\n    return json\n")})
    parsed = scan_project(root)
    module = parsed.info.modules[0]
    assert [ref.module for ref in module.imports] == ["os"]


def test_empty_project_raises_scan_error(tmp_path: Path):
    from vulnreach.errors import ScanError

    try:
        scan_project(tmp_path)
    except ScanError as exc:
        assert "No Python files" in str(exc) or "no Python files" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ScanError")
