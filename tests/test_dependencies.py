from __future__ import annotations

from vulnreach.dependencies import collect_dependencies


def test_requirements_pins_and_ranges(project_factory):
    root = project_factory(
        {
            "requirements.txt": (
                "# comment\nfakepkg-one==1.2.3\nfakepkg-two>=2.0,<3\nfakepkg-three[extra]==0.5.0\n"
            ),
            "app.py": "x = 1\n",
        }
    )
    result = collect_dependencies(root)
    by_name = result.by_name()
    assert by_name["fakepkg-one"].version == "1.2.3"
    assert by_name["fakepkg-one"].version_source == "pinned"
    assert by_name["fakepkg-two"].version is None
    assert "version could not be determined" in " ".join(result.warnings)
    assert by_name["fakepkg-three"].extras == ("extra",)


def test_requirements_include_and_marker(project_factory):
    root = project_factory(
        {
            "requirements.txt": "-r base.txt\nfakepkg-main==1.0\n",
            "base.txt": ("fakepkg-base==4.0.0\nfakepkg-never==1.0.0; python_version < '1'\n"),
            "app.py": "x = 1\n",
        }
    )
    result = collect_dependencies(root)
    names = {dependency.name for dependency in result.dependencies}
    assert {"fakepkg-main", "fakepkg-base"} <= names
    assert "fakepkg-never" not in names


def test_pyproject_dependencies_and_dev_group(project_factory):
    root = project_factory(
        {
            "pyproject.toml": (
                "[project]\n"
                'name = "demo"\n'
                'version = "0.1.0"\n'
                'dependencies = ["fakepkg-prod==1.0.0"]\n'
                "[project.optional-dependencies]\n"
                'dev = ["fakepkg-dev==2.0.0"]\n'
            ),
            "app.py": "x = 1\n",
        }
    )
    normal = collect_dependencies(root)
    assert {d.name for d in normal.dependencies} == {"fakepkg-prod"}

    with_dev = collect_dependencies(root, include_dev=True)
    assert {d.name for d in with_dev.dependencies} == {"fakepkg-prod", "fakepkg-dev"}


def test_invalid_requirement_is_a_warning(project_factory):
    root = project_factory(
        {"requirements.txt": "not a valid requirement !!!\n", "app.py": "x = 1\n"}
    )
    result = collect_dependencies(root)
    assert result.dependencies == []
    assert any("unparsable requirement" in warning for warning in result.warnings)


def test_import_name_mapping_for_known_distribution(project_factory):
    root = project_factory({"requirements.txt": "pyyaml==6.0.1\n", "app.py": "x = 1\n"})
    result = collect_dependencies(root)
    dependency = result.by_name()["pyyaml"]
    assert "yaml" in dependency.import_names


def test_mysql_connector_import_name_mapping(project_factory):
    root = project_factory(
        {
            "requirements.txt": "mysql-connector-python\n",
            "app.py": "import mysql.connector\n",
        }
    )
    result = collect_dependencies(root)
    dependency = result.by_name()["mysql-connector-python"]
    assert "mysql" in dependency.import_names


def test_missing_manifest_warns(project_factory):
    root = project_factory({"app.py": "x = 1\n"})
    result = collect_dependencies(root)
    assert result.dependencies == []
    assert any("no dependency manifest" in warning.lower() for warning in result.warnings)


def test_recursive_include_is_ignored(project_factory):
    root = project_factory(
        {
            "requirements.txt": "-r requirements.txt\nfakepkg==1.0.0\n",
            "app.py": "x = 1\n",
        }
    )
    result = collect_dependencies(root)
    assert [d.name for d in result.dependencies] == ["fakepkg"]
    assert any("recursive" in warning for warning in result.warnings)
