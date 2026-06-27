"""Packaging and release guardrails for the renamed PyPI distribution."""

from __future__ import annotations

import re
from pathlib import Path

import capguard

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text()


def _project_field(name: str) -> str:
    pyproject = _read("pyproject.toml")
    match = re.search(rf'^{re.escape(name)} = "([^"]+)"$', pyproject, re.MULTILINE)
    assert match, f"missing project field {name!r}"
    return match.group(1)


def test_distribution_name_and_runtime_version_stay_in_sync():
    assert _project_field("name") == "capguard-runtime"
    assert _project_field("version") == capguard.__version__
    assert 'capguard = "capguard.cli:main"' in _read("pyproject.toml")


def test_docs_install_the_renamed_distribution():
    docs = "\n".join(_read(path) for path in [
        "README.md",
        "docs/index.md",
        "docs/quickstart.md",
    ])
    assert "pip install capguard-runtime" in docs
    assert "pypi.org/project/capguard-runtime/" in _read("README.md")
    assert not re.search(r"pip install capguard(?![-\w])", docs)


def test_release_workflow_builds_checks_smokes_then_publishes():
    workflow = _read(".github/workflows/release.yml")
    assert "capguard-runtime" in workflow
    assert "python-version: \"3.12\"" in workflow
    assert "id-token: write" in workflow
    assert "needs: build" in workflow
    assert "GITHUB_REF_NAME" in workflow
    assert "ruff check capguard tests examples" in workflow
    assert "pytest -q" in workflow
    assert "capguard bench" in workflow
    assert "python -m build" in workflow
    assert "python -m twine check dist/*" in workflow
    assert "python -m venv /tmp/capguard-release-smoke" in workflow
    assert 'md.version("capguard-runtime") == capguard.__version__' in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "pypa/gh-action-pypi-publish@release/v1" in workflow
    assert "password" not in workflow.lower()


def test_release_checklist_names_the_exact_publisher_and_smoke_steps():
    checklist = _read("RELEASE.md")
    assert "PyPI project name: `capguard-runtime`" in checklist
    assert "GitHub owner / repository: `harsha-mangena/capguard`" in checklist
    assert "Workflow filename: `release.yml`" in checklist
    assert "GitHub environment: `pypi`" in checklist
    assert "python -m twine check dist/*" in checklist
    assert "pip install capguard-runtime" in checklist
    assert "git tag -a v0.1.0" in checklist
