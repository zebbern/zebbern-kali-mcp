"""pyproject.toml is the single source of truth for the release version.

Every other place that needs the version must derive it. Hardcoding it in the
workflow or the verifier is what made a bump a five-file hand edit, where a
missed spot fails late and confusingly (a wheel-not-found in a publish job).
"""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github" / "scripts"))
import verify_release_artifacts as verifier  # noqa: E402

PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def declared_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "pyproject.toml declares no version"
    return match.group(1)


def test_verifier_reads_the_version_from_pyproject():
    assert verifier.VERSION == declared_version()


def test_verifier_artifact_names_derive_from_that_version():
    version = declared_version()

    assert verifier.WHEEL_NAME == f"zebbern_kali_mcp-{version}-py3-none-any.whl"
    assert verifier.SDIST_NAME == f"zebbern_kali_mcp-{version}.tar.gz"
    assert verifier._DIST_INFO_DIR == f"zebbern_kali_mcp-{version}.dist-info"
    assert verifier._REQUIRED_METADATA["Version"] == version


def test_publish_workflow_hardcodes_no_version():
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert declared_version() not in workflow, (
        "publish.yml pins the version literally, so a release needs the file "
        "hand-edited and a missed occurrence fails late"
    )


def test_publish_workflow_validates_the_requested_version_against_pyproject():
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "declared-version" in workflow, (
        "the workflow does not ask the tree what version it declares"
    )
    assert '"$REQUESTED_VERSION" = "$DECLARED"' in workflow, (
        "the version input is unchecked, so a release can be dispatched for a "
        "version the tree does not declare"
    )


@pytest.mark.parametrize("literal", ("1.0.1", "1.0.2", "1.0.3", "1.0.4"))
def test_no_stale_version_literals_survive_in_the_verifier(literal):
    source = Path(verifier.__file__).read_text(encoding="utf-8")

    assert literal not in source
