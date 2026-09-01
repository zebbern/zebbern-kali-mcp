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
INTEGRATION_WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"
CONFIG_PY = ROOT / "zebbern-kali" / "core" / "config.py"


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


def test_publish_is_gated_on_the_integration_workflow():
    """A release must not ship without the container and live suites running.

    `pytest -q` alone cannot prove this: the live tests skip themselves when no
    backend answers, so the release job passes without executing a single tool.
    """
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "./.github/workflows/integration.yml" in workflow
    assert "needs: [gate, integration]" in workflow


def test_integration_workflow_runs_both_layers():
    integration = (ROOT / ".github" / "workflows" / "integration.yml").read_text(
        encoding="utf-8"
    )

    assert "run_smoke.py" in integration, "container smoke missing"
    assert "--check-trim" in integration, "trim profile not asserted against a real image"
    assert "pytest -m live" in integration, "live tool execution missing"


def _config_version() -> str:
    text = CONFIG_PY.read_text(encoding="utf-8")
    match = re.search(r'(?m)^VERSION\s*=\s*"([^"]+)"', text)
    assert match, "zebbern-kali/core/config.py declares no VERSION"
    return match.group(1)


def test_backend_version_tracks_pyproject():
    """The backend/Docker VERSION and the client wheel version move in lockstep.

    config.py cannot derive its version: pyproject.toml is not shipped in the
    container image (.dockerignore excludes it) and the backend runs from source,
    not a pip install, so importlib.metadata has nothing to read. The value is a
    hand-maintained literal; this test is what enforces that a bump touches both.
    """
    assert _config_version() == declared_version()


def test_integration_gate_pins_an_image_digest():
    """The gate must test a reproducible, immutable image, never a floating tag."""
    workflow = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")

    assert re.search(
        r"(?m)^\s*IMAGE:\s*ghcr\.io/zebbern/zebbern-kali-mcp@sha256:[0-9a-f]{64}\s*$",
        workflow,
    ), "integration.yml must pin the image by @sha256 digest, not a tag like :latest"
    # Scoped to the IMAGE: line rather than banning the substring file-wide, so a
    # comment mentioning :latest cannot fail this test for the wrong reason.
    assert not re.search(
        r"(?m)^\s*IMAGE:.*:latest\s*$", workflow
    ), "integration.yml still pins IMAGE to a floating :latest tag"


def test_the_live_layer_uses_the_same_pinned_image_as_the_smoke_layer():
    """Pinning only the pull is not enough.

    The live layer starts the backend with `docker compose up`, and a digest pull
    leaves no local tag behind -- so unless the digest reaches compose, it would
    miss :latest and rebuild the image from the Dockerfile, a ~36 minute build
    against a 45 minute job timeout. Compose must consume the pinned digest.
    """
    workflow = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert re.search(
        r"(?m)^\s*image:\s*\$\{ZKM_IMAGE:-", compose
    ), "docker-compose.yml must take its image from ZKM_IMAGE, with a local default"
    assert "ZKM_IMAGE: ${{ env.IMAGE }}" in workflow, (
        "the gate must pass its pinned digest to compose as ZKM_IMAGE, or the "
        "live layer runs against different bits than the smoke layer certified"
    )
