import hashlib
import importlib.util
import json
import sys
import zipfile
from pathlib import Path
from tarfile import TarFile, TarInfo

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / ".github" / "scripts" / "verify_release_artifacts.py"
spec = importlib.util.spec_from_file_location("release_artifact_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = verifier
spec.loader.exec_module(verifier)


def _metadata(name="zebbern-kali-mcp", version="1.0.2"):
    return "\n".join(
        [
            "Metadata-Version: 2.1",
            f"Name: {name}",
            f"Version: {version}",
            "Requires-Python: >=3.10",
            "Requires-Dist: mcp>=1.28,<2",
            "Requires-Dist: requests>=2.28.0",
            'Requires-Dist: Flask>=2.3,<4; extra == "test"',
            'Requires-Dist: pytest>=8,<9; extra == "test"',
            "",
        ]
    ).encode()


def _source_files():
    files = {
        "README.md": (PROJECT_ROOT / "README.md").read_bytes(),
        "pyproject.toml": (PROJECT_ROOT / "pyproject.toml").read_bytes(),
        "LICENSE": (PROJECT_ROOT / "LICENSE").read_bytes(),
        "mcp_server.py": (PROJECT_ROOT / "mcp_server.py").read_bytes(),
    }
    files.update(
        {
            path.relative_to(PROJECT_ROOT).as_posix(): path.read_bytes()
            for path in (PROJECT_ROOT / "mcp_tools").glob("*.py")
        }
    )
    return files


def _write_valid_dist(
    tmp_path,
    *,
    metadata=None,
    extra_sdist_members=None,
    extra_wheel_members=None,
):
    dist = tmp_path / "dist"
    dist.mkdir()
    source_files = _source_files()
    metadata = metadata or _metadata()
    wheel_name = "zebbern_kali_mcp-1.0.2-py3-none-any.whl"
    sdist_name = "zebbern_kali_mcp-1.0.2.tar.gz"
    with zipfile.ZipFile(dist / wheel_name, "w") as archive:
        for name, data in source_files.items():
            if name in {"README.md", "pyproject.toml", "LICENSE"}:
                continue
            archive.writestr(name, data)
        archive.writestr("zebbern_kali_mcp-1.0.2.dist-info/licenses/LICENSE", source_files["LICENSE"])
        archive.writestr("zebbern_kali_mcp-1.0.2.dist-info/METADATA", metadata)
        archive.writestr("zebbern_kali_mcp-1.0.2.dist-info/WHEEL", b"Wheel-Version: 1.0\n")
        archive.writestr(
            "zebbern_kali_mcp-1.0.2.dist-info/entry_points.txt",
            b"[console_scripts]\nzebbern-kali-mcp = mcp_server:main\n",
        )
        archive.writestr("zebbern_kali_mcp-1.0.2.dist-info/top_level.txt", b"mcp_server\nmcp_tools\n")
        archive.writestr("zebbern_kali_mcp-1.0.2.dist-info/RECORD", b"")
        for name, data in (extra_wheel_members or {}).items():
            archive.writestr(name, data)
    with TarFile.open(dist / sdist_name, "w:gz") as archive:
        prefix = "zebbern-kali-mcp-1.0.2/"
        sdist_members = {
            **source_files,
            "PKG-INFO": metadata,
            **(extra_sdist_members or {}),
        }
        for name, data in sdist_members.items():
            info = TarInfo(prefix + name)
            info.size = len(data)
            archive.addfile(info, fileobj=__import__("io").BytesIO(data))
    return dist


def test_valid_wheel_and_sdist_produce_deterministic_manifest(tmp_path):
    dist = _write_valid_dist(tmp_path)
    manifest_path = tmp_path / "manifest.json"

    manifest = verifier.verify_build(dist, PROJECT_ROOT, manifest_path)

    assert list(manifest) == [
        "zebbern_kali_mcp-1.0.2-py3-none-any.whl",
        "zebbern_kali_mcp-1.0.2.tar.gz",
    ]
    assert manifest_path.read_text() == json.dumps(manifest, indent=2) + "\n"
    assert all(set(item) == {"bytes", "sha256"} for item in manifest.values())


def test_corrupted_source_file_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path)
    wheel = dist / "zebbern_kali_mcp-1.0.2-py3-none-any.whl"
    corrupted = tmp_path / "corrupt"
    corrupted.mkdir()
    with zipfile.ZipFile(wheel) as source, zipfile.ZipFile(corrupted / wheel.name, "w") as target:
        for item in source.infolist():
            target.writestr(item, b"tampered" if item.filename == "mcp_server.py" else source.read(item))
    wheel.write_bytes((corrupted / wheel.name).read_bytes())

    with pytest.raises(verifier.VerificationError, match="mcp_server.py"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_unsafe_archive_member_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path)
    wheel = dist / "zebbern_kali_mcp-1.0.2-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("../credentials.txt", b"secret")

    with pytest.raises(verifier.VerificationError, match="unsafe archive member"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_executable_wheel_member_not_present_in_source_is_rejected(tmp_path):
    dist = _write_valid_dist(
        tmp_path,
        extra_wheel_members={"release_hook.pth": b"import release_hook\n"},
    )

    with pytest.raises(verifier.VerificationError, match="unexpected wheel member"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_test_source_name_containing_password_is_not_treated_as_a_secret(tmp_path):
    dist = _write_valid_dist(
        tmp_path,
        extra_sdist_members={"tests/test_password_redaction.py": b"def test_redaction(): pass\n"},
    )

    verifier.verify_build(dist, PROJECT_ROOT)


def test_environment_file_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path, extra_sdist_members={".env": b"TOKEN=secret\n"})

    with pytest.raises(verifier.VerificationError, match="credential-like archive member"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_wrong_metadata_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path, metadata=_metadata(version="9.9.9"))

    with pytest.raises(verifier.VerificationError, match="Version"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_extra_artifact_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path)
    (dist / "unexpected.whl").write_bytes(b"not a release artifact")

    with pytest.raises(verifier.VerificationError, match="unexpected artifact"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_nested_artifact_is_rejected(tmp_path):
    dist = _write_valid_dist(tmp_path)
    nested = dist / "nested"
    nested.mkdir()
    (nested / "unexpected.whl").write_bytes(b"not a release artifact")

    with pytest.raises(verifier.VerificationError, match="unexpected artifact"):
        verifier.verify_build(dist, PROJECT_ROOT)


def test_manifest_revalidation_detects_hash_change(tmp_path):
    dist = _write_valid_dist(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    verifier.verify_build(dist, PROJECT_ROOT, manifest_path)
    wheel = dist / "zebbern_kali_mcp-1.0.2-py3-none-any.whl"
    wheel.write_bytes(wheel.read_bytes() + b"changed")

    with pytest.raises(verifier.VerificationError, match="sha256"):
        verifier.revalidate_manifest(dist, manifest_path)


def test_manifest_revalidation_rejects_extra_file(tmp_path):
    dist = _write_valid_dist(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    verifier.verify_build(dist, PROJECT_ROOT, manifest_path)
    (dist / "extra.whl").write_bytes(b"unexpected")

    with pytest.raises(verifier.VerificationError, match="unexpected artifact"):
        verifier.revalidate_manifest(dist, manifest_path)


def test_manifest_revalidation_rejects_nested_file(tmp_path):
    dist = _write_valid_dist(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    verifier.verify_build(dist, PROJECT_ROOT, manifest_path)
    nested = dist / "nested"
    nested.mkdir()
    (nested / "extra.whl").write_bytes(b"unexpected")

    with pytest.raises(verifier.VerificationError, match="unexpected artifact"):
        verifier.revalidate_manifest(dist, manifest_path)


def test_missing_version_json_proves_pypi_absence(monkeypatch):
    monkeypatch.setattr(verifier, "_pypi_request", lambda version, timeout: (404, None))

    verifier.check_pypi_absent()


def test_successful_version_json_proves_version_exists(monkeypatch):
    monkeypatch.setattr(verifier, "_pypi_request", lambda version, timeout: (200, {}))

    with pytest.raises(verifier.VerificationError, match="already exists"):
        verifier.check_pypi_absent()


def test_post_publish_retries_transient_pypi_failure(tmp_path, monkeypatch):
    dist = _write_valid_dist(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = verifier.verify_build(dist, PROJECT_ROOT, manifest_path)
    files = [
        {
            "filename": name,
            "size": values["bytes"],
            "digests": {"sha256": values["sha256"]},
        }
        for name, values in manifest.items()
    ]
    attempts = []

    def request(version, timeout):
        attempts.append((version, timeout))
        if len(attempts) == 1:
            raise verifier.PyPIRequestError("temporary PyPI failure")
        return 200, {"urls": files}

    monkeypatch.setattr(verifier, "_pypi_request", request)

    verifier.verify_pypi_release(manifest_path, retries=2, delay=0)

    assert len(attempts) == 2
