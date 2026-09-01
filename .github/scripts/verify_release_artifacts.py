"""Verify the exact files that are eligible for the 1.0.4 PyPI release.

This module intentionally uses only the Python standard library.  The same
checks are used before uploading an Actions artifact and after downloading it
in a later job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from tarfile import TarError, TarFile


VERSION = "1.0.4"
PROJECT_NAME = "zebbern-kali-mcp"
WHEEL_NAME = "zebbern_kali_mcp-1.0.4-py3-none-any.whl"
SDIST_NAME = "zebbern_kali_mcp-1.0.4.tar.gz"
EXPECTED_ARTIFACTS = (SDIST_NAME, WHEEL_NAME)
PYPI_JSON_URL = f"https://pypi.org/pypi/{PROJECT_NAME}/{{version}}/json"

_REQUIRED_SOURCE_FILES = ("README.md", "pyproject.toml", "LICENSE", "mcp_server.py")
_REQUIRED_METADATA = {
    "Name": PROJECT_NAME,
    "Version": VERSION,
    "Requires-Python": ">=3.10",
}
_EXPECTED_REQUIREMENTS = {"mcp>=1.28,<2", "requests>=2.28.0"}
_EXPECTED_TEST_REQUIREMENTS = {
    'Flask>=2.3,<4; extra == "test"',
    'pytest>=8,<9; extra == "test"',
}
_ENTRY_POINT = "zebbern-kali-mcp = mcp_server:main"
_DIST_INFO_DIR = "zebbern_kali_mcp-1.0.4.dist-info"
_CREDENTIAL_FILE = re.compile(
    r"^(?:"
    r"\.env(?:\..+)?|"
    r"credentials?(?:\.(?:json|ya?ml|toml|ini|txt))?|"
    r"secrets?(?:\.(?:json|ya?ml|toml|ini|txt))?|"
    r"(?:api[_-]?)?token\.(?:json|ya?ml|toml|ini|txt)|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|"
    r"private[_-]?key(?:\.(?:pem|key))?"
    r")$",
    re.I,
)
_FORBIDDEN_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
}


class VerificationError(ValueError):
    """Raised when a release artifact does not satisfy its contract."""


class PyPIRequestError(VerificationError):
    """Raised for a transient or invalid response from the PyPI API."""


def _fail(message: str) -> None:
    raise VerificationError(message)


def _safe_member_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        _fail(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        _fail(f"unsafe archive member: {name!r}")
    parts = path.parts
    lowered = [part.lower() for part in parts]
    if any(_CREDENTIAL_FILE.fullmatch(part) for part in parts):
        _fail(f"credential-like archive member: {name!r}")
    if any(part in _FORBIDDEN_PARTS for part in lowered) or any(
        part.lower().endswith((".pyc", ".pyo")) for part in parts
    ):
        _fail(f"repository/cache/bytecode archive member: {name!r}")
    return "/".join(parts)


def _read_zip(path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                name = _safe_member_name(info.filename)
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    _fail(f"tar/zip link member: {info.filename!r}")
                if name in members:
                    _fail(f"duplicate archive member: {name!r}")
                members[name] = archive.read(info)
    except zipfile.BadZipFile as exc:
        _fail(f"invalid wheel archive: {path.name}: {exc}")
    return members


def _read_sdist(path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with TarFile.open(path, mode="r:gz") as archive:
            for info in archive.getmembers():
                name = _safe_member_name(info.name)
                if info.isdir():
                    continue
                if info.issym() or info.islnk() or info.isdev() or not info.isfile():
                    _fail(f"tar link/device member: {info.name!r}")
                if name in members:
                    _fail(f"duplicate archive member: {name!r}")
                extracted = archive.extractfile(info)
                if extracted is None:
                    _fail(f"unreadable archive member: {name!r}")
                members[name] = extracted.read()
    except (OSError, EOFError, TarError) as exc:
        _fail(f"invalid source archive: {path.name}: {exc}")
    return members


def _strip_sdist_root(members: dict[str, bytes]) -> dict[str, bytes]:
    roots = {name.split("/", 1)[0] for name in members}
    if len(roots) != 1:
        _fail("source archive must have exactly one top-level directory")
    root = next(iter(roots))
    return {name[len(root) + 1 :]: data for name, data in members.items() if "/" in name}


def _metadata_values(data: bytes) -> dict[str, list[str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"metadata is not UTF-8: {exc}")
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line[:1].isspace() or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result.setdefault(key, []).append(value.strip())
    return result


def _normalized_requirement(value: str) -> str:
    value = value.strip().lower()
    requirement, separator, marker = value.partition(";")
    requirement = re.sub(r"\s+", "", requirement)
    marker = re.sub(r"\s+", "", marker) if separator else ""
    match = re.match(r"^([a-z0-9_.-]+)(.*)$", requirement)
    if not match:
        return re.sub(r"\s+", "", value)
    name, constraints = match.groups()
    if not constraints:
        return name + ((";" + marker) if marker else "")
    pieces = [piece for piece in constraints.split(",") if piece]
    return name + ",".join(sorted(pieces)) + ((";" + marker) if marker else "")


def _validate_metadata(members: dict[str, bytes]) -> None:
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA") or name == "PKG-INFO"]
    if len(metadata_names) != 1:
        _fail("artifact must contain exactly one metadata file")
    values = _metadata_values(members[metadata_names[0]])
    for key, expected in _REQUIRED_METADATA.items():
        actual = values.get(key, [])
        if actual != [expected]:
            _fail(f"metadata {key} mismatch: expected {expected!r}, got {actual!r}")
    requirements = {
        _normalized_requirement(value)
        for value in values.get("Requires-Dist", [])
        if ";" not in value
    }
    expected = {_normalized_requirement(value) for value in _EXPECTED_REQUIREMENTS}
    if requirements != expected:
        _fail(f"metadata runtime dependencies mismatch: expected {sorted(expected)}, got {sorted(requirements)}")
    optional = {
        _normalized_requirement(value)
        for value in values.get("Requires-Dist", [])
        if ";" in value
    }
    expected_optional = {_normalized_requirement(value) for value in _EXPECTED_TEST_REQUIREMENTS}
    if optional != expected_optional:
        _fail(f"metadata test dependencies mismatch: expected {sorted(expected_optional)}, got {sorted(optional)}")


def _validate_entry_point(members: dict[str, bytes]) -> None:
    names = [name for name in members if name.endswith(".dist-info/entry_points.txt")]
    if len(names) != 1:
        _fail("artifact must contain exactly one entry_points.txt")
    lines = [line.strip() for line in members[names[0]].decode("utf-8").splitlines() if line.strip()]
    if lines != ["[console_scripts]", _ENTRY_POINT]:
        _fail("console entry point mismatch")


def _validate_source_members(members: dict[str, bytes], source_root: Path, *, wheel: bool) -> None:
    expected = {
        name: (source_root / name).read_bytes() for name in _REQUIRED_SOURCE_FILES
        if not wheel or name not in {"README.md", "pyproject.toml", "LICENSE"}
    }
    package_dir = source_root / "mcp_tools"
    package_files = sorted(path for path in package_dir.glob("*.py") if path.is_file())
    expected.update(
        {path.relative_to(source_root).as_posix(): path.read_bytes() for path in package_files}
    )
    if wheel:
        expected_wheel_members = set(expected) | {
            f"{_DIST_INFO_DIR}/METADATA",
            f"{_DIST_INFO_DIR}/WHEEL",
            f"{_DIST_INFO_DIR}/entry_points.txt",
            f"{_DIST_INFO_DIR}/top_level.txt",
            f"{_DIST_INFO_DIR}/RECORD",
            f"{_DIST_INFO_DIR}/licenses/LICENSE",
        }
        actual_wheel_members = set(members)
        if actual_wheel_members != expected_wheel_members:
            missing = sorted(expected_wheel_members - actual_wheel_members)
            extra = sorted(actual_wheel_members - expected_wheel_members)
            _fail(f"unexpected wheel member set: missing={missing}, extra={extra}")
        license_names = [name for name in members if name.endswith(".dist-info/licenses/LICENSE")]
        if len(license_names) != 1:
            _fail("wheel must contain exactly one packaged LICENSE")
        if members[license_names[0]] != (source_root / "LICENSE").read_bytes():
            _fail("packaged source differs from checkout: LICENSE")
    for name, data in expected.items():
        if name not in members:
            _fail(f"missing packaged source file: {name}")
        if members[name] != data:
            _fail(f"packaged source differs from checkout: {name}")
    for name in members:
        if name == "mcp_server.py" or name.startswith("mcp_tools/") and name.endswith(".py"):
            if name not in expected:
                _fail(f"unexpected packaged source file: {name}")


def _validate_artifact(path: Path, source_root: Path) -> None:
    if path.name == WHEEL_NAME:
        members = _read_zip(path)
        _validate_entry_point(members)
    elif path.name == SDIST_NAME:
        members = _strip_sdist_root(_read_sdist(path))
    else:
        _fail(f"unexpected artifact: {path.name}")
    _validate_metadata(members)
    _validate_source_members(members, source_root, wheel=path.name == WHEEL_NAME)


def _digest(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _require_artifact_set(dist: Path) -> dict[str, Path]:
    if not dist.is_dir():
        _fail(f"distribution directory does not exist: {dist}")
    children = list(dist.iterdir())
    names = {path.name for path in children}
    invalid = sorted(path.name for path in children if path.is_symlink() or not path.is_file())
    if names != set(EXPECTED_ARTIFACTS) or invalid:
        missing = sorted(set(EXPECTED_ARTIFACTS) - names)
        extra = sorted(names - set(EXPECTED_ARTIFACTS))
        _fail(
            "unexpected artifact set: "
            f"missing={missing}, extra={extra}, non_regular={invalid}"
        )
    return {name: dist / name for name in EXPECTED_ARTIFACTS}


def verify_build(dist_dir: Path | str, source_root: Path | str, manifest_path: Path | str | None = None) -> dict[str, dict[str, object]]:
    """Validate a fresh build and optionally write its deterministic manifest."""
    dist = Path(dist_dir)
    source = Path(source_root)
    artifacts = _require_artifact_set(dist)
    for path in artifacts.values():
        _validate_artifact(path, source)
    manifest = {name: _digest(artifacts[name]) for name in sorted(EXPECTED_ARTIFACTS)}
    if manifest_path is not None:
        Path(manifest_path).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def revalidate_manifest(dist_dir: Path | str, manifest_path: Path | str) -> dict[str, dict[str, object]]:
    """Check downloaded artifact bytes against a previously signed manifest."""
    dist = Path(dist_dir)
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"invalid artifact manifest: {exc}")
    if not isinstance(manifest, dict) or set(manifest) != set(EXPECTED_ARTIFACTS):
        _fail("manifest artifact set mismatch")
    artifacts = _require_artifact_set(dist)
    for name in sorted(EXPECTED_ARTIFACTS):
        actual = _digest(artifacts[name])
        entry = manifest[name]
        if not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"}:
            _fail(f"invalid manifest entry for {name}")
        if entry != actual:
            _fail(f"manifest sha256/size mismatch for {name}: expected {manifest[name]}, got {actual}")
    return manifest


def _pypi_request(version: str, timeout: float) -> tuple[int, dict | None]:
    url = PYPI_JSON_URL.format(version=urllib.parse.quote(version, safe=""))
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return int(response.status), payload
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        raise PyPIRequestError(f"PyPI returned HTTP {exc.code} while checking {version}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise PyPIRequestError(f"PyPI request failed: {exc}") from exc
    return 0, None


def check_pypi_absent(version: str = VERSION, *, timeout: float = 10.0) -> None:
    """Require that the target version is not already on official PyPI."""
    status, payload = _pypi_request(version, timeout)
    if status == 404:
        return
    if status == 200:
        _fail(f"PyPI version already exists: {PROJECT_NAME} {version}")
    _fail(f"could not prove PyPI version absence: HTTP {status}")


def verify_pypi_release(manifest_path: Path | str, version: str = VERSION, *, retries: int = 12, delay: float = 5.0, timeout: float = 10.0) -> None:
    """Poll PyPI and require exactly the manifest files and SHA-256 values."""
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"invalid artifact manifest: {exc}")
    if not isinstance(manifest, dict) or set(manifest) != set(EXPECTED_ARTIFACTS):
        _fail("manifest artifact set mismatch")
    expected: dict[str, dict[str, object]] = {}
    for name in EXPECTED_ARTIFACTS:
        values = manifest[name]
        if not isinstance(values, dict) or set(values) != {"bytes", "sha256"}:
            _fail(f"invalid manifest entry for {name}")
        if not isinstance(values["bytes"], int) or not isinstance(values["sha256"], str):
            _fail(f"invalid manifest values for {name}")
        expected[name] = values
    last_error = "release not visible"
    for attempt in range(max(1, retries)):
        try:
            status, payload = _pypi_request(version, timeout)
        except PyPIRequestError as exc:
            last_error = str(exc)
        else:
            files = payload.get("urls") if isinstance(payload, dict) else None
            if status == 200 and isinstance(files, list):
                if len(files) != len({item.get("filename") for item in files if isinstance(item, dict)}):
                    last_error = "PyPI manifest contains duplicate or invalid filenames"
                    actual = {}
                else:
                    actual = {
                        item.get("filename"): {
                            "bytes": item.get("size"),
                            "sha256": item.get("digests", {}).get("sha256"),
                        }
                        for item in files
                    }
                if actual == expected:
                    return
                last_error = f"PyPI manifest mismatch: expected {sorted(expected)}, got {sorted(actual)}"
            elif status == 200:
                last_error = "PyPI response is missing the urls list"
        if attempt + 1 < max(1, retries):
            time.sleep(max(0.0, delay))
    _fail(last_error)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify release artifacts and their PyPI publication.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--dist-dir", type=Path, required=True)
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--manifest", type=Path)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--dist-dir", type=Path, required=True)
    manifest.add_argument("--manifest", type=Path, required=True)
    absent = subparsers.add_parser("pypi-absent")
    absent.add_argument("--version", default=VERSION)
    absent.add_argument("--timeout", type=float, default=10.0)
    published = subparsers.add_parser("post-publish")
    published.add_argument("--manifest", type=Path, required=True)
    published.add_argument("--version", default=VERSION)
    published.add_argument("--retries", type=int, default=12)
    published.add_argument("--delay", type=float, default=5.0)
    published.add_argument("--timeout", type=float, default=10.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            verify_build(args.dist_dir, args.source_root, args.manifest)
        elif args.command == "manifest":
            revalidate_manifest(args.dist_dir, args.manifest)
        elif args.command == "pypi-absent":
            check_pypi_absent(args.version, timeout=args.timeout)
        elif args.command == "post-publish":
            verify_pypi_release(args.manifest, args.version, retries=args.retries, delay=args.delay, timeout=args.timeout)
    except VerificationError as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
