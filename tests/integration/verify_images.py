#!/usr/bin/env python3
"""Verify the contents and layer reuse of locally built image variants."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

try:
    from .run_smoke import require_safe_project_name
except ImportError:  # pragma: no cover - supports direct CLI execution by path
    from run_smoke import require_safe_project_name


IMAGE_CONTAINER = re.compile(r"^zkm-smoke-image-(?:full|lean|no-cado)-[0-9a-f]{12}$")
VARIANTS = ("full", "lean", "no-cado")


@dataclass(frozen=True)
class ImageFacts:
    """Immutable facts reported by ``docker image inspect``."""

    image: str
    image_id: str
    size: int
    layers: tuple[str, ...]


class ImageProbeError(RuntimeError):
    """Raised when a disposable image content probe fails."""


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"image inspect field {field!r} must be a non-empty string")
    return value


def parse_image_inspect(payload: str | bytes, *, image: str = "") -> ImageFacts:
    """Parse and validate one Docker image-inspect JSON response."""
    try:
        decoded = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("docker image inspect output must be valid JSON") from exc
    if not isinstance(decoded, list) or len(decoded) != 1:
        raise ValueError("docker image inspect output must contain exactly one image")
    record = decoded[0]
    if not isinstance(record, dict):
        raise ValueError("docker image inspect image record must be an object")

    image_id = _nonempty_string(record.get("Id"), "Id")
    size = record.get("Size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("image inspect field 'Size' must be a non-negative integer")

    rootfs = record.get("RootFS")
    if not isinstance(rootfs, dict) or rootfs.get("Type") != "layers":
        raise ValueError("image inspect RootFS.Type must be 'layers'")
    layers = rootfs.get("Layers")
    if not isinstance(layers, list) or not layers:
        raise ValueError("image inspect RootFS.Layers must be a non-empty list")
    if any(not isinstance(layer, str) or not layer.strip() for layer in layers):
        raise ValueError("image inspect RootFS.Layers must contain non-empty strings")

    return ImageFacts(image=image, image_id=image_id, size=size, layers=tuple(layers))


def image_facts(image: str) -> ImageFacts:
    """Inspect an existing local image without pulling, tagging, or rebuilding it."""
    command = ["docker", "image", "inspect", image]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        raise RuntimeError(
            f"docker image inspect failed for {image!r}; stdout={stdout!r}; stderr={stderr!r}"
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"docker image inspect failed for {image!r}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return parse_image_inspect(result.stdout, image=image)


def _layer_sequence(value: ImageFacts | Sequence[str]) -> Sequence[str]:
    if isinstance(value, ImageFacts):
        return value.layers
    return value


def common_layer_prefix(full: ImageFacts | Sequence[str], lean: ImageFacts | Sequence[str]) -> int:
    """Return the number of identical ordered layers from the RootFS start."""
    shared = 0
    for full_layer, lean_layer in zip(_layer_sequence(full), _layer_sequence(lean)):
        if full_layer != lean_layer:
            break
        shared += 1
    return shared


def _new_probe_name(variant: str) -> str:
    if variant not in VARIANTS:
        raise ValueError(f"unsupported image variant: {variant!r}")
    name = f"zkm-smoke-image-{variant}-{uuid.uuid4().hex[:12]}"
    require_safe_project_name(name)
    if not IMAGE_CONTAINER.fullmatch(name):
        raise ValueError(f"invalid generated image probe name: {name!r}")
    return name


def variant_probe_script(variant: str) -> str:
    """Return the shell predicate for one image variant."""
    scripts = {
        "full": (
            "set -eu; command -v msfconsole >/dev/null 2>&1; "
            "command -v msfvenom >/dev/null 2>&1; "
            "test -e /opt/cado-nfs/cado-nfs.py"
        ),
        "lean": (
            "set -eu; ! command -v msfconsole >/dev/null 2>&1; "
            "! command -v msfvenom >/dev/null 2>&1; "
            "test -e /opt/cado-nfs/cado-nfs.py"
        ),
        "no-cado": "set -eu; test ! -e /opt/cado-nfs",
    }
    try:
        return scripts[variant]
    except KeyError as exc:
        raise ValueError(f"unsupported image variant: {variant!r}") from exc


def content_probe_command(image: str, variant: str) -> list[str]:
    """Build the exact disposable-container command for a variant predicate."""
    probe_name = _new_probe_name(variant)
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        probe_name,
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        variant_probe_script(variant),
    ]


def run_content_probe(image: str, variant: str) -> subprocess.CompletedProcess[str]:
    """Run one disposable content predicate and retain output in failures."""
    command = content_probe_command(image, variant)
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        raise ImageProbeError(
            f"image content probe failed for {variant!r}; "
            f"stdout={stdout!r}; stderr={stderr!r}"
        ) from exc
    if result.returncode != 0:
        raise ImageProbeError(
            f"image content probe failed for {variant!r}; "
            f"stdout={result.stdout!r}; stderr={result.stderr!r}"
        )
    return result


def require_common_layer_threshold(full: ImageFacts, lean: ImageFacts) -> int:
    """Require the expected full/lean RootFS layer reuse and return its prefix."""
    prefix = common_layer_prefix(full, lean)
    threshold = min(len(full.layers), len(lean.layers)) - 6
    if prefix < threshold:
        raise RuntimeError(
            "common layer prefix threshold failed: "
            f"prefix={prefix}, required>={threshold}, "
            f"full_layers={len(full.layers)}, lean_layers={len(lean.layers)}"
        )
    return prefix


def verify_variants(full_image: str, lean_image: str, no_cado_image: str) -> int:
    """Verify all requested variants and print machine-readable evidence."""
    facts = {
        "full": image_facts(full_image),
        "lean": image_facts(lean_image),
        "no-cado": image_facts(no_cado_image),
    }
    for variant, image in (
        ("full", full_image),
        ("lean", lean_image),
        ("no-cado", no_cado_image),
    ):
        run_content_probe(image, variant)
    prefix = require_common_layer_threshold(facts["full"], facts["lean"])
    for variant in VARIANTS:
        current = facts[variant]
        print(
            f"{variant}: image={current.image} id={current.image_id} "
            f"size={current.size} layers={len(current.layers)}"
        )
    threshold = min(len(facts["full"].layers), len(facts["lean"].layers)) - 6
    print(f"common_layer_prefix={prefix} threshold={threshold}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify local Kali MCP image variants")
    parser.add_argument("--full", required=True, metavar="IMAGE")
    parser.add_argument("--lean", required=True, metavar="IMAGE")
    parser.add_argument("--no-cado", required=True, metavar="IMAGE")
    args = parser.parse_args(argv)
    return verify_variants(args.full, args.lean, args.no_cado)


if __name__ == "__main__":
    raise SystemExit(main())
