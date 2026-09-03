"""Three upload tools asked for base64 and then wrote it out verbatim.

Each documents `content` as base64-encoded, and each defaulted
`encoding="utf-8"` -- the mode transfer_manager uses to `printf` the string
through untouched. Measured against a live reverse shell, uploading

    c3dlZXAtdmVyaWZ5LTQ0NDQtcm91bmQtdHJpcAo=      (29 bytes decoded)

landed a 40-byte file containing that base64 text. Passing encoding="base64"
to the same call landed the right 29 bytes, so only the default was wrong.

The checksum verification did not catch it and could not: it hashes the
content the caller sent and the bytes on the target, and with the printf path
those are the same string. It confirms a faithful transfer of the wrong thing,
and reports success either way -- so the one signal an operator would trust
here agrees with the bug.

That matters most for the case the tools exist for: pushing a binary through a
shell. A base64 text file where an ELF was expected does not run.

kali_download and the *_download_content tools were already right, returning
base64 and saying so; the asymmetry was one-sided.
"""

import re
from pathlib import Path

import pytest

MCP_TOOLS = Path(__file__).resolve().parents[1] / "mcp_tools"

# (module, tool) for every wrapper that forwards `encoding` into
# transfer_manager, where it selects decode-vs-verbatim.
FORWARDING_UPLOADS = [
    ("reverse_shell.py", "reverse_shell_upload_content"),
    ("ssh_manager.py", "ssh_session_upload_content"),
    ("file_operations.py", "target_upload_file"),
]


def _signature(module, tool):
    source = (MCP_TOOLS / module).read_text(encoding="utf-8")
    start = source.index(f"def {tool}")
    return source[start:source.index(")", start)]


def _docstring(module, tool):
    source = (MCP_TOOLS / module).read_text(encoding="utf-8")
    start = source.index(f"def {tool}")
    first = source.index('"""', start)
    return source[first:source.index('"""', first + 3)]


@pytest.mark.parametrize("module,tool", FORWARDING_UPLOADS, ids=lambda v: str(v))
def test_the_encoding_default_matches_what_content_is_documented_as(module, tool):
    signature = _signature(module, tool)
    match = re.search(r'encoding: str = "([^"]+)"', signature)

    assert match, f"{tool} lost its encoding parameter"
    assert match.group(1) == "base64", (
        f"{tool} documents content as base64 but defaults to "
        f'{match.group(1)!r}, which writes the base64 text out literally'
    )


@pytest.mark.parametrize("module,tool", FORWARDING_UPLOADS, ids=lambda v: str(v))
def test_content_is_still_documented_as_base64(module, tool):
    """If this ever stops being true the default above is wrong again."""
    doc = _docstring(module, tool)

    assert re.search(r"content:.*[Bb]ase64", doc), (
        f"{tool} no longer says content is base64"
    )


@pytest.mark.parametrize("module,tool", FORWARDING_UPLOADS, ids=lambda v: str(v))
def test_the_utf8_escape_hatch_is_explained(module, tool):
    """utf-8 is still legitimate for writing a plain string, so it stays --
    but an agent picking it needs to know what it does to base64 content."""
    doc = _docstring(module, tool)

    assert "utf-8" in doc
    assert "checksum" in doc, (
        "the docstring should say why the checksum does not catch this"
    )


def test_kali_upload_is_left_alone():
    """kali_upload decodes regardless -- its `encoding` describes the file's
    character encoding, not the transfer, and it was measured correct (29
    bytes from the same input). Changing it would break a working tool."""
    signature = _signature("file_operations.py", "kali_upload")

    assert 'encoding: str = "utf-8"' in signature, (
        "kali_upload does not forward encoding to transfer_manager and was "
        "verified to decode correctly; it is deliberately not part of this fix"
    )
