import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import ctf_platform


class FakeResponse:
    def __init__(self, body=b"payload", headers=None, status_code=200):
        self.body = body
        self.headers = headers or {}
        self.status_code = status_code
        self.text = body.decode(errors="replace")

    def iter_content(self, chunk_size=8192):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset:offset + chunk_size]


class FakeSession:
    def __init__(self, responses):
        self.responses = responses if isinstance(responses, list) else [responses]
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        index = min(len(self.calls) - 1, len(self.responses) - 1)
        return self.responses[index]

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def restore_platform_config():
    original = dict(ctf_platform._platform_config)
    yield
    ctf_platform._platform_config.clear()
    ctf_platform._platform_config.update(original)


def configure_platform(session):
    ctf_platform._platform_config.update({
        "url": "https://ctf.example",
        "token": "victim-token",
        "platform_type": "ctfd",
        "session": session,
    })


def test_same_origin_download_keeps_platform_authorization(tmp_path):
    session = FakeSession(FakeResponse())
    configure_platform(session)

    result = ctf_platform.download_file({
        "file_url": "https://ctf.example/files/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result["success"] is True
    assert session.calls[0]["headers"]["Authorization"] == "Token victim-token"


def test_cross_origin_download_does_not_send_platform_state(tmp_path, monkeypatch):
    platform_session = FakeSession(FakeResponse())
    external_session = FakeSession(FakeResponse())
    configure_platform(platform_session)
    monkeypatch.setattr(ctf_platform.requests, "Session", lambda: external_session)

    result = ctf_platform.download_file({
        "file_url": "https://downloads.example/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result["success"] is True
    assert platform_session.calls == []
    assert external_session.calls[0].get("headers", {}) == {}


def test_redirect_to_cross_origin_switches_to_credential_free_session(tmp_path, monkeypatch):
    platform_session = FakeSession([
        FakeResponse(
            status_code=302,
            headers={"Location": "/files/signed/challenge.bin"},
        ),
        FakeResponse(
            status_code=307,
            headers={"Location": "https://cdn.example/challenge.bin"},
        ),
    ])
    external_session = FakeSession(FakeResponse())
    configure_platform(platform_session)
    monkeypatch.setattr(ctf_platform.requests, "Session", lambda: external_session)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result["success"] is True
    assert [call["url"] for call in platform_session.calls] == [
        "https://ctf.example/files/challenge.bin",
        "https://ctf.example/files/signed/challenge.bin",
    ]
    assert all(
        call["headers"]["Authorization"] == "Token victim-token"
        for call in platform_session.calls
    )
    assert external_session.calls == [{
        "url": "https://cdn.example/challenge.bin",
        "headers": {},
        "timeout": 60,
        "stream": True,
        "allow_redirects": False,
    }]


def test_redirect_limit_stops_cycles(tmp_path):
    session = FakeSession(FakeResponse(
        status_code=302,
        headers={"Location": "/files/challenge.bin"},
    ))
    configure_platform(session)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result == {"success": False, "error": "Too many download redirects"}
    assert len(session.calls) == ctf_platform.MAX_DOWNLOAD_REDIRECTS + 1


def test_response_filename_is_confined_to_output_directory(tmp_path):
    session = FakeSession(FakeResponse(headers={
        "Content-Disposition": 'attachment; filename="../../escape.bin"',
    }))
    configure_platform(session)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result["success"] is True
    assert Path(result["filepath"]) == tmp_path / "escape.bin"
    assert (tmp_path / "escape.bin").read_bytes() == b"payload"
    assert not (tmp_path.parent / "escape.bin").exists()


def test_oversized_download_is_rejected_without_partial_file(tmp_path):
    session = FakeSession(FakeResponse(body=b"12345"))
    configure_platform(session)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
        "max_bytes": 4,
    })

    assert result["success"] is False
    assert "maximum size" in result["error"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("max_bytes", [0, -1, "four", 4.5, True])
def test_invalid_per_call_limit_returns_validation_error(tmp_path, max_bytes):
    session = FakeSession(FakeResponse())
    configure_platform(session)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
        "max_bytes": max_bytes,
    })

    assert result == {
        "success": False,
        "error": "max_bytes must be a positive integer",
    }
    assert session.calls == []


def test_per_call_limit_cannot_exceed_configured_cap(tmp_path, monkeypatch):
    session = FakeSession(FakeResponse())
    configure_platform(session)
    monkeypatch.setenv("CTF_MAX_DOWNLOAD_BYTES", "4")

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
        "max_bytes": 5,
    })

    assert result == {
        "success": False,
        "error": "max_bytes cannot exceed the configured limit of 4 bytes",
    }
    assert session.calls == []


@pytest.mark.parametrize("configured_limit", ["invalid", "0", "-1"])
def test_invalid_configured_limit_returns_validation_error(
    tmp_path,
    monkeypatch,
    configured_limit,
):
    session = FakeSession(FakeResponse())
    configure_platform(session)
    monkeypatch.setenv("CTF_MAX_DOWNLOAD_BYTES", configured_limit)

    result = ctf_platform.download_file({
        "file_url": "/files/challenge.bin",
        "output_dir": str(tmp_path),
    })

    assert result == {
        "success": False,
        "error": "CTF_MAX_DOWNLOAD_BYTES must be a positive integer",
    }
    assert session.calls == []
