#!/usr/bin/env python3
"""CTF platform client supporting CTFd-compatible API and rCTF."""

import os
import json
import tempfile
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

import requests
from typing import Dict, Any, Optional, List
from core.config import logger

# Stored credentials (in-memory, per container session)
_platform_config: Dict[str, Any] = {
    "url": None,
    "token": None,
    "platform_type": None,  # "ctfd" or "rctf"
    "session": None,
}

DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024
MAX_DOWNLOAD_REDIRECTS = 5
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class _DownloadTooLarge(Exception):
    pass


def _get_session() -> requests.Session:
    """Return the configured requests session."""
    if _platform_config["session"] is None:
        _platform_config["session"] = requests.Session()
    return _platform_config["session"]


def _headers() -> Dict[str, str]:
    """Build auth headers for the configured platform."""
    token = _platform_config.get("token")
    ptype = _platform_config.get("platform_type", "ctfd")
    if not token:
        return {"Content-Type": "application/json"}
    if ptype == "rctf":
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
    # CTFd default
    return {
        "Content-Type": "application/json",
        "Authorization": f"Token {token}",
    }


def _api(path: str) -> str:
    """Build full API URL."""
    base = (_platform_config.get("url") or "").rstrip("/")
    return f"{base}{path}"


def _origin(url: str) -> tuple[str, Optional[str], Optional[int]]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, parsed.hostname.lower() if parsed.hostname else None, parsed.port or default_port


def _is_http_url(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme.lower() in {"http", "https"} and parsed.hostname is not None


def _download_limit(params: Dict[str, Any]) -> tuple[Optional[int], Optional[str]]:
    configured_value = os.environ.get(
        "CTF_MAX_DOWNLOAD_BYTES",
        str(DEFAULT_MAX_DOWNLOAD_BYTES),
    )
    try:
        configured_limit = int(configured_value)
    except (TypeError, ValueError):
        return None, "CTF_MAX_DOWNLOAD_BYTES must be a positive integer"
    if configured_limit < 1:
        return None, "CTF_MAX_DOWNLOAD_BYTES must be a positive integer"

    if "max_bytes" not in params:
        return configured_limit, None

    requested_limit = params["max_bytes"]
    if type(requested_limit) is not int or requested_limit < 1:
        return None, "max_bytes must be a positive integer"
    if requested_limit > configured_limit:
        return (
            None,
            f"max_bytes cannot exceed the configured limit of {configured_limit} bytes",
        )
    return requested_limit, None


def _download_filename(file_url: str, content_disposition: str) -> str:
    candidate = ""
    if content_disposition:
        message = Message()
        message["Content-Disposition"] = content_disposition
        candidate = message.get_filename() or ""
    if not candidate:
        candidate = unquote(Path(urlsplit(file_url).path).name)

    candidate = candidate.replace("\\", "/").rsplit("/", 1)[-1]
    candidate = candidate.replace("\x00", "").strip()
    if candidate in {"", ".", ".."}:
        return "challenge_file"
    return candidate


def connect(params: Dict[str, Any]) -> Dict[str, Any]:
    """Connect to a CTF platform and verify credentials.

    params:
        url: CTF platform base URL (e.g. https://ctf.example.com)
        token: API token or session token
        platform_type: "ctfd" (default) or "rctf"
        cookies: Optional dict of cookies (for cookie-based auth)
        verify_ssl: Whether to verify SSL (default True)
    """
    url = params.get("url", "").rstrip("/")
    token = params.get("token", "")
    platform_type = params.get("platform_type", "ctfd")
    cookies = params.get("cookies")
    verify_ssl = params.get("verify_ssl", True)

    if not url:
        return {"success": False, "error": "url is required"}

    _platform_config["url"] = url
    _platform_config["token"] = token
    _platform_config["platform_type"] = platform_type

    session = _get_session()
    session.verify = verify_ssl
    if cookies and isinstance(cookies, dict):
        session.cookies.update(cookies)

    # Verify connection by fetching scoreboard or user info
    try:
        if platform_type == "rctf":
            resp = session.get(_api("/api/v1/users/me"), headers=_headers(), timeout=15)
        else:
            resp = session.get(_api("/api/v1/users/me"), headers=_headers(), timeout=15)

        if resp.status_code == 200:
            data = resp.json()
            user_data = data.get("data", data)
            return {
                "success": True,
                "platform_url": url,
                "platform_type": platform_type,
                "user": user_data,
                "message": f"Connected to {url} as {user_data.get('name', 'unknown')}",
            }
        elif resp.status_code == 401:
            return {"success": False, "error": "Authentication failed — check your token"}
        else:
            return {
                "success": False,
                "error": f"Unexpected status {resp.status_code}: {resp.text[:500]}",
            }
    except requests.RequestException as e:
        return {"success": False, "error": f"Connection failed: {str(e)}"}


def list_challenges(params: Dict[str, Any]) -> Dict[str, Any]:
    """List all available challenges.

    params:
        category: Optional category filter
    """
    if not _platform_config.get("url"):
        return {"success": False, "error": "Not connected — call ctf_connect first"}

    session = _get_session()
    category = params.get("category")

    try:
        resp = session.get(_api("/api/v1/challenges"), headers=_headers(), timeout=15)
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:500]}"}

        data = resp.json()
        challenges = data.get("data", [])

        if category:
            challenges = [c for c in challenges if c.get("category", "").lower() == category.lower()]

        # Normalize output
        result = []
        for c in challenges:
            result.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "category": c.get("category"),
                "value": c.get("value"),
                "solves": c.get("solves", 0),
                "solved_by_me": c.get("solved_by_me", False),
                "description": c.get("description", "")[:200],
                "tags": c.get("tags", []),
            })

        return {
            "success": True,
            "count": len(result),
            "challenges": result,
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}


def get_challenge(params: Dict[str, Any]) -> Dict[str, Any]:
    """Get full details for a specific challenge.

    params:
        challenge_id: The challenge ID (int)
    """
    if not _platform_config.get("url"):
        return {"success": False, "error": "Not connected — call ctf_connect first"}

    challenge_id = params.get("challenge_id")
    if not challenge_id:
        return {"success": False, "error": "challenge_id is required"}

    session = _get_session()

    try:
        resp = session.get(
            _api(f"/api/v1/challenges/{challenge_id}"),
            headers=_headers(),
            timeout=15,
        )
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:500]}"}

        data = resp.json().get("data", {})

        # Also fetch files/hints if available
        files = data.get("files", [])
        hints = data.get("hints", [])

        return {
            "success": True,
            "challenge": {
                "id": data.get("id"),
                "name": data.get("name"),
                "category": data.get("category"),
                "description": data.get("description"),
                "value": data.get("value"),
                "solves": data.get("solves", 0),
                "solved_by_me": data.get("solved_by_me", False),
                "max_attempts": data.get("max_attempts"),
                "connection_info": data.get("connection_info"),
                "files": files,
                "hints": hints,
                "tags": data.get("tags", []),
                "type": data.get("type"),
            },
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}


def submit_flag(params: Dict[str, Any]) -> Dict[str, Any]:
    """Submit a flag for a challenge.

    params:
        challenge_id: The challenge ID (int)
        flag: The flag string to submit
    """
    if not _platform_config.get("url"):
        return {"success": False, "error": "Not connected — call ctf_connect first"}

    challenge_id = params.get("challenge_id")
    flag = params.get("flag", "")

    if not challenge_id:
        return {"success": False, "error": "challenge_id is required"}
    if not flag:
        return {"success": False, "error": "flag is required"}

    session = _get_session()

    try:
        payload = {"challenge_id": challenge_id, "submission": flag}
        resp = session.post(
            _api("/api/v1/challenges/attempt"),
            headers=_headers(),
            json=payload,
            timeout=15,
        )

        if resp.status_code not in (200, 201):
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:500]}"}

        data = resp.json().get("data", resp.json())
        status = data.get("status", "unknown")
        message = data.get("message", "")

        return {
            "success": True,
            "correct": status == "correct",
            "already_solved": status == "already_solved",
            "status": status,
            "message": message,
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}


def download_file(params: Dict[str, Any]) -> Dict[str, Any]:
    """Download a challenge file to local disk.

    params:
        challenge_id: The challenge ID (to look up files)
        file_url: Direct file URL (alternative to challenge_id)
        output_dir: Where to save (default: /app/tmp/ctf_files)
    """
    if not _platform_config.get("url"):
        return {"success": False, "error": "Not connected — call ctf_connect first"}

    max_bytes, limit_error = _download_limit(params)
    if limit_error:
        return {"success": False, "error": limit_error}

    session = _get_session()
    output_dir = Path(params.get("output_dir", "/app/tmp/ctf_files")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    file_url = params.get("file_url")
    challenge_id = params.get("challenge_id")

    temporary_path: Optional[Path] = None
    external_session = None
    resp = None
    try:
        if not file_url and challenge_id:
            # Fetch challenge to get file list
            chall = get_challenge({"challenge_id": challenge_id})
            if not chall.get("success"):
                return chall
            files = chall["challenge"].get("files", [])
            if not files:
                return {"success": False, "error": "Challenge has no files"}
            file_url = files[0]

        if not file_url:
            return {"success": False, "error": "file_url or challenge_id is required"}

        base_url = _platform_config["url"].rstrip("/") + "/"
        file_url = urljoin(base_url, file_url)
        if not _is_http_url(file_url):
            return {"success": False, "error": "Download URL must use HTTP or HTTPS"}

        redirects_followed = 0
        while True:
            same_origin = _origin(file_url) == _origin(base_url)
            if same_origin:
                request_session = session
                request_headers = _headers()
            else:
                if external_session is None:
                    external_session = requests.Session()
                    external_session.verify = params.get("verify_ssl", True)
                request_session = external_session
                request_headers = {}

            resp = request_session.get(
                file_url,
                headers=request_headers,
                timeout=60,
                stream=True,
                allow_redirects=False,
            )
            if resp.status_code not in _REDIRECT_STATUS_CODES:
                break

            location = resp.headers.get("Location")
            if not location:
                break
            if redirects_followed >= MAX_DOWNLOAD_REDIRECTS:
                return {"success": False, "error": "Too many download redirects"}

            next_url = urljoin(file_url, location)
            close = getattr(resp, "close", None)
            if close:
                close()
            resp = None
            if not _is_http_url(next_url):
                return {"success": False, "error": "Download URL must use HTTP or HTTPS"}
            file_url = next_url
            redirects_followed += 1

        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code} fetching file"}

        content_length = resp.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > max_bytes:
                    raise _DownloadTooLarge
            except ValueError:
                pass

        filename = _download_filename(
            file_url,
            resp.headers.get("Content-Disposition", ""),
        )
        filepath = (output_dir / filename).resolve()
        if filepath.parent != output_dir:
            return {"success": False, "error": "Download filename escapes output directory"}

        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output_dir,
            prefix=f".{filename}.",
            suffix=".part",
            delete=False,
        ) as f:
            temporary_path = Path(f.name)
            downloaded = 0
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                downloaded += len(chunk)
                if downloaded > max_bytes:
                    raise _DownloadTooLarge
                f.write(chunk)
        os.replace(temporary_path, filepath)
        temporary_path = None

        return {
            "success": True,
            "filepath": str(filepath),
            "filename": filename,
            "size_bytes": downloaded,
        }
    except _DownloadTooLarge:
        return {
            "success": False,
            "error": f"Download exceeds maximum size of {max_bytes} bytes",
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Download failed: {str(e)}"}
    except (OSError, ValueError) as e:
        return {"success": False, "error": f"Download failed: {str(e)}"}
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        if resp is not None:
            close = getattr(resp, "close", None)
            if close:
                close()
        if external_session is not None:
            close = getattr(external_session, "close", None)
            if close:
                close()


def scoreboard(params: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch the current scoreboard.

    params:
        top: Number of top entries to return (default 20)
    """
    if not _platform_config.get("url"):
        return {"success": False, "error": "Not connected — call ctf_connect first"}

    session = _get_session()
    top = params.get("top", 20)

    try:
        resp = session.get(_api("/api/v1/scoreboard"), headers=_headers(), timeout=15)
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:500]}"}

        data = resp.json().get("data", [])
        entries = data[:top] if isinstance(data, list) else data

        return {
            "success": True,
            "entries": entries,
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Request failed: {str(e)}"}


def get_status(params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Return current connection status."""
    return {
        "success": True,
        "connected": _platform_config.get("url") is not None,
        "platform_url": _platform_config.get("url"),
        "platform_type": _platform_config.get("platform_type"),
    }
