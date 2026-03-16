#!/usr/bin/env python3
"""CTF platform client supporting CTFd-compatible API and rCTF."""

import os
import json
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

    session = _get_session()
    output_dir = params.get("output_dir", "/app/tmp/ctf_files")
    os.makedirs(output_dir, exist_ok=True)

    file_url = params.get("file_url")
    challenge_id = params.get("challenge_id")

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

        # Handle relative URLs
        if file_url.startswith("/"):
            file_url = _platform_config["url"] + file_url

        resp = session.get(file_url, headers=_headers(), timeout=60, stream=True)
        if resp.status_code != 200:
            return {"success": False, "error": f"HTTP {resp.status_code} fetching file"}

        # Determine filename from URL or Content-Disposition
        filename = file_url.split("/")[-1].split("?")[0] or "challenge_file"
        cd = resp.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            filename = cd.split("filename=")[-1].strip('" ')

        filepath = os.path.join(output_dir, filename)
        with open(filepath, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        file_size = os.path.getsize(filepath)
        return {
            "success": True,
            "filepath": filepath,
            "filename": filename,
            "size_bytes": file_size,
        }
    except requests.RequestException as e:
        return {"success": False, "error": f"Download failed: {str(e)}"}


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
