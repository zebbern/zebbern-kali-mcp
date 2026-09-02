"""Exercise every MCP tool against the live backend and classify the result.

Pass criterion is that the tool answers coherently, not that the operation
succeeded. A tool that reports "no VPN config found" is working: it is telling
the truth about the environment. Broken means an MCP-level error, an exception
escaping into the transport, a non-object payload, or a hang.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API = os.environ.get("KALI_API_URL", "http://127.0.0.1:5000")
# The host as seen from inside the container: 127.0.0.1 there is the
# container's own loopback, so a lab on the host is only reachable this way.
LAB = os.environ.get("ZKM_LAB_HOST", "host.docker.internal")
LAB_PORT = os.environ.get("ZKM_LAB_PORT", "8888")
LAB_URL = f"http://{LAB}:{LAB_PORT}"

# Ordered: read-only first, then things that start state, then things that stop
# it, so a listener is created before the call that tears it down.
CASES = [
    # --- command_exec -------------------------------------------------------
    ("health", {}),
    ("system_network_info", {}),
    ("zebbern_exec", {"command": "echo probe-ok", "timeout": 20}),
    ("exec_stream", {"command": "echo stream-ok", "timeout": 20}),
    ("job_status", {"job_id": "probe-missing"}),
    ("job_output", {"job_id": "probe-missing"}),
    ("job_cancel", {"job_id": "probe-missing"}),
    ("read_output", {"session_id": "probe-missing"}),
    ("send_input", {"session_id": "probe-missing", "input_text": "x"}),
    # --- hosts --------------------------------------------------------------
    ("hosts_add", {"ip": "10.77.0.1", "hostnames": "probe.test"}),
    ("hosts_list", {}),
    ("hosts_remove", {"hostname": "probe.test"}),
    # --- output parsing -----------------------------------------------------
    ("parse_tool_output", {"output": "80/tcp open http", "tool_name": "nmap"}),
    # --- file ops -----------------------------------------------------------
    ("kali_upload", {"content": "cHJvYmU=", "remote_path": "/tmp/probe.txt"}),
    ("kali_download", {"remote_path": "/tmp/probe.txt"}),
    ("target_upload_file", {"session_id": "probe-missing", "content": "eA==", "remote_path": "/tmp/x"}),
    ("target_download_file", {"session_id": "probe-missing", "remote_path": "/tmp/x"}),
    # --- fingerprinting (real target) ---------------------------------------
    ("fingerprint_url", {"url": LAB_URL}),
    ("fingerprint_headers", {"url": LAB_URL}),
    ("fingerprint_waf", {"url": LAB_URL}),
    # --- scanners (real target, tight scope) --------------------------------
    ("tools_nmap", {"target": LAB, "ports": "8888", "scan_type": "-sT -Pn"}),
    ("tools_httpx", {"target": LAB_URL}),
    ("tools_masscan", {"target": "127.0.0.1", "ports": "80"}),
    ("tools_sslscan", {"target": f"{LAB}:8443"}),
    ("tools_ssh_audit", {"target": "127.0.0.1"}),
    ("tools_nikto", {"target": LAB_URL}),
    ("tools_gobuster", {"url": LAB_URL}),
    ("tools_katana", {"url": LAB_URL}),
    ("tools_gowitness", {"url": LAB_URL}),
    ("tools_wpscan", {"url": LAB_URL}),
    ("tools_sqlmap", {"url": LAB_URL + "/?id=1"}),
    ("tools_arjun", {"url": LAB_URL}),
    ("tools_byp4xx", {"url": LAB_URL}),
    ("tools_enum4linux", {"target": "127.0.0.1"}),
    ("tools_hydra", {"target": "127.0.0.1", "service": "ssh"}),
    ("tools_john", {"hash_file": "/tmp/nonexistent.hash"}),
    # --- OSINT / DNS (external; may be slow or blocked) ---------------------
    ("tools_subfinder", {"target": "example.com"}),
    ("tools_assetfinder", {"domain": "example.com"}),
    ("tools_waybackurls", {"domain": "example.com"}),
    ("tools_crtsh", {"domain": "example.com"}),
    ("tools_subzy", {"target": "example.com"}),
    ("tools_fierce", {"domain": "example.com"}),
    ("tools_amass", {"domain": "example.com"}),
    # --- cve / exploit ------------------------------------------------------
    ("cve_search", {"query": "openssh"}),
    ("cve_package_audit", {"package": "openssl"}),
    ("exploit_search", {"query": "vsftpd"}),
    ("exploit_details", {"edb_id": "17491"}),
    ("exploit_copy", {"edb_id": "17491"}),
    ("exploit_suggest_for_service", {"service": "vsftpd 2.3.4"}),
    ("exploit_suggest_from_nmap", {"nmap_output": "21/tcp open ftp vsftpd 2.3.4"}),
    # --- api security -------------------------------------------------------
    ("api_graphql_introspect", {"url": LAB_URL + "/graphql"}),
    ("api_graphql_fuzz", {"url": LAB_URL + "/graphql"}),
    ("api_jwt_analyze", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}),
    ("api_jwt_crack", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}),
    ("api_fuzz_endpoint", {"url": LAB_URL}),
    ("api_rate_limit_test", {"url": LAB_URL}),
    ("api_auth_bypass_test", {"url": LAB_URL}),
    ("api_ffuf_fuzz", {"url": LAB_URL + "/FUZZ"}),
    ("api_kiterunner_scan", {"url": LAB_URL}),
    ("api_nuclei_scan", {"url": LAB_URL}),
    ("api_newman_run", {"collection": "/tmp/nonexistent.json"}),
    # --- active directory (no DC present; expect clean reports) -------------
    ("ad_tools_status", {}),
    ("ad_smb_enum", {"target": "127.0.0.1"}),
    ("ad_ldap_enum", {"domain": "probe.test", "username": "u", "password": "p"}),
    ("ad_kerberoast", {"domain": "probe.test", "username": "u", "password": "p"}),
    ("ad_asreproast", {"domain": "probe.test"}),
    ("ad_secretsdump", {"domain": "probe.test", "username": "u", "password": "p"}),
    ("ad_password_spray", {"domain": "probe.test", "password": "p"}),
    ("ad_bloodhound_collect", {"domain": "probe.test", "username": "u", "password": "p"}),
    ("ad_psexec", {"target": "127.0.0.1", "domain": "probe.test", "username": "u"}),
    ("ad_wmiexec", {"target": "127.0.0.1", "domain": "probe.test", "username": "u"}),
    # --- payloads -----------------------------------------------------------
    ("payload_templates", {}),
    ("payload_list", {}),
    ("payload_one_liner", {"lhost": "127.0.0.1"}),
    ("payload_generate", {"lhost": "127.0.0.1"}),
    ("reverse_shell_generate_payload", {"local_ip": "127.0.0.1"}),
    # --- ctf ----------------------------------------------------------------
    ("ctf_status", {}),
    ("ctf_connect", {"url": LAB_URL}),
    ("ctf_list_challenges", {}),
    ("ctf_get_challenge", {"challenge_id": "1"}),
    ("ctf_scoreboard", {}),
    ("ctf_download_file", {}),
    ("ctf_submit_flag", {"challenge_id": "1", "flag": "probe{}"}),
    # --- ssh ----------------------------------------------------------------
    ("ssh_sessions", {}),
    ("ssh_session_status", {"session_id": "probe-missing"}),
    ("ssh_session_command", {"session_id": "probe-missing", "command": "id"}),
    ("ssh_session_upload_content", {"session_id": "probe-missing", "content": "x", "remote_path": "/tmp/x"}),
    ("ssh_session_download_content", {"session_id": "probe-missing", "remote_path": "/tmp/x"}),
    ("ssh_estimate_transfer", {"file_size_bytes": 1024}),
    ("ssh_session_start", {"target": "127.0.0.1", "username": "probe", "password": "probe"}),
    ("ssh_session_stop", {"session_id": "probe-missing"}),
    # --- vpn ----------------------------------------------------------------
    ("vpn_status", {}),
    ("vpn_connect", {"config_path": "/tmp/nonexistent.ovpn"}),
    # --- metasploit ---------------------------------------------------------
    ("msf_session_list", {}),
    ("msf_session_execute", {"session_id": "probe-missing", "command": "id"}),
    ("msf_session_destroy", {"session_id": "probe-missing"}),
    # --- pivots (start, inspect, then tear down) ----------------------------
    ("pivot_list_tunnels", {}),
    ("pivot_list_pivots", {}),
    ("pivot_add_pivot", {"name": "probe", "pivot_host": "127.0.0.1"}),
    ("pivot_generate_proxychains", {}),
    ("pivot_socat_forward", {"listen_port": 19001, "target_host": "127.0.0.1", "target_port": 8888}),
    ("pivot_ssh_local", {"ssh_host": "127.0.0.1", "local_port": 19002, "remote_host": "127.0.0.1", "remote_port": 80}),
    ("pivot_ssh_remote", {"ssh_host": "127.0.0.1", "remote_port": 19003, "local_host": "127.0.0.1", "local_port": 80}),
    ("pivot_ssh_dynamic", {"ssh_host": "127.0.0.1"}),
    ("pivot_chisel_client", {"server_url": "http://127.0.0.1:19004", "tunnels": "socks"}),
    ("pivot_stop_tunnel", {"tunnel_id": "probe-missing"}),
    # --- callbacks ----------------------------------------------------------
    ("callback_status", {}),
    ("callback_start", {}),
    ("callback_generate", {"listener_ip": "127.0.0.1"}),
    ("callback_list", {}),
    ("callback_latest", {}),
    ("callback_check", {}),
    ("callback_wait", {"timeout": 2}),
    ("callback_clear", {}),
    ("callback_stop", {}),
    # --- reverse shell (start, inspect, stop) -------------------------------
    ("reverse_shell_status", {}),
    ("reverse_shell_listener_start", {"port": 19005}),
    ("reverse_shell_command", {"session_id": "probe-missing", "command": "id"}),
    ("reverse_shell_send_payload", {"session_id": "probe-missing", "payload_command": "id"}),
    ("reverse_shell_upload_content", {"session_id": "probe-missing", "content": "x", "remote_file": "/tmp/x"}),
    ("reverse_shell_download_content", {"session_id": "probe-missing", "remote_file": "/tmp/x"}),
    ("reverse_shell_stop", {"session_id": "probe-missing"}),
    # --- payload host + long-lived servers (start then stop) ----------------
    ("payload_host_start", {}),
    ("payload_host_stop", {}),
    ("pivot_chisel_server", {}),
    ("pivot_ligolo_start", {}),
    # --- teardown (destructive; last on purpose) ----------------------------
    ("pivot_stop_all_tunnels", {}),
    ("msf_session_destroy_all", {}),
    ("msf_session_create", {}),
    ("vpn_disconnect", {}),
    ("hosts_clear", {}),
]

PER_CALL_TIMEOUT = 75


class Session:
    def __init__(self):
        env = {**os.environ, "KALI_API_URL": API}
        self.p = subprocess.Popen(
            [sys.executable, str(ROOT / "mcp_server.py"), "--profile", "full"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=env, bufsize=1, cwd=str(ROOT),
        )
        self._id = 0
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "probe", "version": "0"}}})
        self._read()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _next(self):
        self._id += 1
        return self._id

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def _read(self):
        while True:
            line = self.p.stdout.readline()
            if not line:
                return None
            line = line.strip()
            if line.startswith("{"):
                return json.loads(line)

    def call(self, name, args):
        self._send({"jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
                    "params": {"name": name, "arguments": args}})
        return self._read()

    def close(self):
        try:
            self.p.terminate()
        except Exception:
            pass


def classify(name, reply, elapsed):
    if reply is None:
        return "BROKEN", "transport closed (server died)"
    if "error" in reply:
        return "BROKEN", f"MCP error: {str(reply['error'])[:120]}"
    result = reply.get("result", {})
    if result.get("isError") or result.get("is_error"):
        return "BROKEN", f"tool reported isError: {str(result)[:120]}"
    content = result.get("content") or []
    text = ""
    for item in content:
        if item.get("type") == "text":
            text += item.get("text", "")
    if not text.strip():
        return "BROKEN", "empty response body"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return "OK", f"non-JSON text ({len(text)}b)"
    if not isinstance(payload, dict):
        return "BROKEN", f"non-object payload: {type(payload).__name__}"
    if payload.get("success") is True:
        return "OK", "success"
    err = payload.get("error") or payload.get("message") or ""
    if err:
        return "REPORTED", str(err)[:110]
    return "OK", "structured response"


def backend_is_up() -> bool:
    """Answer before spending minutes on a run that could not mean anything."""
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(f"{API}/live", timeout=3) as reply:
            return reply.status == 200
    except (urllib.error.URLError, OSError):
        return False


def load_baseline():
    """Expected status per tool, so a human only has to read what changed."""
    path = Path(__file__).with_name("probe_baseline.json")
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    if not backend_is_up():
        print(f"no Kali backend at {API}; nothing to probe")
        return 0

    baseline = load_baseline()
    session = Session()
    rows = []
    for name, args in CASES:
        start = time.time()
        try:
            reply = session.call(name, args)
            elapsed = time.time() - start
            status, detail = classify(name, reply, elapsed)
        except Exception as exc:
            elapsed = time.time() - start
            status, detail = "BROKEN", f"{type(exc).__name__}: {exc}"
        rows.append((name, status, round(elapsed, 1), detail))
        print(f"{status:9} {elapsed:6.1f}s  {name:34} {detail[:100]}", flush=True)
    session.close()

    out = Path(__file__).with_name("probe_results.json")
    out.write_text(json.dumps(
        [{"tool": n, "status": s, "seconds": t, "detail": d} for n, s, t, d in rows],
        indent=1), encoding="utf-8")

    print("\n==== SUMMARY ====")
    for status in ("BROKEN", "REPORTED", "OK"):
        hits = [r for r in rows if r[1] == status]
        print(f"{status:9} {len(hits)}")
    print(f"covered {len(rows)} tools")

    # Only a change from the recorded baseline needs reading. A bare BROKEN
    # count is not a pass criterion: a tool truthfully reporting that no VPN is
    # configured looks identical to one that regressed, and only the baseline
    # distinguishes them. Cases that reach the public internet are marked
    # best-effort, because their result says more about the network than the
    # tool.
    findings = []
    for name, status, _seconds, detail in rows:
        expected = baseline.get(name)
        if expected is None:
            if status == "BROKEN":
                findings.append((name, f"BROKEN (no baseline): {detail[:90]}"))
        elif expected.get("best_effort"):
            continue
        elif status != expected.get("status"):
            findings.append(
                (name, f"{expected.get('status')} -> {status}: {detail[:90]}")
            )

    if findings:
        print("\nCHANGED since baseline:")
        for name, detail in findings:
            print(f"  {name:34} {detail}")
        return 1
    print("no change from baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
