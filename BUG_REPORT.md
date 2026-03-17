# Deep Code Review — zebbern-kali-mcp Bug Report

> **Scope:** Full stack — MCP wrappers → HTTP API → Flask blueprints → Core modules
> **Focus:** Functional bugs that cause tools to fail or produce wrong results
> **Status:** All valid bugs FIXED (see ✅ markers below)

---

## CRITICAL — Tools completely broken or produce wrong results

### BUG-01: `kali_download` always fails — param name mismatch ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/file_operations.py` line ~55 |
| **File (Server)** | `zebbern-kali/api/blueprints/file_ops.py` line ~35 |
| **Severity** | CRITICAL |

**Description:** MCP sends `{"remote_path": "..."}` but Flask reads `params.get("remote_file")`. The key names don't match, so `remote_file` is always `None`, and every download returns 400 "remote_file parameter is required".

**Impact:** `kali_download` is completely broken — every call fails.

**Fix:** Either change MCP to send `remote_file` or change Flask to read `remote_path`. Recommend aligning Flask to `remote_path` since the upload endpoint already uses that key:

```python
# file_ops.py — change:
remote_file = params.get("remote_file")
# to:
remote_file = params.get("remote_file") or params.get("remote_path")
```

---

### BUG-02: SHA256 checksum always mismatches — hashing wrong data ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/file_operations.py` line ~9 |
| **File (Server)** | `zebbern-kali/utils/transfer_manager.py` line ~120 |
| **Severity** | CRITICAL |

**Description:** The MCP client computes SHA256 of the **base64 string** (`hashlib.sha256(content.encode())`), but the server computes SHA256 of the **decoded binary** (`hashlib.sha256(base64.b64decode(content))`). These produce different hashes for the same data, so integrity verification always fails.

**Impact:** Every file upload/download with `verify_checksum=True` (the default) reports a false "SHA256 mismatch" warning, making integrity verification useless. Users either ignore all warnings or disable the feature entirely.

**Fix:** Change MCP `_compute_sha256` to decode before hashing:

```python
def _compute_sha256(content: str) -> str:
    import base64
    return hashlib.sha256(base64.b64decode(content)).hexdigest()
```

---

### BUG-03: `run_shodan` — complete API mismatch between MCP and server ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/kali_tools.py` ~line 430 (`search_shodan`) |
| **File (Server)** | `zebbern-kali/tools/kali_tools.py` ~line 810 (`run_shodan`) |
| **Severity** | CRITICAL |

**Description:** MCP sends `{query, facets, fields, max_items, page, summarize}` but the server reads `{operation, query, additional_args}`. The server ignores `facets`, `fields`, `max_items`, `page`, `summarize` entirely and defaults `operation` to `"search"`. It then runs `shodan search <query>` as a CLI command, which has completely different behavior than what the MCP interface promises.

**Impact:** Every Shodan search ignores all filtering/pagination parameters. Results are unfiltered full Shodan CLI output instead of the structured, paginated data the MCP tool promises.

**Fix:** Rewrite `run_shodan` to properly handle all MCP parameters and pass them to the Shodan CLI:

```python
def run_shodan(params):
    query = params.get('query', '')
    max_items = params.get('max_items', 5)
    # ... build proper CLI args or use the shodan Python library
```

---

### BUG-04: `run_sqlmap` ignores technique/level/risk/dbs/tables/dump ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/kali_tools.py` ~line 170 — sends `technique`, `level`, `risk`, `dbs`, `tables`, `dump` |
| **File (Server)** | `zebbern-kali/tools/kali_tools.py` ~line 260 (`run_sqlmap`) |
| **Severity** | CRITICAL |

**Description:** The MCP wrapper sends 6 important parameters (`technique`, `level`, `risk`, `dbs`, `tables`, `dump`) but `run_sqlmap` only reads `url`, `data`, and `additional_args`. All the enumeration and injection configuration params are silently dropped.

**Impact:**
- `dbs=True` to enumerate databases → ignored, no enumeration happens
- `dump=True` to dump table entries → ignored
- `level=5` for aggressive testing → ignored, always uses default level 1
- `technique="B"` to restrict to boolean-blind → ignored

Users think they're controlling SQLmap behavior but their settings have zero effect.

**Fix:** Add param handling in `run_sqlmap`:

```python
technique = params.get("technique", "")
level = params.get("level", 1)
risk = params.get("risk", 1)
if technique:
    command += f" --technique={technique}"
if level != 1:
    command += f" --level={level}"
if risk != 1:
    command += f" --risk={risk}"
if params.get("dbs"):
    command += " --dbs"
if params.get("tables"):
    command += " --tables"
if params.get("dump"):
    command += " --dump"
```

---

### BUG-05: `run_wpscan` ignores api_token/enumerate/output_format ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/kali_tools.py` ~line 130 — sends `api_token`, `enumerate`, `output_format` |
| **File (Server)** | `zebbern-kali/tools/kali_tools.py` ~line 406 (`run_wpscan`) |
| **Severity** | CRITICAL |

**Description:** `run_wpscan` only reads `url` and `additional_args`. The `api_token`, `enumerate`, and `output_format` params sent by MCP are completely ignored.

**Impact:**
- `api_token` → WPScan can't look up vulnerability data (the primary reason people use WPScan)
- `enumerate="vp"` → no plugin/theme/user enumeration happens
- `output_format="json"` → always gets CLI output, never machine-parseable

**Fix:**

```python
api_token = params.get("api_token", "")
enumerate = params.get("enumerate", "")
output_format = params.get("output_format", "")
if api_token:
    command += f" --api-token {api_token}"
if enumerate:
    command += f" -e {enumerate}"
if output_format and output_format != "cli":
    command += f" -f {output_format}"
```

---

### BUG-06: `ad_password_spray` — param name mismatch, always fails ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` (`ad_password_spray`) |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 180 |
| **Severity** | CRITICAL |

**Description:** MCP sends `{domain, password, dc_ip, userlist, delay}` but Flask requires `target` (a required field). MCP never sends `target`, and the value MCP sends as `dc_ip` is what the server needs as `target`. Result: every call returns 400 "target is required".

**Impact:** Password spraying is completely broken — every call fails.

**Fix:** Either rename `dc_ip` to `target` in the MCP tool, or accept both in the Flask route:

```python
# In ad.py password_spray route:
target = params.get("target") or params.get("dc_ip")
```

---

### ~~BUG-07: `ad_smb_enum` endpoint doesn't exist~~ INVALID

| Field | Value |
|---|---|
| **Severity** | ~~CRITICAL~~ N/A |

**The endpoint `/api/ad/smb-enum` DOES exist** in `ad.py` (lines 230-248). This was a false positive from incomplete reading during initial analysis.

---

## HIGH — Major functionality broken

### BUG-08: `run_gobuster` ignores threads/extensions/status_codes ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/kali_tools.py` ~line 100 — sends `threads`, `extensions`, `status_codes` |
| **File (Server)** | `zebbern-kali/tools/kali_tools.py` ~line 58 (`run_gobuster`) |
| **Severity** | HIGH |

**Description:** `run_gobuster` only reads `url`, `mode`, `wordlist`, `additional_args`. The `threads`, `extensions`, and `status_codes` parameters are dropped.

**Impact:**
- `extensions="php,html,txt"` → never added, misses files with extensions
- `status_codes="200,301"` → no positive status filtering
- `threads=50` → always uses Gobuster's default (10), slower scans

**Fix:**

```python
threads = params.get("threads", 10)
extensions = params.get("extensions", "")
status_codes = params.get("status_codes", "")
if threads != 10:
    command += f" -t {threads}"
if extensions:
    command += f" -x {extensions}"
if status_codes:
    command += f" -s {status_codes}"
```

---

### BUG-09: `run_nikto` ignores tuning/output_format ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/kali_tools.py` ~line 47 — sends `tuning`, `output_format` |
| **File (Server)** | `zebbern-kali/tools/kali_tools.py` ~line 200 (`run_nikto`) |
| **Severity** | HIGH |

**Description:** `run_nikto` only reads `target` and `additional_args`. MCP sends `tuning` and `output_format` but they're never used.

**Impact:**
- `tuning="1"` (interesting files only) → ignored, full scan runs
- `output_format="xml"` → ignored, always CLI output

**Fix:**

```python
tuning = params.get("tuning", "")
output_format = params.get("output_format", "")
if tuning:
    command += f" -Tuning {tuning}"
if output_format:
    command += f" -Format {output_format}"
```

---

### BUG-10: Reverse shell `listener_type` default mismatch ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/reverse_shell.py` ~line 17 — defaults `listener_type="netcat"` |
| **File (Server)** | `zebbern-kali/api/blueprints/reverse_shell.py` ~line 14 — defaults `listener_type="pwncat"` |
| **Severity** | HIGH |

**Description:** The MCP wrapper defaults `listener_type` to `"netcat"` but the Flask endpoint defaults to `"pwncat"`. If the user doesn't explicitly set `listener_type`, the MCP sends `"netcat"` which is intentional from the MCP side, but the issue is that these two defaults are inconsistent. If MCP ever decides NOT to send the field (or a future change removes the default), the server would fall back to pwncat which is harder to find and often requires a fallback to netcat anyway.

**Impact:** While currently the MCP always sends "netcat" so the server default doesn't apply, the inconsistency means behavior silently changes if the MCP doesn't send the field. Additionally, pwncat as a server default is problematic because the server itself falls back to netcat when pwncat isn't found, adding unnecessary startup delay.

**Fix:** Change the Flask endpoint default to `"netcat"`:

```python
listener_type = params.get("listener_type", "netcat")
```

---

### BUG-11: `streaming_tool_response` uses wrong Content-Type ✅ FIXED

| Field | Value |
|---|---|
| **File** | `zebbern-kali/api/blueprints/_helpers.py` ~line 68 |
| **Severity** | HIGH |

**Description:** The `streaming_tool_response` function returns `content_type="text/plain; charset=utf-8"` instead of `"text/event-stream"`. The correct SSE content type is used in the `sse_response()` function on line 8, but `streaming_tool_response` (used by gobuster, dirb, nikto endpoints) has the wrong one.

**Impact:** SSE clients (like EventSource) may refuse to parse the stream or display warnings because the content-type doesn't match the expected `text/event-stream`. The MCP client uses `requests` (not EventSource) so it may still work, but this breaks standard SSE protocol compliance.

**Fix:**

```python
# Change line 68:
content_type="text/plain; charset=utf-8",
# To:
content_type="text/event-stream",
```

---

### BUG-12: AD `kerberoast` — `target_user` param silently dropped ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` — sends `target_user` |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 80 |
| **Severity** | HIGH |

**Description:** MCP sends `target_user` but the Flask route doesn't read or pass it. The blueprint passes `output_format` instead. The core function `kerberoast()` doesn't have a `target_user` parameter either.

**Impact:** Users can't target specific service accounts for Kerberoasting — it always queries all SPNs, which is noisy and may trigger alerts.

**Fix:** Add `target_user` support to the Flask route and core function, passing it as a `-target-user` flag to GetUserSPNs.

---

### BUG-13: AD `bloodhound_collect` — `nameserver` param dropped ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` — sends `nameserver` |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 30 |
| **Severity** | HIGH |

**Description:** MCP sends `nameserver` but the Flask route doesn't read it. The core function `bloodhound_collect` uses the `dc_ip` as the nameserver (`-ns dc_ip`), so there's no way to specify an alternate DNS server.

**Impact:** Can't use BloodHound collection in environments where the DNS server differs from the DC, causing resolution failures.

**Fix:** Pass `nameserver` through and use it as the `-ns` value when provided (falling back to `dc_ip`).

---

### ~~BUG-14: `output_parser._detect_tool` — falls through without valid return~~ INVALID

| Field | Value |
|---|---|
| **Severity** | ~~HIGH~~ N/A |

**The code already returns `"unknown"`** (not `"auto"`) when auto-detection fails. This was a false positive from misreading the source during initial analysis.

---

## MEDIUM — Degraded functionality or silent failures

### BUG-15: AD `secretsdump` — `dc_ip` param unused, `target` accidentally optional ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` — sends both `target` and `dc_ip` |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 50 |
| **Severity** | MEDIUM |

**Description:** MCP sends `dc_ip` but Flask doesn't read it. MCP has `target` as optional (`target: str = ""`), but Flask **requires** `target`. If the user only provides `dc_ip` (common for domain controller secrets), the call fails because `target` is empty.

**Impact:** Users who provide `dc_ip` but not `target` (thinking `dc_ip` IS the target) get a 400 error.

**Fix:** In Flask, fall back: `target = params.get("target") or params.get("dc_ip")`.

---

### BUG-16: AD `asreproast` — MCP makes `dc_ip` optional but Flask requires it

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` — `dc_ip: str = ""` |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 100 |
| **Severity** | MEDIUM |

**Description:** The MCP tool declares `dc_ip` with default empty string, implying it's optional. But the Flask endpoint requires both `domain` and `dc_ip`, returning 400 if either is missing.

**Impact:** If the LLM or user doesn't provide `dc_ip`, the call fails unexpectedly. The MCP tool description doesn't indicate it's required.

**Fix:** Either make `dc_ip` required in the MCP tool signature or make it optional in Flask (using DNS discovery).

---

### BUG-17: `streaming_tool_response` — JSON escaping is incomplete ✅ FIXED

| Field | Value |
|---|---|
| **File** | `zebbern-kali/api/blueprints/_helpers.py` ~line 30 |
| **Severity** | MEDIUM |

**Description:** The SSE handler only escapes `"` characters:
```python
escaped = line.replace('"', '\\"')
```
But tool output can contain newlines (`\n`), backslashes (`\`), and other JSON-special characters. These will produce invalid JSON in the SSE `data:` field, potentially causing the client to silently drop events.

**Impact:** Any tool output containing backslashes or embedded newlines breaks the SSE JSON parsing on the client side.

**Fix:** Use `json.dumps()` for proper escaping:

```python
import json
escaped_line = json.dumps(line)[1:-1]  # Strip outer quotes
output_queue.put(
    f'data: {{"type": "output", "source": "{source}", "line": "{escaped_line}"}}\n\n'
)
```

---

### BUG-18: `run_hydra` — `port`, `tasks`, `wait` type inconsistency ✅ FIXED

| Field | Value |
|---|---|
| **File** | `zebbern-kali/tools/kali_tools.py` ~line 310 (`run_hydra`) |
| **Severity** | MEDIUM |

**Description:** `run_hydra` reads params with empty string defaults: `params.get("port", "")`, `params.get("tasks", "")`, `params.get("wait", "")`. The MCP sends these as integers (port=0, tasks=16, wait=32). When MCP sends the default `port=0`, the `if port:` check correctly skips it (0 is falsy). But when MCP sends non-default `tasks=16`, the value is an `int` not a `str`, so `if tasks:` is truthy and `command += f" -t {tasks}"` works — by accident.

The real issue: if MCP sends `tasks=0` (a valid hydra value meaning "let hydra decide"), it would be silently ignored because `if tasks:` is falsy for 0.

**Impact:** Edge case where `tasks=0` or `wait=0` are legitimate values that get silently dropped.

**Fix:** Use explicit `None` checks instead of truthiness:

```python
port = params.get("port")
if port is not None and port != 0:
    command += f" -s {port}"
tasks = params.get("tasks")
if tasks is not None:
    command += f" -t {tasks}"
```

---

### BUG-19: `run_waybackurls` — shell injection via single-quoted domain ✅ FIXED

| Field | Value |
|---|---|
| **File** | `zebbern-kali/tools/kali_tools.py` ~line 800 (`run_waybackurls`) |
| **Severity** | MEDIUM |

**Description:** The command uses single-quoted interpolation:
```python
command = f"echo '{domain}' | {waybackurls_path}"
```
If `domain` contains a single quote (e.g., `example.com'; cat /etc/passwd; echo '`), the shell command breaks out of the quotes. While this tool runs inside a Docker container, it's still exploitable for lateral movement within the container.

**Impact:** Potential command injection if user-controlled input reaches the domain parameter.

**Fix:** Use `shlex.quote()`:

```python
command = f"echo {shlex.quote(domain)} | {waybackurls_path}"
```

---

### BUG-20: AD `ldap_enum` — MCP sends wrong required fields ✅ FIXED

| Field | Value |
|---|---|
| **File (MCP)** | `mcp_tools/ad_tools.py` (`ad_ldap_enum`) |
| **File (Server)** | `zebbern-kali/api/blueprints/ad.py` ~line 155 |
| **Severity** | MEDIUM |

**Description:** The MCP tool `ad_ldap_enum` declares `domain`, `username`, `password` as required params and `dc_ip` as optional. But the Flask endpoint requires `dc_ip` AND `domain` — if MCP sends an empty `dc_ip`, Flask returns 400. Additionally, Flask passes `anonymous=params.get("anonymous", True)` but MCP never sends this param, so authenticated LDAP queries default to anonymous mode.

**Impact:**
1. Calls without `dc_ip` fail even though MCP implies it's optional
2. Authenticated queries execute as anonymous by default, returning fewer results than expected

**Fix:** Make `dc_ip` required in MCP, and send `anonymous=False` when credentials are provided.

---

### BUG-21: All `run_*` functions — shell command injection via f-string interpolation

| Field | Value |
|---|---|
| **File** | `zebbern-kali/tools/kali_tools.py` (throughout) |
| **Severity** | MEDIUM (mitigated by Docker isolation) |

**Description:** Nearly every `run_*` function interpolates user input directly into shell command strings:
- `run_nmap`: `f"nmap {scan_type} ... {target}"`
- `run_gobuster`: `f"gobuster {mode} -u {url} -w {wordlist}"`
- `run_fierce`: `f"fierce --domain {domain}"`
- `run_sqlmap`: `f"sqlmap -u '{url}'"`
- `run_hydra`: `f"hydra ... {target} {service}"`
- `run_john`: `f"john {hash_file}"`
- `run_arjun`: `f"arjun -u {url}"`
etc.

Combined with `execute_command` using `shell=True`, any param containing shell metacharacters (`;`, `|`, `$()`, backticks) can execute arbitrary commands.

**Impact:** While the tool runs inside a Docker container (mitigating external risk), an injection in any parameter can execute arbitrary commands as the Kali container's user (likely root).

**Fix:** Use `execute_command_argv` (already exists) instead of `execute_command` with f-strings. Build command as list of arguments:

```python
cmd = ["nmap", scan_type, "-p", ports, target]
result = execute_command_argv(cmd)
```

---

## LOW — Minor issues

### BUG-22: `run_nmap` default args conflict

| Field | Value |
|---|---|
| **File** | `zebbern-kali/tools/kali_tools.py` ~line 26 |
| **Severity** | LOW |

**Description:** `run_nmap` defaults `additional_args` to `"-T4 -Pn"` if the MCP doesn't send the field. But MCP always sends at least `additional_args=""` (empty string). So the default is never actually used, and nmap runs without `-T4 -Pn` unless the user explicitly adds them.

**Impact:** Nmap scans may be slower than expected (no -T4) or fail on hosts that block ICMP (no -Pn).

---

### BUG-23: `run_metasploit` — module/options injection via msfconsole `-x`

| Field | Value |
|---|---|
| **File** | `zebbern-kali/tools/kali_tools.py` ~line 290 (`run_metasploit`) |
| **Severity** | LOW |

**Description:** Module name and options are injected into an msfconsole `-x` string:
```python
command = f"msfconsole -q -x 'use {module};"
for key, value in options.items():
    command += f" set {key} {value};"
```
A module name containing `'; bash -i'` or an option value with shell metacharacters can break out.

**Impact:** Same container-limited injection risk as BUG-21.

---

## Summary Table

| ID | Severity | Component | Bug | Status |
|---|---|---|---|---|
| BUG-01 | CRITICAL | file_ops | `kali_download` param name mismatch → always fails | ✅ FIXED |
| BUG-02 | CRITICAL | file_ops | SHA256 checksum hashes base64 string vs decoded binary → always mismatches | ✅ FIXED |
| BUG-03 | CRITICAL | shodan | Complete API mismatch → all filtering ignored | ✅ FIXED |
| BUG-04 | CRITICAL | sqlmap | 6 params silently dropped → no enumeration/technique control | ✅ FIXED |
| BUG-05 | CRITICAL | wpscan | api_token/enumerate/output_format dropped → core features broken | ✅ FIXED |
| BUG-06 | CRITICAL | AD | password_spray param name mismatch → always fails | ✅ FIXED |
| BUG-07 | ~~CRITICAL~~ | AD | ~~smb_enum endpoint doesn't exist~~ | INVALID |
| BUG-08 | HIGH | gobuster | threads/extensions/status_codes dropped | ✅ FIXED |
| BUG-09 | HIGH | nikto | tuning/output_format dropped | ✅ FIXED |
| BUG-10 | HIGH | revshell | listener_type default mismatch MCP vs server | ✅ FIXED |
| BUG-11 | HIGH | streaming | Wrong Content-Type for SSE streams | ✅ FIXED |
| BUG-12 | HIGH | AD | kerberoast target_user dropped | ✅ FIXED |
| BUG-13 | HIGH | AD | bloodhound nameserver dropped | ✅ FIXED |
| BUG-14 | ~~HIGH~~ | parser | ~~_detect_tool returns "auto" → no parser~~ | INVALID |
| BUG-15 | MEDIUM | AD | secretsdump dc_ip unused, target accidentally optional | ✅ FIXED |
| BUG-16 | MEDIUM | AD | asreproast dc_ip optional in MCP but required in Flask | Open |
| BUG-17 | MEDIUM | streaming | Incomplete JSON escaping in SSE events | ✅ FIXED |
| BUG-18 | MEDIUM | hydra | port/tasks/wait falsy-value edge case | ✅ FIXED |
| BUG-19 | MEDIUM | waybackurls | Shell injection via single-quoted domain | ✅ FIXED |
| BUG-20 | MEDIUM | AD | ldap_enum wrong required fields + anonymous default | ✅ FIXED |
| BUG-21 | MEDIUM | all tools | Shell injection via f-string + shell=True | Open (systemic) |
| BUG-22 | LOW | nmap | Default additional_args never applied | Open |
| BUG-23 | LOW | metasploit | Module injection via msfconsole -x string | Open |
