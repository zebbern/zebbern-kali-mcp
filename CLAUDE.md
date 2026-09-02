# CLAUDE.md

Operational notes for this repo. Everything here is a mistake that has actually
been made, not general advice.

## Two release tracks, and they are not the same

The wheel ships **only** `mcp_server.py` and `mcp_tools/*` (`pyproject.toml`
`py-modules` / `packages.find`). Everything under `zebbern-kali/` ships in the
**Docker image** instead, and reaches users when `docker-publish.yml` rebuilds
— not when you publish to PyPI.

Before proposing a release, check which track the change is on:

```bash
git diff --name-only <last-tag>..main
```

A change under `zebbern-kali/` does not justify a PyPI bump, and a PyPI release
does not deliver it. This has been misread once already — a proposed release
turned out to contain nothing but a comment.

## The local backend image goes stale silently

`ghcr.io/zebbern/zebbern-kali-mcp:latest` moves on every `docker-publish` run,
which triggers on any push to `main` touching `Dockerfile`, `.dockerignore`,
`docker/**`, `docker-compose*.yml`, `entrypoint.sh`, `requirements.txt` or
`zebbern-kali/**`. A local copy
pulled earlier keeps serving, and the symptoms never look like staleness:

- container reports `unhealthy` (an old image predating the `/live` route)
- `/health` reports an old `version`
- tests pass against bits nobody ships

```bash
docker compose pull && docker compose up -d --force-recreate
docker buildx imagetools inspect ghcr.io/zebbern/zebbern-kali-mcp:latest   # remote
docker image inspect ghcr.io/zebbern/zebbern-kali-mcp:latest --format '{{index .RepoDigests 0}}'
```

Compare those two digests before trusting anything the backend says. This has
happened three times.

## Targeting the host from inside the container

Inside the container `127.0.0.1` is the **container's own loopback**. The host
(and anything published on it, e.g. a crAPI lab on 8888) is reachable as
`host.docker.internal`. Scanning `127.0.0.1` finds an empty container and looks
exactly like a broken MCP server.

Services on another compose network that are not host-published (crAPI's
`crapi-identity:8080`, `crapi-community:6060`) need the Kali container attached
to that network.

## Releasing

`publish.yml` is `workflow_dispatch` on `main` only. `validate-input` runs
`verify_release_artifacts.py declared-version` and refuses if the dispatched
version differs from `pyproject.toml`.

1. Bump **two** files: `pyproject.toml` and `zebbern-kali/core/config.py`.
   Everything else derives. `test_backend_version_tracks_pyproject` fails if
   only one is touched — that guard exists because they used to drift by hand.
   `config.py` must keep a **literal** VERSION: `pyproject.toml` is excluded
   from the image by `.dockerignore` and the backend runs from source, so
   deriving it would break `/health` at container startup.
2. Re-pin the integration gate digest (see below) if the image changed.
3. Dry-run the gate: `gh workflow run integration.yml --ref main`.
4. `gh workflow run publish.yml --ref main -f version=X.Y.Z`
5. Tag afterwards: `git tag -a vX.Y.Z <commit> && git push origin vX.Y.Z`.
   Tags for 1.0.2–1.0.4 had to be backfilled because this step was skipped.

**PyPI index lag is normal.** For a few minutes after publish, the JSON API and
`uvx --from pkg==X.Y.Z` will claim the version does not exist. The
`post-publish-verify` job matching filenames and SHA-256s is authoritative;
`https://pypi.org/simple/zebbern-kali-mcp/` updates before the JSON API.

## The integration gate pins a digest — re-pin it

`.github/workflows/integration.yml` `env.IMAGE` is an immutable `@sha256:`
digest, and `publish.yml` has `needs: [gate, integration]`, so no release ships
without real tools executing.

Nothing keeps that pin in step with `:latest`. It drifted three builds within
hours of being introduced. Re-pin as a release step, and pin a digest you have
**actually booted**, not one you only looked up.

The digest is also passed to compose as `ZKM_IMAGE`, because a digest pull
leaves no local tag — without it, `docker compose up` would miss `:latest` and
rebuild from the Dockerfile, far exceeding the job timeout.

## Verify published packages from a clean cwd

`uvx --from pkg==X python -c "import mcp_tools..."` run **inside this repo**
imports the local source, not the installed package, and will happily confirm a
fix that was never published. Run it from somewhere else and assert on
`site-packages` in `__file__`. This produced a false positive once.

## Windows: the backend cannot be imported

`kali_server.py` and `api.routes` pull in `metasploit_manager` → `pty` →
`termios`, which do not exist on Windows. Import-safe modules: `api/auth.py`,
`mcp_tools/*`. For anything else, either load the module by path
(`importlib.util.spec_from_file_location`) or assert on the **source text** —
both patterns are already used in `tests/`.

## Timeouts and truncation

A timeout here is a backstop for a **hung** process, not a budget for a slow
one. A four-hour scan is the workload, not a bug.

**Which layer binds first.** Four independent deadlines stack on one synchronous
tool call, and the smallest wins:

```
mcp_server --timeout  ->  mcp_tools/_client.py  DEFAULT_REQUEST_TIMEOUT (90000)
                          requests read timeout, connect stays 10s
api/blueprints/*      ->  the route's own params.get("timeout", N)
core/tool_config.py   ->  TOOL_TIMEOUTS[tool], default 3600, max 86400
core/command_executor ->  subprocess wait
```

**There is a fifth deadline, it is the smallest, and it is not in that list:
the MCP harness abandons a tool call at roughly 60 seconds.** It sits above
every layer above and outside this repo, so nothing here raises it. Measured: a
synchronous `zebbern_exec` sleeping 310s came back as a harness-level
`Error: Request timed out` — not our client's
`{"error": "Request failed: ReadTimeout"}` — while the container process was
still alive at 110s. `exec_stream` does not evade it; SSE runs between our
client and the backend and the harness only ever sees one request and one
response, so it fails the same way at 70s.

That makes `tools_hydra`'s 86400s budget unreachable and turns the orphan
described below into the normal outcome rather than an edge case. It is easy to
watch: run the 65535-port background case in `tests/test_live_tools.py` against
a backend that does not honour the flag, then
`docker exec zebbern-kali ps -eo pid,etime,cmd | grep nmap` — the scan is still
going minutes after the client gave up, with nothing left to reach it by.

**`background=True` is the only escape.** Every subprocess-backed `tools_*`
wrapper takes it. The flag rides `params` into the runner, `execute_command`
hands the command to `job_manager`, and the job dict comes back through an
unchanged route. Drive it with `job_status` / `job_output` / `job_cancel`, and
`job_list` when the id itself is gone. Backgrounded jobs keep their table
budget: `execute_command` passes the resolved timeout into `job_manager.start`,
which otherwise defaults to 3600 and would cap hydra at one hour silently.

The `if background:` check must stay **before** the streaming branch in
`execute_command`. `gobuster`, `nikto` and `bash` are streaming-classified and
both runners that reach them always pass an `on_output` callback, so a check
placed after that branch leaves exactly the tools most likely to outrun the
harness running in the foreground while the flag reads as supported.

Three things that look like bugs and are not:

- **The default is False, so a forgotten flag still orphans at ~60s.** The
  docstrings are the whole mechanism. Auto-promoting a synchronous call to a job
  at a soft deadline is the more robust design and a materially larger change.
- **`run_subzy` leaks its temp targets file when backgrounded, on purpose.**
  With an inline `target` it writes a `NamedTemporaryFile` and unlinks it after
  `execute_command` returns; backgrounded that return is immediate, so the
  unlink would delete the target list out from under a job that has not read it
  yet. The guard is `if target and not background`, and the OS temp reaper
  collects what is left.
- **The tools routes answer 200 with the job dict, not `/api/exec`'s 202.** That
  keeps route edits at zero and `safe_post` reads the JSON either way.

Known and still open:

- **`api_nuclei_scan` posts to `/api/api-security/nuclei`**, a different route
  with no background support. It can still orphan.
- **`heavy_tool_post` holds its semaphore slot for the full client read
  timeout.** Nine tools share `MAX_HEAVY_TASKS = 5`; when the harness walks away
  the MCP thread is still blocked in `safe_post`, so five orphaned scans can
  wedge the heavy surface for up to 90000s.
- **`exec_stream`'s description recommends it for "long-running commands like
  nmap, nuclei, fuzzing"**, which is the opposite of true.

The MSF chain is the exception to "smallest wins": `msf_session_execute` always
puts `timeout` in the request body, so the route's `params.get("timeout", 14400)`
never fires for an MCP caller and **the outermost default decides**. All three
(`mcp_tools/metasploit.py`, the route, `MetasploitSession.execute`) must be
raised together; the first is the only one on the wheel track, so it can regress
in a PyPI-only change that never touches the image.

**The client must always outlive the backend.** Set below a backend budget it
does not cap that budget, it destroys the answer: `requests` raises
`ReadTimeout` before the backend can serialize its reply, `safe_post` returns
`{"error": "Request failed: ReadTimeout"}`, and every byte of partial output is
gone — which makes the whole `timed_out`/`partial_results` contract below
unreachable. Worse, the backend does **not** notice: it keeps running the
subprocess with nobody listening, so the scan is orphaned rather than cancelled
and its output is unreachable forever.

The shipped defaults satisfy that rule with margin — client `90000` (25h) >
table max `86400` (hydra, john) — and
`test_the_client_read_timeout_outlives_the_longest_tool_budget` asserts
`DEFAULT_REQUEST_TIMEOUT > max(TOOL_TIMEOUTS.values())` so the two release
tracks cannot drift back past each other. They already had: the client sat at
14400 while eight table entries were at or above it. Raise the client whenever
a table entry grows past it; do not shorten a tool's budget to fit under the
client. The connect timeout stays 10s — an unreachable server is a different
failure and must still fail fast.

That guard only sees `TOOL_TIMEOUTS`. The one backend deadline computed by
**formula** is `ad_tools.password_spray`'s `len(users) * 5`, which a SecLists
username file turns into ~41,500,000s, far past the client. It is clamped to
`SPRAY_TIMEOUT_CEILING` (86400) for that reason — and clamping loses nothing,
because the `TimeoutExpired` handler returns the partial spray and the
credentials it already parsed, which is strictly more than the `ReadTimeout`
path returns. Any future formula-derived deadline needs the same ceiling and
its own guard.

`get_tool_timeout` keys on a bare binary name. `execute_command` resolves it
with `get_command_timeout`, which strips `sudo`/`timeout 4h`/`env FOO=1`/an
absolute path and takes the longest budget across a pipeline — before that,
`sudo nmap`, `/usr/bin/nmap` and `echo x | waybackurls` all missed their entry
and silently dropped to the default.

**`success: True` and `timed_out: True` coexist on purpose.** A truncated scan's
partial output is worth keeping, so `CommandExecutor`, `/api/exec` and
`MetasploitSession.execute` all report success with output present. Callers
must check `timed_out`, never `success`, to know a command finished. Do not
"fix" this by flipping success. `partial_results` is a real `bool` from all
four emitters — two of them used to return the stdout *string*, truthy but not
a bool, which a strict client reads as a type change rather than a flag.

**Output is never capped or truncated.** `CommandExecutor` accumulates into a
list and joins once (it used to do `self.stdout_data += line`, O(n^2) in line
count — tolerable under a 5-minute cap, not under 24 hours). `MetasploitSession`
does the same for its PTY reader: `output_buffer` is a property over a chunk
list, with `_output_len` and a 512-char `_output_tail` so the wait loop's
per-poll work stays constant. 64MB of 4096-byte reads measured at 131.3s by
concatenation against 0.004s of appends plus one 0.016s join — roughly half a
megabyte a second, which a verbose module outruns. `stdout_data`,
`stderr_data` and `output_buffer` all stay public `str`s holding every byte;
the tail exists for the prompt *match* only.

Unbounded memory on a very long run is a **known, accepted** hazard: dropping
operator output to bound it is the same sin as redacting it. If it ever needs
bounding, spill to disk; do not discard.

Because those attributes are now **derived**, deleting a `_finalize_output()`
call makes every tool's output vanish while still reporting `success: True`, and
the whole suite stayed green through it. `tests/test_command_executor_output.py`
runs the real class on real processes for exactly that reason.

**`exec_stream` registers no job and cannot be cancelled.** On client disconnect
the `finally` in `stream_command_execution` only sets `consumer_closed`, which
stops the queue; the subprocess is never killed and runs to its full timeout,
untracked. For anything you may need to abort, use
`zebbern_exec(background=True)` and `job_cancel`.

**A backend restart drops every session silently.** Jobs, reverse-shell
listeners, SSH sessions and MSF sessions are in-memory only; after a restart the
`*_status` tools return empty with no error, which reads exactly like "it never
started". `job_list` answers `{"jobs": [], "count": 0}` for the same reason, so
an empty listing means "this backend has run nothing", not "nothing is
running". Pivot tunnels are the exception — `network_pivot` persists to
`state.json` and reloads them as `status="stopped"`, visibly dropped rather than
vanished. Given how routine `docker compose up -d --force-recreate` is here,
this is the first thing to suspect when a long scan disappears.

**`probe_tools.py` compares outcome categories, not output.** A clean run proves
outcome stability, not correctness: a tool whose output format drifts but still
exits 0 passes the probe. "0 BROKEN" is not evidence that a tool still works.

## Invariants not to break

- **Fail-open in `mcp_tools/__init__.py`.** A malformed, unknown-schema or
  unreachable capability manifest registers the *full* tool set. Core-module
  tools are never hidden, and a manifest hiding >50% of the surface is ignored.
  Hiding a tool is unrecoverable — discovery is a startup snapshot — while a
  broken-but-present tool just fails once.
- **`exec_stream`'s return contract**: `success`, `output`, `return_code`,
  `timed_out`, `streamed`, plus `incomplete`/`error` only when no result frame
  arrived. A missing result frame must never report success.
- **`msf_session_execute` must keep reporting `timed_out` *and*
  `console_exited`.** The wait loop's three exits — prompt reached, msfconsole
  died, budget expired — all fall through to one return, and before the flags
  existed a module that outran its timeout was indistinguishable from one that
  finished. `timed_out` starts `True` and only the two early exits clear it;
  that is not inverted, it has been misread as inverted twice. It means "the
  budget expired" and nothing else. The death exit clears it too, so it needs
  its own flag: `console_exited` is the difference between a console that was
  OOM-killed mid-exploit and one that reached a prompt, which were otherwise
  field-for-field identical dicts — and under the rule below (check `timed_out`,
  never `success`) that made a crash read as a completed run. It feeds
  `partial_results = bool((timed_out or console_exited) and output)`, and it
  does **not** flip `success` or cap the output. The death exit also clears
  `is_ready`, which is honest but effectively unobservable through
  `msf_session_list`: that path calls `_cleanup_dead_sessions()` first, which
  evicts the dead session before `is_ready` is read. Nothing between the session
  and the MCP caller reshapes that dict — the route does `jsonify(result)`,
  `safe_post` does `response.json()` — so both fields survive on their own; keep
  it that way. Guarded semantically (not just by source substrings) in
  `tests/test_tool_timeouts.py`, which drives the real loop with a stubbed
  process.
- **The MSF prompt test matches the trailing line, not the last 200 chars.**
  `"msf" in buf[-200:] and ">" in buf[-200:]` misses a `meterpreter` or shell
  prompt, i.e. exactly what you wait on after an exploit lands, and at a 14400
  default that miss is a 4-hour uncancellable block rather than a 5-minute
  stall. `_ends_on_prompt` anchors on the last line and accepts msf/msf6,
  meterpreter, shell and generic `>` `#` `$` prompts. It strips ANSI for the
  **match only** — the buffer returned to the operator is never rewritten.
- **SSE frames**: one JSON object per `data:` line. Both emitters serialize
  through `json.dumps`; never add `indent=`, and never hand-build a frame that
  interpolates anything. (`_helpers.py` still emits one hand-built heartbeat,
  but it is a constant literal with no interpolation, so it is safe.)
- Defaults `API_LISTEN_HOST=0.0.0.0` and an empty `KALI_API_TOKEN` are load
  bearing (the container needs `0.0.0.0` to be reachable through the loopback
  port publish). Do not "fix" the exposure warning by changing them.

## Tests

```bash
.venv/Scripts/python.exe -m pytest -q            # ~785 passed, 1 skipped
.venv/Scripts/python.exe -m pytest -m live -q    # 14, needs a backend on :5000
python tests/integration/run_smoke.py --image <img> --expect-variant full --check-trim
python tests/integration/probe_tools.py          # all 132 tools, needs a backend
```

`live` tests skip themselves when no backend answers, which is why CI stays
green without Docker — and why a green `pytest -q` alone proves nothing about
tool execution. Two live tests additionally skip without a web lab on host
port 8888, and three skip against a backend older than
`BACKGROUND_TOOLS_CONTRACT_VERSION` — the same version gate the truncation
cases use, because the contract ships in the image while `integration.yml` pins
the previous digest.

Most other tests are contract-level with a mocked client: they prove the client
shapes the right request, not that a tool runs.

`probe_tools.py` is the only thing that exercises the whole 132-tool surface.
It calls each tool once and compares the outcome against
`tests/integration/probe_baseline.json`, so a run prints only what changed.
Deliberately manual and not collected by pytest: it runs real scanners, starts
and stops real listeners, and reaches the public internet for a handful of
OSINT tools, which is why those are marked best-effort in the baseline. A raw
"BROKEN count" is not a pass criterion — a tool truthfully reporting that no
VPN is configured looks the same as one that regressed, and only the baseline
tells them apart. Re-record the baseline when a tool's expected outcome
legitimately changes.
