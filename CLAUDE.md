# CLAUDE.md

Operational notes for this repo. Every entry is a mistake that has actually been made
here, not general advice. The measurements are recorded because they cost real effort
and cannot be cheaply re-derived.

Read [Three rules](#three-rules) first; the rest of the file leans on them.

[Three rules](#three-rules) ·
[Release tracks](#release-tracks) ·
[Releasing](#releasing) ·
[Integration gate](#the-integration-gate-pins-a-digest) ·
[Things that go stale silently](#things-that-go-stale-silently) ·
[Environment](#environment) ·
[Timeouts](#timeouts) ·
[Background jobs](#background-jobs) ·
[Output integrity](#output-integrity) ·
[Session lifetime](#session-lifetime) ·
[Invariants not to break](#invariants-not-to-break) ·
[Tests](#tests-and-what-they-do-not-prove) ·
[Defect shapes](#defect-shapes-that-keep-recurring) ·
[Mutation checking](#check-that-a-guard-fails-when-you-break-the-thing)

## Three rules

**1. Check the flag, never `success`.** `success: true` is the least informative field
in any reply here: a truncated scan, a crashed msfconsole, an unpinned chisel tunnel
and an already-cancelled job all carry it. The flags that answer the question are
`timed_out`, `console_exited`, `connected`, `listening`, `canceled`, `version_match`,
`output_logged`, `carry_over`. They are **advisory** — they never flip `success` or
`status`, and "fixing" that is the recurring wrong instinct. A flag that cannot tell
"no" from "nothing could tell me" returns `None`, not `False`.

**2. Output is never capped, truncated, redacted or discarded** — not by a buffer
ceiling, not to bound memory, not to make room in a window. Unbounded memory on a very
long run is a **known, accepted** hazard; dropping operator output to bound it is the
same sin as redacting it. If it ever needs bounding, spill to disk. The only bounded
thing here is a *polling window*, and whatever it could not hand back must be carried.

**3. A live process is not a working one, and a status read must not have side effects
on what it reports.** `proc.poll()` proves nothing against a tool that retries forever
— read its log. A liveness probe that dials through a forwarder is traffic against the
target, not a status check.

## Release tracks

The wheel ships **only** `mcp_server.py` and `mcp_tools/*` (`pyproject.toml`
`py-modules` / `packages.find`). Everything under `zebbern-kali/` ships in the **Docker
image** instead, and reaches users when `docker-publish.yml` rebuilds — not when you
publish to PyPI. Before proposing a release check which track the change is on, with
`git diff --name-only <last-tag>..main`: a change under `zebbern-kali/` does not justify
a PyPI bump, and a PyPI release does not deliver it. This has been misread once already
— a proposed release turned out to contain nothing but a comment.

## Releasing

`publish.yml` is `workflow_dispatch` on `main` only. `validate-input` runs
`verify_release_artifacts.py declared-version` and refuses if the dispatched version
differs from `pyproject.toml`.

1. Bump **two** files: `pyproject.toml` and `zebbern-kali/core/config.py` (currently
   1.0.17). Everything else derives. `test_backend_version_tracks_pyproject` fails if
   only one is touched — they used to drift by hand. `config.py` must keep a **literal**
   VERSION: `pyproject.toml` is excluded from the image by `.dockerignore` and the
   backend runs from source, so deriving it would break `/health` at container startup.
2. Re-pin the integration gate digest (below) if the image changed.
3. Dry-run the gate: `gh workflow run integration.yml --ref main`.
4. `gh workflow run publish.yml --ref main -f version=X.Y.Z`
5. Tag afterwards: `git tag -a vX.Y.Z <commit> && git push origin vX.Y.Z`. Tags for
   1.0.2–1.0.4 had to be backfilled because this step was skipped.
6. Bump the pinned `uvx zebbern-kali-mcp@X.Y.Z` in the MCP client config (see
   [the deployed client](#the-deployed-mcp-client)).

**PyPI index lag is normal.** For a few minutes after publish the JSON API and
`uvx --from pkg==X.Y.Z` will claim the version does not exist. The
`post-publish-verify` job matching filenames and SHA-256s is authoritative;
`https://pypi.org/simple/zebbern-kali-mcp/` updates before the JSON API.

## The integration gate pins a digest

`.github/workflows/integration.yml` `env.IMAGE` is an immutable `@sha256:` digest and
`publish.yml` has `needs: [gate, integration]`, so no release ships without real tools
executing. Nothing keeps that pin in step with `:latest`; it drifted three builds within
hours of being introduced. Re-pin as a release step, and pin a digest you have
**actually booted**, not one you only looked up. The digest is also passed to compose as
`ZKM_IMAGE`, because a digest pull leaves no local tag — without it `docker compose up`
would miss `:latest` and rebuild from the Dockerfile, far exceeding the job timeout.

**A backend-only PR is all-green having never run its own code.** The gate's
`pull_request.paths` covers `mcp_tools/**`, `tests/integration/**` and the compose files
but **not `zebbern-kali/**`** — structural, not an oversight: the gate boots a pinned
*published* digest, so running it on an unmerged backend change would certify the old
backend and prove nothing about the diff. A PR that rewrites tool execution therefore
shows lint and Trivy green and nothing else, reading exactly like a validated change.
The only real check is post-merge — rebuild, boot the new digest, call the tools through
a client, then re-pin. Cheaper pre-merge check:
[two containers from one image](#two-containers-from-one-image-then-diff-the-replies).

## Things that go stale silently

### The local backend image

`ghcr.io/zebbern/zebbern-kali-mcp:latest` moves on every `docker-publish` run, which
triggers on any push to `main` touching `Dockerfile`, `.dockerignore`, `docker/**`,
`docker-compose*.yml`, `entrypoint.sh`, `requirements.txt` or `zebbern-kali/**`. A local
copy pulled earlier keeps serving, and the symptoms never look like staleness: the
container reports `unhealthy` (an old image predating the `/live` route), `/health`
reports an old `version`, and tests pass against bits nobody ships.

```bash
docker compose pull && docker compose up -d --force-recreate
docker buildx imagetools inspect ghcr.io/zebbern/zebbern-kali-mcp:latest   # remote
docker image inspect ghcr.io/zebbern/zebbern-kali-mcp:latest --format '{{index .RepoDigests 0}}'
```

Compare those two digests before trusting anything the backend says. This has happened
three times.

### The deployed MCP client

`uvx zebbern-kali-mcp` with **no version** reuses whatever environment uv already cached
for that command; restarting the MCP re-runs the same cached archive. The deployed client
sat on **1.0.5 through six releases** while every check looked fine. It hid because
`health` returned the backend's `/health` verbatim and that `version` is the
**backend's** — nothing reported the client's own. The symptoms read as product bugs: a
tool missing entirely (`job_list` → "No such tool available"); a documented argument
silently ignored (`tools_nmap(background=True)` runs synchronously, because the 1.0.5
wrapper has no such parameter); `/health` saying the current version, so nothing looks
wrong. `health` now also returns `client_version`, `version_match` and a `version_note`
when they disagree — check that before believing a missing tool is a bug.

```bash
# what the running MCP actually is, not what PyPI has
ls "$LOCALAPPDATA/uv/cache/archive-v0/<hash>/Lib/site-packages" | grep dist-info
```

**`--refresh` is not sufficient, measured.** Both configs carried it across a restart
taken minutes after 1.0.14 was on PyPI, and the client still reported 1.0.13. The flag
had genuinely worked — 1.0.14 was in `uv/cache/archive-v0/` — but the server process came
up on the older archive anyway, refreshing the cache without changing what ran. Nothing
about that is visible except `version_match`. Pin instead:
`uvx zebbern-kali-mcp@X.Y.Z` resolves that exact version and nothing else. It must be
bumped by hand each release, and that is the point — forgetting leaves `health` reporting
`version_match: false`, a failure that announces itself, where `--refresh` fails
silently.

**A correct pin is still not proof of what is running.** At 1.0.17 both configs read
`@1.0.17`, the 1.0.17 archive was cached, 1.0.17 processes were alive — and `health`
reported `client_version: 1.0.16` across three restarts. Four processes spawned before
the pin was fixed were still running and still held the session's connection; the app
starts new servers without stopping the old ones, so generations accumulate. Killing
exactly those four flipped `version_match` to true with no further restart. Everything
above pointed at uv and none of it applied, so ask the OS what is running before
touching the cache or the config again:

```powershell
Get-CimInstance Win32_Process | ? { $_.CommandLine -like '*zebbern*' } |
  Select ProcessId, CreationDate, CommandLine
```

Two generations in that listing, or a `CreationDate` older than the last config edit, is
the whole answer. The version in the argv is the version running.

**`claude_desktop_config.json` is regenerated by the app; hand edits do not survive.**
`%APPDATA%\Claude\claude_desktop_config.json` and `~/.claude.json` both define
`kali-tools` and the desktop app reads its own. An edit there verified as `@1.0.17`, then
read `@1.0.16` again after the next restart — which is what spawned the stale generation
above — while the same edit to `~/.claude.json` held. Change it through the app's MCP
settings, or re-check the file after restarting.

**Nothing in the test suite catches any of this**: `pytest`, the live tests and
`probe_tools.py` all spawn `mcp_server.py` from the repo source, so they validate the
source and never the installed artifact.

### Published-package checks run from a clean cwd

`uvx --from pkg==X python -c "import mcp_tools..."` run **inside this repo** imports the
local source, not the installed package, and will happily confirm a fix that was never
published. Run it from somewhere else and assert on `site-packages` in `__file__`. This
produced a false positive once.

## Environment

**Targeting the host from inside the container.** Inside the container `127.0.0.1` is
the **container's own loopback**; the host and anything published on it (e.g. a crAPI lab
on 8888) is `host.docker.internal`. Scanning `127.0.0.1` finds an empty container and
looks exactly like a broken MCP server. Services on another compose network that are not
host-published (crAPI's `crapi-identity:8080`, `crapi-community:6060`) need the Kali
container attached to that network.

**Windows: the backend cannot be imported.** `kali_server.py` and `api.routes` pull in
`metasploit_manager` → `pty` → `termios`, absent on Windows. Import-safe: `api/auth.py`,
`mcp_tools/*`. For anything else, load the module by path
(`importlib.util.spec_from_file_location`) or assert on the **source text** — both
patterns are already in `tests/`.

## Timeouts

A timeout here is a backstop for a **hung** process, not a budget for a slow one. A
four-hour scan is the workload, not a bug.

Four independent deadlines stack on one synchronous tool call, smallest wins:

```
mcp_server --timeout  ->  mcp_tools/_client.py  DEFAULT_REQUEST_TIMEOUT (90000)
                          requests read timeout, connect stays 10s
api/blueprints/*      ->  the route's own params.get("timeout", N)
core/tool_config.py   ->  TOOL_TIMEOUTS[tool], default 3600, max 86400
core/command_executor ->  subprocess wait
```

**There is a fifth deadline, it is the smallest, and it is not in that list: the MCP
harness abandons a tool call at roughly 60 seconds.** It sits above every layer and
outside this repo, so nothing here raises it. Measured: a synchronous `zebbern_exec`
sleeping 310s came back as a harness-level `Error: Request timed out` — not our client's
`{"error": "Request failed: ReadTimeout"}` — while the container process was still alive
at 110s. `exec_stream` does not evade it; SSE runs between our client and the backend and
the harness only ever sees one request and one response, so it fails the same way at
70s. That makes `tools_hydra`'s 86400s budget unreachable and turns an orphaned scan into
the normal outcome. To watch it: run the 65535-port background case in
`tests/test_live_tools.py` against a backend that does not honour the flag, then
`docker exec zebbern-kali ps -eo pid,etime,cmd | grep nmap` — the scan is still going
minutes after the client gave up, with nothing left to reach it by. **A background job is
the only escape.**

**The client must always outlive the backend.** Set below a backend budget it does not cap
that budget, it destroys the answer: `requests` raises `ReadTimeout` before the backend
can serialize its reply, `safe_post` returns `{"error": "Request failed: ReadTimeout"}`,
and every byte of partial output is gone, making the `timed_out`/`partial_results`
contract unreachable. Worse, the backend does **not** notice — it keeps running the
subprocess with nobody listening, so the scan is orphaned rather than cancelled and its
output is unreachable forever. The shipped defaults satisfy the rule with margin — client
`90000` (25h) > table max `86400` (hydra, john) — and
`test_the_client_read_timeout_outlives_the_longest_tool_budget` asserts
`DEFAULT_REQUEST_TIMEOUT > max(TOOL_TIMEOUTS.values())` so the two release tracks cannot
drift back past each other. They already had: the client sat at 14400 while eight table
entries were at or above it. Raise the client whenever a table entry grows past it; never
shorten a tool's budget to fit under the client. The connect timeout stays 10s — an
unreachable server is a different failure and must fail fast.

That guard only sees `TOOL_TIMEOUTS`. The one backend deadline computed by **formula** is
`ad_tools.password_spray`'s `len(users) * 5`, which a SecLists username file turns into
~41,500,000s. It is clamped to `SPRAY_TIMEOUT_CEILING` (86400), and clamping loses nothing
because the `TimeoutExpired` handler returns the partial spray and the credentials already
parsed — strictly more than the `ReadTimeout` path. Any future formula-derived deadline
needs the same ceiling and its own guard.

`get_tool_timeout` keys on a bare binary name; `execute_command` resolves it with
`get_command_timeout`, which strips `sudo`/`timeout 4h`/`env FOO=1`/an absolute path and
takes the longest budget across a pipeline. Before that, `sudo nmap`, `/usr/bin/nmap` and
`echo x | waybackurls` all missed their entry and silently dropped to the default.

**The MSF chain is the exception to "smallest wins":** `msf_session_execute` always puts
`timeout` in the request body, so the route's `params.get("timeout", 14400)` never fires
for an MCP caller and **the outermost default decides**. All three
(`mcp_tools/metasploit.py`, the route, `MetasploitSession.execute`) must be raised
together; the first is the only one on the wheel track, so it can regress in a PyPI-only
change that never touches the image.

**`success: True` and `timed_out: True` coexist on purpose** (rule 1): a truncated scan's
partial output is worth keeping, so `CommandExecutor`, `/api/exec` and
`MetasploitSession.execute` all report success with output present. Do not "fix" this by
flipping success. `partial_results` is a real `bool` from all four emitters — two used to
return the stdout *string*, truthy but not a bool, which a strict client reads as a type
change rather than a flag.

**A scan is finished when it is finished, and nothing here times one.** Output arriving only
at the end is not a defect: the inline wait hands back a `job_id` and the job keeps running,
the `stdbuf` wrap only changes flushing, and `job_output`'s clamp bounds how long a *poll*
blocks, never the process. "Polling returns only the banner, it looks like a hang" is
answered by saying so — adding `--stats-every` to the `tools_nmap` wrapper was considered and
**rejected**, because a progress flag earns nothing `job_status` does not already give, and
anything that stops a scan to report on it returns a worse scan. Closed question.

## Background jobs

`background=True` rides `params` into the runner, `execute_command` hands the command to
`job_manager`, and the job dict comes back through an unchanged route. Drive it with
`job_status` / `job_output` / `job_cancel`, and `job_list` when the id itself is gone.
Backgrounded jobs keep their table budget: `execute_command` passes the resolved timeout
into `job_manager.start`, which otherwise defaults to 3600 and would cap hydra at one hour
silently.

The `if background:` check must stay **before** the streaming branch in `execute_command`.
`gobuster`, `nikto` and `bash` are streaming-classified and both runners that reach them
always pass an `on_output` callback, so a check placed after that branch leaves exactly the
tools most likely to outrun the harness running in the foreground while the flag reads as
supported.

### Seventeen wrappers auto-promote

Fourteen heavy `tools_*` wrappers plus `api_nuclei_scan`, `api_ffuf_fuzz` and
`zebbern_exec` go through `run_promotable`: the job starts first, then the client waits
inline for `ZKM_INLINE_WAIT_SECONDS` (default 50, floored at 1) and returns either the
finished result or a `job_id` handle. For these an incoming `background` is ignored on the
way in and `background=True` means only "do not wait". Starting the job *before* the wait
is the whole safety argument — a mis-tuned budget costs a poll, never the scan, because the
harness abort lands on the poll and `job_list` still finds the job. The other seven
backgroundable wrappers stay opt-in: their tiers are under 3600 and a poll round-trip would
cost more than it saves. `_await_job`'s sleep starts at 0.25s and doubles to
`ZKM_INLINE_POLL_SECONDS`; a flat poll put a ~2s floor under every quick `zebbern_exec`
round-trip once it promoted on every call. Steady state for a long scan is unchanged, and
the backoff is shared by all seventeen.

**`PROMOTED_TOOLS` holds exactly 14 keys and that is deliberate** — only the `tools_*`
wrappers. `api_nuclei_scan`, `api_ffuf_fuzz` and `zebbern_exec` are deliberately absent:
`run_promotable` never reads the map (`heavy` and `background` are passed explicitly) so
behaviour is unaffected, but a non-`tools_*` key would falsify the "fourteen" sentences
above and break `tests/test_autopromote_tier_guard.py`. What must stay in step is each
tool's `TOOL_TIMEOUTS` tier, which that test guards case by case.

Three things that look like bugs and are not:

- **The tools routes answer 200 with the job dict, not `/api/exec`'s 202.** Keeps route
  edits at zero, and `safe_post` reads the JSON either way.
- **`run_subzy` leaks its temp targets file when backgrounded, on purpose.** With an inline
  `target` it writes a `NamedTemporaryFile` and unlinks it after `execute_command` returns;
  backgrounded that return is immediate, so the unlink would delete the target list out
  from under a job that has not read it yet. The guard is `if target and not background`;
  the OS temp reaper collects the rest.
- **The promoted shape drops `execution_time` and the echoed `command`** and rebuilds
  stdout as `"\n".join(ring lines)`, so a trailing newline no longer round-trips. Every
  `tools_*` wrapper already had that divergence; the exact-match live test and
  `run_smoke`'s nonce both use `printf <nonce>` with no newline.

**`api_nuclei_scan` and `api_ffuf_fuzz` needed their own answer** because both runners build
an `output_file`, call `subprocess.run` directly rather than `execute_command`, and parse that
file afterwards — backgrounded, the parse never runs. Each has a `background` branch that drops
`-o` (and ffuf's `-of`) and lets the scanner's own structured output land on stdout:
`nuclei -jsonl`, `ffuf -json`, both newline-delimited JSON, teed 100% to the job log like any
other background job. Every other flag mirrors the synchronous branch, which is byte-for-byte
unchanged and still the path a direct HTTP caller gets.

**`zebbern_exec` was the last tool that could orphan its own output.** It posted synchronously
to `api/exec`, whose **foreground** branch is the one execution path in the repo that tees
nowhere — only the background branch reaches `job_manager`, which writes
`$JOB_OUTPUT_DIR/<job_id>.log` — so a command outrunning the ~60s harness abort left a
subprocess running with nobody listening and nothing on disk, and an operator who passed
`timeout=300` had no way to see the value never mattered. It now goes through
`run_promotable(heavy=False)`; `heavy=False` is deliberate, so it cannot become a
`heavy_tool_post` caller taking one of five semaphore slots for every `whoami`. Its `timeout`
bounds the **job** and is the operator's number: the `api/exec` background branch hands the raw
value to `job_manager.start` without `get_command_timeout` resolution, unlike
`execute_command`, so `zebbern_exec('hydra ...')` is capped by this argument (default 3600),
never by hydra's `TOOL_TIMEOUTS` tier. Do not "fix" that in the route — direct HTTP callers
would be surprised by a timeout they did not ask for.

**Any new `heavy_tool_post` caller must pass a `read_timeout`**; without one it holds a slot
out of five for the full 90000s client timeout. The only remaining call site is inside
`run_promotable`, which always passes `read_timeout=budget`, capping the semaphore hold at
~50s even against a backend that ignores `background`.

`api_kiterunner_scan` and `api_newman_run` are the other two `api_security` wrappers with
no bound, and they cannot orphan for a reason that is not in the code: `kiterunner`, `kr`
and `newman` are **not installed in the image**, so they fail immediately with "command not
found". Install any of them and they need the same treatment — and newman needs a different
answer, because its structured report goes to a `--reporter-json-export` file rather than
stdout.

### Job output is teed to disk, and never pruned

Every background job's full stdout+stderr is written to `$JOB_OUTPUT_DIR/<job_id>.log` (the
image sets `/app/tmp/jobs`; from source without the env it falls back to the OS temp dir).
The in-memory ring that `job_output`/`read_output` return is only a bounded polling window
and still clips and evicts — but the file has 100%, so `output_truncated` no longer means
loss. `output_logged=false` is the one state that does: the log dir was not writable and
only the ring exists. These files are never rotated, capped or auto-deleted (rule 2);
cleanup is manual (`rm /app/tmp/jobs/*.log`) or by container recreate. A long engagement can
grow this without bound; accepted cost.

`job_output` clamps an over-max wait instead of rejecting it — it was an undocumented
`HTTP 400 timeout cannot exceed 30 seconds`, raised before the job was even looked up — and
reports `wait_timeout`, `wait_capped` and `max_output_wait` so it cannot lie about what it
waited. `job_cancel` on an already-terminal job is 200 with
`canceled: false, already_terminal: true` instead of HTTP 409. Genuinely bad input (negative
timeout, `lines<1`) still 400s and an unknown job still 404s; all four verified live.

**A buffering fix can only be proved by a program that does not flush on its own.**
Background jobs launch under `stdbuf -oL -eL /bin/sh -c`
(`job_manager._line_buffered_launch`) so a C-stdio tool line-buffers into its pipe instead of
holding ~4-8KB until exit. The obvious demonstration is worthless: `seq 1 3; sleep 6` shows
all three lines mid-run **with the wrap removed**, because seq flushes at its own exit before
the sleep; ping and awk call `setvbuf` themselves. Measured wrapped against unwrapped, the
only thing that distinguishes them is a purpose-built printf/printf/sleep C binary with no
`setvbuf`: `["first","second"]` wrapped, `[]` unwrapped.

**The honest negative result: `stdbuf` has a narrower scope than "C-stdio tools" and is not
the fix for the nmap case.** At equal sample times the wrap changed **nothing** for masscan,
hydra, gobuster or sqlmap — Go binaries, CPython and perl each run a buffering layer stdbuf
cannot reach, so job output arriving only at exit is not always buffering. For nmap, a
backgrounded scan sampled at 4s/8s/12s gave 1 stdout line each time **with** the wrap and 0
each time without it: the wrap gets the banner out immediately where an unmodified backend
showed nothing at all, and that banner is the whole of what it buys. No mid-scan progress
appeared at any sample — not even with the probe passing a progress flag to force the issue,
which is a measuring instrument for that one measurement and not a way to run a scan here.
Do not carry it into a wrapper, a default, or a suggestion to an operator.

## Output integrity

**Nothing is capped or truncated** (rule 2). `CommandExecutor` accumulates into a list and
joins once — it used to do `self.stdout_data += line`, O(n^2) in line count, tolerable under
a 5-minute cap and not under 24 hours. `MetasploitSession` does the same for its PTY reader:
`output_buffer` is a property over a chunk list, with `_output_len` and a 512-char
`_output_tail` so the wait loop's per-poll work stays constant. 64MB of 4096-byte reads
measured at 131.3s by concatenation against 0.004s of appends plus one 0.016s join — roughly
half a megabyte a second, which a verbose module outruns. `stdout_data`, `stderr_data` and
`output_buffer` stay public `str`s holding every byte; the tail exists for the prompt *match*
only. Because those attributes are now **derived**, deleting a `_finalize_output()` call
makes every tool's output vanish while still reporting `success: True`, and the whole suite
stayed green through it — `tests/test_command_executor_output.py` runs the real class on real
processes for exactly that reason.

**A window over a stream has to carry what it could not hand back, and the carry has to live
on the session.** `ReverseShellManager.read_output` — the read half of the raw caught-shell
channel — held its remainder buffer and line surplus in **locals**, so every byte `os.read`
had already taken off the PTY and not returned died with the call: a newline-less remainder,
and every complete line past `max_lines`. That destroyed the exact case the channel exists
for — a REPL, `su` asking for a password, `(gdb)` all stop on a prompt with no newline, so the
operator saw an empty window, indistinguishable from a hung target. The discard was
pre-existing; the branch exposed the function as an MCP tool under a docstring promising
"anything left is returned by the next call ... Nothing is discarded to make room", and **a
new docstring over old behaviour is a new false claim** — a review found it where the suite
could not. Both carry-overs are now `self._raw_read_buf` / `self._raw_pending_lines`; a
newline-less remainder comes back in the window that *read* it rather than one call later (one
call late is useless to whoever waits on a password prompt, and the cost is a long line
arriving in two pieces, bytes and order intact); `carry_over: {lines, bytes}` reports what is
still held. Verified live: `printf "Password: "` comes back in the same window.

`max_lines` was a soft bound reported as a hard one — the ceiling was tested only on the outer
loop, so one `os.read` could append a whole burst past it while the route answered
`window_limit: 100` beside `lines_returned: 500`. The tempting fix, breaking the inner loop at
the ceiling, **discards** complete lines already read off the PTY, so the surplus is carried
instead and the ceiling became hard at zero loss: a 12-line burst read with `lines=4` returned
4/4/4/3 across four calls, in order, with `carry_over` draining 10 → 6 → 2 → 0. Reporting the
carry-over is not decoration — under a hard ceiling "exactly my limit" otherwise reads
identically to "that was everything", and an operator stops polling with lines still held.
Companion trap, in the test: a helper that builds the manager with `object.__new__` has to set
the carry-over attributes itself, so the helper supplies the fix and the `__init__` mutation
never goes red. `__init__` opens no PTY, so build through the real constructor.

**A signal exit used to be indistinguishable from a silent success.** A shell killed by a
signal comes back as a negative `return_code`, empty stdout and `success: False` —
field-for-field what a command that ran and printed nothing looks like. The way to land there
is `pkill -f <pattern>` whose pattern matched the shell running it: that shell's argv contains
the command text, so the command kills itself and reports `-15` with no explanation.
`_note_signal_exit` in `mcp_tools/command_exec.py` now names SIGTERM/SIGKILL/SIGINT. It is
additive only (`setdefault`, so it never clobbers the truncation note), touches no byte of
output, and annotates nothing when there is output, when `timed_out` is set (`-1` is that
sentinel, not a signal), or on a still-running handoff.

**A note that explains a failure must not assert a cause it did not observe.** The note is in
two halves. The observed half — signal name, no output, and that an outside kill
(`job_cancel`, the OOM killer, a stopped backend) looks identical — stays unconditional. The
self-match clause was gated on `"kill" in command.lower()`, so `kill -TERM 4567`, a PID kill
that cannot self-match, was confidently told its pattern had killed its own shell when the
real cause was a `job_cancel` or the OOM killer; `grep killer` fired it too. It is now phrased
as a possibility to rule out, says outright that nothing observed what sent the signal, and is
attached only to commands that select victims *indirectly*: `pkill -f`/`--full`,
`fuser -k`/`--kill`, `killall` (`_PATTERN_KILLERS`), matched by token equality on the binary's
basename within one shell segment, so a flag in a later segment cannot be credited to it
(`pkill nginx && echo -f`). `kill` and `pgrep` are deliberately absent: one names PIDs, the
other kills nothing. Every entry in `_SIGNAL_EXITS` is exercised by a test parametrized over
the table itself, plus a second parametrization pinning the three signals by name so deleting
one goes red — a table-driven test alone just yields one case fewer.

## Session lifetime

**A backend restart drops every session silently.** Jobs, reverse-shell listeners, SSH
sessions and MSF sessions are in-memory only; after a restart the `*_status` tools return
empty with no error, reading exactly like "it never started". `job_list` answers
`{"jobs": [], "count": 0}` for the same reason, so an empty listing means "this backend has
run nothing", not "nothing is running". Pivot tunnels are the exception — `network_pivot`
persists to `state.json` and reloads them as `status="stopped"`, visibly dropped rather than
vanished. Given how routine `docker compose up -d --force-recreate` is here, this is the
first thing to suspect when a long scan disappears.

**`exec_stream` registers no job and cannot be cancelled.** On client disconnect the
`finally` in `stream_command_execution` only sets `consumer_closed`, which stops the queue;
the subprocess is never killed and runs to its full timeout, untracked. For anything you may
need to abort, use `zebbern_exec(background=True)` and `job_cancel`.

## Invariants not to break

- **Fail-open in `mcp_tools/__init__.py`.** A malformed, unknown-schema or unreachable
  capability manifest registers the *full* tool set. Core-module tools are never hidden, and
  a manifest hiding >50% of the surface is ignored. Hiding a tool is unrecoverable —
  discovery is a startup snapshot — while a broken-but-present tool just fails once.
- **`exec_stream`'s return contract**: `success`, `output`, `return_code`, `timed_out`,
  `streamed`, plus `incomplete`/`error` only when no result frame arrived. A missing result
  frame must never report success.
- **`msf_session_execute` must keep reporting `timed_out` *and* `console_exited`.** The wait
  loop's three exits — prompt reached, msfconsole died, budget expired — all fall through to
  one return, and before the flags existed a module that outran its timeout was
  indistinguishable from one that finished. `timed_out` starts `True` and only the two early
  exits clear it; that is not inverted, it has been misread as inverted twice. It means "the
  budget expired" and nothing else. The death exit clears it too, so it needs its own flag:
  `console_exited` is the difference between a console OOM-killed mid-exploit and one that
  reached a prompt, otherwise field-for-field identical dicts — and under rule 1 that made a
  crash read as a completed run. It feeds
  `partial_results = bool((timed_out or console_exited) and output)` and does **not** flip
  `success` or cap the output. The death exit also clears `is_ready`, honest but effectively
  unobservable through `msf_session_list`, which calls `_cleanup_dead_sessions()` first and
  evicts the session before `is_ready` is read. Nothing between the session and the MCP caller
  reshapes that dict — the route does `jsonify(result)`, `safe_post` does `response.json()` —
  so both fields survive on their own; keep it that way. Guarded semantically (not just by
  source substrings) in `tests/test_tool_timeouts.py`, which drives the real loop with a
  stubbed process.
- **The MSF prompt test matches the trailing line, not the last 200 chars.**
  `"msf" in buf[-200:] and ">" in buf[-200:]` misses a `meterpreter` or shell prompt, i.e.
  exactly what you wait on after an exploit lands, and at a 14400 default that miss is a
  4-hour uncancellable block rather than a 5-minute stall. `_ends_on_prompt` anchors on the
  last line and accepts msf/msf6, meterpreter, shell and generic `>` `#` `$` prompts. It
  strips ANSI for the **match only** — the buffer returned to the operator is never
  rewritten.
- **SSE frames**: one JSON object per `data:` line. Both emitters serialize through
  `json.dumps`; never add `indent=`, and never hand-build a frame that interpolates anything.
  (`_helpers.py` still emits one hand-built heartbeat, but it is a constant literal with no
  interpolation, so it is safe.)
- Defaults `API_LISTEN_HOST=0.0.0.0` and an empty `KALI_API_TOKEN` are load bearing (the
  container needs `0.0.0.0` to be reachable through the loopback port publish). Do not "fix"
  the exposure warning by changing them.

## Tests, and what they do not prove

```bash
.venv/Scripts/python.exe -m pytest -q            # 1506 passed, 6 skipped, ~4m
.venv/Scripts/python.exe -m pytest -m live -q    # 15 passed, 3 skipped; backend on :5000
python tests/integration/run_smoke.py --image <img> --expect-variant full --check-trim
python tests/integration/probe_tools.py          # all 135 tools, needs a backend
```

`live` tests skip themselves when no backend answers, which is why CI stays green without
Docker — and why a green `pytest -q` alone proves nothing about tool execution. Two live
tests additionally skip without a web lab on host port 8888, and three skip against a backend
older than `BACKGROUND_TOOLS_CONTRACT_VERSION` — the same version gate the truncation cases
use, because the contract ships in the image while `integration.yml` pins the previous
digest. One of the six skips in a plain `pytest -q` run is Windows-only:
`tests/test_job_manager.py` skips its real-`stdbuf` case with "GNU stdbuf is absent on this
system"; its companion case asserts where the wrap lives and runs everywhere, so on Windows
the line-buffered launch is never executed, only located. Most other tests are
contract-level with a mocked client: they prove the client shapes the right request, not that
a tool runs.

**`probe_tools.py` compares outcome categories, not output.** A tool whose output format
drifts but still exits 0 passes, so "0 BROKEN" is not evidence that a tool still works. It is
the only thing that exercises the whole 135-tool surface: one call per tool, compared against
`tests/integration/probe_baseline.json`, so a run prints only what changed. Deliberately
manual and not collected by pytest — it runs real scanners, starts and stops real listeners,
and reaches the public internet for a handful of OSINT tools, which is why those are marked
best-effort in the baseline. A raw "BROKEN count" is not a pass criterion: a tool truthfully
reporting that no VPN is configured looks the same as one that regressed, and only the
baseline tells them apart. Re-record the baseline when a tool's expected outcome legitimately
changes. Two ways a BROKEN can be something other than the tool:

- **The harness.** The probe spawned `mcp_server.py` with `text=True` and no `encoding=`, so
  the child's UTF-8 JSON was decoded with `locale.getpreferredencoding()` — cp1252 on
  Windows. Any reply carrying a byte outside it raised `UnicodeDecodeError` inside
  `readline()` and the tool was recorded BROKEN. Measured on `api_nuclei_scan` (`byte 0x90`),
  and **intermittent**, because it depended on what the scan happened to find — the worst way
  for a baseline diff to be wrong, since the baseline exists so a human only reads what
  changed. Read the detail on a new BROKEN before believing it.
- **A changed wrapper signature.** Making `ad_ldap_enum`'s `dc_ip` required meant the probe's
  existing call was rejected in the MCP layer before reaching the backend, which reads
  identically to the tool failing. Update the case, then re-record.

**The tool count is pinned in six places, so adding one tool is a six-file change** — the
count is **135 full / 125 trim**, asserted in `tests/test_tool_descriptions.py`,
`tests/test_tool_profiles.py` (twice, including the trim count, and in two test *names*),
`tests/test_integration_harness.py` (eleven sites, two of them inside
`pytest.raises(match=...)` strings that embed the number),
`tests/integration/run_smoke.py` (`FULL_TOOL_COUNT`) and `README.md`; a new tool also needs a
`tests/integration/probe_tools.py` case and a `tests/integration/probe_baseline.json` entry. A
plan that says "add a tool" and lists only the wrapper file goes red in four test files it
never names — and in a parallel batch, in files another agent owns. Adding the two
reverse-shell tools did exactly that. Two README numbers were found stale independently of
that change — the `web --exclude-module callback_catcher` line said 57 against an actual and
long-asserted 58, and the ctf line said 75 against 78 — so the README counts had already
drifted from the suite.

**Check whether a family is really untestable before writing it off.** `ctf_*` was recorded as
unexecutable next to `ad_*` and `vpn_*` and is nothing of the sort: it is an HTTP client for
the CTFd v1 API, so a mock CTFd exercises all seven tools including both submit_flag outcomes
and a byte-identical file download, and they came back clean. Re-checking the rest on the
strength of that found the `ad_smb_enum` bug, so the wrong assumption cost a real defect left
in place. Genuinely unexecutable here: the `ad_*` attack tools, which need a live domain
controller, and `vpn_connect`, which needs a peer — but their status and failure paths are
still testable, and that is where `ad_smb_enum` was caught returning
`success: true, null_session: true` against a host running no SMB, a security claim asserted
from the auth mode chosen rather than any result.

### Two containers from one image, then diff the replies

The only real check is post-merge: rebuild, boot, call the tools. There is a cheaper one, and
it found a real regression on this branch where a green suite and a green mutation run did
not. Start **two** containers from the same published image, `docker cp` the changed
`zebbern-kali/` files into one and restart it, leave the other untouched as a control, then
call the same endpoint on both and diff the replies. The backend runs from source, so the
patched container really is running the new code. It does not prove the image **builds** — a
Dockerfile change is still unverified by this — and it must not touch the operator's own
running container.

What it caught: the reverse-shell marker fix below made captured output strictly **worse** in
the common case. The old substring END test happened to fire on the PTY echo of the end-marker
command and break before that line was appended; the new exact-match test correctly does not
fire on the echo, so the loop ran past it, and the surviving append filter only skipped lines
literally starting with `echo '`, which a prompt-prefixed `root@h:~# echo 'END_x'` never does.
A live `whoami` returned 5 lines against the control's 4, the extra one being the harness's own
marker command. The full suite was green, 78/78 mutation guards were red, and every unit test
passed through all of it — the guards asserted the new boundary logic, which was correct;
nothing asserted the captured output against the old behaviour. So when a change rewrites
capture or boundary logic, diff the captured output against the previous behaviour, not just
against what the new logic intends: a guard written alongside the new logic agrees with it.

Two traps in how that was diagnosed:

- The first conclusion from the live reply was "the fixed branch never ran", because
  `end_marker_found` and `shell_responsive` both came back null rather than false from code
  that can only produce a bool. Wrong: `end_marker_found` is nested in `debug_info` and
  `shell_responsive` only exists on the status reply, so those were absent keys being read. A
  null from a reply is not evidence about a branch — check where the field actually lives
  before inferring control flow from it.
- The real tell was `history_suppressed: true`, emitted at exactly one place in the patched
  branch, which proved it had run.

## Defect shapes that keep recurring

**Neither the suite nor the probe can tell you a tool works.** Calling each tool through an
MCP client and reading the reply found roughly twenty defects across ~65 tools, every one of
them green in `pytest` and in the probe first; around a third answered `success: true`.
Nothing automated catches this class: the contract tests assert the request the *client*
builds and the client was usually right, and the probe compares outcome categories, where
"non-zero exit" was already expected. A docstring is not evidence either — several documented
arguments no code read. So: call the tool, read the reply, and check it says what that tool
should say. One call, one output. The shapes, worth checking first in anything new:

- **An argument the wrapper sends and nothing reads.** `pivot_add_pivot`'s `method`, the
  three SSH tunnels' `password`, `api_fuzz_endpoint`'s `parameters` (the route read
  `params`), `api_graphql_fuzz`'s `variables` (absent entirely, so it sent zero requests and
  called the target clean), `pivot_ligolo_start`'s `interface` (the route read `tun_name`),
  `reverse_shell_listener_start`'s `auto_upgrade` (no reader anywhere, and no TTY-upgrade code
  to be a reader), and `pivot_chisel_client`'s `fingerprint` — the only one where the dropped
  argument *was* the security control: an operator who pinned the server's host key got an
  unpinned tunnel. `kali_upload`'s `encoding` is the same shape and still ships:
  `api/kali/upload` hands content to `upload_to_kali_with_verification`, which takes no
  `encoding` and always base64-decodes; documented as inert rather than removed, because
  removing it is a published-schema change. Audit mechanically, not by eye: walk every key
  each wrapper serialises against the code that receives it, remembering that most routes
  pass `params` straight to a runner, so the search has to reach `core/` and `tools/` and not
  stop at the blueprint.
- **The mirror: the backend demands what the schema calls optional.**
  `ad_ldap_enum(domain, username, password)` and `ad_secretsdump(domain, username, password)`
  both answered a 400 naming exactly what was missing — honest replies, but `dc_ip` and
  `target` carried `"default": ""` in the published JSON schema, so the obvious minimal call
  was the one that always failed. Audit by finding every route that 400s on a missing key and
  checking it against the wrappers that post there. A signature cannot express "one of two",
  so `ad_secretsdump` checks locally and returns the backend's own wording.
- **`success: true` for work that did not happen.** `reverse_shell_command` against a dead
  shell, `exploit_copy` carrying "Could not find EDB-ID #" as its message, a chisel client
  already defunct, `payload_generate` with an empty file. Check the thing the tool exists to
  produce, not the exit code.
- **A liveness check is not enough** (rule 3). The fix for the defunct chisel client was
  `proc.poll()` after 1.5s, and that is exactly what a *failing* client evades: chisel
  retries a failed handshake forever rather than exiting. A deliberately wrong
  `--fingerprint` answered `success: true, fingerprint_pinned: true` with a tunnel id while
  the log looped on "Invalid fingerprint" — the one event pinning exists to catch, reported
  as a working client. It now reads the log: a mismatch fails and terminates the client
  (never transient, and never something to leave retrying against whatever answered), any
  other connection error keeps the process but reports `connected: false`. Note the shape:
  **the fix that made pinning real is what made this reachable**, found by driving the fix on
  the image it shipped in rather than by reviewing it.
- **The same gap from the server end.** `pivot_list_tunnels` detected a dead chisel server by
  pid, and a pid is the weaker half of the answer — a server whose control socket is gone
  keeps its pid and reads as "active", which is how an operator came to stack three clients on
  a dead tunnel. Every local-listener tunnel (`chisel_server`, `socat`, `ssh_local`,
  `ssh_dynamic`, `ligolo_proxy` — `LOCAL_LISTENER_TYPES` in `core/network_pivot.py`) now
  carries `listening`, on the same advisory contract as `connected`. `chisel_client` and
  `ssh_remote` get `listening: null`, not false — their listener is on the far end, and a
  false there would be a false alarm in the one tool an operator consults when they already
  distrust the tunnel. Auto-restart stays deliberately absent: resurrecting a pentest tunnel
  could reattach to a changed target and would hide the instability.
- **A status read with side effects on what it reports** (rule 3). That flag answered with a
  real `socket.create_connection` for every type in `LOCAL_LISTENER_TYPES`, and two of those
  are pure *forwarders*: socat runs `fork,reuseaddr`, so accepting forks a child that dials
  `target_host:target_port`, and `ssh -L` opens a channel to the forwarded host the moment it
  accepts. So read-only `pivot_list_tunnels` opened a TCP connection to e.g. `10.0.0.5:445` on
  every call. The set is split now: `CONNECT_SAFE_LISTENER_TYPES` (`chisel_server`,
  `ssh_dynamic`, `ligolo_proxy`) terminate the connect at their own endpoint and keep the 0.3s
  connect to `127.0.0.1`; `FORWARDER_LISTENER_TYPES` (`socat`, `ssh_local`) are answered from
  the kernel socket table instead (`ss -ltn`, falling back to `netstat -ltn`, both in the image,
  fetched at most once per listing), proving the socket exists without dialling through it.
  `LOCAL_LISTENER_TYPES` is the union, so it still means what it did. `_listening_ports` returns
  `None` rather than an empty set when nothing can answer, so an unreadable table yields
  `listening: None` instead of a confident `False`, and `listening_method` (`connect` /
  `socket_table` / `pid` / `unavailable` / `None`) says which answer you got and distinguishes
  the two kinds of null. Verified live: `chisel_server` reports `method=connect`, a socat
  forward with a dead downstream reports `method=socket_table`, and a killed socat reports
  `status=stopped listening=False method=pid`. The guards in
  `tests/test_pivot_listener_probe.py` assert the absence of the connection behaviourally — a
  real listening socket is handed to the test, nothing accepts from it, and `select()` says
  whether a connection reached the accept queue — because an assertion about which helper was
  called would have passed against the defect.
- **A derived value that answers a different question than the one asked.** `_get_local_ip`
  UDP-connects to `8.8.8.8` and returns the default-route source, which inside the container
  is the docker bridge (`172.17.0.2`) — an address no target can reach, handed out as the
  advertised host. Preferring "the default route" is not the fix either: an operator hit this
  with tun0 up at `10.10.17.215`, because their `.ovpn` did not redirect the default gateway,
  so the VPN interface has to be consulted explicitly. The advertised host now comes back
  with `advertised_host_source` and a note naming the trap when it is a guess. Separately,
  the advertised `connect_command` used a bare `R:socks`, whose remote port defaults to 1080 —
  the port `vpn_connect`'s own SOCKS already holds and reports as
  `socks_proxy: {port: 1080, running: true}` — producing "Server cannot listen on
  R:127.0.0.1:1080=>socks" in an endless retry loop. The reverse SOCKS port is now chosen,
  reported, and moved with a note when 1080 is taken.
- **Verification that confirms the wrong invariant.** The upload checksum hashed what the
  caller sent and what landed, and down the utf-8 path those were the same base64 string — so
  it certified a faithful transfer of the wrong bytes.
- **Boundary detection that matches a substring instead of the executed line.**
  `reverse_shell_command` wraps the command in `echo '<marker>'` lines, and a PTY echoes what
  is written to it, so `marker in text` was satisfied by the echo of the typed line with no
  shell behind it. On a live-but-silent caught shell that produced
  `success: true, lines_captured: 0`. The dead-session (EOF) path was already guarded by
  `session_closed`; the live-echo path was not, and `success` requiring `not session_closed`
  did not help because nothing had closed. `_executed_marker` now takes equality on the line
  (ANSI stripped for the match only), and `_executed_marker_span` carries the base64 branch —
  the span matters on its own, because `text_buffer.find(marker)` returns the FIRST
  occurrence, which *is* the echo, so the `clean_content` offsets stayed anchored on it after
  the boolean test had been fixed. Same shape as `_ends_on_prompt`: anchor on the line, strip
  ANSI for the match, never rewrite the buffer.
- **Markers landing in the target's shell history.** An operator read
  `echo 'START_36892201'` out of `/home/worker/.bash_history` and briefly took their own
  markers for the target's. A prelude now sets `HISTFILE=/dev/null` and `set +o history`, each
  command individually guarded so a dash/ash/busybox target lacking `set -o history` cannot
  error into the capture, and the prelude is drained to the first executed start marker so
  neither it nor its echo can enter output. It is not the forbidden redaction: it hides
  nothing from the operator, it keeps the operator's own injected markers out of the target's
  history. `suppress_history` defaults True and `history_suppressed` reports only that the
  prelude was sent, never that the target honoured it — verified live against an unmodified
  control, which reported the real histfile and `history on` where the patched target reported
  `HISTFILE=[/dev/null]` and `history off`. Caught shells also have a raw channel, which needs
  no markers at all: `reverse_shell_send_input` / `reverse_shell_read_output` on
  `api/reverse-shell/<id>/send-raw` (POST) and `/read-output` (GET). The generic `send_input` /
  `read_output` still resolve through `job_manager` and still only serve `zebbern_exec` jobs;
  reverse shells live in `active_sessions` and the two sets stay disjoint.
- **A default that contradicts the docstring above it.** Three upload tools documented base64
  content and defaulted `encoding="utf-8"`; `callback_wait` defaulted to 60s, exactly the
  harness abort. `reverse_shell_command` had the same 60 and lost the same race, so its own
  `timed_out` and the partial capture under it never came back. 45 is measured, not round, and
  it is defaulted in three places across both release tracks (wrapper, route,
  `ReverseShellManager.send_command`), all now guarded strictly under 55.
- **Copy-paste output that does not run.** Two of three `callback_generate` DNS commands were
  malformed, and a lookup that never leaves the box looks exactly like a target that did not
  call back.
- **A tool reaching outside itself.** `payload_host_start` called `os.chdir`, which is
  process-wide, moving the cwd of every later `zebbern_exec` from the mounted volume to a
  container-layer directory.

The two *disagreement* shapes (an argument nothing reads; a 400 on a schema-optional key) are
the exception to "nothing automated catches this", and worth re-running as audits after any
change to the tool surface: they compare two artefacts that already exist rather than judging
behaviour, so a script can do it. The endpoint-and-verb check is now permanent in
`tests/test_wrapper_endpoints_exist.py` (240 call sites against 146 declared routes). The
key-reachability and 400-vs-optional audits stay manual, because both are noisy: routes that
hand `params` wholesale to a runner look like dropped keys, and a 400 naming what is missing
is often the honest answer.

## Check that a guard fails when you break the thing

A test written alongside a fix passes whether or not it tests the fix. Prove it fails when the
fix is reverted:

```bash
.venv/Scripts/python.exe scripts/mutation_check.py --spec tests/mutations.json \
    --python .venv/Scripts/python.exe
```

Do not do this by hand with `str.replace`. It was done that way three times in one session and
silently matched nothing every time — a CRLF file against an LF needle, an escaped backslash
mangled by a heredoc, a comment containing the same words as the code. The tests passed, and
"mutation-checked red" went into a commit message for a guard that had never been exercised.
The script refuses to call that a pass: it requires the target text to occur exactly the
expected number of times, the file to change on disk, the result to still parse, the tests to
fail, and the file to be restored byte-for-byte. A mutation that cannot be applied is the
loudest outcome, because that is the case that used to look like success. It has earned this
twice:

- Run across the guards written in one sweep, 22 of 26 verified and four did not: three
  anchors that silently matched nothing, and one guard that genuinely did not catch its
  mutation — `exploit_copy`'s post-copy file check, which the by-hand run had appeared to
  cover because it mutated two things at once and the other one carried the test.
- **A mutation entry is coupled to the source line it quotes.** Merging this round's entries
  made an existing one stale: the pivot listener fix moved the line the entry
  `pivot list: claim every listener is up` anchored on, and the script said
  `expected the target text 1x, found 0x. The mutation would not have applied, which is
  exactly the case that used to look like a pass.` The entry was re-anchored. A later refactor
  of a quoted line silently invalidates that guard's proof until the script is re-run.

Add a mutation to `tests/mutations.json` whenever you add a guard. The spec holds **103**
entries and the last full run was **103/103 guards verified red**.
