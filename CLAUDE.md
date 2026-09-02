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

## Invariants not to break

- **Fail-open in `mcp_tools/__init__.py`.** A malformed, unknown-schema or
  unreachable capability manifest registers the *full* tool set. Core-module
  tools are never hidden, and a manifest hiding >50% of the surface is ignored.
  Hiding a tool is unrecoverable — discovery is a startup snapshot — while a
  broken-but-present tool just fails once.
- **`exec_stream`'s return contract**: `success`, `output`, `return_code`,
  `timed_out`, `streamed`, plus `incomplete`/`error` only when no result frame
  arrived. A missing result frame must never report success.
- **SSE frames**: one JSON object per `data:` line. Both emitters serialize
  through `json.dumps`; never add `indent=`, and never hand-build a frame that
  interpolates anything. (`_helpers.py` still emits one hand-built heartbeat,
  but it is a constant literal with no interpolation, so it is safe.)
- Defaults `API_LISTEN_HOST=0.0.0.0` and an empty `KALI_API_TOKEN` are load
  bearing (the container needs `0.0.0.0` to be reachable through the loopback
  port publish). Do not "fix" the exposure warning by changing them.

## Tests

```bash
.venv/Scripts/python.exe -m pytest -q            # ~628 passed, 1 skipped
.venv/Scripts/python.exe -m pytest -m live -q    # 9, needs a backend on :5000
python tests/integration/run_smoke.py --image <img> --expect-variant full --check-trim
```

`live` tests skip themselves when no backend answers, which is why CI stays
green without Docker — and why a green `pytest -q` alone proves nothing about
tool execution. Two live tests additionally skip without a web lab on host
port 8888.

Most other tests are contract-level with a mocked client: they prove the client
shapes the right request, not that a tool runs.
