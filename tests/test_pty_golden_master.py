"""Golden master for the three PTY managers' read paths, frozen before A3.

``pty.openpty`` + ``select.select`` + ``os.read`` on a master fd is implemented
three independent times -- ``reverse_shell_manager`` (send_command / read_output),
``metasploit_manager`` (MetasploitSession.execute) and ``ssh_manager``
(send_command). A3 factors that triplicated fd lifecycle into one helper. The
earlier field report is explicit that a rewrite of capture/boundary logic
regressed once while the whole suite -- and a full mutation run -- stayed green,
because every unit test and guard was written alongside the new logic and so
agreed with it; the only check that caught it compared the *captured output*
against the previous behaviour.

A delegated-agent decision under zebbern's standing authority grant,
2026-10-02, treats that report as evidence rather than a prohibition: the right
answer is not to refuse the refactor but to build the equivalence check the
report says is missing, and to build it so it runs in CI on a Windows host with
no backend rather than only through the two-container method. That check is this
file.

How it works: ``tests/_pty_golden_recorder.py`` drives each manager's real
read-path method through a scripted timeline of byte chunks (injected os.read /
select.select / os.write, a controllable clock, deterministic uuid markers) and
captures the full return value. Those captures were frozen to
``tests/fixtures/pty_golden/*.json`` at record time. This test replays every
timeline through the CURRENT managers and asserts the result still equals the
frozen fixture. Recorded now against today's managers, these fixtures prove the
timelines describe real current behaviour; carried past A3, the same assertions
become the regression guard the report asked for -- any byte or flag the
extraction changes in a read path's output turns one of these red.

The recorder sets up the suite's Windows pty seam on import, so this test runs
with no backend and no real PTY. Only ``execution_time`` is normalized out of
the comparison -- it is a clock-read count a background reader thread perturbs,
so pinning it would be brittle without guarding anything; every other field is
asserted exactly.
"""

import json

import pytest

import _pty_golden_recorder as recorder


def _load_fixture(name):
    path = recorder.FIXTURE_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(recorder.CASES))
def test_read_path_output_matches_golden_master(name):
    """Replaying the timeline through the current manager still yields the
    frozen capture, byte for byte and flag for flag."""
    fixture = _load_fixture(name)
    result = recorder.run_case(name)
    assert result == fixture


def test_every_case_has_a_frozen_fixture():
    """A case with no fixture would silently never be checked."""
    missing = [
        name for name in recorder.CASES
        if not (recorder.FIXTURE_DIR / f"{name}.json").exists()
    ]
    assert missing == []


def test_the_recorded_surface_covers_all_three_managers():
    """Guard the coverage the whole exercise depends on: each manager's read
    path has at least one frozen timeline, so none can be refactored unseen."""
    names = " ".join(recorder.CASES)
    assert "rs_send_command" in names
    assert "rs_read_output" in names
    assert "ssh_send_command" in names
    assert "msf_execute" in names
    # The three MSF prompt detectors are each pinned, since _prompt_kind is
    # exactly the kind of boundary logic the report warns regresses silently.
    assert "msf_execute_prompt_reached_exact_msf" in recorder.CASES
    assert "msf_execute_prompt_reached_meterpreter" in recorder.CASES
    assert "msf_execute_prompt_reached_generic_prompt" in recorder.CASES
