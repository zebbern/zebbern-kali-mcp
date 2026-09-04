"""ad_smb_enum reported an anonymous SMB session against a host running no SMB.

Measured against 127.0.0.1 with nothing on 445:

    {"success": true, "null_session": true, "shares": []}

Both fields were wrong, and both in the direction that misleads.

`success` was a literal in the results dict and smbclient's return code was
never read, so a refused connection produced a clean enumeration of no shares.

`null_session` was set from the auth mode chosen -- before smbclient ran -- so
it meant "an anonymous session was attempted" while reading as "anonymous
access is allowed". That is a security finding asserted with no evidence, and
it is the kind an operator writes into a report.

The attempt and the outcome are now separate fields, and the outcome is only
set when smbclient actually connected and listed. Verified both ways against a
real Samba server in the container: refused gives success false with
NT_STATUS_CONNECTION_REFUSED, and a guest-readable share gives null_session
true with the share's real read/write flags.

ldap_enum in the same module already did this correctly -- it overwrites
success with `successful_queries > 0 and not custom_query_failed` -- so this is
about smb_enum specifically, not the module.
"""

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import ad_tools as ad  # noqa: E402


LISTING = """
\tSharename       Type      Comment
\t---------       ----      -------
\tsweepshare      Disk
\tIPC$            IPC       IPC Service (sweep)
"""


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def tool(tmp_path, monkeypatch):
    inst = object.__new__(ad.ADTools)
    inst.output_dir = str(tmp_path)
    (tmp_path / "smb").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(inst, "_test_share_access",
                        lambda *a, **kw: {"read": True, "write": False},
                        raising=False)
    return inst


def _run(monkeypatch, result):
    monkeypatch.setattr(ad.subprocess, "run", lambda *a, **kw: result)


class TestAnUnreachableHostIsNotAFinding:
    def test_a_refused_connection_is_not_success(self, tool, monkeypatch):
        _run(monkeypatch, _Result(
            returncode=1,
            stderr="do_connect: Connection to 10.0.0.9 failed "
                   "(Error NT_STATUS_CONNECTION_REFUSED)",
        ))

        result = tool.smb_enum(target="10.0.0.9")

        assert result["success"] is False
        assert "NT_STATUS_CONNECTION_REFUSED" in result["error"]
        assert result["return_code"] == 1

    def test_a_refused_connection_claims_no_null_session(self, tool, monkeypatch):
        """The claim that mattered: it read as 'anonymous access allowed'."""
        _run(monkeypatch, _Result(returncode=1, stderr="connection refused"))

        result = tool.smb_enum(target="10.0.0.9")

        assert result["null_session"] is False, (
            "no session was established, so this must not assert one"
        )

    def test_the_attempt_is_still_recorded_separately(self, tool, monkeypatch):
        """Knowing an anonymous attempt was made is useful; it is just not the
        same fact as the attempt having worked."""
        _run(monkeypatch, _Result(returncode=1, stderr="connection refused"))

        result = tool.smb_enum(target="10.0.0.9")

        assert result["null_session_attempted"] is True


class TestARealAnonymousSessionIsReported:
    def test_a_successful_anonymous_listing_sets_null_session(self, tool, monkeypatch):
        _run(monkeypatch, _Result(returncode=0, stdout=LISTING))

        result = tool.smb_enum(target="10.0.0.9")

        assert result["success"] is True
        assert result["null_session"] is True
        assert result["null_session_attempted"] is True

    def test_the_shares_come_back(self, tool, monkeypatch):
        _run(monkeypatch, _Result(returncode=0, stdout=LISTING))

        names = {s["name"] for s in tool.smb_enum(target="10.0.0.9")["shares"]}

        assert "sweepshare" in names

    def test_authenticated_enumeration_claims_no_null_session(self, tool, monkeypatch):
        """Credentials were supplied, so nothing anonymous happened at all."""
        _run(monkeypatch, _Result(returncode=0, stdout=LISTING))

        result = tool.smb_enum(target="10.0.0.9", username="bob", password="pw")

        assert result["null_session"] is False
        assert result["null_session_attempted"] is False
        assert result["success"] is True
