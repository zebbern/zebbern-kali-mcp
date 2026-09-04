"""The AD tools reported findings they had not obtained.

Swept by pointing each at a host running no domain controller and reading the
reply -- the same method that caught ad_smb_enum. Four of the eight were wrong,
and the AD family is the one where being wrong is most expensive: these run
against a client's DC mid-engagement, and their output goes into a report.

    ad_kerberoast     success: true, spns_found: 0      "no kerberoastable accounts"
    ad_secretsdump    success: true, ntds_total: 0      "the DC has no secrets"
    ad_password_spray valid_credentials: 3 entries      credentials that do not exist
    ad_wmiexec        died on its own argument parsing  could never run at all

The first two share a root cause: impacket scripts exit 0 when they cannot
connect, printing the reason to stdout as "[-] ...", so a return code of zero
means nothing. Measured:

    GetUserSPNs  exit=0  [-] [Errno Connection error (...:389)]
    secretsdump  exit=0  [-] RemoteOperations failed: DCERPC Runtime Error

The rule used here does not over-fit: results present is a success whatever
impacket grumbled, and no results plus an error line is a failure. A benign
warning alongside a real dump still succeeds.

The spray was the worst of them. netexec marks a guest-mapped login [+] like
any other hit, and every [+] was taken as a valid credential. Against a Samba
host with "map to guest = Bad User" -- which accepts any username and any
password -- a three-name spray reported three valid domain credentials, every
line ending "(Guest)". Inventing credentials is the worst answer this tool can
give.
"""

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core import ad_tools as ad  # noqa: E402

SPRAY_OUTPUT = (
    "SMB  127.0.0.1  445  HOST  [*] Unix - Samba (name:HOST) (Null Auth:True)\n"
    "SMB  127.0.0.1  445  HOST  [+] corp.local\\alice:Spring2026! (Guest)\n"
    "SMB  127.0.0.1  445  HOST  [+] corp.local\\bob:Spring2026! (Guest)\n"
    "SMB  127.0.0.1  445  HOST  [+] corp.local\\real:Spring2026!\n"
    "SMB  127.0.0.1  445  HOST  [+] corp.local\\adm:Spring2026! (Pwn3d!)\n"
)


class TestGuestIsNotACredential:
    def test_a_guest_mapped_login_is_not_a_valid_credential(self):
        for line in SPRAY_OUTPUT.splitlines():
            if "(Guest)" in line:
                assert ad._is_real_hit(line) is False, (
                    f"a guest mapping is not a credential: {line!r}"
                )

    def test_a_genuine_hit_still_counts(self):
        real = [l for l in SPRAY_OUTPUT.splitlines()
                if "real:" in l or "Pwn3d" in l]

        assert real, "fixture lost its genuine hits"
        for line in real:
            assert ad._is_real_hit(line) is True, f"dropped a real hit: {line!r}"

    def test_an_informational_line_is_not_a_hit(self):
        assert ad._is_real_hit("SMB 127.0.0.1 445 HOST [*] Unix - Samba") is False

    def test_a_failed_login_is_not_a_hit(self):
        assert ad._is_real_hit("SMB 127.0.0.1 445 HOST [-] corp.local\\x:y") is False

    def test_only_the_genuine_hits_survive_a_whole_spray(self):
        kept = [l for l in SPRAY_OUTPUT.splitlines() if ad._is_real_hit(l)]

        assert len(kept) == 2, (
            f"expected the two real hits, kept {len(kept)}: {kept!r}"
        )


class TestImpacketExitCodesAreNotEvidence:
    """impacket exits 0 having failed, so the [-] lines are what matter."""

    def _impacket(self, monkeypatch, stdout, returncode=0):
        class _Result:
            pass

        res = _Result()
        res.returncode = returncode
        res.stdout = stdout
        res.stderr = ""
        monkeypatch.setattr(ad.subprocess, "run", lambda *a, **kw: res)
        monkeypatch.setattr(ad.os.path, "exists", lambda p: True)

    def test_the_error_lines_are_surfaced(self, monkeypatch, tmp_path):
        tool = object.__new__(ad.ADTools)
        tool.impacket_path = str(tmp_path)
        self._impacket(
            monkeypatch,
            "Impacket v0.13.0\n[-] [Errno Connection error (corp.local:389)]\n",
        )

        result = tool._run_impacket("GetUserSPNs", ["corp.local/u:p@10.0.0.1"])

        assert result["tool_errors"] == [
            "[-] [Errno Connection error (corp.local:389)]"
        ], "without these the caller cannot tell a failure from an empty result"

    def test_clean_output_reports_no_errors(self, monkeypatch, tmp_path):
        tool = object.__new__(ad.ADTools)
        tool.impacket_path = str(tmp_path)
        self._impacket(monkeypatch, "Impacket v0.13.0\nServicePrincipalName  Name\n")

        result = tool._run_impacket("GetUserSPNs", ["corp.local/u:p@10.0.0.1"])

        assert result["tool_errors"] == []


class TestWmiexecCanActuallyRunACommand:
    def test_the_command_is_positional(self):
        """It was sent as -c, which wmiexec rejects outright:
        `error: ambiguous option: -c could match -codec, -com-version`."""
        source = (BACKEND_ROOT / "core" / "ad_tools.py").read_text(encoding="utf-8")
        start = source.index("def wmiexec") if "def wmiexec" in source else None
        if start is None:
            start = source.index("wmiexec")
        window = source[start:start + 3000]

        assert 'args.extend(["-c", command])' not in window, (
            "wmiexec takes the command as a positional argument"
        )


def test_asreproast_can_be_given_the_password_its_username_needs():
    """The backend authenticates only when it has both, so a username with no
    way to pass a password was a dead argument."""
    wrapper = (Path(__file__).resolve().parents[1]
               / "mcp_tools" / "ad_tools.py").read_text(encoding="utf-8")
    start = wrapper.index("def ad_asreproast")
    signature = wrapper[start:wrapper.index(")", start)]

    assert "password" in signature, "username alone is silently ignored"
