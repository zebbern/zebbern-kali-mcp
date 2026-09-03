"""Two of the three DNS payloads callback_generate hands out did not work.

These are copy-paste commands. A malformed one does not fail loudly -- it costs
the operator the conclusion, because a lookup that never leaves the box looks
exactly like a target that did not call back. Run against a live listener:

    nslookup <tag>.test <ip> -port=5353   -> printed its usage message, no query
    host <tag>.test <ip>                  -> went to port 53, connection refused

nslookup takes its options before the host on Linux, and host has no positional
port argument at all. The corrected forms both resolved and both landed in the
catcher; the originals contributed nothing to a capture of nine callbacks.

dig was always right, which is why the other two went unnoticed -- anyone who
tried dig first would conclude the whole family worked.
"""

import re
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "zebbern-kali"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from core.callback_catcher import CallbackCatcher  # noqa: E402

LISTENER = "10.10.14.5"
DNS_PORT = 5353


@pytest.fixture(scope="module")
def dns_payloads():
    result = CallbackCatcher.generate_payload(
        listener_ip=LISTENER, dns_port=DNS_PORT, payload_type="dns"
    )
    return result["payloads"]["dns"]


def test_nslookup_puts_its_options_before_the_host(dns_payloads):
    """Trailing options make nslookup print usage and exit without querying."""
    command = dns_payloads["nslookup"]
    tokens = command.split()

    assert tokens[0] == "nslookup"
    assert tokens[1] == f"-port={DNS_PORT}", (
        f"the port option must precede the host: {command!r}"
    )
    assert tokens[-2].endswith(".test")
    assert tokens[-1] == LISTENER


def test_host_is_told_which_port_to_use(dns_payloads):
    """Without -p it queries 53, where the catcher is not listening."""
    command = dns_payloads["host"]

    assert f"-p {DNS_PORT}" in command, (
        f"host has no positional port, so this went to 53: {command!r}"
    )
    assert command.split()[0] == "host"


def test_dig_still_targets_the_listener_and_port(dns_payloads):
    """The one that was always correct."""
    command = dns_payloads["dig"]

    assert f"@{LISTENER}" in command
    assert f"-p {DNS_PORT}" in command


@pytest.mark.parametrize("tool", ["nslookup", "dig", "host"])
def test_every_dns_command_carries_the_listener_and_the_port(dns_payloads, tool):
    """A command that reaches the default resolver on the default port is
    indistinguishable, to the operator, from a target that stayed quiet."""
    command = dns_payloads[tool]

    assert LISTENER in command, f"{tool} does not name the listener: {command!r}"
    assert str(DNS_PORT) in command, f"{tool} does not name the port: {command!r}"


def test_all_dns_commands_share_the_generated_identifier(dns_payloads):
    tag = dns_payloads["identifier"]

    for tool in ("nslookup", "dig", "host"):
        assert f"{tag}.test" in dns_payloads[tool], (
            f"{tool} would not be matched by callback_check({tag!r})"
        )


def test_a_non_default_port_reaches_every_command():
    """The port is interpolated in three places; a hardcoded one would only
    show up against a non-default listener."""
    payloads = CallbackCatcher.generate_payload(
        listener_ip=LISTENER, dns_port=15353, payload_type="dns"
    )["payloads"]["dns"]

    for tool in ("nslookup", "dig", "host"):
        assert "15353" in payloads[tool], f"{tool} ignored the port"
        assert not re.search(r"\b5353\b", payloads[tool]), f"{tool} hardcodes 5353"


class TestCallbackWaitFitsUnderTheHarnessAbort:
    """callback_wait polls client-side, so the whole wait happens inside one
    tool call and the MCP harness's ~60s abort is a hard ceiling on it.

    Its default was exactly 60, which races that abort, and its own docstring
    suggested 120 -- a value that can never return the tool's answer. A harness
    timeout cannot be told apart from "nothing called back", which is the one
    distinction this tool exists to make.
    """

    WRAPPER = (
        Path(__file__).resolve().parents[1] / "mcp_tools" / "callback_catcher.py"
    ).read_text(encoding="utf-8")

    def _signature(self):
        start = self.WRAPPER.index("def callback_wait")
        return self.WRAPPER[start:self.WRAPPER.index(")", start)]

    def _docstring(self):
        start = self.WRAPPER.index("def callback_wait")
        first = self.WRAPPER.index('"""', start)
        return self.WRAPPER[first:self.WRAPPER.index('"""', first + 3)]

    def test_the_default_wait_is_under_the_abort(self):
        match = re.search(r"timeout_seconds: int = (\d+)", self._signature())

        assert match, "callback_wait lost its timeout_seconds default"
        assert int(match.group(1)) <= 50, (
            "a default at or above ~60 races the harness abort and loses the "
            "tool's own timeout message"
        )

    def test_no_example_suggests_a_value_that_cannot_return(self):
        doc = self._docstring()
        suggested = [
            int(n) for n in re.findall(r"callback_wait\(timeout_seconds=(\d+)", doc)
        ]

        assert suggested, "the example calls disappeared"
        assert all(value <= 50 for value in suggested), (
            f"an example suggests {suggested}, which the harness abandons"
        )

    def test_the_ceiling_is_explained_rather_than_just_applied(self):
        """An agent that does not know why will raise it back."""
        doc = self._docstring()

        assert "harness" in doc
        assert "callback_check" in doc, (
            "it should say how to watch longer -- callbacks are stored, so "
            "polling again misses nothing"
        )
