"""Agent-facing contracts for the tool surface.

FastMCP turns each tool's docstring into the description an agent reads when it
chooses between 132 tools. These checks are deterministic proxies for the
failure modes that only show up at agent level: a tool nobody can tell apart
from its neighbour, or a required argument whose origin is never stated.
"""

import collections
import inspect
import re

import pytest

from mcp_tools import register_all


class _Recording:
    """Capture registrations in order; a dict alone would hide name collisions."""

    def __init__(self):
        self.tools = {}
        self.registered_names = []

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            resolved = name or function.__name__
            self.registered_names.append(resolved)
            self.tools[resolved] = function
            return function

        return decorator


def _register_everything():
    recording = _Recording()
    register_all(recording, object(), "full", None)
    return recording


def _duplicates(names):
    """Return the names registered more than once."""
    counts = collections.Counter(names)
    return sorted(name for name, count in counts.items() if count > 1)


_RECORDING = _register_everything()
TOOLS = _RECORDING.tools


def _words(text: str) -> set[str]:
    """Identifier-like tokens, so a short name is not matched inside a longer word."""
    return set(re.findall("[A-Za-z_][A-Za-z0-9_]*", text))


def _doc(function) -> str:
    return (function.__doc__ or "").strip()


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_every_tool_has_a_usable_description(name):
    doc = _doc(TOOLS[name])

    assert doc, f"{name} has no docstring, so an agent sees no description"
    assert len(doc) >= 25, f"{name} description is too terse to choose on: {doc!r}"


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_every_required_argument_is_named_in_the_description(name):
    function = TOOLS[name]
    doc = _doc(function)

    undocumented = [
        parameter
        for parameter, spec in inspect.signature(function).parameters.items()
        if spec.default is inspect.Parameter.empty
        and parameter not in _words(doc)
    ]

    assert not undocumented, (
        f"{name} requires {undocumented} but never names them in its description, "
        "so an agent cannot tell what to pass or where the value comes from"
    )


def test_no_two_tools_share_an_opening_line():
    openings = collections.defaultdict(list)
    for name, function in TOOLS.items():
        doc = _doc(function)
        if doc:
            openings[doc.splitlines()[0].strip()].append(name)

    duplicates = {line: names for line, names in openings.items() if len(names) > 1}

    assert not duplicates, f"indistinguishable tool descriptions: {duplicates}"


def test_tool_names_are_unique_across_every_module():
    duplicates = _duplicates(_RECORDING.registered_names)

    assert not duplicates, f"tool names registered by more than one module: {duplicates}"
    assert len(_RECORDING.registered_names) == 132


def test_the_duplicate_detector_actually_detects_duplicates():
    """Guard the guard: a collision must be reported by name, not absorbed."""
    assert _duplicates(["a", "b", "a", "c", "c"]) == ["a", "c"]
    assert _duplicates(["a", "b", "c"]) == []


def test_word_matching_does_not_accept_a_name_inside_a_longer_word():
    """`ip` must not count as documented merely because `description` contains it."""
    assert "ip" not in _words("description of the recipient script")
    assert "ip" in _words("ip: the target address")


def test_exec_stream_is_not_sold_as_the_long_running_tool():
    """exec_stream does not stream to the agent and does not evade the harness
    abort: SSE runs between our client and the backend, so the harness sees one
    request and one response and gives up at the same point a synchronous call
    does. Recommending it for nmap and fuzzing pointed agents at the one tool
    that registers no job and cannot be cancelled.

    Written to the invariant rather than the wording: what must be gone is the
    long-running claim, and what must be present is the background route out.
    """
    doc = _doc(TOOLS["exec_stream"]).lower()

    assert "long-running" not in doc, "still advertised for long-running commands"
    assert "nmap, nuclei" not in doc, "still names the tools it is worst at"
    assert "background" in doc, "does not point at the background route"
    assert "job_" in doc or "job_status" in doc, "names no job tool to drive"
