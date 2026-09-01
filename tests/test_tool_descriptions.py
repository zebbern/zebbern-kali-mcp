"""Agent-facing contracts for the tool surface.

FastMCP turns each tool's docstring into the description an agent reads when it
chooses between 131 tools. These checks are deterministic proxies for the
failure modes that only show up at agent level: a tool nobody can tell apart
from its neighbour, or a required argument whose origin is never stated.
"""

import collections
import inspect

import pytest

from mcp_tools import register_all


class _Recording:
    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **_kwargs):
        def decorator(function):
            self.tools[name or function.__name__] = function
            return function

        return decorator


def _all_tools():
    recording = _Recording()
    register_all(recording, object(), "full", None)
    return recording.tools


TOOLS = _all_tools()


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
        if spec.default is inspect.Parameter.empty and parameter not in doc
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
    assert len(TOOLS) == 131
