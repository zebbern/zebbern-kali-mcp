"""Cross-track drift guard on the auto-promoted tool set.

``PROMOTED_TOOLS`` lives in the wheel; ``TOOL_TIMEOUTS`` lives in the image.
The two release tracks move independently, so nothing but this stops a tool
being auto-promoted after its budget drops into the quick-lookup tier -- where
a 50s inline wait plus a job handle is pure overhead on a call that answers in
two seconds.

``tool_config.py`` imports only ``os`` and ``shlex``, so it loads on Windows
where the rest of the backend cannot. It is loaded by path rather than by
package import to keep this file independent of ``sys.path`` order.
"""

import importlib.util
from pathlib import Path

from mcp_tools._autopromote import PROMOTED_TOOLS

TOOL_CONFIG_PATH = (
    Path(__file__).resolve().parents[1] / "zebbern-kali" / "core" / "tool_config.py"
)

# The tier a promoted tool must be in: a backstop for a hung process, not a
# budget for a slow one. Below this a tool is a quick lookup and promoting it
# would trade a fast answer for a job handle.
PROMOTION_FLOOR = 3600


def _tool_config():
    spec = importlib.util.spec_from_file_location(
        "tested_tool_config", TOOL_CONFIG_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_promoted_tool_is_actually_a_3600plus_tier_tool():
    timeouts = _tool_config().TOOL_TIMEOUTS

    for name in PROMOTED_TOOLS:
        assert timeouts.get(name, 0) >= PROMOTION_FLOOR, (
            f"{name} auto-promotes but its TOOL_TIMEOUTS tier is "
            f"{timeouts.get(name)!r}, below the {PROMOTION_FLOOR}s floor"
        )


def test_a_promoted_tool_has_an_explicit_entry_not_the_default():
    """"Falls through to the 3600 default" is not the same claim as "is a
    long-running tool". The default is a backstop for everything unlisted, so
    inheriting it proves nothing about the tool."""
    timeouts = _tool_config().TOOL_TIMEOUTS

    for name in PROMOTED_TOOLS:
        assert name in timeouts, f"{name} auto-promotes on the default tier alone"


def test_the_promoted_set_is_the_expected_fourteen():
    assert set(PROMOTED_TOOLS) == {
        "nmap", "nikto", "gobuster", "wpscan", "sqlmap", "hydra", "masscan",
        "katana", "amass",
        "arjun", "fierce", "enum4linux", "gowitness", "john",
    }


def test_the_heavy_flag_matches_the_client_semaphore_group():
    """The nine that share MAX_HEAVY_TASKS = 5, and the five that do not."""
    heavy = {name for name, is_heavy in PROMOTED_TOOLS.items() if is_heavy}

    assert heavy == {
        "nmap", "nikto", "gobuster", "wpscan", "sqlmap", "hydra", "masscan",
        "katana", "amass",
    }
