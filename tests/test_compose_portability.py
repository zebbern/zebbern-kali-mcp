"""A resource limit the host cannot satisfy stops the container from starting.

`cpus` is validated against the host's core count, and Docker refuses outright
rather than clamping:

    range of CPUs is from 0.01 to 4.00, as there are only 4 CPUs available

An 8.0 cap, added to give headless Chrome headroom, failed every integration
run on a 4-core GitHub runner -- and would fail the same way for any user on
fewer cores than whoever last edited the file. The container never boots, so
this reads as a broken image rather than a compose setting.

Uncapped is both more headroom than any number and portable, so the fix was to
delete the cap, not to pick a smaller one. These guard against a fixed cap
coming back, and against the same shape appearing in the host-network variant.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
COMPOSE_FILES = [REPO / "docker-compose.yml", REPO / "docker-compose.host.yml"]


def _limits_block(text):
    """The lines under deploy.resources.limits, without pulling in a YAML dep."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == "limits:":
            indent = len(line) - len(line.lstrip())
            block = []
            for following in lines[index + 1:]:
                if following.strip() and (len(following) - len(following.lstrip())) <= indent:
                    break
                block.append(following)
            return block
    return []


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_no_fixed_cpu_cap(path):
    if not path.exists():
        pytest.skip(f"{path.name} is not present")
    settings = [
        line.strip()
        for line in _limits_block(path.read_text(encoding="utf-8"))
        if line.strip() and not line.strip().startswith("#")
    ]

    offenders = [line for line in settings if line.startswith("cpus:")]

    assert not offenders, (
        f"{path.name} pins {offenders[0]!r}; Docker refuses to start the "
        "container on any host with fewer cores, which is how CI broke"
    )


def test_the_shm_size_that_gowitness_needs_is_still_there():
    """The other half of the same change, and the one that actually fixed the
    empty screenshots. Docker's 64MB default is where Chrome maps renderer
    shared memory, and it failed by writing no image while exiting 0."""
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")

    assert "shm_size:" in text
