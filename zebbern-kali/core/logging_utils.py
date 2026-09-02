"""Small helpers for rendering commands in logs and response metadata."""

import shlex
from collections.abc import Sequence


def render_command(command) -> str:
    """Render a command exactly as it was run.

    Nothing is masked. This tool runs on the operator's own machine against
    their own targets, so its logs and responses are their own information --
    hiding a credential here would only hide it from the person holding it,
    while making a failed command harder to reproduce and risking a rewrite
    that no longer matches what actually executed.
    """
    if isinstance(command, str):
        return command
    if isinstance(command, Sequence):
        return shlex.join(str(part) for part in command)
    return str(command)
