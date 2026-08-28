"""Small helpers for useful diagnostics without credential disclosure."""

import re
import shlex
from collections.abc import Sequence


REDACTED = "[REDACTED]"

_FLAG_SECRET = re.compile(
    r"(?i)(?P<flag>"
    r"(?:--(?:password|passwd|pass|token|api[-_]?token|api[-_]?key|auth[-_]?token|access[-_]?token|secret|hash|hashes|nthash|lmhash)"
    r"|-(?:p|w|hashes))"
    r"(?:\s+|=))"
    r"(?P<value>'[^']*'|\"[^\"]*\"|\S+)"
)
_SHORT_ATTACHED_SECRET = re.compile(
    r"(?i)(?<!\S)(?P<flag>-(?:p|w))(?P<value>[^\s=]\S*)"
)
_URL_CREDENTIAL = re.compile(
    r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)"
    r"(?P<value>\S+)"
    r"(?P<suffix>@(?:\[[^\]]+\]|[^/\s:]+)(?::\d+)?)"
)
_EMBEDDED_CREDENTIAL = re.compile(
    r"(?P<identity>(?:[A-Za-z0-9_.-]+[/\\])?[A-Za-z0-9_.-]+):"
    r"(?!//)"
    r"(?P<value>\S+)"
    r"(?P<suffix>@(?:\[[^\]]+\]|[A-Za-z0-9_.-]+)(?::\d+)?)"
)
_SMB_CREDENTIAL = re.compile(
    r"(?P<identity>[A-Za-z0-9_.\\/-]+)%[^'\"\s]+"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)(?P<name>kali_api_token|password|passwd|token|api[_-]?(?:token|key)|auth[_-]?token|access[_-]?token|secret)="
    r"(?P<value>[^&\s]+)"
)


def redact_command(command) -> str:
    """Render a command while replacing common credential argument forms."""
    if isinstance(command, str):
        rendered = command
    elif isinstance(command, Sequence):
        rendered = shlex.join(str(part) for part in command)
    else:
        rendered = str(command)

    rendered = _FLAG_SECRET.sub(lambda match: f"{match.group('flag')}{REDACTED}", rendered)
    rendered = _SHORT_ATTACHED_SECRET.sub(
        lambda match: f"{match.group('flag')}{REDACTED}",
        rendered,
    )
    rendered = _URL_CREDENTIAL.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}{match.group('suffix')}",
        rendered,
    )
    rendered = _EMBEDDED_CREDENTIAL.sub(
        lambda match: f"{match.group('identity')}:{REDACTED}{match.group('suffix')}",
        rendered,
    )
    rendered = _SMB_CREDENTIAL.sub(
        lambda match: f"{match.group('identity')}%{REDACTED}",
        rendered,
    )
    return _ASSIGNMENT_SECRET.sub(
        lambda match: f"{match.group('name')}={REDACTED}",
        rendered,
    )
