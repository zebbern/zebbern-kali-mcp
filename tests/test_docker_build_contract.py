"""Static contracts for the qualified Docker build graph.

These checks intentionally run against the source files.  Dockerfile source
policy is the contract at this stage; later tasks pair it with Docker's parser
and live-build checks.
"""

import re
import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
WORKFLOW = ROOT / ".github" / "workflows" / "docker-publish.yml"


GO_SELECTORS = (
    ("NUCLEI_VERSION", "v3.11.1", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
    ("HTTPX_VERSION", "v1.10.0", "github.com/projectdiscovery/httpx/cmd/httpx"),
    ("SUBFINDER_VERSION", "v2.16.0", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
    ("FFUF_VERSION", "v2.2.1", "github.com/ffuf/ffuf/v2"),
    ("ASSETFINDER_VERSION", "v0.1.1", "github.com/tomnomnom/assetfinder"),
    ("WAYBACKURLS_VERSION", "v0.1.0", "github.com/tomnomnom/waybackurls"),
    (
        "GOWITNESS_VERSION",
        "v0.0.0-20260422172756-4f562901bc23",
        "github.com/sensepost/gowitness",
    ),
    ("CHISEL_GO_VERSION", "v1.11.8", "github.com/jpillora/chisel"),
    ("SUBZY_VERSION", "v1.2.1", "github.com/PentestPad/subzy"),
    (
        "INTERACTSH_VERSION",
        "v1.3.1",
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client",
    ),
    (
        "INTERACTSH_VERSION",
        "v1.3.1",
        "github.com/projectdiscovery/interactsh/cmd/interactsh-server",
    ),
    ("DALFOX_VERSION", "v2.13.0", "github.com/hahwul/dalfox/v2"),
    ("GETJS_VERSION", "v1.0.0", "github.com/003random/getJS"),
    (
        "JSLUICE_VERSION",
        "v0.0.0-20240110145140-0ddfab153e06",
        "github.com/BishopFox/jsluice/cmd/jsluice",
    ),
    ("MAPCIDR_VERSION", "v1.1.97", "github.com/projectdiscovery/mapcidr/cmd/mapcidr"),
)

GIT_REFS = (
    (
        "PETITPOTAM_REF",
        "c5d5221dc5e6aac3bc7de97a34fa8d89c2f1900b",
        "https://github.com/topotam/PetitPotam.git",
        "/opt/PetitPotam",
    ),
    (
        "BYP4XX_REF",
        "b337580a3a62f9af604ad29e12161573bf3c36ed",
        "https://github.com/lobuhi/byp4xx.git",
        "/opt/byp4xx",
    ),
    (
        "WINRMEXEC_REF",
        "a2a5e0f1770ad8deca7e982a7afd2a0d45e41a5b",
        "https://github.com/ozelis/winrmexec.git",
        "/opt/winrmexec",
    ),
    (
        "KRBRELAYX_REF",
        "10b45a33bc4361ec4a5546eea62db2e4244d3255",
        "https://github.com/dirkjanm/krbrelayx.git",
        "/opt/krbrelayx",
    ),
    (
        "GMSADUMPER_REF",
        "e03187ca5c2b38b8742a20b919ebe38633c0b084",
        "https://github.com/micahvandeusen/gMSADumper.git",
        "/opt/gMSADumper",
    ),
    (
        "GHAURI_REF",
        "18e367781caca5f9783a242f34aa90164edc902a",
        "https://github.com/r0oth3x49/ghauri.git",
        "/opt/ghauri",
    ),
    (
        "JWT_TOOL_REF",
        "3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b",
        "https://github.com/ticarpi/jwt_tool.git",
        "/opt/jwt_tool",
    ),
    (
        "GRAPHW00F_REF",
        "4901f824140a2da168876412593c213afbdd75fb",
        "https://github.com/dolevf/graphw00f.git",
        "/opt/graphw00f",
    ),
    (
        "PARAMSPIDER_REF",
        "c44bdaae54789b237028e309b603d1aa5ad52e5e",
        "https://github.com/devanshbatham/paramspider.git",
        "/opt/paramspider",
    ),
    (
        "SECRETFINDER_REF",
        "d06119dedd9c1505137d1ec4792d5d5b65c7425d",
        "https://github.com/m4ll0k/SecretFinder.git",
        "/opt/SecretFinder",
    ),
    (
        "RSACTFTOOL_REF",
        "af87bb487666b1bf3070e1bb058d97b78a342808",
        "https://github.com/RsaCtfTool/RsaCtfTool.git",
        "/opt/RsaCtfTool",
    ),
    (
        "CADO_NFS_REF",
        "4a6af6c97c2874d95f27c80c305ce34e09977a03",
        "https://gitlab.inria.fr/cado-nfs/cado-nfs.git",
        "/opt/cado-nfs",
    ),
)

BINARY_HASHES = (
    (
        "nc64.exe",
        "NC64_SHA256",
        "3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571",
        "/opt/windows/nc64.exe",
    ),
    (
        "cloudflared",
        "CLOUDFLARED_SHA256",
        "fcfb02b575a52ca1af2e3267af4e1517bcdeb30ac48c834c69abaed3c0576ad2",
        "/usr/local/bin/cloudflared",
    ),
    (
        "ngrok",
        "NGROK_SHA256",
        "e4e0f05c3b016699daa3fc4ff03d0870e49f705171d2dac5f16d00c55c10dee5",
        "/usr/local/bin/ngrok",
    ),
    (
        "linpeas.sh",
        "LINPEAS_SHA256",
        "f26df15f977c63f3b09ed8012bcb309636c333ad588e4518bb904f75856fa249",
        "/opt/privesc-tools/linpeas.sh",
    ),
    (
        "winPEASx64.exe",
        "WINPEASX64_SHA256",
        "def3b9b40e3ab71d863a4b1f4b57a4a0020b749ff2ba4c04d3b72c4f963f83bd",
        "/opt/privesc-tools/winPEASx64.exe",
    ),
    (
        "winPEASx86.exe",
        "WINPEASX86_SHA256",
        "dec47f3d67ca7997542a5d9f147e74db067159499f2cd69942aad9ed5276091c",
        "/opt/privesc-tools/winPEASx86.exe",
    ),
    (
        "winPEAS.bat",
        "WINPEAS_BAT_SHA256",
        "11e4ea92ce2465f3d30c5a56fd4aeba2aecaf4d1c2670ac42bd61c4db2becf87",
        "/opt/privesc-tools/winPEAS.bat",
    ),
)

STANDALONE_SELECTORS = (
    ("TruffleHog", "TRUFFLEHOG_VER", "3.88.24", "trufflesecurity/trufflehog/releases/download", "v"),
    ("Katana", "KATANA_VER", "1.1.0", "projectdiscovery/katana/releases/download", "v"),
    ("Ligolo-ng", "LIGOLO_VER", "0.7.5", "nicocha30/ligolo-ng/releases/download", "v"),
    ("Chisel Windows", "CHISEL_VER", "1.10.1", "jpillora/chisel/releases/download", "v"),
    ("RunasCs", "RUNAS_VER", "1.5", "antonioCoco/RunasCs/releases/download", "v"),
    ("cloudflared", "CFVER", "2026.8.2", "cloudflare/cloudflared/releases/download", ""),
    ("ngrok", "NGROK_VERSION", "3.39.11", "bin.equinox.io/c/bNyj1mQVY4c", None),
    ("PEASS-ng", "PEAS_VER", "20260824-c1d29dcd", "peass-ng/PEASS-ng/releases/download", ""),
    ("Mimikatz", "MIMI_VER", "2.2.0-20220919", "gentilkiwi/mimikatz/releases/download", ""),
    ("Caido fallback", "CAIDO_VER", "0.58.2", "caido.download/releases", "v"),
)

NC64_COMMIT = "fa87aa42c460d34966efb998a1788efca6db11a7"
NC64_DESTINATION = "/opt/windows/nc64.exe"
EXPECTED_BASE_FROM = (
    "FROM kalilinux/kali-rolling@sha256:"
    "ef7a551400b01dc501ff97f192c5b2b1ec629576dab5032822190cd2684ca4e1"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shell_variable(argument: str) -> str:
    """Match either valid Dockerfile shell spelling: $NAME or ${NAME}."""
    escaped = re.escape(argument)
    return rf"\$(?:\{{{escaped}\}}|{escaped})"


def _shell_commands(run_instruction: str) -> list[list[str]]:
    """Tokenize simple RUN command chains while honoring shell comments."""
    _, _, body = run_instruction.partition(" ")
    lexer = shlex.shlex(body, posix=True, punctuation_chars=";&|()")
    lexer.commenters = "#"
    lexer.whitespace_split = True
    commands = []
    command = []
    for token in lexer:
        if token and all(character in ";&|()" for character in token):
            if command:
                commands.append(command)
                command = []
        else:
            command.append(token)
    if command:
        commands.append(command)
    return commands


def _output_option(arguments: list[str], short: str, long: str) -> str | None:
    """Return a downloader output option, including common short-option clusters."""
    for index, argument in enumerate(arguments):
        if argument == long:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith(f"{long}="):
            return argument.partition("=")[2]
        match = re.fullmatch(rf"-[A-Za-z]*{re.escape(short)}(?P<value>.*)", argument)
        if match is not None:
            value = match.group("value")
            return value or (arguments[index + 1] if index + 1 < len(arguments) else None)
    return None


def _is_download_command(command: list[str], url: str, destination: str) -> bool:
    """Match an actual wget/curl command that binds one URL to its output path."""
    if not command:
        return False
    executable = command[0].rsplit("/", 1)[-1]
    arguments = command[1:]
    if executable == "wget":
        output = _output_option(arguments, "O", "--output-document")
    elif executable == "curl":
        output = _output_option(arguments, "o", "--output")
    else:
        return False
    return url in arguments and output == destination


def test_variant_split_follows_all_common_expensive_layers():
    """Regression: a lean build must not split before shared expensive layers."""
    text = _read(DOCKERFILE)
    for marker in ("ARG INCLUDE_CADO_NFS=true", "ARG INCLUDE_METASPLOIT=true", "COPY zebbern-kali/"):
        assert marker in text, f"Dockerfile is missing required layer marker: {marker}"
    assert text.index("ARG INCLUDE_CADO_NFS=true") < text.index("ARG INCLUDE_METASPLOIT=true")
    assert text.index("ARG INCLUDE_METASPLOIT=true") < text.index("COPY zebbern-kali/")


def test_defaulted_build_args_are_adjacent_to_their_first_consuming_instruction():
    """Pin updates must invalidate only the layer that consumes each build argument."""
    instructions = _logical_docker_instructions(_read(DOCKERFILE))
    stages = _docker_instruction_stages(instructions)
    misplaced = []

    for declaration_index, instruction in enumerate(instructions):
        if not instruction.startswith("ARG "):
            continue
        [(variable, value)] = _docker_variable_assignments(instruction)
        if value is None or stages[declaration_index] < 0:
            continue

        consumers = [
            index
            for index in range(declaration_index + 1, len(instructions))
            if stages[index] == stages[declaration_index]
            and _instruction_uses_variable(instructions[index], variable)
        ]
        if not consumers:
            misplaced.append(f"{variable}: no consuming instruction")
            continue

        first_consumer = consumers[0]
        intervening = instructions[declaration_index + 1:first_consumer]
        if any(not candidate.startswith("ARG ") for candidate in intervening):
            misplaced.append(
                f"{variable}: non-ARG instruction between declaration and "
                f"{instructions[first_consumer].split(maxsplit=1)[0]} consumer"
            )

    assert not misplaced, (
        "defaulted build ARGs must be in the contiguous ARG block immediately before "
        "their first consuming instruction: " + "; ".join(misplaced)
    )


def test_direct_sources_are_not_moving_targets():
    """Regression: a rebuild must not silently consume moving upstream content."""
    text = _read(DOCKERFILE)
    executable_text = "\n".join(_logical_docker_instructions(text))
    assert "@latest" not in executable_text
    assert "/releases/latest" not in executable_text
    assert "/master/nc64.exe" not in executable_text
    assert "/main/" not in executable_text
    assert "/master/" not in executable_text
    assert "refs/heads/" not in executable_text
    assert not re.search(r"\bgit\s+clone\b", executable_text), "default-branch git clones are moving sources"
    assert "git clone --depth 1" not in executable_text
    nc64_url = "https://raw.githubusercontent.com/int0x33/nc.exe/${NC64_COMMIT}/nc64.exe"
    nc64_downloads = [
        (index, command)
        for index, instruction in enumerate(_logical_docker_instructions(text))
        if instruction.startswith("RUN ")
        for command in _shell_commands(instruction)
        if _is_download_command(command, nc64_url, NC64_DESTINATION)
    ]
    assert len(nc64_downloads) == 1, (
        "nc64 must download the qualified commit-addressed ARG URL exactly once with "
        f"wget or curl to {NC64_DESTINATION}"
    )
    instructions = _logical_docker_instructions(text)
    assert _qualified_arg_is_visible(
        instructions, "NC64_COMMIT", NC64_COMMIT, [nc64_downloads[0][0]]
    ), "nc64 must consume the qualified NC64_COMMIT ARG in the build stage"


def test_kali_base_and_go_tools_use_the_qualified_versions():
    """Regression: a rebuild must use the qualified base and every Go selector."""
    text = _read(DOCKERFILE)
    instructions = _logical_docker_instructions(text)
    from_instructions = [
        instruction for instruction in instructions if instruction.startswith("FROM ")
    ]
    assert from_instructions == [EXPECTED_BASE_FROM], (
        "the single executable FROM instruction must use the qualified Kali base digest"
    )

    missing = []
    for argument, version, package in GO_SELECTORS:
        install = rf"go install -v {re.escape(package)}@{_shell_variable(argument)}"
        consumers = [
            index
            for index, instruction in enumerate(instructions)
            if instruction.startswith("RUN ") and re.search(install, instruction)
        ]
        if len(consumers) != 1 or not _qualified_arg_is_visible(
            instructions, argument, version, consumers
        ):
            missing.append(
                f"ARG {argument}={version} visible in the consuming stage with "
                f"go install {package}@${argument}"
            )
    assert not missing, "missing qualified Go contracts: " + "; ".join(missing)

    go_section_start = text.index("go install")
    go_section_end = text.index("# Verify all Go tools are installed")
    assert "|| true" not in text[go_section_start:go_section_end], (
        "Go installation failures must stop the build instead of being suppressed"
    )


def test_git_sources_use_all_qualified_refs_and_verified_checkouts():
    """Regression: a rebuild must not use an unreviewed branch or shallow clone."""
    instructions = _logical_docker_instructions(_read(DOCKERFILE))
    missing = []
    for argument, commit, url, destination in GIT_REFS:
        checkout = rf'checkout-source {re.escape(url)} "{_shell_variable(argument)}" {re.escape(destination)}'
        owners = [
            index
            for index, instruction in enumerate(instructions)
            if instruction.startswith("RUN ") and re.search(checkout, instruction)
        ]
        variable_consumers = [
            index
            for index, instruction in enumerate(instructions)
            if instruction.startswith("RUN ")
            and _instruction_uses_variable(instruction, argument)
        ]
        if (
            len(owners) != 1
            or variable_consumers != owners
            or not _qualified_arg_is_visible(instructions, argument, commit, owners)
        ):
            missing.append(
                f"one in-stage ARG {argument}={commit} owned only by "
                f"checkout-source {url} ${argument} {destination}"
            )
    assert not missing, "missing qualified Git contracts: " + "; ".join(missing)


def test_required_git_source_blocks_do_not_contain_or_fallbacks():
    """Required Git-source-owning RUN blocks must not contain `||` OR fallbacks."""
    text = _read(DOCKERFILE)
    masked = []
    for argument, _commit, url, destination in GIT_REFS:
        checkout = rf'checkout-source {re.escape(url)} "{_shell_variable(argument)}" {re.escape(destination)}'
        source_blocks = [
            block for block in _run_blocks(text) if re.search(checkout, block)
        ]
        assert len(source_blocks) == 1, f"expected one required Git source block for {argument}"
        if "||" in source_blocks[0]:
            masked.append(f"{argument}: {source_blocks[0]}")
    assert not masked, (
        "required Git-source-owning RUN blocks must not contain `||` OR fallbacks, "
        "including unconditional-success fallback paths: " + "; ".join(masked)
    )


def _run_blocks(text: str) -> list[str]:
    """Return each Dockerfile RUN instruction as one source block."""
    return [instruction for instruction in _logical_docker_instructions(text) if instruction.startswith("RUN ")]


def _logical_docker_instructions(text: str) -> list[str]:
    """Parse continued Docker instructions with canonical instruction keywords."""
    normalized = re.sub(r"\\[ \t]*(?:\r?\n)", " ", text)
    instructions = []
    for line in normalized.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?P<keyword>[A-Za-z]+)(?:\s+(?P<body>.*)|$)", stripped)
        if match is not None:
            keyword = match.group("keyword").upper()
            body = match.group("body")
            instructions.append(keyword if body is None else f"{keyword} {body}")
    return instructions


def _docker_instruction_stages(instructions: list[str]) -> list[int]:
    """Return the zero-based build stage containing each logical instruction."""
    stage = -1
    stages = []
    for instruction in instructions:
        if instruction.startswith("FROM "):
            stage += 1
        stages.append(stage)
    return stages


def _instruction_uses_variable(instruction: str, variable: str) -> bool:
    """Detect a real variable reference, excluding ARG declarations and shell comments."""
    if instruction.startswith("ARG "):
        return False
    if instruction.startswith("RUN "):
        searchable = " ".join(
            token for command in _shell_commands(instruction) for token in command
        )
    else:
        searchable = instruction
    return re.search(_shell_variable(variable), searchable) is not None


def _docker_variable_assignments(instruction: str) -> list[tuple[str, str | None]]:
    """Return ARG/ENV assignments without interpreting their shell values."""
    keyword, _, body = instruction.partition(" ")
    if keyword == "ARG":
        token = body.split(maxsplit=1)[0]
        name, separator, value = token.partition("=")
        return [(name, value if separator else None)]
    if keyword != "ENV":
        return []

    tokens = shlex.split(body, comments=True, posix=True)
    if not tokens:
        return []
    if "=" not in tokens[0]:
        return [(tokens[0], " ".join(tokens[1:]))]
    assignments = []
    for token in tokens:
        name, separator, value = token.partition("=")
        if separator:
            assignments.append((name, value))
    return assignments


def _qualified_arg_is_visible(
    instructions: list[str], variable: str, value: str, consumers: list[int]
) -> bool:
    """Require one qualified default and an in-stage declaration for every consumer."""
    stages = _docker_instruction_stages(instructions)
    declarations = []
    for index, instruction in enumerate(instructions):
        for name, declared_value in _docker_variable_assignments(instruction):
            if instruction.startswith("ARG ") and name == variable:
                declarations.append((index, stages[index], declared_value))

    defaults = [declaration for declaration in declarations if declaration[2] is not None]
    if len(defaults) != 1 or defaults[0][2] != value:
        return False

    default_index, default_stage, _ = defaults[0]
    if default_stage < 0:
        return False
    for consumer in consumers:
        consumer_stage = stages[consumer]
        if consumer_stage != default_stage or default_index >= consumer:
            return False
    return True


def _declared_asset_variables(
    instructions: list[str],
    seeds: set[str],
    literals: tuple[str, ...],
    name_pattern: str,
) -> set[str]:
    """Trace direct ARG/ENV aliases for named assets without evaluating shell code."""
    variables = set(seeds)
    assignments = [
        assignment
        for instruction in instructions
        for assignment in _docker_variable_assignments(instruction)
    ]
    changed = True
    while changed:
        changed = False
        for name, value in assignments:
            value = value or ""
            names_asset = re.search(name_pattern, name, re.IGNORECASE) is not None
            contains_asset = any(literal in value for literal in literals)
            aliases_asset = any(
                re.search(_shell_variable(variable), value) for variable in variables
            )
            if name not in variables and (names_asset or contains_asset or aliases_asset):
                variables.add(name)
                changed = True
    return variables


def _asset_run_indices(
    instructions: list[str],
    seeds: set[str],
    literals: tuple[str, ...],
    name_pattern: str,
) -> list[int]:
    """Find RUN instructions that consume a named asset or its declared aliases."""
    variables = _declared_asset_variables(instructions, seeds, literals, name_pattern)
    return [
        index
        for index, instruction in enumerate(instructions)
        if instruction.startswith("RUN ")
        and (
            any(literal in instruction for literal in literals)
            or any(re.search(_shell_variable(variable), instruction) for variable in variables)
        )
    ]


def _has_checksum_pipeline(block: str, variable: str, path: str) -> bool:
    """Require one variable/path pair to feed the checksum verifier."""
    block = re.sub(r"\\[ \t]*(?:\r?\n)", " ", block)
    variable_ref = _shell_variable(variable)
    escaped_path = re.escape(path)
    return re.search(
        rf"(?:{variable_ref}[^\n]*{escaped_path}|{escaped_path}[^\n]*{variable_ref})[^\n]*sha256sum\s+-c\s+-",
        block,
    ) is not None


def test_downloaded_binaries_have_per_artifact_checksum_pipelines():
    """Regression: a changed download must fail the check for that exact artifact."""
    text = _read(DOCKERFILE)
    blocks = _run_blocks(text)
    missing = []
    for filename, variable, digest, path in BINARY_HASHES:
        declaration = f"ARG {variable}={digest}"
        if declaration not in text or not any(
            _has_checksum_pipeline(block, variable, path) for block in blocks
        ):
            missing.append(f"{filename}: {declaration} -> {path} via sha256sum -c -")
    assert not missing, "missing per-artifact checksum pipelines: " + "; ".join(missing)

    assert 'ARG NGROK_VERSION=3.39.11' in text
    ngrok_blocks = [block for block in blocks if "/usr/local/bin/ngrok" in block]
    assert any(
        re.search(r'ngrok version\s+\|\s+grep -F\s+"(?:3\.39\.11|\$\{?NGROK_VERSION\}?)"', block)
        for block in ngrok_blocks
    ), "the ngrok binary must be checked against its qualified version"


def test_standalone_downloads_use_all_qualified_selectors():
    """Regression: rebuilds must use the reviewed release/ref for every standalone input."""
    text = _read(DOCKERFILE)
    instructions = _logical_docker_instructions(text)
    missing = []
    for label, variable, version, url_anchor, url_prefix in STANDALONE_SELECTORS:
        consuming = []
        if url_prefix is None:
            consuming = [
                (index, instruction)
                for index, instruction in enumerate(instructions)
                if instruction.startswith("RUN ")
                and re.search(r"\bngrok\s+version\b", instruction)
                and re.search(_shell_variable(variable), instruction)
            ]
        else:
            url_pattern = rf"{re.escape(url_anchor)}/{re.escape(url_prefix)}{_shell_variable(variable)}/"
            consuming = [
                (index, instruction)
                for index, instruction in enumerate(instructions)
                if instruction.startswith("RUN ") and re.search(url_pattern, instruction)
            ]
        consumer_indices = [index for index, _ in consuming]
        if len(consuming) != 1 or not _qualified_arg_is_visible(
            instructions, variable, version, consumer_indices
        ):
            missing.append(
                f"{label}: one qualified ARG {variable}={version} and an in-stage declaration "
                f"before one consuming RUN using ${variable}"
            )
    assert not missing, "missing qualified standalone selectors: " + "; ".join(missing)


def test_runascs_download_extraction_and_output_check_are_required():
    """A qualified image must fail when RunasCs cannot be installed and verified."""
    instructions = _logical_docker_instructions(_read(DOCKERFILE))
    blocks = [
        instruction
        for instruction in instructions
        if instruction.startswith("RUN ")
        and "antonioCoco/RunasCs/releases/download" in instruction
    ]
    assert len(blocks) == 1, "RunasCs must have one owning RUN instruction"
    block = blocks[0]
    owner_index = instructions.index(block)

    assert _qualified_arg_is_visible(instructions, "RUNAS_VER", "1.5", [owner_index])
    assert "||" not in block, "RunasCs installation must not have a success fallback"
    assert "WARN: RunasCs" not in block
    required_chain = r"\s*&&\s*".join(
        re.escape(operation)
        for operation in (
            'wget -q "https://github.com/antonioCoco/RunasCs/releases/download/v${RUNAS_VER}/RunasCs.zip" -O /tmp/RunasCs.zip',
            "unzip -o /tmp/RunasCs.zip -d /opt/windows-tools/",
            "test -f /opt/windows-tools/RunasCs.exe",
        )
    )
    assert re.search(required_chain, block), (
        "RunasCs versioned download, extraction, and exact output check must form one "
        "required && chain"
    )


def test_caido_fallback_uses_the_official_versioned_asset_and_cleans_apt_lists():
    """Regression: the optional fallback must remain usable after APT is unavailable."""
    blocks = [block for block in _run_blocks(_read(DOCKERFILE)) if "caido-cli" in block]
    assert len(blocks) == 1, "Caido installation must have one owning RUN instruction"
    block = blocks[0]

    assert (
        "https://caido.download/releases/v${CAIDO_VER}/"
        "caido-cli-v${CAIDO_VER}-linux-x86_64.tar.gz"
    ) in block
    assert block.count("rm -rf /var/lib/apt/lists/*") == 2, (
        "Caido must clear APT lists after both a successful APT install and an APT failure "
        "before the fallback download"
    )


def _case_body(text: str, variable: str) -> tuple[str, int, int]:
    matches = list(
        re.finditer(
            rf'case\s+"\${re.escape(variable)}"\s+in(?P<body>.*?)^\s*esac\b',
            text,
            re.MULTILINE | re.DOTALL,
        )
    )
    assert len(matches) == 1, f"expected exactly one complete case for {variable}"
    match = matches[0]
    return match.group("body"), match.start(), match.end()


def _case_branch(body: str, label: str, next_label: str) -> str:
    match = re.search(
        rf"^\s*{re.escape(label)}\)\s*(?P<branch>.*?);;[ \t]*(?:\\[ \t]*\r?\n)?(?=^\s*{re.escape(next_label)}\))",
        body,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"case is missing a complete {label}) branch"
    return match.group("branch")


def test_cado_and_metasploit_verification_is_strict():
    """Regression: optional layers must own their commands and fail closed."""
    text = _read(DOCKERFILE)
    assert 'ARG INCLUDE_CADO_NFS=true' in text
    assert 'ARG CADO_NFS_REF=4a6af6c97c2874d95f27c80c305ce34e09977a03' in text
    cado_conditionals = re.findall(
        r"\b(?:case|if|elif|while|until|test)\b[^\n]*INCLUDE_CADO_NFS[^\n]*|\[[^\n]*INCLUDE_CADO_NFS[^\n]*",
        text,
    )
    assert len(cado_conditionals) == 1 and cado_conditionals[0].lstrip().startswith(
        'case "$INCLUDE_CADO_NFS" in'
    ), "CADO-NFS must have only one case-based conditional"
    cado_body, cado_start, cado_end = _case_body(text, "INCLUDE_CADO_NFS")
    cado_true = _case_branch(cado_body, "true", "false")
    cado_false = _case_branch(cado_body, "false", "*")
    cado_invalid = re.search(
        r"^\s*\*\)\s*(?P<branch>.*?);;[ \t]*(?:\\[ \t]*\r?\n)?[ \t\r\n]*\Z",
        cado_body,
        re.MULTILINE | re.DOTALL,
    )
    assert cado_invalid is not None, "CADO-NFS case must reject invalid values"

    assert re.search(
        rf'checkout-source https://gitlab\.inria\.fr/cado-nfs/cado-nfs\.git "{_shell_variable("CADO_NFS_REF")}" /opt/cado-nfs',
        cado_true,
    )
    assert 'make -C /opt/cado-nfs -j"$(nproc)"' in cado_true
    assert 'test -f /opt/cado-nfs/cado-nfs.py' in cado_true
    for operation in (
        'checkout-source https://gitlab.inria.fr/cado-nfs/cado-nfs.git',
        'make -C /opt/cado-nfs',
        'test -f /opt/cado-nfs/cado-nfs.py',
    ):
        assert text.count(operation) == cado_true.count(operation) == 1, (
            f"CADO operation must occur exactly once and only in true: {operation}"
        )
    assert 'Skipping CADO-NFS for an explicit development build' in cado_false
    assert re.fullmatch(
        r'\s*echo\s+"Skipping CADO-NFS for an explicit development build"\s*',
        cado_false,
    )
    for forbidden in ("checkout-source", "make -C", "cado-nfs.py"):
        assert forbidden not in cado_false, f"CADO false branch must not run {forbidden}"
    assert 'INCLUDE_CADO_NFS must be true or false' in cado_invalid.group("branch")
    assert 'exit 1' in cado_invalid.group("branch")
    cado_chain = r"\s*&&\s*".join(
        re.escape(operation)
        for operation in (
            'checkout-source https://gitlab.inria.fr/cado-nfs/cado-nfs.git "$CADO_NFS_REF" /opt/cado-nfs',
            'make -C /opt/cado-nfs -j"$(nproc)"',
            'test -f /opt/cado-nfs/cado-nfs.py',
        )
    )
    assert re.search(cado_chain, re.sub(r"\\[ \t]*\r?\n", " ", cado_true)), (
        "CADO-NFS checkout, build, and output verification must form one && chain"
    )

    assert not re.search(r'if\s+\[\s*"\$INCLUDE_METASPLOIT"', text)
    conditional_refs = re.findall(
        r"\b(?:case|if|elif|while|until|test)\b[^\n]*INCLUDE_METASPLOIT[^\n]*|\[[^\n]*INCLUDE_METASPLOIT[^\n]*",
        text,
    )
    assert len(conditional_refs) == 1 and conditional_refs[0].lstrip().startswith(
        'case "$INCLUDE_METASPLOIT" in'
    ), "Metasploit must have only one case-based conditional"
    metasploit_body, metasploit_start, metasploit_end = _case_body(text, "INCLUDE_METASPLOIT")
    metasploit_true = _case_branch(metasploit_body, "true", "false")
    metasploit_false = _case_branch(metasploit_body, "false", "*")
    metasploit_invalid = re.search(
        r"^\s*\*\)\s*(?P<branch>.*?);;[ \t]*(?:\\[ \t]*\r?\n)?[ \t\r\n]*\Z",
        metasploit_body,
        re.MULTILINE | re.DOTALL,
    )
    assert metasploit_invalid is not None, "Metasploit case must reject invalid values"
    assert 'apt-get install' in metasploit_true
    assert 'metasploit-framework' in metasploit_true
    assert 'command -v msfconsole' in metasploit_true
    assert 'command -v msfvenom' in metasploit_true
    for operation in ('metasploit-framework', 'command -v msfconsole', 'command -v msfvenom'):
        assert text.count(operation) == metasploit_true.count(operation) == 1, (
            f"Metasploit operation must occur exactly once and only in true: {operation}"
        )
    assert 'Skipping Metasploit Framework (INCLUDE_METASPLOIT=false)' in metasploit_false
    assert re.fullmatch(
        r'\s*echo\s+"Skipping Metasploit Framework \(INCLUDE_METASPLOIT=false\)"\s*',
        metasploit_false,
    )
    for forbidden in ("apt-get", "metasploit-framework", "command -v"):
        assert forbidden not in metasploit_false, f"Metasploit false branch must not run {forbidden}"
    assert 'INCLUDE_METASPLOIT must be true or false' in metasploit_invalid.group("branch")
    assert 'exit 1' in metasploit_invalid.group("branch")
    metasploit_chain = r"\s*&&\s*".join(
        re.escape(operation)
        for operation in (
            "apt-get update",
            "apt-get install -y --no-install-recommends metasploit-framework",
            "rm -rf /var/lib/apt/lists/*",
            "command -v msfconsole",
            "command -v msfvenom",
        )
    )
    assert re.search(metasploit_chain, re.sub(r"\\[ \t]*\r?\n", " ", metasploit_true)), (
        "Metasploit install, cleanup, and executable checks must form one && chain"
    )

    instructions = _logical_docker_instructions(text)
    cado_case_instructions = [
        (index, instruction)
        for index, instruction in enumerate(instructions)
        if instruction.startswith("RUN ") and 'case "$INCLUDE_CADO_NFS" in' in instruction
    ]
    assert len(cado_case_instructions) == 1
    cado_case_index, _ = cado_case_instructions[0]
    cado_literals = (
        "https://gitlab.inria.fr/cado-nfs/cado-nfs.git",
        "4a6af6c97c2874d95f27c80c305ce34e09977a03",
        "/opt/cado-nfs",
        "cado-nfs.py",
    )
    assert _asset_run_indices(
        instructions,
        {"INCLUDE_CADO_NFS", "CADO_NFS_REF"},
        cado_literals,
        r"(?:CADO|NFS)",
    ) == [cado_case_index], "CADO assets and declared aliases must occur only in the owning case RUN"

    metasploit_case_instructions = [
        (index, instruction)
        for index, instruction in enumerate(instructions)
        if instruction.startswith("RUN ") and 'case "$INCLUDE_METASPLOIT" in' in instruction
    ]
    assert len(metasploit_case_instructions) == 1
    metasploit_case_index, _ = metasploit_case_instructions[0]
    assert _asset_run_indices(
        instructions,
        {"INCLUDE_METASPLOIT"},
        ("metasploit-framework", "msfconsole", "msfvenom"),
        r"(?:METASPLOIT|MSF)",
    ) == [metasploit_case_index], (
        "Metasploit assets and declared aliases must occur only in the owning case RUN"
    )

    copy_position = text.index("COPY zebbern-kali/")
    metasploit_arg_position = text.index("ARG INCLUDE_METASPLOIT=true")
    assert cado_end < metasploit_arg_position <= metasploit_start < metasploit_end < copy_position


def test_publication_workflow_passes_cado_to_both_build_variants():
    """Regression: published full and lean images must both include qualified CADO-NFS."""
    text = _read(WORKFLOW)
    step_names = (
        ("Build and push (with Metasploit)", "INCLUDE_METASPLOIT=true"),
        ("Build and push (no Metasploit)", "INCLUDE_METASPLOIT=false"),
    )
    missing = []
    for name, metasploit_arg in step_names:
        marker = f"      - name: {name}"
        assert text.count(marker) == 1, f"workflow must contain one unique build step: {name}"
        start = text.index(marker)
        next_step = text.find("\n      - name:", start + len(marker))
        block = text[start:] if next_step == -1 else text[start:next_step]
        action_fields = re.findall(
            r"(?m)^ {8}uses: docker/build-push-action@[0-9a-f]{40}(?:[ \t]+#.*)?$", block
        )
        build_arg_keys = re.findall(
            r"(?m)^ {10}([A-Za-z0-9-]*build-args[A-Za-z0-9-]*)\s*:", block
        )
        build_args_fields = re.findall(
            r"(?m)^ {10}build-args:[ \t]*\|(?:\r?\n {12}[^\r\n]*)*", block
        )
        entries = (
            [line.strip() for line in build_args_fields[0].splitlines()[1:] if line.strip()]
            if len(build_args_fields) == 1
            else []
        )
        if (
            len(action_fields) != 1
            or build_arg_keys != ["build-args"]
            or len(build_args_fields) != 1
            or entries != [metasploit_arg, "INCLUDE_CADO_NFS=true"]
        ):
            missing.append(name)
    assert not missing, "workflow build steps missing qualified args/action: " + ", ".join(missing)


def _workflow_push_paths(text: str) -> list[str]:
    """Parse list entries owned by the workflow's on.push.paths mapping."""
    lines = text.splitlines()

    def find_key(start: int, end: int, indent: int, key: str) -> int:
        matches = [
            index
            for index in range(start, end)
            if re.fullmatch(rf" {{{indent}}}{re.escape(key)}:\s*(?:#.*)?", lines[index])
        ]
        assert len(matches) == 1, f"expected one {key}: key at indentation {indent}"
        return matches[0]

    def block_end(start: int, parent_indent: int, limit: int) -> int:
        for index in range(start + 1, limit):
            stripped = lines[index].lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(lines[index]) - len(stripped)
            if indent <= parent_indent:
                return index
        return limit

    on_index = find_key(0, len(lines), 0, "on")
    on_end = block_end(on_index, 0, len(lines))
    push_index = find_key(on_index + 1, on_end, 2, "push")
    push_end = block_end(push_index, 2, on_end)
    paths_index = find_key(push_index + 1, push_end, 4, "paths")
    paths_end = block_end(paths_index, 4, push_end)

    paths = []
    for line in lines[paths_index + 1:paths_end]:
        match = re.fullmatch(
            r"\s{6,}-\s*(?:'([^']+)'|\"([^\"]+)\"|([^\s#]+))\s*(?:#.*)?",
            line,
        )
        if match is not None:
            paths.append(next(value for value in match.groups() if value is not None))
    return paths


def test_publication_workflow_owns_checkout_helper_changes():
    """Changes to copied Docker helper sources must trigger the publication workflow."""
    assert "docker/**" in _workflow_push_paths(_read(WORKFLOW))
