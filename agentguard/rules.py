"""The rule set. Every rule is deterministic and traces to a published incident.

Rules never execute, import or install anything from the scanned repository.
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlparse

from .discover import Scan, line_of
from .model import FAIL, WARN, Finding, Server, mask

# --------------------------------------------------------------------------- secrets

SECRET_PATTERNS = [
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[0-9A-Za-z_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{32,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{40,}")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("JWT (for example a Supabase service key)",
     re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
SECRET_NAME = re.compile(r"(?i)(secret|token|passw(or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential)")
PLACEHOLDER = re.compile(
    r"(?i)(^\s*$|\$\{|\$[A-Z_]+|^<.*>$|your[_\- ]|xxx+|example|changeme|placeholder|redacted|"
    r"^\*+$|^env:|^op://|^vault:|insert|todo|dummy|sample|test[_-]?key)"
)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def find_secret(key: str, value: str):
    """Return (kind, secret_text) when value holds a real-looking secret."""
    if not value or PLACEHOLDER.search(value):
        return None
    for kind, pattern in SECRET_PATTERNS:
        m = pattern.search(value)
        if m:
            return kind, m.group(0)
    if SECRET_NAME.search(key) and len(value) >= 20 and " " not in value and entropy(value) >= 3.5:
        return "High-entropy value in a secret-named field", value
    return None


def rule_secrets(scan: Scan):
    for s in scan.servers:
        places = [(f"env.{k}", k, v) for k, v in s.env.items()]
        places += [(f"headers.{k}", k, v) for k, v in s.headers.items()]
        places += [(f"args[{i}]", "", a) for i, a in enumerate(s.args)]
        places += [("url", "", s.url)]
        for label, key, value in places:
            hit = find_secret(key, value)
            if hit:
                kind, secret = hit
                yield Finding(
                    "AG-SEC-001", FAIL, "Secret in config", s.file, s.line, f"{s.name} → {label}",
                    f"{kind} found: {mask(secret)}.",
                    "Remove it from the file, load it from an environment variable or secret store, "
                    "and rotate the key because it has been committed.",
                    "OWASP MCP01 Token Mismanagement and Secret Exposure",
                )

# ---------------------------------------------------------------------- supply chain

NODE_RUNNERS = {"npx", "bunx", "pnpx"}
PY_RUNNERS = {"uvx", "pipx"}
EXACT_VERSION = re.compile(r"^\d+(\.\d+){1,3}([\-+.][0-9A-Za-z.\-]+)?$")
FLAGS_WITH_VALUE = {"-p", "--package", "--from", "--python", "--with", "-c", "--call", "--registry", "--index-url"}

# Versions fixed per the advisories. Re-check each against its primary advisory before release.
KNOWN_VULNERABLE = {
    "mcp-remote": ("0.1.16", "CVE-2025-6514: a malicious server could run shell commands on the client"),
    "mcp-server-git": ("2025.12.18", "CVE-2025-68143, 68144, 68145"),
}


def base_command(command: str) -> str:
    return re.split(r"[\\/]", command.strip())[-1].lower().removesuffix(".cmd").removesuffix(".exe")


def package_spec(server: Server):
    """Return (ecosystem, name, version_or_None) for package-runner launches, else None."""
    cmd = base_command(server.command)
    args = list(server.args)
    if cmd in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        cmd, args = "npx", args[1:]
    if cmd == "uv" and args[:2] == ["tool", "run"]:
        cmd, args = "uvx", args[2:]
    if cmd == "pipx" and args[:1] == ["run"]:
        args = args[1:]
    if cmd not in NODE_RUNNERS | PY_RUNNERS:
        return None
    spec, skip = None, False
    for i, a in enumerate(args):
        if skip:
            skip = False
            if args[i - 1] in ("-p", "--package", "--from"):
                spec = a
                break
            continue
        if a in FLAGS_WITH_VALUE:
            skip = True
            continue
        if a.startswith("-"):
            continue
        spec = a
        break
    if not spec:
        return None
    eco = "npm" if cmd in NODE_RUNNERS else "pypi"
    if "==" in spec:
        name, version = spec.split("==", 1)
    elif "@" in spec[1:]:
        cut = spec.rindex("@")
        name, version = spec[:cut], spec[cut + 1:]
    else:
        name, version = spec, None
    return eco, name, version


def version_tuple(version: str):
    return tuple(int(p) for p in re.findall(r"\d+", version)[:4])


def rule_supply_chain(scan: Scan):
    for s in scan.servers:
        spec = package_spec(s)
        if spec:
            eco, name, version = spec
            if re.match(r"^(git\+|https?://|github:|git@)", name):
                yield Finding(
                    "AG-SUP-004", WARN, "Package installed from a URL", s.file, s.line, s.name,
                    f"`{name}` is fetched from a URL or git ref at run time.",
                    "Install from a registry with an exact version, or pin the git ref to a full commit SHA.",
                    "postmark-mcp backdoor, Sep 2025",
                )
            elif version is None or not EXACT_VERSION.match(version):
                shown = f"@{version}" if version else "with no version"
                yield Finding(
                    "AG-SUP-001", FAIL, "Unpinned package", s.file, s.line, s.name,
                    f"`{name}` runs {shown}, so every start installs whatever is newest.",
                    f"Pin an exact version, for example `{name}{'==' if eco == 'pypi' else '@'}1.2.3`, "
                    "and update it on purpose.",
                    "postmark-mcp backdoor (15 clean releases, then a malicious one), Sep 2025",
                )
            short = name.split("/")[-1]
            if version and EXACT_VERSION.match(version) and short in KNOWN_VULNERABLE:
                fixed, why = KNOWN_VULNERABLE[short]
                if version_tuple(version) < version_tuple(fixed):
                    yield Finding(
                        "AG-SUP-003", FAIL, "Known-vulnerable version", s.file, s.line, s.name,
                        f"`{short}` {version} is affected by {why}.",
                        f"Upgrade to {fixed} or later.", why.split(":")[0],
                    )
        cmd = base_command(s.command)
        joined = " ".join([s.command] + s.args)
        if re.search(r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh\b", joined):
            yield Finding(
                "AG-SUP-005", FAIL, "Download piped to a shell", s.file, s.line, s.name,
                "The launch command downloads a script and runs it without any check.",
                "Vendor the script into the repo, or install a pinned release and verify its checksum.",
                "SmartLoader fake MCP server campaign, Feb 2026",
            )
        if cmd in ("docker", "podman") and "run" in s.args:
            image = docker_image(s.args)
            if image and "@sha256:" not in image:
                yield Finding(
                    "AG-SUP-002", WARN, "Container image not pinned by digest", s.file, s.line, s.name,
                    f"Image `{image}` can change under the same tag.",
                    "Pin the image by digest: `image@sha256:…`.",
                    "Cursor MCPoison CVE-2025-54136 (approved entry silently changed)",
                )


DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--mount", "-p", "--publish", "--name", "--network", "--net",
    "-w", "--workdir", "-u", "--user", "--env-file", "--entrypoint", "-l", "--label", "--platform",
    "--add-host", "-h", "--hostname", "--memory", "-m", "--cpus",
}


def docker_image(args: list):
    try:
        rest = args[args.index("run") + 1:]
    except ValueError:
        return None
    skip = False
    for a in rest:
        if skip:
            skip = False
            continue
        if a in DOCKER_VALUE_FLAGS:
            skip = True
            continue
        if a.startswith("-"):
            continue
        return a
    return None

# -------------------------------------------------------------------------- exposure

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "host.docker.internal"}


def rule_exposure(scan: Scan):
    for s in scan.servers:
        open_bind = False
        for i, a in enumerate(s.args):
            nxt = s.args[i + 1] if i + 1 < len(s.args) else ""
            if a in ("--host", "--bind", "--listen", "--address", "-H") and nxt.startswith("0.0.0.0"):
                open_bind = True
            if re.match(r"(?i)^--?(host|bind|listen|address|addr)[=:]0\.0\.0\.0", a):
                open_bind = True
        for k, v in s.env.items():
            if re.search(r"(?i)(host|bind|listen|addr)", k) and v.strip().startswith("0.0.0.0"):
                open_bind = True
        if open_bind:
            yield Finding(
                "AG-NET-001", FAIL, "Server listens on every network interface", s.file, s.line, s.name,
                "Bound to 0.0.0.0, so anyone on the same network can reach it.",
                "Bind to 127.0.0.1, or put it behind authentication if it must be reachable.",
                "MCP Inspector unauthenticated remote code execution, Jun 2025",
            )
        for target in [s.url] + [a for a in s.args if re.match(r"(?i)^(https?|wss?)://", a)]:
            if not target:
                continue
            parsed = urlparse(target)
            if parsed.scheme in ("http", "ws") and (parsed.hostname or "") not in LOCAL_HOSTS:
                yield Finding(
                    "AG-NET-002", FAIL, "Unencrypted connection to a remote server", s.file, s.line, s.name,
                    f"`{parsed.scheme}://{parsed.hostname}` sends tool calls and tokens in clear text.",
                    "Use https:// (or wss://).",
                    "MCP specification, security best practices",
                )
            if parsed.username or parsed.password:
                yield Finding(
                    "AG-SEC-002", FAIL, "Credentials inside a URL", s.file, s.line, s.name,
                    "The server URL carries a username or password, which ends up in logs and history.",
                    "Move the credential to a header loaded from an environment variable, and rotate it.",
                    "OWASP MCP01 Token Mismanagement and Secret Exposure",
                )

# ---------------------------------------------------------------------- excess power

BROAD_PATH = re.compile(r"^(/|~|~/|\$HOME/?|\$\{HOME\}/?|[A-Za-z]:\\?|/(Users|home)/[^/]+/?|/root/?|/etc/?)$")
SKIP_PERMS = re.compile(r"--dangerously-skip-permissions|--yolo\b|--dangerously-bypass-approvals")


def rule_excess_power(scan: Scan):
    for s in scan.servers:
        for a in s.args:
            if BROAD_PATH.match(a):
                yield Finding(
                    "AG-PWR-001", WARN, "Whole-disk or home-folder access", s.file, s.line, s.name,
                    f"The server is given `{a}`, which includes SSH keys, browser data and other projects.",
                    "Pass only the project folder the agent needs.",
                    "Anthropic Filesystem server EscapeRoute CVE-2025-53109 / 53110",
                )
                break
        auto = s.raw.get("autoApprove") or s.raw.get("alwaysAllow")
        if auto is True or (isinstance(auto, list) and ("*" in auto or len(auto) >= 10)):
            yield Finding(
                "AG-PWR-002", WARN, "Tools run without asking", s.file, s.line, s.name,
                "This server's tools are auto-approved, so a poisoned tool acts with no human check.",
                "Auto-approve only specific read-only tools.",
                "Invariant Labs tool poisoning demo, Apr 2025",
            )
        if SKIP_PERMS.search(" ".join(s.args)):
            yield Finding(
                "AG-PWR-003", FAIL, "Permission prompts disabled", s.file, s.line, s.name,
                "The launch command turns off all permission checks.",
                "Remove the flag and allow specific tools instead.", "OWASP ASI02 Tool Misuse",
            )
    for path, data, text in scan.settings:
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        if perms.get("defaultMode") == "bypassPermissions":
            yield Finding(
                "AG-PWR-003", FAIL, "Permission prompts disabled", path, line_of(text, "bypassPermissions"),
                "permissions.defaultMode", "Every tool call is allowed with no check.",
                "Use the default mode and list the specific commands to allow.", "OWASP ASI02 Tool Misuse",
            )
        for rule in perms.get("allow") or []:
            if isinstance(rule, str) and re.match(r"^(\*|Bash|Bash\(\*\)|Bash\(\*:\*\)|Bash\(:\*\))$", rule.strip()):
                yield Finding(
                    "AG-PWR-004", WARN, "Any shell command allowed", path, line_of(text, f'"{rule}"'),
                    "permissions.allow", f"`{rule}` lets the agent run any command without asking.",
                    "Allow specific commands, for example `Bash(npm test:*)`.", "OWASP ASI02 Tool Misuse",
                )
        if data.get("enableAllProjectMcpServers") is True:
            yield Finding(
                "AG-PWR-005", WARN, "Every project MCP server trusted automatically", path,
                line_of(text, "enableAllProjectMcpServers"), "enableAllProjectMcpServers",
                "Any server added to this repo's .mcp.json starts without approval, including by a pull request.",
                "List approved servers by name instead.", "Cursor MCPoison CVE-2025-54136",
            )
        for cmd in _hook_commands(data.get("hooks")):
            if re.search(r"(curl|wget)[^|;&]*\|\s*(ba|z)?sh\b", cmd):
                yield Finding(
                    "AG-PWR-006", FAIL, "Hook downloads and runs a script", path, line_of(text, cmd[:30]),
                    "hooks", "A hook pipes a download straight into a shell on every matching event.",
                    "Keep hook scripts in the repo and review them like code.",
                    "SmartLoader fake MCP server campaign, Feb 2026",
                )


def _hook_commands(node, depth: int = 0):
    if depth > 8:
        return
    if isinstance(node, dict):
        if isinstance(node.get("command"), str):
            yield node["command"]
        for v in node.values():
            yield from _hook_commands(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            yield from _hook_commands(v, depth + 1)

# ------------------------------------------------------------------------- integrity

HIDDEN_CHARS = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")
INJECTION = re.compile(
    r"(?i)(ignore (all |any )?(previous|prior|above) (instructions|rules)|"
    r"do not (tell|inform|mention|reveal)[^.]{0,40}(user|human)|"
    r"(don'?t|never) (tell|mention|reveal)[^.]{0,40}(user|human)|"
    r"before (using|calling|invoking) (any|this|the) (other )?tool|"
    r"<(important|system|secret|instructions?)>|"
    r"you must (first|always) (read|call|send|include)|"
    r"(send|forward|post|upload|pass)[^.]{0,60}(to https?://|as (a |the )?(sidenote|side note|parameter))|"
    r"this is (very )?(important|crucial)[^.]{0,40}(otherwise|or) the tool)"
)
SENSITIVE_PATH = re.compile(
    r"(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|\.npmrc|\.netrc|mcp\.json|"
    r"\.cursor/|keychain|/etc/passwd|\.git-credentials)"
)


def rule_integrity(scan: Scan):
    for t in scan.tools:
        hidden = HIDDEN_CHARS.findall(t.description + t.name)
        if hidden:
            yield Finding(
                "AG-INT-001", FAIL, "Invisible characters in a tool definition", t.file, t.line, f"tool {t.name}",
                f"{len(hidden)} invisible Unicode characters. People can't see them, but the model reads them.",
                "Remove the server, or strip the characters and report it to the maintainer.",
                "Invariant Labs tool poisoning demo, Apr 2025",
            )
        m = INJECTION.search(t.description)
        if m:
            yield Finding(
                "AG-INT-002", FAIL, "Tool description gives orders to the model", t.file, t.line, f"tool {t.name}",
                f"The description contains instruction-like text: “{m.group(0)[:60]}”.",
                "Don't use this server until the description is plain documentation.",
                "Invariant Labs tool poisoning demo, Apr 2025",
            )
        m = SENSITIVE_PATH.search(t.description)
        if m:
            yield Finding(
                "AG-INT-003", FAIL, "Tool description points at credentials", t.file, t.line, f"tool {t.name}",
                f"The description refers to `{m.group(0)}`, which a normal tool has no reason to mention.",
                "Treat the server as hostile and remove it.",
                "Invariant Labs tool poisoning demo, Apr 2025",
            )
    names = {}
    for t in scan.tools:
        names.setdefault(t.name, set()).add(t.file)
    for t in scan.tools:
        if len(names[t.name]) > 1:
            yield Finding(
                "AG-INT-004", WARN, "Two servers define the same tool name", t.file, t.line, f"tool {t.name}",
                "One server's tool can shadow the other's and capture its calls.",
                "Rename or remove one, and confirm which server should own the name.",
                "Tool shadowing (Invariant Labs, Apr 2025)",
            )
    for path, text in scan.instructions:
        hidden = HIDDEN_CHARS.findall(text)
        if len(hidden) > 1 or (hidden and hidden != ["﻿"]):
            first = HIDDEN_CHARS.search(text.lstrip("﻿"))
            line = text[: first.start()].count("\n") + 1 if first else 1
            yield Finding(
                "AG-INT-001", FAIL, "Invisible characters in an agent instruction file", path, line, "file",
                f"{len(hidden)} invisible Unicode characters that the agent will read as instructions.",
                "Delete them and check the file's git history for who added them.",
                "Hidden Unicode in rules files (Pillar Security, 2025)",
            )

# ----------------------------------------------------------------- toxic combination

PRIVATE = re.compile(r"(?i)(filesystem|postgres|mysql|sqlite|supabase|mongo|gmail|drive|notion|slack|"
                     r"github|gitlab|jira|salesforce|stripe|whatsapp|imap|outlook|obsidian)")
UNTRUSTED = re.compile(r"(?i)(fetch|browser|puppeteer|playwright|search|scrape|crawl|firecrawl|gmail|"
                       r"imap|outlook|slack|github|gitlab|jira|whatsapp|reddit|rss)")
EXFIL = re.compile(r"(?i)(fetch|browser|puppeteer|playwright|gmail|smtp|email|slack|github|gitlab|"
                   r"webhook|whatsapp|discord|telegram|http)")


def rule_toxic_combination(scan: Scan):
    by_file = {}
    for s in scan.servers:
        by_file.setdefault(s.file, []).append(s)
    for path, servers in by_file.items():
        def who(pattern):
            return [s.name for s in servers if pattern.search(" ".join([s.name, s.command, *s.args, s.url]))]
        private, untrusted, exfil = who(PRIVATE), who(UNTRUSTED), who(EXFIL)
        if private and untrusted and exfil and len(set(private + untrusted + exfil)) >= 2:
            yield Finding(
                "AG-TOX-001", WARN, "Private data, untrusted input and a way out in one agent", path,
                min(s.line for s in servers), "all servers",
                f"Private data: {', '.join(private[:3])}. Untrusted content: {', '.join(untrusted[:3])}. "
                f"Can send data out: {', '.join(exfil[:3])}. Text planted in what the agent reads can make "
                "it leak the private data.",
                "Split these across separate agents, make the private source read-only and narrowly "
                "scoped, or require approval for every outbound action.",
                "GitHub MCP toxic agent flow and Supabase MCP data leak, 2025",
            )


ALL_RULES = [rule_secrets, rule_supply_chain, rule_exposure, rule_excess_power, rule_integrity,
             rule_toxic_combination]


def run_rules(scan: Scan) -> list:
    findings, seen = [], set()
    for rule in ALL_RULES:
        for f in rule(scan):
            key = (f.rule, f.file, f.where, f.message)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    findings.sort(key=lambda f: (f.severity != FAIL, f.file, f.line, f.rule))
    return findings
