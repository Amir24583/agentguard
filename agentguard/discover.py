"""Find and parse agent configuration files. Parse only: nothing is ever executed."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .model import Server, Tool

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

MCP_CONFIG_NAMES = {
    ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json",
}
MCP_CONFIG_SUFFIXES = (
    os.path.join(".cursor", "mcp.json"),
    os.path.join(".vscode", "mcp.json"),
    os.path.join(".windsurf", "mcp_config.json"),
)
CLAUDE_SETTINGS = (
    os.path.join(".claude", "settings.json"),
    os.path.join(".claude", "settings.local.json"),
)
TOOL_MANIFEST_NAMES = {"tools.json", "mcp-tools.json"}
INSTRUCTION_NAMES = {"CLAUDE.md", "AGENTS.md", ".cursorrules", "GEMINI.md"}


@dataclass
class Scan:
    servers: list = field(default_factory=list)
    tools: list = field(default_factory=list)
    settings: list = field(default_factory=list)      # (file, dict, text)
    instructions: list = field(default_factory=list)  # (file, text)
    files: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def line_of(text: str, needle: str, start: int = 1) -> int:
    """1-based line of the first occurrence of needle at or after line `start`."""
    if not needle:
        return start
    for i, line in enumerate(text.splitlines(), 1):
        if i >= start and needle in line:
            return i
    return start


def _read(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _load_json(path: str, text: str, scan: Scan):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        scan.errors.append(f"{path}: not valid JSON ({exc.__class__.__name__})")
        return None


def _as_str_list(value) -> list:
    return [str(v) for v in value] if isinstance(value, list) else []


def _as_str_dict(value) -> dict:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def parse_mcp_config(path: str, text: str, data, scan: Scan) -> None:
    if not isinstance(data, dict):
        return
    blocks = [data.get("mcpServers"), data.get("servers")]
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        blocks.append(mcp.get("servers"))
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for name, entry in block.items():
            if not isinstance(entry, dict):
                continue
            line = line_of(text, f'"{name}"')
            scan.servers.append(Server(
                name=str(name), file=path, line=line,
                command=str(entry.get("command") or ""),
                args=_as_str_list(entry.get("args")),
                env=_as_str_dict(entry.get("env")),
                url=str(entry.get("url") or entry.get("serverUrl") or ""),
                headers=_as_str_dict(entry.get("headers")),
                raw=entry,
            ))


def parse_tool_manifest(path: str, text: str, data, scan: Scan) -> None:
    tools = data.get("tools") if isinstance(data, dict) else data
    if not isinstance(tools, list):
        return
    for tool in tools:
        if isinstance(tool, dict) and "name" in tool:
            name = str(tool.get("name"))
            scan.tools.append(Tool(
                name=name, description=str(tool.get("description") or ""),
                file=path, line=line_of(text, f'"{name}"'),
            ))


def scan_path(root: str) -> Scan:
    scan = Scan()
    paths = []
    if os.path.isfile(root):
        paths.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                paths.append(os.path.join(dirpath, fn))
    for path in sorted(paths):
        base = os.path.basename(path)
        is_mcp = base in MCP_CONFIG_NAMES or path.endswith(MCP_CONFIG_SUFFIXES)
        is_settings = path.endswith(CLAUDE_SETTINGS)
        is_tools = base in TOOL_MANIFEST_NAMES
        is_instr = base in INSTRUCTION_NAMES
        explicit = os.path.isfile(root) and path == root
        if not (is_mcp or is_settings or is_tools or is_instr or explicit):
            continue
        text = _read(path)
        if text is None:
            scan.errors.append(f"{path}: unreadable or larger than {MAX_BYTES} bytes")
            continue
        scan.files.append(path)
        if is_instr:
            scan.instructions.append((path, text))
            continue
        data = _load_json(path, text, scan)
        if data is None:
            continue
        if is_settings:
            scan.settings.append((path, data, text))
        if is_tools:
            parse_tool_manifest(path, text, data, scan)
        if is_mcp or (explicit and not is_settings and not is_tools):
            parse_mcp_config(path, text, data, scan)
            if explicit and isinstance(data, dict) and "tools" in data:
                parse_tool_manifest(path, text, data, scan)
    return scan
