"""agentguard.lock: fingerprints of every approved server and tool.

`agentguard lock` records the current state after a human has reviewed it. Every later
scan compares against it, so a server or tool that changes silently fails the build.
"""
from __future__ import annotations

import hashlib
import json
import os

from .discover import Scan
from .model import FAIL, Finding

LOCK_NAME = "agentguard.lock"
REF = "Cursor MCPoison CVE-2025-54136 and the Invariant Labs rug pull demo, 2025"


def _digest(obj) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _rel(path: str, base: str) -> str:
    return os.path.relpath(path, base).replace(os.sep, "/")


def base_dir(root: str) -> str:
    return root if os.path.isdir(root) else os.path.dirname(root) or "."


def snapshot(scan: Scan, base: str) -> dict:
    """Fingerprints only. Env and header values are never stored, only their names."""
    servers, tools = {}, {}
    for s in scan.servers:
        servers[f"{_rel(s.file, base)}#{s.name}"] = _digest({
            "command": s.command, "args": s.args, "url": s.url,
            "env": sorted(s.env), "headers": sorted(s.headers),
        })
    for t in scan.tools:
        tools[f"{_rel(t.file, base)}#{t.name}"] = _digest({"name": t.name, "description": t.description})
    return {"version": 1, "servers": servers, "tools": tools}


def write_lock(scan: Scan, root: str) -> str:
    path = os.path.join(base_dir(root), LOCK_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot(scan, base_dir(root)), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def check_lock(scan: Scan, root: str):
    """Yield findings for anything that differs from the lockfile. No lockfile, no findings."""
    base = base_dir(root)
    path = os.path.join(base, LOCK_NAME)
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as fh:
            locked = json.load(fh)
        old_servers, old_tools = dict(locked["servers"]), dict(locked["tools"])
    except (OSError, ValueError, KeyError, TypeError):
        scan.errors.append(f"{path}: lockfile is damaged; run `agentguard lock` after reviewing the configs")
        return
    now = snapshot(scan, base)
    fix = "Review the change. If it is intended, run `agentguard lock` and commit the new lockfile."
    for s in scan.servers:
        key = f"{_rel(s.file, base)}#{s.name}"
        if key not in old_servers:
            yield Finding("AG-LCK-002", FAIL, "New server not in the lockfile", s.file, s.line, s.name,
                          "This server was added since the last approved state.", fix, REF)
        elif old_servers[key] != now["servers"][key]:
            yield Finding("AG-LCK-001", FAIL, "Server changed since it was approved", s.file, s.line, s.name,
                          "Its command, arguments, URL or the names of its env values differ from the lockfile.",
                          fix, REF)
    for t in scan.tools:
        key = f"{_rel(t.file, base)}#{t.name}"
        if key not in old_tools:
            yield Finding("AG-LCK-004", FAIL, "New tool not in the lockfile", t.file, t.line, f"tool {t.name}",
                          "This tool appeared since the last approved state.", fix, REF)
        elif old_tools[key] != now["tools"][key]:
            yield Finding("AG-LCK-003", FAIL, "Tool description changed since it was approved", t.file, t.line,
                          f"tool {t.name}", "The description the model reads is not the one that was reviewed.",
                          fix, REF)
