"""Command line: agentguard scan <path> [--json | --sarif] [--fail-on fail|warn]
              agentguard lock <path>"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .discover import scan_path
from .lock import check_lock, write_lock
from .model import FAIL, WARN
from .rules import run_rules

DISCLAIMER = ("AgentGuard checks for known, common mistakes. A clean result does not prove "
              "an agent is safe: it cannot see attacks that arrive at run time.")


def load_ignores(root: str):
    """agentguard.json: {"ignore": [{"rule": "AG-PWR-001", "where": "files", "reason": "..."}]}"""
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    path = os.path.join(base, "agentguard.json")
    if not os.path.isfile(path):
        return [], []
    try:
        with open(path, encoding="utf-8") as fh:
            entries = json.load(fh).get("ignore", [])
    except (OSError, ValueError, AttributeError):
        return [], [f"{path}: could not be read, so no findings were ignored"]
    good, errors = [], []
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get("rule") and str(e.get("reason", "")).strip():
            good.append(e)
        else:
            errors.append(f"{path}: an ignore entry needs both \"rule\" and a written \"reason\"")
    return good, errors


def apply_ignores(findings, ignores):
    kept, ignored = [], []
    for f in findings:
        match = next((e for e in ignores if e["rule"] == f.rule
                      and (not e.get("where") or str(e["where"]) in f.where)), None)
        (ignored if match else kept).append((f, match) if match else f)
    return kept, ignored


def color(text: str, code: str, on: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if on else text


def render_text(findings, ignored, scan, root, use_color) -> str:
    out = []
    if not scan.files:
        out.append("No agent or MCP configuration files found.")
    for f in findings:
        tag = color(f.severity, "1;31" if f.severity == FAIL else "1;33", use_color)
        rel = os.path.relpath(f.file, root if os.path.isdir(root) else os.path.dirname(root) or ".")
        out.append(f"{tag}  {f.rule}  {f.title}")
        out.append(f"      {rel}:{f.line}  ({f.where})")
        out.append(f"      {f.message}")
        out.append(f"      Fix: {f.fix}")
        out.append("")
    for f, e in ignored:
        out.append(f"IGNORED  {f.rule}  {f.where}  reason: {e['reason']}")
    fails = sum(f.severity == FAIL for f in findings)
    warns = sum(f.severity == WARN for f in findings)
    for err in scan.errors:
        out.append(f"ERROR  {err}")
    out.append(f"{len(scan.files)} files scanned · {fails} failed · {warns} warnings"
               + (f" · {len(ignored)} ignored" if ignored else ""))
    out.append(DISCLAIMER)
    return "\n".join(out)


def render_sarif(findings, root) -> dict:
    rules = {}
    for f in findings:
        rules.setdefault(f.rule, {"id": f.rule, "name": f.title, "shortDescription": {"text": f.title},
                                  "help": {"text": f.fix}})
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "AgentGuard", "version": __version__, "rules": list(rules.values())}},
            "results": [{
                "ruleId": f.rule,
                "level": "error" if f.severity == FAIL else "warning",
                "message": {"text": f"{f.message} Fix: {f.fix}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": os.path.relpath(f.file, base).replace(os.sep, "/")},
                    "region": {"startLine": max(f.line, 1)}}}],
            } for f in findings],
        }],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="agentguard", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("scan", help="scan a repo folder or a single config file")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 for GitHub code scanning")
    sp.add_argument("--fail-on", choices=["fail", "warn"], default="fail")
    lp = sub.add_parser("lock", help="record the current servers and tools as approved")
    lp.add_argument("path", nargs="?", default=".")
    args = parser.parse_args(argv)

    if args.cmd == "lock":
        if not os.path.exists(args.path):
            print(f"agentguard: {args.path} does not exist", file=sys.stderr)
            return 2
        scan = scan_path(args.path)
        if scan.errors:
            print("\n".join(f"ERROR  {e}" for e in scan.errors), file=sys.stderr)
            return 2
        path = write_lock(scan, args.path)
        print(f"Wrote {path}: {len(scan.servers)} servers, {len(scan.tools)} tools. Commit it.")
        return 0

    try:
        if not os.path.exists(args.path):
            print(f"agentguard: {args.path} does not exist", file=sys.stderr)
            return 2
        scan = scan_path(args.path)
        ignores, ignore_errors = load_ignores(args.path)
        scan.errors.extend(ignore_errors)
        findings, ignored = apply_ignores(run_rules(scan) + list(check_lock(scan, args.path)), ignores)
    except Exception as exc:  # a scanner crash must never look like a pass
        print(f"agentguard: internal error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2

    if args.sarif:
        print(json.dumps(render_sarif(findings, args.path), indent=2))
    elif args.json:
        print(json.dumps({
            "version": __version__, "files": scan.files, "errors": scan.errors,
            "findings": [f.to_dict() for f in findings],
            "ignored": [{**f.to_dict(), "reason": e["reason"]} for f, e in ignored],
            "disclaimer": DISCLAIMER,
        }, indent=2))
    else:
        print(render_text(findings, ignored, scan, args.path, sys.stdout.isatty()))

    if scan.errors:
        return 2
    blocking = [f for f in findings if f.severity == FAIL or args.fail_on == "warn"]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
