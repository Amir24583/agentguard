# AgentGuard

[Website and founding plan](https://amir24583.github.io/agentguard/) · MIT licensed · early version (v0.1)

Deterministic security checks for AI agent and MCP configuration files. No AI model,
no network calls, no dependencies. It only parses files and never runs anything from
the scanned folder.

```bash
python -m agentguard scan path/to/repo            # human-readable report
python -m agentguard scan path/to/repo --json     # for other tools
python -m agentguard scan path/to/repo --sarif    # for GitHub code scanning
python -m agentguard scan examples/risky          # see every kind of finding
python -m agentguard lock path/to/repo            # approve the current servers and tools
python -m unittest discover -s tests -v           # one failing + one passing case per rule
```

Exit codes: `0` clean, `1` findings that block, `2` scanner or input error (never treated as a pass).

## What it reads

`.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`,
`.claude/settings.json`, `tools.json` (a saved `tools/list` result), and instruction files
(`CLAUDE.md`, `AGENTS.md`, `.cursorrules`).

## Rules in this version

| ID | Level | Catches |
| --- | --- | --- |
| AG-SEC-001 | FAIL | API keys and tokens in env, args, headers or URLs (always masked in output) |
| AG-SEC-002 | FAIL | Username or password inside a server URL |
| AG-SUP-001 | FAIL | `npx` / `uvx` package with no exact version |
| AG-SUP-002 | WARN | Docker image not pinned by digest |
| AG-SUP-003 | FAIL | Known-vulnerable versions (mcp-remote < 0.1.16, mcp-server-git < 2025.12.18) |
| AG-SUP-004 | WARN | Package fetched from a URL or git ref |
| AG-SUP-005 | FAIL | `curl ... \| sh` in a launch command |
| AG-NET-001 | FAIL | Server bound to 0.0.0.0 |
| AG-NET-002 | FAIL | Plain http:// to a remote server |
| AG-PWR-001 | WARN | Whole-disk or home-folder access |
| AG-PWR-002 | WARN | Blanket auto-approve of a server's tools |
| AG-PWR-003 | FAIL | Permission prompts disabled |
| AG-PWR-004 | WARN | Any shell command allowed |
| AG-PWR-005 | WARN | Every project MCP server trusted automatically |
| AG-PWR-006 | FAIL | Hook that downloads and runs a script |
| AG-INT-001 | FAIL | Invisible Unicode in tool definitions or instruction files |
| AG-INT-002 | FAIL | Tool description that gives orders to the model |
| AG-INT-003 | FAIL | Tool description that points at credentials |
| AG-INT-004 | WARN | Same tool name defined by two servers |
| AG-LCK-001 to 004 | FAIL | A server or tool that was added or changed since `agentguard lock` |
| AG-TOX-001 | WARN | Private data + untrusted input + a way out in one agent (name-based guess) |

## Ignoring a finding

`agentguard.json` next to the scanned folder. A written reason is required, and ignored
findings still show in the report.

```json
{"ignore": [{"rule": "AG-NET-001", "where": "notes", "reason": "runs in a sealed container"}]}
```

## The lockfile

`agentguard lock` writes `agentguard.lock`, a fingerprint of every server's launch command
and every tool description. Commit it. From then on a scan fails when a server or tool is
added or changed, until someone reviews the change and runs `agentguard lock` again. Env
and header values are never stored, only their names.

## Limits

AgentGuard checks for known, common mistakes in configuration files. A clean result does
not prove an agent is safe. It cannot see prompt injection that arrives at run time or a
server that behaves differently from what it declares.

## Not built yet

GitHub Action wrapper, MCP server source scanning, CI workflow scanning, package age and
typosquat lookups. The known-vulnerable list has two entries and needs checking against
the primary advisories.

## Reporting a security problem

Please email amireias06@gmail.com instead of opening a public issue.
