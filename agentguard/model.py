from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict

FAIL, WARN = "FAIL", "WARN"


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    file: str
    line: int
    where: str          # server / tool / setting the finding is about
    message: str        # what is wrong, with any secret already masked
    fix: str
    ref: str = ""       # incident or advisory behind the rule

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Server:
    """One MCP server entry from a client config."""
    name: str
    file: str
    line: int
    command: str = ""
    args: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url: str = ""
    headers: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


@dataclass
class Tool:
    """One tool definition (name + description) from a tools manifest."""
    name: str
    description: str
    file: str
    line: int


def mask(secret: str) -> str:
    """Never print a secret: first 4 chars plus a short fingerprint."""
    digest = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"{secret[:4]}…(sha256:{digest})"
