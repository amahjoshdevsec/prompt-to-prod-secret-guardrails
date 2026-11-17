"""Shared secret scanner used by the prompt, tool and commit hooks.

Uses Gitleaks (same .gitleaks.toml as CI) when it is installed. Falls back to a
small built-in rule set so the hooks still work on a fresh laptop.
Findings are always redacted: the guard must never print the secret it caught.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parent.parent)
CONFIG = REPO_ROOT / ".gitleaks.toml"
EVENTS = Path(os.environ.get("GUARDRAILS_EVENTS") or REPO_ROOT / ".guardrails" / "events.jsonl")
FORCE_BUILTIN = os.environ.get("GUARDRAILS_ENGINE") == "builtin"

# Fallback rules: a subset of Gitleaks defaults plus the custom internal token.
FALLBACK_RULES = {
    "aws-access-token": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
    "github-pat": re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"),
    "private-key": re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
    "slack-bot-token": re.compile(r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9-]*)\b"),
    "internal-api-token": re.compile(r"\b(eqx_(?:live|test)_[a-z0-9]{32})\b"),
}


def _redact(value: str) -> str:
    return value[:4] + "*" * max(len(value) - 4, 4) if value else "****"


def _scan_gitleaks(text: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        cmd = ["gitleaks", "stdin", "--no-banner", "--redact", "--exit-code", "0",
               "--report-format", "json", "--report-path", str(report)]
        if CONFIG.exists():
            cmd += ["--config", str(CONFIG)]
        subprocess.run(cmd, input=text, text=True, capture_output=True, timeout=10, check=False)
        if not report.exists():
            return []
        raw = json.loads(report.read_text() or "[]")
    return [{"rule": f.get("RuleID", "unknown"), "match": "REDACTED", "line": f.get("StartLine")} for f in raw]


def _scan_fallback(text: str) -> list[dict]:
    findings = []
    for rule, pattern in FALLBACK_RULES.items():
        for m in pattern.finditer(text):
            if rule == "aws-access-token" and "EXAMPLE" in m.group(0):
                continue  # mirror Gitleaks' allowlist for AWS documentation keys
            findings.append({"rule": rule, "match": _redact(m.group(0)),
                             "line": text.count("\n", 0, m.start()) + 1})
    return findings


def scan(text: str) -> list[dict]:
    if not text:
        return []
    if shutil.which("gitleaks") and not FORCE_BUILTIN:
        try:
            return _scan_gitleaks(text)
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            pass  # never let a scanner error silently disable the guard
    return _scan_fallback(text)


def engine() -> str:
    return "gitleaks" if shutil.which("gitleaks") else "builtin"


def log_event(layer: str, findings: list[dict], source: str) -> None:
    """Append one line per finding so report.py can compute catches per layer."""
    EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS.open("a") as fh:
        for f in findings:
            fh.write(json.dumps({"ts": int(time.time()), "layer": layer, "rule": f["rule"],
                                 "source": source, "repo": REPO_ROOT.name}) + "\n")
