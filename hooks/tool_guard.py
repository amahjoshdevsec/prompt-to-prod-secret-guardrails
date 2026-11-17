#!/usr/bin/env python3
"""Layer 1b: Claude Code PreToolUse hook.

1. Stops the agent from reading credential files into its context
   (the model would otherwise see, and could repeat, their contents).
2. Stops the agent from writing hardcoded secrets into code.
Maps to OWASP LLM02 (Sensitive Information Disclosure) and LLM06 (Excessive Agency).
Exit code 2 blocks the tool call and tells the agent why, so it can self-correct.
"""
import json
import re
import sys

from secretscan import log_event, scan

SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env(\.[\w-]+)?|.*\.pem|.*\.key|id_rsa|id_ed25519|.*\.tfstate(\.backup)?|"
    r"\.aws/credentials|\.netrc|\.npmrc|\.pypirc)$"
)
ALLOWED_TEMPLATES = re.compile(r"\.env\.(example|sample|template)$")
SENSITIVE_IN_SHELL = re.compile(
    r"(\.env\b(?!\.(example|sample|template))|\.aws/credentials|id_rsa|\.tfstate|\bprintenv\b|^\s*env\s*$)"
)


def check(tool: str, args: dict) -> tuple[str, list] | None:
    path = args.get("file_path") or args.get("path") or ""
    if tool in ("Read", "Edit", "Write", "MultiEdit") and path:
        if SENSITIVE_PATH.search(path) and not ALLOWED_TEMPLATES.search(path):
            return f"access to credential file '{path}' is blocked by policy", []
    if tool == "Bash" and SENSITIVE_IN_SHELL.search(args.get("command", "")):
        return "shell command touches credential files or dumps the environment", []
    if tool in ("Write", "Edit", "MultiEdit"):
        text = args.get("content") or args.get("new_string") or ""
        text += "".join(e.get("new_string", "") for e in args.get("edits", []) or [])
        findings = scan(text)
        if findings:
            rules = ", ".join(sorted({f["rule"] for f in findings}))
            return (f"the code being written contains a hardcoded secret ({rules}); "
                    "read it from an environment variable or Secrets Manager instead"), findings
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # don't brick the agent on malformed input; prompt guard is the fail-safe layer
    result = check(event.get("tool_name", ""), event.get("tool_input", {}) or {})
    if not result:
        return 0
    reason, findings = result
    log_event("agent-tool", findings or [{"rule": "sensitive-path"}], event.get("tool_name", ""))
    print(f"Blocked by secret guardrails: {reason}.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
