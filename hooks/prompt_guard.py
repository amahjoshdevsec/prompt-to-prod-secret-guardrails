#!/usr/bin/env python3
"""Layer 1a: Claude Code UserPromptSubmit hook.

Scans the prompt before it is sent to the model. Exit code 2 blocks the prompt
and shows stderr to the developer, so the secret never leaves the laptop.
Maps to OWASP Top 10 for LLM Applications: LLM02 Sensitive Information Disclosure.
"""
import json
import sys

from secretscan import log_event, scan

FIX_HINT = (
    "Remove the secret and reference it instead, e.g. an env var name or a "
    "Secrets Manager ARN. It was NOT sent to the model. If you copied it from a "
    "shared place (chat, ticket, doc), rotate it."
)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("prompt_guard: could not parse hook input; blocking to fail safe", file=sys.stderr)
        return 2
    findings = scan(event.get("prompt", ""))
    if not findings:
        return 0
    log_event("prompt", findings, "UserPromptSubmit")
    rules = ", ".join(sorted({f["rule"] for f in findings}))
    print(f"Blocked: your prompt contains a secret ({rules}). {FIX_HINT}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
