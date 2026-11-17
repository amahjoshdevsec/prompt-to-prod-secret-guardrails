#!/usr/bin/env bash
# Layer 2: pre-commit secret scan on STAGED changes only (fast: < 1 s on typical commits).
# Logs catches to .guardrails/events.jsonl so report.py can show the shift-left ratio.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks not installed: run 'make setup'. CI will still scan this commit." >&2
  exit 0
fi

REPORT="$(mktemp)"
trap 'rm -f "$REPORT"' EXIT

if gitleaks git --pre-commit --staged --redact --no-banner \
     --config "$ROOT/.gitleaks.toml" \
     --report-format json --report-path "$REPORT" "$ROOT"; then
  exit 0
fi

python3 - "$REPORT" "$ROOT" <<'PY'
import json, sys, time, pathlib
report, root = sys.argv[1], pathlib.Path(sys.argv[2])
events = root / ".guardrails" / "events.jsonl"
events.parent.mkdir(exist_ok=True)
with events.open("a") as fh:
    for f in json.loads(open(report).read() or "[]"):
        fh.write(json.dumps({"ts": int(time.time()), "layer": "commit", "rule": f.get("RuleID"),
                             "source": f.get("File"), "repo": root.name}) + "\n")
PY

echo "" >&2
echo "Commit blocked: secret found in staged changes (details above, values redacted)." >&2
echo "Fix: remove it, load it from env/Secrets Manager, and rotate it if it was ever pushed." >&2
exit 1
