#!/usr/bin/env python3
"""Layer 4b: the metrics a security manager actually asks for.

  - Coverage: which repos have the guardrail workflow
  - Catches per layer: prompt / agent-tool / commit (local events) vs CI (code scanning)
  - Shift-left ratio: share of secrets caught BEFORE they reached a remote
  - Time to fix: median hours from CI alert to fixed, open alert count

Usage:
  python3 scripts/report.py                                  # local layers only
  python3 scripts/report.py --repos me/app-1 me/app-2        # + coverage and CI alerts (gh auth)
  python3 scripts/report.py --json                           # machine-readable for a dashboard

Note: code scanning alerts need public repos or GitHub Advanced Security.
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEFT_LAYERS = ("prompt", "agent-tool", "commit")


def gh_json(path: str):
    res = subprocess.run(["gh", "api", "--paginate", path], capture_output=True, text=True)
    if res.returncode != 0:
        return None
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:  # --paginate concatenates arrays: "][" between pages
        return json.loads("[" + res.stdout.strip()[1:-1].replace("][", ",") + "]")


def local_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build(events_path: Path, repos: list[str]) -> dict:
    layers = Counter(e["layer"] for e in local_events(events_path))
    coverage, fix_hours, open_alerts = {}, [], 0

    for repo in repos:
        wf = subprocess.run(["gh", "api", f"repos/{repo}/contents/.github/workflows/secret-guardrails.yml"],
                            capture_output=True, text=True)
        coverage[repo] = wf.returncode == 0
        alerts = gh_json(f"repos/{repo}/code-scanning/alerts?tool_name=gitleaks&per_page=100") or []
        layers["ci"] += len(alerts)
        for al in alerts:
            if al.get("state") == "open":
                open_alerts += 1
            elif al.get("fixed_at"):
                fix_hours.append((ts(al["fixed_at"]) - ts(al["created_at"])).total_seconds() / 3600)

    total = sum(layers.values())
    left = sum(layers[l] for l in LEFT_LAYERS)
    return {
        "catches_by_layer": {l: layers.get(l, 0) for l in (*LEFT_LAYERS, "ci")},
        "total_catches": total,
        "shift_left_ratio": round(left / total, 3) if total else None,
        "repos_covered": f"{sum(coverage.values())}/{len(coverage)}" if coverage else "n/a (no --repos)",
        "uncovered_repos": [r for r, ok in coverage.items() if not ok],
        "ci_open_alerts": open_alerts,
        "ci_median_hours_to_fix": round(statistics.median(fix_hours), 1) if fix_hours else None,
    }


def render(m: dict) -> str:
    rows = ["", "Secret guardrails report", "=" * 40]
    for layer, n in m["catches_by_layer"].items():
        rows.append(f"  caught at {layer:<11} {n:>5}  {'#' * min(n, 30)}")
    ratio = m["shift_left_ratio"]
    rows += ["-" * 40,
             f"  shift-left ratio        {'n/a' if ratio is None else f'{ratio:.0%}'}  (caught before reaching a remote)",
             f"  repos covered           {m['repos_covered']}",
             f"  open CI alerts          {m['ci_open_alerts']}",
             f"  median hours to fix     {m['ci_median_hours_to_fix'] or 'n/a'}"]
    if m["uncovered_repos"]:
        rows.append(f"  NOT covered: {', '.join(m['uncovered_repos'])}")
    return "\n".join(rows) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos", nargs="*", default=[])
    ap.add_argument("--events", type=Path, default=ROOT / ".guardrails" / "events.jsonl")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    metrics = build(a.events, a.repos)
    print(json.dumps(metrics, indent=2) if a.json else render(metrics))
    return 0


if __name__ == "__main__":
    sys.exit(main())
