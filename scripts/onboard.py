#!/usr/bin/env python3
"""Layer 4a: onboard repositories to the secret guardrails by opening a PR in each.

Teams get a reviewable PR instead of "please copy this YAML", which is how you
reach hundreds of repos without a ticket per team.

Usage:
  python3 scripts/onboard.py --workflow-ref me/prompt-to-prod-secret-guardrails@main \
      --repos me/app-1 me/app-2            # dry run: prints the plan
  python3 scripts/onboard.py ... --apply   # creates branches + PRs (needs `gh auth login`)

Then enforce with terraform/github-ruleset so the checks are required.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRANCH = "security/secret-guardrails"

# Files copied verbatim: prompt layer, commit layer, shared config.
KIT = [
    ".gitleaks.toml",
    ".pre-commit-config.yaml",
    ".claude/settings.json",
    "CLAUDE.md",
    ".github/copilot-instructions.md",
    "hooks/secretscan.py",
    "hooks/prompt_guard.py",
    "hooks/tool_guard.py",
    "hooks/precommit_gitleaks.sh",
]

CALLER_WORKFLOW = """name: secret-guardrails
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  guardrails:
    uses: {ref}
"""

PR_BODY = """Adds the secret guardrails kit (owned by AppSec):

| Layer | What it does |
| --- | --- |
| AI prompt / agent | Claude Code hooks block secrets in prompts and stop the agent reading credential files |
| Steering | `CLAUDE.md` + Copilot instructions with the secure coding standard |
| Commit | pre-commit Gitleaks + Semgrep on staged changes (`pre-commit install` once) |
| CI | Reusable workflow: Gitleaks, Semgrep, Trivy; fails on NEW findings only |

Existing findings are not blocking. Questions: #appsec. False positive? Comment on the PR annotation.
"""


def gh(*args: str, check: bool = True) -> str:
    res = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or res.stdout.strip())
    return res.stdout if res.returncode == 0 else ""


def put_file(repo: str, path: str, content: bytes, branch: str) -> None:
    existing = gh(f"repos/{repo}/contents/{path}?ref={branch}", "--jq", ".sha", check=False).strip()
    args = [f"repos/{repo}/contents/{path}", "-X", "PUT",
            "-f", f"message=chore(security): add {path}",
            "-f", f"content={base64.b64encode(content).decode()}",
            "-f", f"branch={branch}"]
    if existing:
        args += ["-f", f"sha={existing}"]
    gh(*args)


def onboard(repo: str, workflow_ref: str, apply: bool) -> dict:
    files = {p: (ROOT / p).read_bytes() for p in KIT}
    files[".github/workflows/secret-guardrails.yml"] = CALLER_WORKFLOW.format(
        ref=f"{workflow_ref.split('@')[0]}/.github/workflows/secret-guardrails.yml@{workflow_ref.split('@')[1]}"
    ).encode()

    if not apply:
        return {"repo": repo, "status": "dry-run", "files": sorted(files)}

    base = gh(f"repos/{repo}", "--jq", ".default_branch").strip()
    sha = gh(f"repos/{repo}/git/ref/heads/{base}", "--jq", ".object.sha").strip()
    gh(f"repos/{repo}/git/refs", "-X", "POST", "-f", f"ref=refs/heads/{BRANCH}", "-f", f"sha={sha}", check=False)
    for path, content in files.items():
        put_file(repo, path, content, BRANCH)
    pr = json.loads(gh(f"repos/{repo}/pulls", "-X", "POST",
                       "-f", "title=Add secret guardrails (prompt to pipeline)",
                       "-f", f"head={BRANCH}", "-f", f"base={base}", "-f", f"body={PR_BODY}"))
    return {"repo": repo, "status": "pr-opened", "url": pr.get("html_url")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repos", nargs="*", default=[], help="owner/name ...")
    ap.add_argument("--repos-file", type=Path, help="one owner/name per line")
    ap.add_argument("--workflow-ref", required=True, help="owner/guardrails-repo@ref hosting the reusable workflow")
    ap.add_argument("--apply", action="store_true", help="actually create branches and PRs")
    a = ap.parse_args()

    repos = list(a.repos)
    if a.repos_file:
        repos += [l.strip() for l in a.repos_file.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not repos or "@" not in a.workflow_ref:
        ap.error("give --repos/--repos-file and --workflow-ref owner/repo@ref")

    failures = 0
    for repo in repos:
        try:
            print(json.dumps(onboard(repo, a.workflow_ref, a.apply)))
        except RuntimeError as exc:  # one bad repo must not stop the rollout
            failures += 1
            print(json.dumps({"repo": repo, "status": "failed", "error": str(exc)}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
