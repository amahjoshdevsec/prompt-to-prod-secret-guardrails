# Prompt-to-Prod Secret Guardrails

Stop a leaked secret at five points, from the AI coding assistant prompt to production
response. The further left a secret is caught, the cheaper the fix and the smaller the exposure.

```
 Developer + AI assistant                Git                      GitHub                      AWS
 ───────────────────────────    ─────────────────────    ───────────────────────────    ───────────────────────
 1 PROMPT / AGENT                2 COMMIT                 3 PIPELINE (enforced)          5 RESPONSE
 UserPromptSubmit hook  ──┐      pre-commit:              Reusable workflow:             AWS Health risk event
 PreToolUse hook          │      Gitleaks (staged)        Gitleaks (full history)        -> EventBridge -> Lambda
 CLAUDE.md / Copilot      ├──>   Semgrep          ──>     Semgrep (new only)     ──>     deactivate key, deny-all,
 steering (nudge)         │      (bypassable)             Trivy SCA + IaC                CloudTrail 24h, notify
                          │                               SARIF -> PR annotations
                          │                               Required by Terraform ruleset
                          │
 4 ONBOARD + MEASURE: onboard.py opens a PR per repo; report.py shows catches per layer + shift-left ratio
```

| Layer | Control type | Files | OWASP LLM / Top 10 mapping |
| --- | --- | --- | --- |
| 1 Prompt + agent | Deterministic (hooks) + non-deterministic (steering) | `.claude/settings.json`, `hooks/prompt_guard.py`, `hooks/tool_guard.py`, `CLAUDE.md`, `.github/copilot-instructions.md` | LLM02 Sensitive Information Disclosure, LLM06 Excessive Agency |
| 2 Commit | Deterministic, bypassable (`--no-verify`) | `.pre-commit-config.yaml`, `hooks/precommit_gitleaks.sh`, `.gitleaks.toml` | A07 Identification and Authentication Failures (hardcoded creds) |
| 3 Pipeline | Deterministic, enforced | `.github/workflows/secret-guardrails.yml`, `terraform/github-ruleset/` | A06 Vulnerable Components (Trivy), A03 Injection etc. (Semgrep) |
| 4 Onboard + metrics | Automation | `scripts/onboard.py`, `scripts/report.py` | |
| 5 Response | Automated containment | `terraform/exposed-key-response/` | |

One `.gitleaks.toml` is shared by every layer, including a **custom rule** for an internal
token format (`eqx_live_` + 32 chars, made up for this demo). Default rules never know a
company's own token formats.

## Design decisions

- **Fail on new findings only.** PRs scan only their own commits; Semgrep uses `--baseline-commit`;
  history is baselined in `.gitleaks-baseline.json`. Rolling out a gate that blocks every PR on
  day one teaches developers to bypass it.
- **IDE layer advises, pipeline layer enforces.** Hooks can be skipped on an unmanaged laptop;
  the required check cannot. Steering files nudge the model; hooks and gates guarantee.
- **Redact everywhere.** The guard never echoes the secret it caught.
- **Fix, not just "no".** Every block message says what to do instead.
- **Supply chain of the guardrails themselves.** Gitleaks binary is pinned and checksum-verified;
  pin actions to commit SHAs in production.

## Quick start

```bash
make setup        # brew install gitleaks semgrep pre-commit; pre-commit install
make test         # unit tests for the prompt + tool hooks (no network)
```

## Demo script (3 minutes)

1. **Prompt layer:** `python3 demo/fake_secrets.py`, open `claude` in this repo, paste a line. Blocked before it reaches the model.
2. **Agent layer:** ask Claude to "read .env and summarize it". Blocked by `tool_guard.py`.
3. **Commit layer:** `python3 demo/fake_secrets.py --file && git add demo/leaky_app.py && git commit -m demo`. Blocked.
4. **Pipeline layer:** `git commit --no-verify -m demo && git push` on a branch, open a PR. Required `gitleaks` check fails with an inline annotation.
5. **Metrics:** `python3 scripts/report.py --repos <owner>/<repo>`.
6. Clean up: `git rm demo/leaky_app.py`, delete the branch.

## Onboarding other repos

```bash
python3 scripts/onboard.py --workflow-ref <owner>/prompt-to-prod-secret-guardrails@main --repos <owner>/app-1 <owner>/app-2           # dry run
python3 scripts/onboard.py --workflow-ref <owner>/prompt-to-prod-secret-guardrails@main --repos <owner>/app-1 <owner>/app-2 --apply   # opens PRs
cd terraform/github-ruleset && terraform init && terraform apply   # makes the checks required
```

## Baseline / exception process

Historical findings go in `.gitleaks-baseline.json` (generate with
`gitleaks git --report-path .gitleaks-baseline.json`). Every entry needs a ticket with an owner
and an expiry date, and the secret must be **rotated** before it is baselined: baselining hides
the alert, it does not undo exposure.

## References

- AWS Security Blog: [Balancing speed and safety: A control framework for AI coding agents](https://aws.amazon.com/blogs/security/balancing-speed-and-safety-a-control-framework-for-ai-coding-agents/)
- GitGuardian: [Prevent leaks with AI Hooks](https://docs.gitguardian.com/endpoint-protection/ai-hooks)
- aws-samples: [notify-and-remediate-exposed-access-key](https://github.com/aws-samples/notify-and-remediate-exposed-access-key) (layer 5 is a simplified Terraform port)
