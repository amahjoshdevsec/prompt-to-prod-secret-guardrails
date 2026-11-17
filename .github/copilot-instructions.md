# Secure coding standard for AI assistants (steering file)

GitHub Copilot reads this file as repository custom instructions. It is a
NON-deterministic control: it nudges generated code toward secure defaults.
The hooks in `hooks/` and the CI gates are the DETERMINISTIC controls that enforce it.

## Secrets
- Never hardcode credentials, tokens, keys or connection strings. Read them from
  environment variables or AWS Secrets Manager / SSM Parameter Store.
- Never print, log, or echo secret values, including in error messages and tests.
- Use OIDC / IAM roles for CI and workloads. Never create long-lived access keys.
- Never read `.env`, `*.pem`, `~/.aws/credentials` or Terraform state files.

## Code (OWASP Top 10 / ASVS L2 basics)
- Parameterized queries only; no string-built SQL or shell commands.
- Validate input with allowlists; encode output for its context (HTML, URL, shell).
- Enforce authorization on every object access (no IDOR / BOLA).
- Server-side requests to user-supplied URLs must use an allowlist (SSRF).
- No `pickle`/`yaml.load`/`eval` on untrusted data.

## Dependencies
- Only add packages that exist on the approved internal registry. Prefer
  well-known, maintained packages and pin exact versions. Never invent a package name.

## Infrastructure as code
- Encryption at rest on by default, no public S3 buckets, no 0.0.0.0/0 on admin ports,
  IMDSv2 required on EC2, least-privilege IAM (no `Action: "*"` outside break-glass).
