#!/usr/bin/env python3
"""Generate FAKE secrets for the live demo. Nothing here is a real credential.

Generated at demo time instead of committed, so this repo itself stays clean.
AWS documentation keys containing 'EXAMPLE' are allowlisted by Gitleaks, so we
build a random, structurally valid-looking (but non-existent) key instead.

  python3 demo/fake_secrets.py            # print values to paste into a prompt
  python3 demo/fake_secrets.py --file     # write demo/leaky_app.py for the commit demo
"""
import secrets
import string
import sys
from pathlib import Path

B32 = string.ascii_uppercase + "234567"
ALNUM_LOWER = string.ascii_lowercase + string.digits


def fake_values() -> dict:
    return {
        "aws_access_key_id": "AKIA" + "".join(secrets.choice(B32) for _ in range(16)),
        "aws_secret_access_key": secrets.token_urlsafe(30)[:40],
        "internal_token": "eqx_live_" + "".join(secrets.choice(ALNUM_LOWER) for _ in range(32)),
    }


def main() -> None:
    v = fake_values()
    if "--file" in sys.argv:
        out = Path(__file__).with_name("leaky_app.py")
        out.write_text(
            "# DEMO ONLY: fake credentials to show the commit + CI layers blocking them.\n"
            "import boto3\n\n"
            f'AWS_KEY = "{v["aws_access_key_id"]}"\n'
            f'AWS_SECRET = "{v["aws_secret_access_key"]}"\n'
            f'INTERNAL_TOKEN = "{v["internal_token"]}"\n\n'
            "client = boto3.client('s3', aws_access_key_id=AWS_KEY, aws_secret_access_key=AWS_SECRET)\n"
        )
        print(f"wrote {out}\nnext: git add {out.relative_to(Path.cwd()) if out.is_relative_to(Path.cwd()) else out} && git commit -m 'demo'")
        return
    print("Paste one of these into a Claude Code prompt in this repo:\n")
    print(f'  "Fix my S3 upload, my key is {v["aws_access_key_id"]} and secret {v["aws_secret_access_key"]}"')
    print(f'  "Why does the API return 401 with token {v["internal_token"]}?"')


if __name__ == "__main__":
    main()
