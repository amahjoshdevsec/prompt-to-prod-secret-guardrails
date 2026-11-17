"""Unit tests for the prompt and tool hooks. Fake secrets are generated at runtime."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))
from fake_secrets import fake_values  # noqa: E402


class HookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.events = Path(self.tmp.name) / "events.jsonl"
        self.env = {**os.environ, "CLAUDE_PROJECT_DIR": str(ROOT), "GUARDRAILS_EVENTS": str(self.events)}
        self.v = fake_values()

    def tearDown(self):
        self.tmp.cleanup()

    def run_hook(self, name, payload):
        return subprocess.run([sys.executable, str(ROOT / "hooks" / name)], input=json.dumps(payload),
                              capture_output=True, text=True, env=self.env)

    # ---- prompt layer ----
    def test_prompt_with_aws_key_is_blocked_and_redacted(self):
        r = self.run_hook("prompt_guard.py", {"prompt": f"my key is {self.v['aws_access_key_id']}"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("aws-access-token", r.stderr)
        self.assertNotIn(self.v["aws_access_key_id"], r.stderr + r.stdout)  # never echo the secret
        self.assertEqual(json.loads(self.events.read_text().splitlines()[0])["layer"], "prompt")

    def test_prompt_with_internal_token_is_blocked(self):
        r = self.run_hook("prompt_guard.py", {"prompt": f"401 with {self.v['internal_token']}"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("internal-api-token", r.stderr)

    def test_clean_prompt_passes(self):
        r = self.run_hook("prompt_guard.py", {"prompt": "refactor upload() to read creds from Secrets Manager"})
        self.assertEqual(r.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_aws_documentation_key_is_allowed(self):
        r = self.run_hook("prompt_guard.py", {"prompt": "what is AKIAIOSFODNN7EXAMPLE in the AWS docs?"})
        self.assertEqual(r.returncode, 0)

    def test_malformed_prompt_input_fails_safe(self):
        r = subprocess.run([sys.executable, str(ROOT / "hooks" / "prompt_guard.py")], input="not json",
                           capture_output=True, text=True, env=self.env)
        self.assertEqual(r.returncode, 2)

    # ---- agent tool layer ----
    def test_agent_cannot_read_env_file(self):
        r = self.run_hook("tool_guard.py", {"tool_name": "Read", "tool_input": {"file_path": "/repo/.env"}})
        self.assertEqual(r.returncode, 2)

    def test_agent_can_read_env_example(self):
        r = self.run_hook("tool_guard.py", {"tool_name": "Read", "tool_input": {"file_path": "/repo/.env.example"}})
        self.assertEqual(r.returncode, 0)

    def test_agent_cannot_cat_aws_credentials(self):
        r = self.run_hook("tool_guard.py", {"tool_name": "Bash", "tool_input": {"command": "cat ~/.aws/credentials"}})
        self.assertEqual(r.returncode, 2)

    def test_agent_cannot_write_hardcoded_secret(self):
        code = f'TOKEN = "{self.v["internal_token"]}"\n'
        r = self.run_hook("tool_guard.py", {"tool_name": "Write", "tool_input": {"file_path": "app.py", "content": code}})
        self.assertEqual(r.returncode, 2)
        self.assertIn("Secrets Manager", r.stderr)

    def test_agent_normal_edit_passes(self):
        r = self.run_hook("tool_guard.py", {"tool_name": "Edit", "tool_input": {
            "file_path": "app.py", "old_string": "x", "new_string": 'token = os.environ["API_TOKEN"]'}})
        self.assertEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
