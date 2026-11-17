.PHONY: setup test scan report demo-prompt demo-commit clean-demo

setup:
	brew install gitleaks semgrep pre-commit
	pre-commit install

test:
	GUARDRAILS_ENGINE=builtin python3 -m unittest discover -s tests -v
	@command -v gitleaks >/dev/null && python3 -m unittest discover -s tests -v || echo "gitleaks not installed: skipped gitleaks-engine run"

scan:
	gitleaks git . --config .gitleaks.toml --redact --no-banner

report:
	python3 scripts/report.py

demo-prompt:
	python3 demo/fake_secrets.py

demo-commit:
	python3 demo/fake_secrets.py --file

clean-demo:
	rm -f demo/leaky_app.py .guardrails/events.jsonl
