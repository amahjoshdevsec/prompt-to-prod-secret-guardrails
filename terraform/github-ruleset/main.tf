# Layer 3 enforcement as code: make the guardrail checks REQUIRED on the default branch
# of every onboarded repo, so the pipeline gate cannot be skipped by merging around it.

terraform {
  required_version = ">= 1.5"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.0"
    }
  }
}

provider "github" {
  owner = var.owner # auth via GITHUB_TOKEN env var, never hardcoded
}

resource "github_repository_ruleset" "secret_guardrails" {
  for_each = toset(var.repositories)

  name        = "require-secret-guardrails"
  repository  = each.value
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    pull_request {
      required_approving_review_count = 1
    }

    required_status_checks {
      strict_required_status_checks_policy = false
      dynamic "required_check" {
        for_each = var.required_checks
        content {
          context = required_check.value
        }
      }
    }
  }

  # Break-glass: a security admin team can bypass, and every bypass is audited by GitHub.
  dynamic "bypass_actors" {
    for_each = var.break_glass_team_id == null ? [] : [var.break_glass_team_id]
    content {
      actor_id    = bypass_actors.value
      actor_type  = "Team"
      bypass_mode = "pull_request"
    }
  }
}
