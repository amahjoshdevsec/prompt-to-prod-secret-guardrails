variable "owner" {
  description = "GitHub user or organization that owns the repositories"
  type        = string
}

variable "repositories" {
  description = "Repositories to enforce the guardrails on (names, not URLs)"
  type        = list(string)
}

variable "required_checks" {
  description = "Status check contexts that must pass. When the workflow is called as a reusable workflow, use '<caller job> / <job>' e.g. 'guardrails / gitleaks'."
  type        = list(string)
  default     = ["gitleaks", "semgrep", "trivy"]
}

variable "break_glass_team_id" {
  description = "Optional numeric ID of a team allowed to bypass (audited)"
  type        = number
  default     = null
}
