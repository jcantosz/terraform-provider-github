resource "github_team" "security_reviewers" {
  name        = "security-reviewers"
  description = "Reviewers for push protection bypass requests"
  privacy     = "closed"
}

resource "github_code_security_configuration" "example" {
  name                             = "Baseline"
  description                      = "Organization code security baseline"
  code_security                    = "enabled"
  dependency_graph                 = "enabled"
  dependabot_alerts                = "enabled"
  dependabot_security_updates      = "enabled"
  code_scanning_default_setup      = "enabled"
  private_vulnerability_reporting  = "enabled"
  enforcement                      = "unenforced"
  secret_protection                = "enabled"
  secret_scanning                  = "enabled"
  secret_scanning_push_protection  = "enabled"
  secret_scanning_delegated_bypass = "enabled"
  secret_scanning_validity_checks  = "enabled"

  code_scanning_options {
    allow_advanced = true
  }

  code_scanning_default_setup_options {
    runner_type = "standard"
  }

  secret_scanning_delegated_bypass_options {
    reviewers {
      reviewer_id   = github_team.security_reviewers.id
      reviewer_type = "TEAM"
    }
  }
}
