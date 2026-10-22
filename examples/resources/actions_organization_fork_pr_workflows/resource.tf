# Uses the organization configured as the provider owner.
# Destroy disables fork PR workflows in private repositories.
resource "github_actions_organization_fork_pr_workflows" "example" {
  run_workflows_from_fork_pull_requests = false
}
