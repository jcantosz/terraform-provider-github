# Uses the organization configured as the provider owner.
# Destroy disables self-hosted runners for all repositories in the organization.
resource "github_actions_organization_self_hosted_runners" "example" {
  enabled_repositories = "selected"
  selected_repository_ids = [
    github_repository.example.repo_id,
  ]
}

resource "github_repository" "example" {
  name       = "runner-enabled-example"
  visibility = "private"
}
