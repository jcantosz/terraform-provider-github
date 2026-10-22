resource "github_code_security_configuration" "example" {
  name        = "Selected repository baseline"
  description = "Code security configuration for selected repositories"
  enforcement = "unenforced"
}

resource "github_repository" "example" {
  name       = "example"
  visibility = "private"
}

resource "github_code_security_configuration_repository" "example" {
  configuration_id = github_code_security_configuration.example.id
  repository_id    = github_repository.example.repo_id
}
