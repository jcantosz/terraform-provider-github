resource "github_code_security_configuration" "example" {
  name        = "Public repository baseline"
  description = "Code security defaults for new public repositories"
}

resource "github_code_security_configuration_default" "example" {
  configuration_id      = github_code_security_configuration.example.id
  default_for_new_repos = "public"
}
