# Authoritative: replaces all exclusions for the provider organization.
# Applying removes existing comments. Destroy clears ALL organization rules.
resource "github_organization_copilot_content_exclusions" "example" {
  rule {
    repository = "*"
    paths      = ["/secrets/**", "*.env"]
  }

  rule {
    repository = "https://github.com/example-organization/example-repository"
    paths      = ["/internal/**"]
  }
}
