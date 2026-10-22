resource "github_organization_secret_scanning_pattern_configuration" "provider_pattern" {
  pattern_type            = "provider"
  token_type              = "GITHUB_PERSONAL_ACCESS_TOKEN"
  push_protection_setting = "enabled"
}

resource "github_organization_secret_scanning_pattern_configuration" "custom_pattern" {
  pattern_type            = "custom"
  token_type              = "cp_2"
  push_protection_setting = "enabled"
}
