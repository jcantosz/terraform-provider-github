# The provider owner must explicitly identify the organization.
# Publication and push protection are managed outside this resource.
resource "github_organization_secret_scanning_custom_pattern" "example" {
  name               = "Internal service token"
  pattern            = "internal_service_[0-9A-Za-z]{32}"
  start_delimiter    = "\\A|[^0-9A-Za-z]"
  end_delimiter      = "\\z|[^0-9A-Za-z]"
  must_match         = ["[0-9]"]
  must_not_match     = ["internal_service_0{32}"]
  post_delete_action = "resolve_alerts"
}
