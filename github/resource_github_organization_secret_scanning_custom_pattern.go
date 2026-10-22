package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGithubOrganizationSecretScanningCustomPattern() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a single secret scanning custom pattern in the provider organization, not its configuration policy.",
		CreateContext: resourceGithubOrganizationSecretScanningCustomPatternCreate,
		ReadContext:   resourceGithubOrganizationSecretScanningCustomPatternRead,
		UpdateContext: resourceGithubOrganizationSecretScanningCustomPatternUpdate,
		DeleteContext: resourceGithubOrganizationSecretScanningCustomPatternDelete,
		Importer: &schema.ResourceImporter{
			StateContext: func(ctx context.Context, d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
				meta, id, err := organizationSecretScanningCustomPatternOwner(d, m)
				if err != nil {
					return nil, err
				}
				if id <= 0 {
					return nil, fmt.Errorf("import requires %s:<positive pattern ID>", meta.name)
				}
				resourceID, err := buildID(meta.name, strconv.FormatInt(id, 10))
				if err != nil {
					return nil, err
				}
				d.SetId(resourceID)
				if err := d.Set("post_delete_action", "resolve_alerts"); err != nil {
					return nil, err
				}
				return []*schema.ResourceData{d}, nil
			},
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type: schema.TypeString, Required: true, ForceNew: true,
				Description:      "Name of the custom pattern. Renaming requires replacement.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"pattern": {
				Type: schema.TypeString, Required: true,
				Description:      "Secret format regular expression using GitHub's Hyperscan syntax. Syntax is validated by GitHub, not Go's RE2 engine.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
			},
			"start_delimiter": {
				Type: schema.TypeString, Optional: true, Computed: true,
				Description: "Regular expression preceding the secret. Omission on creation uses GitHub's server default.",
			},
			"end_delimiter": {
				Type: schema.TypeString, Optional: true, Computed: true,
				Description: "Regular expression following the secret. Omission on creation uses GitHub's server default.",
			},
			"must_match": {
				Type: schema.TypeList, Optional: true,
				Description: "Additional regular expressions the secret must match. An empty list clears all requirements.",
				Elem:        &schema.Schema{Type: schema.TypeString, ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty)},
			},
			"must_not_match": {
				Type: schema.TypeList, Optional: true,
				Description: "Additional regular expressions the secret must not match. An empty list clears all exclusions.",
				Elem:        &schema.Schema{Type: schema.TypeString, ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty)},
			},
			"post_delete_action": {
				Type: schema.TypeString, Optional: true, Default: "resolve_alerts",
				Description:      "Action for associated alerts on destroy: resolve_alerts preserves alert history (default); delete_alerts permanently deletes alerts. This is local deletion behavior, not a remote pattern attribute.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"resolve_alerts", "delete_alerts"}, false)),
			},
			"slug": {
				Type: schema.TypeString, Computed: true,
				Description: "Server-generated URL-friendly pattern identifier.",
			},
			"state": {
				Type: schema.TypeString, Computed: true,
				Description: "Publication state reported by GitHub. This API does not manage publication.",
			},
			"push_protection_enabled": {
				Type: schema.TypeBool, Computed: true,
				Description: "Push protection status reported by GitHub. This API does not manage push protection.",
			},
			"custom_pattern_version": {
				Type: schema.TypeString, Computed: true,
				Description: "Server concurrency token, refreshed before updates and deletion.",
			},
		},
	}
}

func organizationSecretScanningCustomPatternOwner(d *schema.ResourceData, m any) (*Owner, int64, error) {
	if err := checkOrganization(m); err != nil {
		return nil, 0, err
	}
	meta := m.(*Owner)
	if meta.name == "" {
		return nil, 0, fmt.Errorf("an explicit organization provider owner is required")
	}
	if d.Id() == "" {
		return meta, 0, nil
	}
	org, rawID, parseErr := parseID2(d.Id())
	id, err := strconv.ParseInt(rawID, 10, 64)
	if parseErr != nil || err != nil || id <= 0 || !strings.EqualFold(org, meta.name) {
		return nil, 0, fmt.Errorf("expected custom pattern ID %s:<positive pattern ID>, got %q", meta.name, d.Id())
	}
	return meta, id, nil
}

func organizationSecretScanningCustomPatternNotFound(err error) bool {
	apiError, ok := errors.AsType[*github.ErrorResponse](err)
	return ok && apiError.Response != nil && apiError.Response.StatusCode == http.StatusNotFound
}

func organizationSecretScanningCustomPatternFind(ctx context.Context, meta *Owner, id int64) (*github.SecretScanningCustomPattern, error) {
	for pattern, err := range meta.v3client.SecretScanning.ListCustomPatternsForOrgIter(ctx, meta.name, nil) {
		if err != nil {
			return nil, err
		}
		if pattern != nil && pattern.ID == id {
			return pattern, nil
		}
	}
	return nil, nil
}

func organizationSecretScanningCustomPatternStrings(d *schema.ResourceData, key string) []string {
	values := d.Get(key).([]any)
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = value.(string)
	}
	return result
}

func organizationSecretScanningCustomPatternState(d *schema.ResourceData, pattern *github.SecretScanningCustomPattern) diag.Diagnostics {
	if pattern == nil || pattern.ID <= 0 {
		return diag.Errorf("GitHub returned no valid custom pattern")
	}
	for key, value := range map[string]any{
		"name": pattern.Name, "pattern": pattern.Pattern, "slug": pattern.Slug,
		"state": pattern.State, "push_protection_enabled": pattern.PushProtectionEnabled,
		"start_delimiter": pattern.GetStartDelimiter(), "end_delimiter": pattern.GetEndDelimiter(),
		"must_match": pattern.MustMatch, "must_not_match": pattern.MustNotMatch,
		"custom_pattern_version": pattern.GetCustomPatternVersion(),
	} {
		if err := d.Set(key, value); err != nil {
			return diag.FromErr(fmt.Errorf("setting custom pattern %s: %w", key, err))
		}
	}
	return nil
}

func resourceGithubOrganizationSecretScanningCustomPatternCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, _, err := organizationSecretScanningCustomPatternOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	pattern := &github.SecretScanningCustomPatternRequest{
		Name: d.Get("name").(string), Pattern: d.Get("pattern").(string),
		MustMatch:    organizationSecretScanningCustomPatternStrings(d, "must_match"),
		MustNotMatch: organizationSecretScanningCustomPatternStrings(d, "must_not_match"),
	}
	if value, ok := d.GetOkExists("start_delimiter"); ok {
		pattern.StartDelimiter = github.Ptr(value.(string))
	}
	if value, ok := d.GetOkExists("end_delimiter"); ok {
		pattern.EndDelimiter = github.Ptr(value.(string))
	}
	result, _, err := meta.v3client.SecretScanning.CreateCustomPatternsForOrg(ctx, meta.name, github.SecretScanningCreateCustomPatternsRequest{
		Patterns: []*github.SecretScanningCustomPatternRequest{pattern},
	})
	if err != nil {
		return diag.FromErr(fmt.Errorf("creating organization secret scanning custom pattern: %w", err))
	}
	if result == nil || len(result.CreatedPatterns) != 1 || result.CreatedPatterns[0] == nil || result.CreatedPatterns[0].ID <= 0 {
		return diag.Errorf("GitHub did not return exactly one created custom pattern with a valid ID")
	}
	created := result.CreatedPatterns[0]
	id, err := buildID(meta.name, strconv.FormatInt(created.ID, 10))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return organizationSecretScanningCustomPatternState(d, created)
}

func resourceGithubOrganizationSecretScanningCustomPatternRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, id, err := organizationSecretScanningCustomPatternOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	pattern, err := organizationSecretScanningCustomPatternFind(ctx, meta, id)
	if err != nil && !organizationSecretScanningCustomPatternNotFound(err) {
		return diag.FromErr(fmt.Errorf("reading organization secret scanning custom pattern: %w", err))
	}
	if pattern == nil {
		d.SetId("")
		return nil
	}
	return organizationSecretScanningCustomPatternState(d, pattern)
}

func resourceGithubOrganizationSecretScanningCustomPatternUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, id, err := organizationSecretScanningCustomPatternOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	body := github.SecretScanningUpdateCustomPatternRequest{}
	if d.HasChange("pattern") {
		body.Pattern = github.Ptr(d.Get("pattern").(string))
	}
	if d.HasChange("start_delimiter") {
		body.StartDelimiter = github.Ptr(d.Get("start_delimiter").(string))
	}
	if d.HasChange("end_delimiter") {
		body.EndDelimiter = github.Ptr(d.Get("end_delimiter").(string))
	}
	matchChanged, excludeChanged := d.HasChange("must_match"), d.HasChange("must_not_match")
	if matchChanged {
		body.MustMatch = organizationSecretScanningCustomPatternStrings(d, "must_match")
	}
	if excludeChanged {
		body.MustNotMatch = organizationSecretScanningCustomPatternStrings(d, "must_not_match")
	}
	if body.Pattern == nil && body.StartDelimiter == nil && body.EndDelimiter == nil && !matchChanged && !excludeChanged {
		return nil
	}
	current, err := organizationSecretScanningCustomPatternFind(ctx, meta, id)
	if err != nil {
		return diag.FromErr(fmt.Errorf("refreshing custom pattern version before update: %w", err))
	}
	if current == nil {
		return diag.Errorf("custom pattern %s no longer exists; refresh Terraform state before updating", d.Id())
	}
	body.CustomPatternVersion = current.CustomPatternVersion
	var updated *github.SecretScanningCustomPattern
	if (matchChanged && len(body.MustMatch) == 0) || (excludeChanged && len(body.MustNotMatch) == 0) {
		// go-github's omitempty slices cannot express clearing. Shadow only
		// changed lists while retaining the typed request and response.
		payload := struct {
			github.SecretScanningUpdateCustomPatternRequest
			MustMatch    *[]string `json:"must_match,omitempty"`
			MustNotMatch *[]string `json:"must_not_match,omitempty"`
		}{SecretScanningUpdateCustomPatternRequest: body}
		if matchChanged {
			payload.MustMatch = &body.MustMatch
		}
		if excludeChanged {
			payload.MustNotMatch = &body.MustNotMatch
		}
		request, requestErr := meta.v3client.NewRequest(ctx, http.MethodPatch, fmt.Sprintf("orgs/%s/secret-scanning/custom-patterns/%d", meta.name, id), payload)
		if requestErr != nil {
			return diag.FromErr(requestErr)
		}
		_, err = meta.v3client.Do(request, &updated)
	} else {
		updated, _, err = meta.v3client.SecretScanning.UpdateCustomPatternForOrg(ctx, meta.name, id, body)
	}
	if err != nil {
		return diag.FromErr(fmt.Errorf("updating organization secret scanning custom pattern (refresh and retry if version conflicted): %w", err))
	}
	return organizationSecretScanningCustomPatternState(d, updated)
}

func resourceGithubOrganizationSecretScanningCustomPatternDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, id, err := organizationSecretScanningCustomPatternOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	current, err := organizationSecretScanningCustomPatternFind(ctx, meta, id)
	if err != nil && !organizationSecretScanningCustomPatternNotFound(err) {
		return diag.FromErr(fmt.Errorf("refreshing custom pattern version before deletion: %w", err))
	}
	if current == nil {
		d.SetId("")
		return nil
	}
	_, err = meta.v3client.SecretScanning.DeleteCustomPatternsForOrg(ctx, meta.name, github.SecretScanningDeleteCustomPatternsRequest{
		Patterns:         []*github.SecretScanningCustomPatternToDelete{{PatternID: id, CustomPatternVersion: current.CustomPatternVersion}},
		PostDeleteAction: github.Ptr(d.Get("post_delete_action").(string)),
	})
	if err != nil && !organizationSecretScanningCustomPatternNotFound(err) {
		return diag.FromErr(fmt.Errorf("deleting organization secret scanning custom pattern (refresh and retry if version conflicted): %w", err))
	}
	d.SetId("")
	return nil
}
