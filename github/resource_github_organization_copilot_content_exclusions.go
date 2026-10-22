package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGithubOrganizationCopilotContentExclusions() *schema.Resource {
	return &schema.Resource{
		Description:   "Authoritatively manages all Copilot content exclusion rules for the provider organization using a public preview API. Applying replaces the entire policy and removes existing comments. Destroy clears all organization content exclusions; it does not restore the previous policy.",
		CreateContext: resourceGithubOrganizationCopilotContentExclusionsWrite,
		ReadContext:   resourceGithubOrganizationCopilotContentExclusionsRead,
		UpdateContext: resourceGithubOrganizationCopilotContentExclusionsWrite,
		DeleteContext: resourceGithubOrganizationCopilotContentExclusionsDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceGithubOrganizationCopilotContentExclusionsImport,
		},
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, _ any) error {
			if !d.NewValueKnown("rule") {
				return nil
			}
			// SDK set hashes can appear known while nested repository keys are not.
			if config := d.GetRawConfig(); !config.IsNull() && !config.GetAttr("rule").IsWhollyKnown() {
				return nil
			}
			_, err := expandOrganizationCopilotContentExclusions(d.Get("rule").(*schema.Set))
			return err
		},
		Schema: map[string]*schema.Schema{
			"rule": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "The complete organization-wide set of exclusion rules. Omitted or empty clears all rules. Each repository key must appear only once.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"repository": {
							Type:             schema.TypeString,
							Required:         true,
							Description:      "Repository key accepted by GitHub, including the wildcard '*' and supported repository URL keys. Keys are preserved verbatim.",
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotWhiteSpace),
						},
						"paths": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "The file paths or exclusion patterns for this repository key, using GitHub's content exclusion syntax.",
							Elem: &schema.Schema{
								Type:             schema.TypeString,
								ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
							},
						},
					},
				},
			},
		},
	}
}

func organizationCopilotContentExclusionsOwner(d *schema.ResourceData, m any) (*Owner, error) {
	if err := checkOrganization(m); err != nil {
		return nil, err
	}
	meta := m.(*Owner)
	if meta.name == "" {
		return nil, fmt.Errorf("an explicit provider organization owner is required")
	}
	if d.Id() != "" && !strings.EqualFold(d.Id(), meta.name) {
		return nil, fmt.Errorf("organization %q does not match provider owner %q", d.Id(), meta.name)
	}
	return meta, nil
}

func expandOrganizationCopilotContentExclusions(rules *schema.Set) (github.CopilotOrganizationContentExclusionDetails, error) {
	policy := make(github.CopilotOrganizationContentExclusionDetails, rules.Len())
	for _, value := range rules.List() {
		rule := value.(map[string]any)
		repository := rule["repository"].(string)
		if strings.TrimSpace(repository) == "" {
			return nil, fmt.Errorf("rule repository must not be empty or whitespace")
		}
		if _, exists := policy[repository]; exists {
			return nil, fmt.Errorf("duplicate rule repository key %q; combine its paths in a single rule", repository)
		}
		pathSet := rule["paths"].(*schema.Set)
		paths := make([]string, 0, pathSet.Len())
		for _, path := range pathSet.List() {
			if path.(string) == "" {
				return nil, fmt.Errorf("rule paths must not contain empty strings")
			}
			paths = append(paths, path.(string))
		}
		slices.Sort(paths)
		policy[repository] = paths
	}
	return policy, nil
}

type organizationCopilotContentExclusionsUpdateResponse struct {
	Message string `json:"message"`
}

func putOrganizationCopilotContentExclusions(ctx context.Context, meta *Owner, policy github.CopilotOrganizationContentExclusionDetails) error {
	req, err := meta.v3client.NewRequest(ctx, http.MethodPut, fmt.Sprintf("orgs/%s/copilot/content_exclusion", meta.name), policy)
	if err != nil {
		return err
	}
	var result organizationCopilotContentExclusionsUpdateResponse
	_, err = meta.v3client.Do(req, &result)
	return err
}

func organizationCopilotContentExclusionsNotFound(err error) bool {
	apiError, ok := errors.AsType[*github.ErrorResponse](err)
	return ok && apiError.Response != nil && apiError.Response.StatusCode == http.StatusNotFound
}

func resourceGithubOrganizationCopilotContentExclusionsWrite(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationCopilotContentExclusionsOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	policy, err := expandOrganizationCopilotContentExclusions(d.Get("rule").(*schema.Set))
	if err != nil {
		return diag.FromErr(err)
	}
	if err := putOrganizationCopilotContentExclusions(ctx, meta, policy); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(meta.name)
	return nil
}

func resourceGithubOrganizationCopilotContentExclusionsRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationCopilotContentExclusionsOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	policy, _, err := meta.v3client.Copilot.GetOrganizationContentExclusionDetails(ctx, meta.name)
	if err != nil {
		if organizationCopilotContentExclusionsNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	rules := make([]any, 0, len(policy))
	for repository, paths := range policy {
		rules = append(rules, map[string]any{"repository": repository, "paths": paths})
	}
	return diag.FromErr(d.Set("rule", rules))
}

func resourceGithubOrganizationCopilotContentExclusionsDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationCopilotContentExclusionsOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	err = putOrganizationCopilotContentExclusions(ctx, meta, github.CopilotOrganizationContentExclusionDetails{})
	if err != nil && !organizationCopilotContentExclusionsNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func resourceGithubOrganizationCopilotContentExclusionsImport(_ context.Context, d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	if d.Id() == "" {
		return nil, fmt.Errorf("import ID must be the organization slug")
	}
	meta, err := organizationCopilotContentExclusionsOwner(d, m)
	if err != nil {
		return nil, err
	}
	d.SetId(meta.name)
	return []*schema.ResourceData{d}, nil
}
