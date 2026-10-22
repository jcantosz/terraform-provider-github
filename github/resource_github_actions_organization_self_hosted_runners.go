package github

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGithubActionsOrganizationSelfHostedRunners() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages which repositories may use self-hosted runners in the provider organization. Destroy resets enabled_repositories to none; it does not restore the previous policy.",
		CreateContext: resourceGithubActionsOrganizationSelfHostedRunnersWrite,
		ReadContext:   resourceGithubActionsOrganizationSelfHostedRunnersRead,
		UpdateContext: resourceGithubActionsOrganizationSelfHostedRunnersWrite,
		DeleteContext: resourceGithubActionsOrganizationSelfHostedRunnersDelete,
		Importer:      &schema.ResourceImporter{StateContext: importOrganizationActionsPolicy},
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, _ any) error {
			if !d.NewValueKnown("enabled_repositories") || !d.NewValueKnown("selected_repository_ids") {
				return nil
			}
			return validateOrganizationSelfHostedRunnerSelection(d.Get("enabled_repositories").(string), d.Get("selected_repository_ids").(*schema.Set))
		},
		Schema: map[string]*schema.Schema{
			"enabled_repositories": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Repositories allowed to use self-hosted runners: all, selected, or none.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"all", "selected", "none"}, false)),
			},
			"selected_repository_ids": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Numeric repository IDs allowed when enabled_repositories is selected. Omitted or empty means no repositories. Must be empty for all or none.",
				Elem: &schema.Schema{
					Type:             schema.TypeInt,
					ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(1)),
				},
			},
		},
	}
}

func validateOrganizationSelfHostedRunnerSelection(policy string, ids *schema.Set) error {
	switch policy {
	case "selected":
		return nil
	case "all", "none":
		if ids.Len() != 0 {
			return fmt.Errorf("selected_repository_ids may only be set when enabled_repositories is selected")
		}
		return nil
	default:
		return fmt.Errorf("enabled_repositories must be all, selected, or none")
	}
}

func resourceGithubActionsOrganizationSelfHostedRunnersWrite(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	policy := d.Get("enabled_repositories").(string)
	selected := d.Get("selected_repository_ids").(*schema.Set)
	if err := validateOrganizationSelfHostedRunnerSelection(policy, selected); err != nil {
		return diag.FromErr(err)
	}
	ids := make([]int64, 0, selected.Len())
	for _, id := range selected.List() {
		if id.(int) < 1 {
			return diag.Errorf("selected_repository_ids must contain positive repository IDs")
		}
		ids = append(ids, int64(id.(int)))
	}
	slices.Sort(ids)
	if d.IsNewResource() || d.HasChange("enabled_repositories") {
		_, err = meta.v3client.Actions.UpdateSelfHostedRunnersSettingsInOrganization(ctx, meta.name, github.SelfHostedRunnersSettingsOrganizationOpt{
			EnabledRepositories: &policy,
		})
		if err != nil {
			return diag.FromErr(err)
		}
	}
	// Preserve the policy in state if the second request fails during create.
	d.SetId(meta.name)
	if policy == "selected" {
		_, err = meta.v3client.Actions.SetRepositoriesSelfHostedRunnersAllowedInOrganization(ctx, meta.name, ids)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}

func resourceGithubActionsOrganizationSelfHostedRunnersRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	settings, _, err := meta.v3client.Actions.GetSelfHostedRunnersSettingsInOrganization(ctx, meta.name)
	if err != nil {
		if organizationActionsPolicyNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	ids := make([]int, 0)
	if settings.GetEnabledRepositories() == "selected" {
		for repo, err := range meta.v3client.Actions.ListRepositoriesSelfHostedRunnersAllowedInOrganizationIter(ctx, meta.name, &github.ListOptions{PerPage: 100}) {
			if err != nil {
				if organizationActionsPolicyNotFound(err) {
					d.SetId("")
					return nil
				}
				return diag.FromErr(err)
			}
			ids = append(ids, int(repo.GetID()))
		}
	}
	if err := d.Set("enabled_repositories", settings.GetEnabledRepositories()); err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(d.Set("selected_repository_ids", ids))
}

func resourceGithubActionsOrganizationSelfHostedRunnersDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = meta.v3client.Actions.UpdateSelfHostedRunnersSettingsInOrganization(ctx, meta.name, github.SelfHostedRunnersSettingsOrganizationOpt{
		EnabledRepositories: new("none"),
	})
	if err != nil && !organizationActionsPolicyNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
