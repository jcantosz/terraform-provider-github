package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGithubActionsOrganizationForkPRWorkflows() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages whether workflows from fork pull requests can run in private repositories in the provider organization. Destroy resets this setting to false; it does not restore the previous policy.",
		CreateContext: resourceGithubActionsOrganizationForkPRWorkflowsWrite,
		ReadContext:   resourceGithubActionsOrganizationForkPRWorkflowsRead,
		UpdateContext: resourceGithubActionsOrganizationForkPRWorkflowsWrite,
		DeleteContext: resourceGithubActionsOrganizationForkPRWorkflowsDelete,
		Importer:      &schema.ResourceImporter{StateContext: importOrganizationActionsPolicy},
		Schema: map[string]*schema.Schema{
			"run_workflows_from_fork_pull_requests": {
				Type:        schema.TypeBool,
				Required:    true,
				Description: "Whether workflows triggered by fork pull requests may run in private repositories in the organization.",
			},
		},
	}
}

func organizationActionsPolicyOwner(d *schema.ResourceData, m any) (*Owner, error) {
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

func importOrganizationActionsPolicy(_ context.Context, d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	if d.Id() == "" {
		return nil, fmt.Errorf("import ID must be the organization slug")
	}

	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return nil, err
	}
	d.SetId(meta.name)
	return []*schema.ResourceData{d}, nil
}

func organizationActionsPolicyNotFound(err error) bool {
	apiError, ok := errors.AsType[*github.ErrorResponse](err)
	return ok && apiError.Response != nil && apiError.Response.StatusCode == http.StatusNotFound
}

func resourceGithubActionsOrganizationForkPRWorkflowsWrite(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = meta.v3client.Actions.UpdatePrivateRepoForkPRWorkflowSettingsInOrganization(ctx, meta.name, &github.WorkflowsPermissionsOpt{
		RunWorkflowsFromForkPullRequests: d.Get("run_workflows_from_fork_pull_requests").(bool),
	})
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(meta.name)
	return nil
}

func resourceGithubActionsOrganizationForkPRWorkflowsRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	settings, _, err := meta.v3client.Actions.GetPrivateRepoForkPRWorkflowSettingsInOrganization(ctx, meta.name)
	if err != nil {
		if organizationActionsPolicyNotFound(err) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	return diag.FromErr(d.Set("run_workflows_from_fork_pull_requests", settings.GetRunWorkflowsFromForkPullRequests()))
}

func resourceGithubActionsOrganizationForkPRWorkflowsDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta, err := organizationActionsPolicyOwner(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	_, err = meta.v3client.Actions.UpdatePrivateRepoForkPRWorkflowSettingsInOrganization(ctx, meta.name, &github.WorkflowsPermissionsOpt{
		RunWorkflowsFromForkPullRequests: false,
	})
	if err != nil && !organizationActionsPolicyNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
