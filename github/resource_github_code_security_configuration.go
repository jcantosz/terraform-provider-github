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

func resourceGithubCodeSecurityConfiguration() *schema.Resource {
	fields := map[string]*schema.Schema{
		"name": {
			Type: schema.TypeString, Required: true, Description: "Unique name of the organization code security configuration.",
			ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty),
		},
		"description": {
			Type: schema.TypeString, Optional: true, Description: "Description of the code security configuration.",
			ValidateDiagFunc: validation.ToDiagFunc(validation.StringLenBetween(0, 255)),
		},
	}
	for name := range codeSecurityConfigurationStrings(&github.CodeSecurityConfiguration{}) {
		values := []string{"enabled", "disabled", "not_set"}
		if name == "advanced_security" {
			values = []string{"enabled", "disabled", "code_security", "secret_protection"}
		}
		if name == "enforcement" {
			values = []string{"enforced", "unenforced"}
		}
		fields[name] = &schema.Schema{
			Type: schema.TypeString, Optional: true, Computed: true,
			Description:      "The " + name + " setting. Valid values: " + strings.Join(values, ", ") + ". Omit to preserve the server's value or default.",
			ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(values, false)),
		}
	}
	fields["advanced_security"].ConflictsWith = []string{"code_security", "secret_protection"}
	fields["code_security"].ConflictsWith = []string{"advanced_security"}
	fields["secret_protection"].ConflictsWith = []string{"advanced_security"}
	fields["dependency_graph_autosubmit_action_options"] = codeSecurityOptions("Automatic dependency submission options.", map[string]*schema.Schema{
		"labeled_runners": {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Use runners labeled dependency-submission."},
	})
	fields["code_scanning_options"] = codeSecurityOptions("Code scanning feature options.", map[string]*schema.Schema{
		"allow_advanced": {Type: schema.TypeBool, Optional: true, Computed: true, Description: "Allow advanced code scanning setup."},
	})
	fields["code_scanning_default_setup_options"] = codeSecurityOptions("Code scanning default setup runner options.", map[string]*schema.Schema{
		"runner_type": {
			Type: schema.TypeString, Required: true, Description: "Runner type for code scanning default setup.",
			ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"standard", "labeled"}, false)),
		},
		"runner_label": {Type: schema.TypeString, Optional: true, Description: "Runner label when runner_type is labeled.", ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotEmpty)},
	})
	fields["secret_scanning_delegated_bypass_options"] = codeSecurityOptions("Secret scanning delegated bypass options.", map[string]*schema.Schema{
		"reviewers": {
			Type: schema.TypeSet, Optional: true, Computed: true, Description: "Teams or organization roles allowed to review push protection bypass requests. An explicit empty set removes reviewers.",
			Elem: &schema.Resource{Schema: map[string]*schema.Schema{
				"reviewer_id": {
					Type: schema.TypeInt, Required: true, Description: "Numeric ID of the reviewer team or organization role.",
					ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(1)),
				},
				"reviewer_type": {
					Type: schema.TypeString, Required: true, Description: "Reviewer type: TEAM or ROLE.",
					ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"TEAM", "ROLE"}, false)),
				},
				"security_configuration_id": {
					Type: schema.TypeInt, Computed: true, Description: "Security configuration ID returned by GitHub for this reviewer.",
				},
			}},
		},
	})
	return &schema.Resource{
		Description:   "Manages an organization code security configuration independently of defaults and repository attachments.",
		CreateContext: resourceGithubCodeSecurityConfigurationCreate,
		ReadContext:   resourceGithubCodeSecurityConfigurationRead,
		UpdateContext: resourceGithubCodeSecurityConfigurationUpdate,
		DeleteContext: resourceGithubCodeSecurityConfigurationDelete,
		Importer:      &schema.ResourceImporter{StateContext: codeSecurityConfigurationImport},
		Schema:        fields,
	}
}

func codeSecurityOptions(description string, fields map[string]*schema.Schema) *schema.Schema {
	return &schema.Schema{Type: schema.TypeList, Optional: true, Computed: true, MaxItems: 1, Description: description, Elem: &schema.Resource{Schema: fields}}
}

func codeSecurityConfigurationStrings(c *github.CodeSecurityConfiguration) map[string]**string {
	return map[string]**string{
		"advanced_security":                         &c.AdvancedSecurity,
		"code_security":                             &c.CodeSecurity,
		"dependency_graph":                          &c.DependencyGraph,
		"dependency_graph_autosubmit_action":        &c.DependencyGraphAutosubmitAction,
		"dependabot_alerts":                         &c.DependabotAlerts,
		"dependabot_delegated_alert_dismissal":      &c.DependabotDelegatedAlertDismissal,
		"dependabot_security_updates":               &c.DependabotSecurityUpdates,
		"code_scanning_default_setup":               &c.CodeScanningDefaultSetup,
		"code_scanning_delegated_alert_dismissal":   &c.CodeScanningDelegatedAlertDismissal,
		"secret_protection":                         &c.SecretProtection,
		"secret_scanning":                           &c.SecretScanning,
		"secret_scanning_push_protection":           &c.SecretScanningPushProtection,
		"secret_scanning_delegated_bypass":          &c.SecretScanningDelegatedBypass,
		"secret_scanning_validity_checks":           &c.SecretScanningValidityChecks,
		"secret_scanning_non_provider_patterns":     &c.SecretScanningNonProviderPatterns,
		"secret_scanning_generic_secrets":           &c.SecretScanningGenericSecrets,
		"secret_scanning_delegated_alert_dismissal": &c.SecretScanningDelegatedAlertDismissal,
		"secret_scanning_extended_metadata":         &c.SecretScanningExtendedMetadata,
		"private_vulnerability_reporting":           &c.PrivateVulnerabilityReporting,
		"enforcement":                               &c.Enforcement,
	}
}

func codeSecurityConfigurationExpand(d *schema.ResourceData, changedOnly bool) github.CodeSecurityConfiguration {
	c := github.CodeSecurityConfiguration{Name: d.Get("name").(string), Description: d.Get("description").(string)}
	for name, field := range codeSecurityConfigurationStrings(&c) {
		if v, ok := d.GetOk(name); ok && (!changedOnly || d.HasChange(name)) {
			*field = github.Ptr(v.(string))
		}
	}
	if options := d.Get("dependency_graph_autosubmit_action_options").([]any); len(options) > 0 && (!changedOnly || d.HasChange("dependency_graph_autosubmit_action_options")) {
		v := options[0].(map[string]any)
		c.DependencyGraphAutosubmitActionOptions = &github.DependencyGraphAutosubmitActionOptions{LabeledRunners: github.Ptr(v["labeled_runners"].(bool))}
	}
	if options := d.Get("code_scanning_options").([]any); len(options) > 0 && (!changedOnly || d.HasChange("code_scanning_options")) {
		v := options[0].(map[string]any)
		c.CodeScanningOptions = &github.CodeScanningOptions{AllowAdvanced: github.Ptr(v["allow_advanced"].(bool))}
	}
	if options := d.Get("code_scanning_default_setup_options").([]any); len(options) > 0 && (!changedOnly || d.HasChange("code_scanning_default_setup_options")) {
		v := options[0].(map[string]any)
		c.CodeScanningDefaultSetupOptions = &github.CodeScanningDefaultSetupOptions{RunnerType: v["runner_type"].(string)}
		if label := v["runner_label"].(string); label != "" {
			c.CodeScanningDefaultSetupOptions.RunnerLabel = github.Ptr(label)
		}
	}
	if options := d.Get("secret_scanning_delegated_bypass_options").([]any); len(options) > 0 && (!changedOnly || d.HasChange("secret_scanning_delegated_bypass_options")) {
		v := options[0].(map[string]any)
		reviewers := v["reviewers"].(*schema.Set).List()
		c.SecretScanningDelegatedBypassOptions = &github.SecretScanningDelegatedBypassOptions{Reviewers: make([]*github.BypassReviewer, 0, len(reviewers))}
		for _, raw := range reviewers {
			reviewer := raw.(map[string]any)
			c.SecretScanningDelegatedBypassOptions.Reviewers = append(c.SecretScanningDelegatedBypassOptions.Reviewers, &github.BypassReviewer{
				ReviewerID: int64(reviewer["reviewer_id"].(int)), ReviewerType: reviewer["reviewer_type"].(string),
			})
		}
	}
	return c
}

func codeSecurityConfigurationFlatten(d *schema.ResourceData, c *github.CodeSecurityConfiguration) diag.Diagnostics {
	if c == nil {
		return diag.Errorf("GitHub returned an empty code security configuration")
	}
	values := map[string]any{"name": c.Name, "description": c.Description}
	for name, field := range codeSecurityConfigurationStrings(c) {
		values[name] = *field
	}
	values["dependency_graph_autosubmit_action_options"] = nil
	if o := c.DependencyGraphAutosubmitActionOptions; o != nil {
		values["dependency_graph_autosubmit_action_options"] = []any{map[string]any{"labeled_runners": o.GetLabeledRunners()}}
	}
	values["code_scanning_options"] = nil
	if o := c.CodeScanningOptions; o != nil {
		values["code_scanning_options"] = []any{map[string]any{"allow_advanced": o.GetAllowAdvanced()}}
	}
	values["code_scanning_default_setup_options"] = nil
	if o := c.CodeScanningDefaultSetupOptions; o != nil {
		values["code_scanning_default_setup_options"] = []any{map[string]any{"runner_type": o.RunnerType, "runner_label": o.GetRunnerLabel()}}
	}
	values["secret_scanning_delegated_bypass_options"] = nil
	if o := c.SecretScanningDelegatedBypassOptions; o != nil {
		reviewers := make([]any, 0, len(o.Reviewers))
		for _, reviewer := range o.Reviewers {
			if reviewer != nil {
				reviewers = append(reviewers, map[string]any{
					"reviewer_id": reviewer.ReviewerID, "reviewer_type": reviewer.ReviewerType, "security_configuration_id": reviewer.GetSecurityConfigurationID(),
				})
			}
		}
		values["secret_scanning_delegated_bypass_options"] = []any{map[string]any{"reviewers": reviewers}}
	}
	for name, value := range values {
		if err := d.Set(name, value); err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}

func resourceGithubCodeSecurityConfigurationCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	c, _, err := owner.v3client.Organizations.CreateCodeSecurityConfiguration(ctx, owner.name, codeSecurityConfigurationExpand(d, false))
	if err != nil {
		return diag.FromErr(err)
	}
	if c == nil || c.GetID() <= 0 {
		return diag.Errorf("GitHub returned no code security configuration ID")
	}
	d.SetId(strconv.FormatInt(c.GetID(), 10))
	return codeSecurityConfigurationFlatten(d, c)
}

func resourceGithubCodeSecurityConfigurationRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	id, err := codeSecurityID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	c, _, err := owner.v3client.Organizations.GetCodeSecurityConfiguration(ctx, owner.name, id)
	if codeSecurityNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	return codeSecurityConfigurationFlatten(d, c)
}

func resourceGithubCodeSecurityConfigurationUpdate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	id, err := codeSecurityID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	c, _, err := owner.v3client.Organizations.UpdateCodeSecurityConfiguration(ctx, owner.name, id, codeSecurityConfigurationExpand(d, true))
	if err != nil {
		return diag.FromErr(err)
	}
	return codeSecurityConfigurationFlatten(d, c)
}

func resourceGithubCodeSecurityConfigurationDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	id, err := codeSecurityID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	_, err = owner.v3client.Organizations.DeleteCodeSecurityConfiguration(ctx, owner.name, id)
	if err != nil && !codeSecurityNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func codeSecurityConfigurationImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	if err := checkOrganization(meta); err != nil {
		return nil, err
	}
	if _, err := codeSecurityID(d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

func codeSecurityID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("expected a positive numeric ID, got %q", raw)
	}
	return id, nil
}

func codeSecurityNotFound(err error) bool {
	var response *github.ErrorResponse
	return errors.As(err, &response) && response.Response != nil && response.Response.StatusCode == http.StatusNotFound
}
