package github

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGithubCodeSecurityConfigurationRepository() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages a single selected repository attachment, without owning other attachments to the configuration.",
		CreateContext: resourceGithubCodeSecurityConfigurationRepositoryCreate,
		ReadContext:   resourceGithubCodeSecurityConfigurationRepositoryRead,
		DeleteContext: resourceGithubCodeSecurityConfigurationRepositoryDelete,
		Importer:      &schema.ResourceImporter{StateContext: resourceGithubCodeSecurityConfigurationRepositoryImport},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(5 * time.Minute),
			Read:   schema.DefaultTimeout(5 * time.Minute),
			Delete: schema.DefaultTimeout(5 * time.Minute),
		},
		Schema: map[string]*schema.Schema{
			"configuration_id": {Type: schema.TypeInt, Required: true, ForceNew: true, Description: "Numeric code security configuration ID.", ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(1))},
			"repository_id":    {Type: schema.TypeInt, Required: true, ForceNew: true, Description: "Numeric organization repository ID. Renames do not change this ID.", ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(1))},
			"status":           {Type: schema.TypeString, Computed: true, Description: "GitHub attachment status. Queued or processing attachments are polled to a terminal state."},
		},
	}
}

func resourceGithubCodeSecurityConfigurationRepositoryCreate(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	configurationID := int64(d.Get("configuration_id").(int))
	repositoryID := int64(d.Get("repository_id").(int))
	// v92's typed attach method dereferences a nil response on transport errors.
	// Keep the same request shape while preserving context and transport diagnostics.
	body := struct {
		Scope                 string  `json:"scope"`
		SelectedRepositoryIDs []int64 `json:"selected_repository_ids"`
	}{Scope: "selected", SelectedRepositoryIDs: []int64{repositoryID}}
	req, err := owner.v3client.NewRequest(ctx, "POST", fmt.Sprintf("orgs/%s/code-security/configurations/%d/attach", owner.name, configurationID), body)
	if err != nil {
		return diag.FromErr(err)
	}
	if response, err := owner.v3client.Do(req, nil); err != nil && (response == nil || response.StatusCode != http.StatusAccepted) {
		return diag.FromErr(err)
	}
	d.SetId(fmt.Sprintf("%d:%d", configurationID, repositoryID))
	if err := d.Set("status", "attaching"); err != nil {
		return diag.FromErr(err)
	}
	attachment, err := codeSecurityRepositoryWait(ctx, owner, configurationID, repositoryID, false, d.Timeout(schema.TimeoutCreate))
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("status", attachment.GetStatus()); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func codeSecurityRepositoryAttachment(ctx context.Context, owner *Owner, configurationID, repositoryID int64) (*github.RepositoryAttachment, error) {
	for attachment, err := range owner.v3client.Organizations.ListCodeSecurityConfigurationRepositoriesIter(ctx, owner.name, configurationID, &github.ListCodeSecurityConfigurationRepositoriesOptions{PerPage: 100}) {
		if err != nil {
			return nil, err
		}
		if attachment != nil && attachment.Repository != nil && attachment.Repository.GetID() == repositoryID {
			return attachment, nil
		}
	}
	return nil, nil
}

func codeSecurityRepositoryWait(ctx context.Context, owner *Owner, configurationID, repositoryID int64, detaching bool, timeout time.Duration) (*github.RepositoryAttachment, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := []string{"attached", "enforced", "enterprise_enforced"}
	pending := []string{"queued", "attaching", "updating", "detached", "removed"}
	if detaching {
		target = []string{"detached", "removed", "removed_by_enterprise"}
		pending = []string{"queued", "attached", "enforced", "enterprise_enforced", "attaching", "updating"}
	}
	wait := &retry.StateChangeConf{
		Pending: pending, Target: target, Timeout: timeout, PollInterval: 2 * time.Second,
		Refresh: func() (any, string, error) {
			attachment, err := codeSecurityRepositoryAttachment(ctx, owner, configurationID, repositoryID)
			if detaching && codeSecurityNotFound(err) {
				return &github.RepositoryAttachment{}, "detached", nil
			}
			if err != nil {
				return nil, "", err
			}
			if attachment == nil {
				if detaching {
					return &github.RepositoryAttachment{}, "detached", nil
				}
				return &github.RepositoryAttachment{}, "queued", nil
			}
			if attachment.GetStatus() == "failed" {
				return nil, "", fmt.Errorf("GitHub failed to attach configuration %d to repository %d; resolve GitHub's configuration requirements and replace the attachment resource", configurationID, repositoryID)
			}
			return attachment, attachment.GetStatus(), nil
		},
	}
	result, err := wait.WaitForStateContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("waiting for code security configuration %d repository %d relationship: %w", configurationID, repositoryID, err)
	}
	return result.(*github.RepositoryAttachment), nil
}

func resourceGithubCodeSecurityConfigurationRepositoryRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	configurationID, repositoryID, err := codeSecurityRepositoryIDs(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	attachment, err := codeSecurityRepositoryAttachment(ctx, owner, configurationID, repositoryID)
	if codeSecurityNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	pending := d.Get("status") == "queued" || d.Get("status") == "attaching" || d.Get("status") == "updating"
	if attachment != nil {
		switch attachment.GetStatus() {
		case "queued", "attaching", "updating":
			pending = true
		case "attached", "enforced", "enterprise_enforced", "failed", "removed_by_enterprise":
			pending = false
		}
	}
	if pending {
		attachment, err = codeSecurityRepositoryWait(ctx, owner, configurationID, repositoryID, false, d.Timeout(schema.TimeoutRead))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if attachment == nil || attachment.GetStatus() == "detached" || attachment.GetStatus() == "removed" || attachment.GetStatus() == "removed_by_enterprise" {
		d.SetId("")
		return nil
	}
	for name, value := range map[string]any{"configuration_id": configurationID, "repository_id": repositoryID, "status": attachment.GetStatus()} {
		if err := d.Set(name, value); err != nil {
			return diag.FromErr(err)
		}
	}
	if attachment.GetStatus() == "failed" {
		return diag.Errorf("GitHub failed to attach configuration %d to repository %d; resolve GitHub's configuration requirements and replace the attachment resource", configurationID, repositoryID)
	}
	return nil
}

func resourceGithubCodeSecurityConfigurationRepositoryDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	configurationID, repositoryID, err := codeSecurityRepositoryIDs(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	// The detach endpoint has no configuration ID: do not detach a replacement
	// configuration assigned externally since the last refresh.
	attachment, err := codeSecurityRepositoryAttachment(ctx, owner, configurationID, repositoryID)
	if err != nil && !codeSecurityNotFound(err) {
		return diag.FromErr(err)
	}
	if attachment != nil && attachment.GetStatus() != "detached" && attachment.GetStatus() != "removed" && attachment.GetStatus() != "removed_by_enterprise" {
		response, err := owner.v3client.Organizations.DetachCodeSecurityConfigurationsFromRepositories(ctx, owner.name, []int64{repositoryID})
		if err != nil && !codeSecurityNotFound(err) && (response == nil || response.StatusCode != http.StatusAccepted) {
			return diag.FromErr(err)
		}
		if !codeSecurityNotFound(err) {
			if _, err := codeSecurityRepositoryWait(ctx, owner, configurationID, repositoryID, true, d.Timeout(schema.TimeoutDelete)); err != nil {
				return diag.FromErr(err)
			}
		}
	}
	d.SetId("")
	return nil
}

func codeSecurityRepositoryIDs(id string) (int64, int64, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected configuration_id:repository_id, got %q", id)
	}
	configurationID, err := codeSecurityID(parts[0])
	if err != nil {
		return 0, 0, err
	}
	repositoryID, err := codeSecurityID(parts[1])
	return configurationID, repositoryID, err
}

func resourceGithubCodeSecurityConfigurationRepositoryImport(ctx context.Context, d *schema.ResourceData, meta any) ([]*schema.ResourceData, error) {
	if err := checkOrganization(meta); err != nil {
		return nil, err
	}
	if _, _, err := codeSecurityRepositoryIDs(d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
