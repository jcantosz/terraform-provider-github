package github

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGithubCodeSecurityConfigurationDefault() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages the new-repository default scope of one organization code security configuration.",
		CreateContext: resourceGithubCodeSecurityConfigurationDefaultWrite,
		UpdateContext: resourceGithubCodeSecurityConfigurationDefaultWrite,
		ReadContext:   resourceGithubCodeSecurityConfigurationDefaultRead,
		DeleteContext: resourceGithubCodeSecurityConfigurationDefaultDelete,
		Importer:      &schema.ResourceImporter{StateContext: codeSecurityConfigurationImport},
		Schema: map[string]*schema.Schema{
			"configuration_id": {
				Type: schema.TypeInt, Required: true, ForceNew: true, Description: "Numeric code security configuration ID.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(1)),
			},
			"default_for_new_repos": {
				Type: schema.TypeString, Required: true, Description: "New repository scope: all, public, private_and_internal, or none. None ensures this configuration is not a default.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"all", "public", "private_and_internal", "none"}, false)),
			},
		},
	}
}

func resourceGithubCodeSecurityConfigurationDefaultWrite(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	id := int64(d.Get("configuration_id").(int))
	_, _, err := owner.v3client.Organizations.SetDefaultCodeSecurityConfiguration(ctx, owner.name, id, d.Get("default_for_new_repos").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(strconv.FormatInt(id, 10))
	return nil
}

func resourceGithubCodeSecurityConfigurationDefaultRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	id, err := codeSecurityID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	defaults, _, err := owner.v3client.Organizations.ListDefaultCodeSecurityConfigurations(ctx, owner.name)
	if codeSecurityNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, item := range defaults {
		if item != nil && item.Configuration != nil && item.Configuration.GetID() == id && item.GetDefaultForNewRepos() != "none" {
			if err := d.Set("configuration_id", id); err != nil {
				return diag.FromErr(err)
			}
			if err := d.Set("default_for_new_repos", item.GetDefaultForNewRepos()); err != nil {
				return diag.FromErr(err)
			}
			return nil
		}
	}
	_, _, err = owner.v3client.Organizations.GetCodeSecurityConfiguration(ctx, owner.name, id)
	if codeSecurityNotFound(err) {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("configuration_id", id); err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("default_for_new_repos", "none"); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func resourceGithubCodeSecurityConfigurationDefaultDelete(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	id, err := codeSecurityID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	owner := meta.(*Owner)
	_, _, err = owner.v3client.Organizations.SetDefaultCodeSecurityConfiguration(ctx, owner.name, id, "none")
	if err != nil && !codeSecurityNotFound(err) {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}
