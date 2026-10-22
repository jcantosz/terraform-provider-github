package github

import (
	"context"
	"errors"
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

func resourceGithubOrganizationSecretScanningPatternConfiguration() *schema.Resource {
	return &schema.Resource{
		Description:   "Manages the push protection setting for one provider or custom secret scanning pattern in the provider organization. Other patterns are not modified. Destroy resets provider patterns to 'not-set' and custom patterns to 'disabled'.",
		CreateContext: resourceGithubOrganizationSecretScanningPatternConfigurationWrite,
		ReadContext:   resourceGithubOrganizationSecretScanningPatternConfigurationRead,
		UpdateContext: resourceGithubOrganizationSecretScanningPatternConfigurationWrite,
		DeleteContext: resourceGithubOrganizationSecretScanningPatternConfigurationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceGithubOrganizationSecretScanningPatternConfigurationImport,
		},
		CustomizeDiff: func(ctx context.Context, d *schema.ResourceDiff, m any) error {
			if d.NewValueKnown("pattern_type") && d.NewValueKnown("push_protection_setting") {
				return validateOrganizationPatternSetting(d.Get("pattern_type").(string), d.Get("push_protection_setting").(string))
			}
			return nil
		},
		Schema: map[string]*schema.Schema{
			"pattern_type": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "The pattern category: 'provider' or 'custom'.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"provider", "custom"}, false)),
			},
			"token_type": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "The token_type identifier returned by the organization pattern configurations API, such as 'GITHUB_PERSONAL_ACCESS_TOKEN' or 'cp_2'. This is not the pattern display name.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsNotWhiteSpace),
			},
			"push_protection_setting": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "The organization override: 'enabled' or 'disabled'. Provider patterns also support 'not-set' to inherit the default.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"enabled", "disabled", "not-set"}, false)),
			},
		},
	}
}

func validateOrganizationPatternSetting(patternType, setting string) error {
	if patternType == "custom" && setting == "not-set" {
		return fmt.Errorf("custom patterns do not support push_protection_setting = \"not-set\"")
	}
	return nil
}

func organizationPatternConfigurationID(id string, meta *Owner) (string, string, error) {
	if err := checkOrganization(meta); err != nil {
		return "", "", err
	}
	if meta.name == "" {
		return "", "", fmt.Errorf("an explicit provider organization owner is required")
	}
	org, patternType, tokenType, err := parseID3(id)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(org, meta.name) {
		return "", "", fmt.Errorf("pattern configuration organization %q does not match provider owner %q", org, meta.name)
	}
	if (patternType != "provider" && patternType != "custom") || strings.TrimSpace(tokenType) == "" {
		return "", "", fmt.Errorf("expected pattern configuration ID in the format organization:provider|custom:token_type")
	}
	return patternType, tokenType, nil
}

func findOrganizationPatternConfiguration(configs *github.SecretScanningPatternConfigs, patternType, tokenType string) *github.SecretScanningPatternOverride {
	if configs == nil {
		return nil
	}
	patterns := configs.ProviderPatternOverrides
	if patternType == "custom" {
		patterns = configs.CustomPatternOverrides
	}
	for _, pattern := range patterns {
		if pattern != nil && pattern.GetTokenType() == tokenType {
			return pattern
		}
	}
	return nil
}

func resourceGithubOrganizationSecretScanningPatternConfigurationWrite(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta := m.(*Owner)
	if err := checkOrganization(meta); err != nil {
		return diag.FromErr(err)
	}
	if meta.name == "" {
		return diag.Errorf("an explicit provider organization owner is required")
	}
	patternType := d.Get("pattern_type").(string)
	tokenType := d.Get("token_type").(string)
	setting := d.Get("push_protection_setting").(string)
	if err := validateOrganizationPatternSetting(patternType, setting); err != nil {
		return diag.FromErr(err)
	}
	if d.Id() != "" {
		if _, _, err := organizationPatternConfigurationID(d.Id(), meta); err != nil {
			return diag.FromErr(err)
		}
	}
	if err := updateOrganizationPatternConfiguration(ctx, meta, patternType, tokenType, setting, false); err != nil {
		return diag.FromErr(err)
	}
	id, err := buildID(meta.name, patternType, tokenType)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return nil
}

func resourceGithubOrganizationSecretScanningPatternConfigurationRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta := m.(*Owner)
	patternType, tokenType, err := organizationPatternConfigurationID(d.Id(), meta)
	if err != nil {
		return diag.FromErr(err)
	}
	configs, resp, err := meta.v3client.SecretScanning.ListPatternConfigsForOrg(ctx, meta.name)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		return diag.FromErr(err)
	}
	pattern := findOrganizationPatternConfiguration(configs, patternType, tokenType)
	if pattern == nil {
		d.SetId("")
		return nil
	}
	if pattern.Setting == nil {
		return diag.Errorf("pattern %q has no organization push protection setting in the API response", tokenType)
	}
	for key, value := range map[string]string{
		"pattern_type":            patternType,
		"token_type":              tokenType,
		"push_protection_setting": pattern.GetSetting(),
	} {
		if err := d.Set(key, value); err != nil {
			return diag.FromErr(err)
		}
	}
	return nil
}

func resourceGithubOrganizationSecretScanningPatternConfigurationDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	meta := m.(*Owner)
	patternType, tokenType, err := organizationPatternConfigurationID(d.Id(), meta)
	if err != nil {
		return diag.FromErr(err)
	}
	setting := "not-set"
	if patternType == "custom" {
		setting = "disabled"
	}
	if err := updateOrganizationPatternConfiguration(ctx, meta, patternType, tokenType, setting, true); err != nil {
		return diag.FromErr(err)
	}
	return nil
}

func updateOrganizationPatternConfiguration(ctx context.Context, meta *Owner, patternType, tokenType, setting string, deleting bool) error {
	// All patterns share a configuration version, so parallel resources may conflict.
	return retry.RetryContext(ctx, time.Minute, func() *retry.RetryError {
		configs, resp, err := meta.v3client.SecretScanning.ListPatternConfigsForOrg(ctx, meta.name)
		if err != nil {
			if deleting && resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil
			}
			return retry.NonRetryableError(err)
		}
		pattern := findOrganizationPatternConfiguration(configs, patternType, tokenType)
		if pattern == nil {
			if deleting {
				return nil
			}
			return retry.NonRetryableError(fmt.Errorf("%s secret scanning pattern %q does not exist in organization %q", patternType, tokenType, meta.name))
		}
		body := &github.SecretScanningPatternConfigsUpdateOptions{
			PatternConfigVersion: configs.PatternConfigVersion,
		}
		if patternType == "provider" {
			body.ProviderPatternSettings = []*github.SecretScanningProviderPatternSetting{{
				TokenType:             tokenType,
				PushProtectionSetting: setting,
			}}
		} else {
			body.CustomPatternSettings = []*github.SecretScanningCustomPatternSetting{{
				TokenType:             tokenType,
				CustomPatternVersion:  pattern.CustomPatternVersion,
				PushProtectionSetting: setting,
			}}
		}
		_, resp, err = meta.v3client.SecretScanning.UpdatePatternConfigsForOrg(ctx, meta.name, body)
		if err == nil || (deleting && resp != nil && resp.StatusCode == http.StatusNotFound) {
			return nil
		}
		var ghErr *github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusConflict {
			return retry.RetryableError(err)
		}
		return retry.NonRetryableError(err)
	})
}

func resourceGithubOrganizationSecretScanningPatternConfigurationImport(ctx context.Context, d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	meta := m.(*Owner)
	patternType, tokenType, err := organizationPatternConfigurationID(d.Id(), meta)
	if err != nil {
		return nil, err
	}
	id, err := buildID(meta.name, patternType, tokenType)
	if err != nil {
		return nil, err
	}
	d.SetId(id)
	return []*schema.ResourceData{d}, nil
}
