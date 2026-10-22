package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func patternConfigurationTestOwner(t *testing.T, handler http.HandlerFunc) *Owner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := github.NewClient(
		github.WithHTTPClient(server.Client()),
		github.WithURLs(new(server.URL+"/"), nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &Owner{name: "test-org", IsOrganization: true, v3client: client}
}

func TestOrganizationSecretScanningPatternConfigurationLifecycle(t *testing.T) {
	t.Parallel()
	for _, patternType := range []string{"provider", "custom"} {
		t.Run(patternType, func(t *testing.T) {
			t.Parallel()
			setting := "disabled"
			gets, patches := 0, 0
			meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/orgs/test-org/secret-scanning/pattern-configurations" {
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					gets++
					fmt.Fprintf(w, `{"pattern_config_version":"v%d","%s_pattern_overrides":[
						{"token_type":"target","custom_pattern_version":"custom-v1","setting":%q},
						{"token_type":"unmanaged","setting":"enabled"}
					]}`, patches, patternType, setting)
				case http.MethodPatch:
					patches++
					var body github.SecretScanningPatternConfigsUpdateOptions
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if body.GetPatternConfigVersion() != fmt.Sprintf("v%d", patches-1) {
						t.Errorf("stale version: %s", body.GetPatternConfigVersion())
					}
					if patternType == "provider" {
						if len(body.ProviderPatternSettings) != 1 || len(body.CustomPatternSettings) != 0 {
							t.Errorf("must only update the managed pattern: %+v", body)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						entry := body.ProviderPatternSettings[0]
						if entry.TokenType != "target" {
							t.Errorf("unexpected token type %s", entry.TokenType)
						}
						setting = entry.PushProtectionSetting
					} else {
						if len(body.CustomPatternSettings) != 1 || len(body.ProviderPatternSettings) != 0 {
							t.Errorf("must only update the managed pattern: %+v", body)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						entry := body.CustomPatternSettings[0]
						if entry.TokenType != "target" || entry.GetCustomPatternVersion() != "custom-v1" {
							t.Errorf("incorrect custom pattern identity/version: %+v", entry)
						}
						setting = entry.PushProtectionSetting
					}
					fmt.Fprintf(w, `{"pattern_config_version":"v%d"}`, patches)
				default:
					t.Errorf("unexpected method %s", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
			res := resourceGithubOrganizationSecretScanningPatternConfiguration()
			d := schema.TestResourceDataRaw(t, res.Schema, map[string]any{
				"pattern_type": patternType, "token_type": "target", "push_protection_setting": "enabled",
			})
			ctx := t.Context()
			if diags := res.CreateContext(ctx, d, meta); diags.HasError() {
				t.Fatal(diags)
			}
			if gets != 1 || patches != 1 || setting != "enabled" {
				t.Fatalf("create: gets=%d patches=%d setting=%s", gets, patches, setting)
			}
			if d.Id() != "test-org:"+patternType+":target" {
				t.Fatalf("unexpected ID %s", d.Id())
			}
			imported := schema.TestResourceDataRaw(t, res.Schema, nil)
			imported.SetId(d.Id())
			if _, err := res.Importer.StateContext(ctx, imported, meta); err != nil {
				t.Fatal(err)
			}
			if gets != 1 {
				t.Fatal("import must not fetch state before Read")
			}
			if diags := res.ReadContext(ctx, imported, meta); diags.HasError() {
				t.Fatal(diags)
			}
			for _, key := range []string{"pattern_type", "token_type", "push_protection_setting"} {
				if imported.Get(key) != d.Get(key) {
					t.Errorf("import %s = %v, want %v", key, imported.Get(key), d.Get(key))
				}
			}
			setting = "disabled"
			if diags := res.ReadContext(ctx, d, meta); diags.HasError() {
				t.Fatal(diags)
			}
			if d.Get("push_protection_setting") != "disabled" {
				t.Fatal("read did not detect remote drift")
			}
			if err := d.Set("push_protection_setting", "enabled"); err != nil {
				t.Fatal(err)
			}
			getsBeforeUpdate := gets
			if diags := res.UpdateContext(ctx, d, meta); diags.HasError() {
				t.Fatal(diags)
			}
			if gets != getsBeforeUpdate+1 || patches != 2 || setting != "enabled" {
				t.Fatalf("update must fetch only the version before writing: gets=%d patches=%d", gets, patches)
			}
			if diags := res.DeleteContext(ctx, d, meta); diags.HasError() {
				t.Fatal(diags)
			}
			wantReset := "not-set"
			if patternType == "custom" {
				wantReset = "disabled"
			}
			if setting != wantReset || patches != 3 {
				t.Fatalf("delete: setting=%s patches=%d", setting, patches)
			}
		})
	}
}

func TestOrganizationSecretScanningPatternConfigurationErrors(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			t.Parallel()
			meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})
			res := resourceGithubOrganizationSecretScanningPatternConfiguration()
			d := schema.TestResourceDataRaw(t, res.Schema, map[string]any{
				"pattern_type": "provider", "token_type": "target", "push_protection_setting": "enabled",
			})
			d.SetId("test-org:provider:target")
			readDiags := res.ReadContext(t.Context(), d, meta)
			if status == http.StatusNotFound {
				if readDiags.HasError() || d.Id() != "" {
					t.Fatalf("404 must clear state: %s %v", d.Id(), readDiags)
				}
			} else if !readDiags.HasError() || d.Id() == "" {
				t.Fatalf("read error must preserve state: %s %v", d.Id(), readDiags)
			}
			d.SetId("test-org:provider:target")
			deleteDiags := res.DeleteContext(t.Context(), d, meta)
			if deleteDiags.HasError() != (status != http.StatusNotFound) {
				t.Fatalf("unexpected delete diagnostics %v", deleteDiags)
			}
			if diags := res.UpdateContext(t.Context(), d, meta); !diags.HasError() {
				t.Fatal("write must propagate errors including 404")
			}
		})
	}
	t.Run("missing pattern", func(t *testing.T) {
		t.Parallel()
		meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("must not write a nonexistent pattern")
			}
			fmt.Fprint(w, `{"pattern_config_version":"v1","provider_pattern_overrides":[]}`)
		})
		res := resourceGithubOrganizationSecretScanningPatternConfiguration()
		d := schema.TestResourceDataRaw(t, res.Schema, map[string]any{
			"pattern_type": "provider", "token_type": "target", "push_protection_setting": "enabled",
		})
		if diags := res.CreateContext(t.Context(), d, meta); !diags.HasError() {
			t.Fatal("creating a nonexistent pattern override must fail")
		}
		d.SetId("test-org:provider:target")
		if diags := res.DeleteContext(t.Context(), d, meta); diags.HasError() {
			t.Fatal(diags)
		}
		if diags := res.ReadContext(t.Context(), d, meta); diags.HasError() || d.Id() != "" {
			t.Fatalf("missing pattern must clear state: %v", diags)
		}
	})
	t.Run("missing setting", func(t *testing.T) {
		t.Parallel()
		meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"provider_pattern_overrides":[{"token_type":"target"}]}`)
		})
		res := resourceGithubOrganizationSecretScanningPatternConfiguration()
		d := schema.TestResourceDataRaw(t, res.Schema, nil)
		d.SetId("test-org:provider:target")
		if diags := res.ReadContext(t.Context(), d, meta); !diags.HasError() || d.Id() == "" {
			t.Fatal("missing setting must not silently default or discard state")
		}
	})
}

func TestOrganizationSecretScanningPatternConfigurationConflict(t *testing.T) {
	t.Parallel()
	gets, patches := 0, 0
	meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
			fmt.Fprintf(w, `{"pattern_config_version":"v%d","provider_pattern_overrides":[{"token_type":"target","setting":"disabled"}]}`, gets)
			return
		}
		patches++
		var body github.SecretScanningPatternConfigsUpdateOptions
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.GetPatternConfigVersion() != fmt.Sprintf("v%d", gets) {
			t.Error("retry must use freshly fetched version")
		}
		if patches == 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		fmt.Fprint(w, `{"pattern_config_version":"v3"}`)
	})
	if err := updateOrganizationPatternConfiguration(t.Context(), meta, "provider", "target", "enabled", false); err != nil {
		t.Fatal(err)
	}
	if gets != 2 || patches != 2 {
		t.Fatalf("expected one conflict retry, got GET=%d PATCH=%d", gets, patches)
	}
}

func TestOrganizationSecretScanningPatternConfigurationValidation(t *testing.T) {
	t.Parallel()
	res := resourceGithubOrganizationSecretScanningPatternConfiguration()
	for _, id := range []string{"", "other-org:provider:target", "test-org:unknown:target", "test-org:custom:", "test-org"} {
		d := schema.TestResourceDataRaw(t, res.Schema, nil)
		d.SetId(id)
		if _, err := res.Importer.StateContext(t.Context(), d, &Owner{name: "test-org", IsOrganization: true}); err == nil {
			t.Errorf("expected import error for %q", id)
		}
	}
	if err := validateOrganizationPatternSetting("custom", "not-set"); err == nil {
		t.Fatal("custom patterns cannot inherit defaults")
	}
	if _, err := res.Diff(t.Context(), nil, terraform.NewResourceConfigRaw(map[string]any{
		"pattern_type": "custom", "token_type": "target", "push_protection_setting": "not-set",
	}), nil); err == nil {
		t.Fatal("plan must reject unsupported custom pattern setting")
	}
	for key, value := range map[string]any{"pattern_type": "unknown", "token_type": " ", "push_protection_setting": "unknown"} {
		if diags := res.Schema[key].ValidateDiagFunc(value, nil); !diags.HasError() {
			t.Errorf("expected validation error for %s", key)
		}

	}
	meta := &Owner{name: "user"}
	if _, _, err := organizationPatternConfigurationID("user:provider:target", meta); err == nil {
		t.Fatal("must reject individual owner")
	}
	if _, _, err := organizationPatternConfigurationID(":provider:target", &Owner{IsOrganization: true}); err == nil {
		t.Fatal("must require an explicit organization owner")
	}
	imported := schema.TestResourceDataRaw(t, res.Schema, nil)
	imported.SetId("TEST-ORG:provider:target")
	if _, err := res.Importer.StateContext(t.Context(), imported, &Owner{name: "test-org", IsOrganization: true}); err != nil {
		t.Fatal(err)
	}
	if imported.Id() != "test-org:provider:target" {
		t.Fatalf("import did not normalize organization casing: %s", imported.Id())
	}
	d := schema.TestResourceDataRaw(t, res.Schema, map[string]any{
		"pattern_type": "custom", "token_type": "target", "push_protection_setting": "not-set",
	})
	if diags := res.CreateContext(t.Context(), d, &Owner{name: "test-org", IsOrganization: true}); !diags.HasError() {
		t.Fatal("apply must reject unsupported custom pattern setting")
	}
}

func TestOrganizationSecretScanningPatternConfigurationReplacement(t *testing.T) {
	t.Parallel()
	res := resourceGithubOrganizationSecretScanningPatternConfiguration()
	for _, key := range []string{"pattern_type", "token_type", "push_protection_setting"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			config := map[string]any{
				"pattern_type": "provider", "token_type": "target", "push_protection_setting": "enabled",
			}
			d := schema.TestResourceDataRaw(t, res.Schema, config)
			d.SetId("test-org:provider:target")
			config[key] = map[string]string{
				"pattern_type": "custom", "token_type": "other", "push_protection_setting": "disabled",
			}[key]
			diff, err := res.Diff(t.Context(), d.State(), terraform.NewResourceConfigRaw(config), nil)
			if err != nil {
				t.Fatal(err)
			}
			if diff == nil || diff.RequiresNew() != (key != "push_protection_setting") {
				t.Fatalf("unexpected replacement behavior for %s: %+v", key, diff)
			}
		})
	}
}

func TestOrganizationSecretScanningPatternConfigurationPatchErrors(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusUnprocessableEntity} {
		for _, deleting := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/delete=%t", status, deleting), func(t *testing.T) {
				t.Parallel()
				meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						fmt.Fprint(w, `{"pattern_config_version":"v1","provider_pattern_overrides":[{"token_type":"target","setting":"enabled"}]}`)
						return
					}
					w.WriteHeader(status)
				})
				err := updateOrganizationPatternConfiguration(t.Context(), meta, "provider", "target", "not-set", deleting)
				if (err != nil) != !(deleting && status == http.StatusNotFound) {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	}
}

func TestOrganizationSecretScanningPatternConfigurationCanceled(t *testing.T) {
	t.Parallel()
	calls := 0
	meta := patternConfigurationTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusConflict)
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := updateOrganizationPatternConfiguration(ctx, meta, "provider", "target", "enabled", false); err == nil {
		t.Fatal("canceled request must fail")
	}
	if calls != 0 {
		t.Fatalf("canceled context sent %d requests", calls)
	}
}

func TestAccGithubOrganizationSecretScanningPatternConfiguration(t *testing.T) {
	tokenType := os.Getenv("GITHUB_TEST_SECRET_SCANNING_TOKEN_TYPE")
	if tokenType == "" {
		t.Skip("set GITHUB_TEST_SECRET_SCANNING_TOKEN_TYPE to a provider pattern in a disposable organization; destroy resets its override")
	}
	config := func(setting string) string {
		return fmt.Sprintf(`
resource "github_organization_secret_scanning_pattern_configuration" "test" {
  pattern_type            = "provider"
  token_type              = %q
  push_protection_setting = %q
}`, tokenType, setting)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { skipUnlessHasOrgs(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config("enabled"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_organization_secret_scanning_pattern_configuration.test", tfjsonpath.New("push_protection_setting"), knownvalue.StringExact("enabled")),
				},
			},
			{
				ResourceName:      "github_organization_secret_scanning_pattern_configuration.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: config("disabled"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_organization_secret_scanning_pattern_configuration.test", tfjsonpath.New("push_protection_setting"), knownvalue.StringExact("disabled")),
				},
			},
		},
	})
}
