package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func codeSecurityTestOwner(t *testing.T, handler http.HandlerFunc) *Owner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	baseURL := server.URL + "/"
	client, err := github.NewClient(github.WithHTTPClient(server.Client()), github.WithURLs(&baseURL, nil))
	if err != nil {
		t.Fatal(err)
	}
	return &Owner{name: "test-org", IsOrganization: true, v3client: client, maxPerPage: 100}
}

func TestCodeSecurityConfigurationRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := resourceGithubCodeSecurityConfiguration()
	if err := r.InternalValidate(nil, true); err != nil {
		t.Fatal(err)
	}
	requests := 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.URL.Path != "/orgs/test-org/code-security/configurations" && req.URL.Path != "/orgs/test-org/code-security/configurations/42" {
			t.Errorf("unexpected path %s", req.URL.Path)
		}
		if req.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.Method == http.MethodPost || req.Method == http.MethodPatch {
			var c github.CodeSecurityConfiguration
			if err := json.NewDecoder(req.Body).Decode(&c); err != nil {
				t.Fatal(err)
			}
			if req.Method == http.MethodPost {
				if c.GetDependencyGraph() != "enabled" || c.DependencyGraphAutosubmitActionOptions.GetLabeledRunners() {
					t.Errorf("unexpected create request: %#v", c)
				}
			} else if c.DependencyGraph != nil || c.DependencyGraphAutosubmitActionOptions != nil {
				t.Errorf("unchanged dependency graph settings were sent: %#v", c)
			}
			if c.SecretScanning != nil {
				t.Error("omitted secret scanning setting was sent")
			}
			if c.AdvancedSecurity != nil || c.CodeSecurity != nil || c.SecretProtection != nil {
				t.Error("server-computed product settings were sent")
			}
			if c.CodeScanningOptions != nil || c.CodeScanningDefaultSetupOptions != nil {
				t.Error("server-computed options were sent")
			}
			if req.Method == http.MethodPost {
				w.WriteHeader(http.StatusCreated)
			}
		}
		fmt.Fprint(w, `{"id":42,"name":"test","description":"configuration","advanced_security":"code_security","code_security":"enabled","secret_protection":"enabled","dependency_graph":"enabled","enforcement":"unenforced","dependency_graph_autosubmit_action_options":{"labeled_runners":false},"code_scanning_options":{"allow_advanced":false},"code_scanning_default_setup_options":{"runner_type":"standard"}}`)
	})
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{
		"name": "test", "description": "configuration", "dependency_graph": "enabled",
		"dependency_graph_autosubmit_action_options": []any{map[string]any{"labeled_runners": false}},
	})
	if diags := r.CreateContext(ctx, d, owner); diags.HasError() {
		t.Fatal(diags)
	}
	if requests != 1 || d.Id() != "42" || d.Get("enforcement") != "unenforced" {
		t.Fatalf("create did not use response state without read: %d %s", requests, d.Id())
	}
	imported := schema.TestResourceDataRaw(t, r.Schema, nil)
	imported.SetId("42")
	if _, err := r.Importer.StateContext(ctx, imported, owner); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(ctx, imported, owner); diags.HasError() {
		t.Fatal(diags)
	}
	for name := range r.Schema {
		if fmt.Sprint(d.Get(name)) != fmt.Sprint(imported.Get(name)) {
			t.Errorf("import mismatch for %s: %v != %v", name, d.Get(name), imported.Get(name))
		}
	}
	diff, err := r.Diff(ctx, d.State(), terraform.NewResourceConfigRaw(map[string]any{
		"name": "test", "description": "updated", "dependency_graph": "enabled",
		"dependency_graph_autosubmit_action_options": []any{map[string]any{"labeled_runners": false}},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	state, diags := r.Apply(ctx, d.State(), diff, owner)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if requests != 3 {
		t.Fatalf("update performed a read: %d requests", requests)
	}
	updated := r.Data(state)
	if diags := r.DeleteContext(ctx, updated, owner); diags.HasError() || updated.Id() != "" {
		t.Fatalf("delete: %v", diags)
	}
}

func TestCodeSecurityConfigurationAllSettings(t *testing.T) {
	r := resourceGithubCodeSecurityConfiguration()
	apiType := reflect.TypeFor[github.CodeSecurityConfiguration]()
	for i := range apiType.NumField() {
		field := apiType.Field(i)
		switch field.Name {
		case "ID", "TargetType", "URL", "HTMLURL", "CreatedAt", "UpdatedAt":
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if r.Schema[name] == nil {
			t.Errorf("missing pinned API configuration field %s", name)
		}
	}
	raw := map[string]any{
		"name": "all-settings", "description": "Full pinned API settings",
		"dependency_graph_autosubmit_action_options": []any{map[string]any{"labeled_runners": true}},
		"code_scanning_options":                      []any{map[string]any{"allow_advanced": true}},
		"code_scanning_default_setup_options":        []any{map[string]any{"runner_type": "labeled", "runner_label": "code-scanning"}},
		"secret_scanning_delegated_bypass_options": []any{map[string]any{"reviewers": []any{
			map[string]any{"reviewer_id": 123, "reviewer_type": "TEAM"},
			map[string]any{"reviewer_id": 456, "reviewer_type": "ROLE"},
		}}},
	}
	for name := range codeSecurityConfigurationStrings(&github.CodeSecurityConfiguration{}) {
		raw[name] = "enabled"
		if name == "enforcement" {
			raw[name] = "unenforced"
		}
	}
	delete(raw, "advanced_security")
	var saved github.CodeSecurityConfiguration
	writes := 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writes++
			if err := json.NewDecoder(req.Body).Decode(&saved); err != nil {
				t.Fatal(err)
			}
			for name, field := range codeSecurityConfigurationStrings(&saved) {
				if writes > 1 {
					if name == "advanced_security" && *field != nil {
						t.Errorf("server-computed advanced_security was sent: %v", **field)
					}
					continue
				}
				want, configured := raw[name]
				if !configured {
					if *field != nil {
						t.Errorf("%s was sent unexpectedly: %v", name, **field)
					}
					continue
				}
				if *field == nil || **field != want {
					t.Errorf("%s was not sent: %v", name, *field)
				}
			}
			options := saved.SecretScanningDelegatedBypassOptions
			if options == nil {
				t.Fatal("missing delegated bypass options")
			}
			if writes == 1 {
				if len(options.Reviewers) != 2 {
					t.Fatalf("reviewers: %#v", options.Reviewers)
				}
				for _, reviewer := range options.Reviewers {
					if reviewer.SecurityConfigurationID != nil {
						t.Error("read-only reviewer configuration ID sent to API")
					}
					reviewer.SecurityConfigurationID = github.Ptr(int64(42))
				}
			} else if options.Reviewers == nil || len(options.Reviewers) != 0 {
				t.Error("clearing reviewers must send a non-nil empty array")
			}
			saved.ID = github.Ptr(int64(42))
		}
		if err := json.NewEncoder(w).Encode(saved); err != nil {
			t.Fatal(err)
		}
	})
	ctx := context.Background()
	d := schema.TestResourceDataRaw(t, r.Schema, raw)
	if diags := r.CreateContext(ctx, d, owner); diags.HasError() {
		t.Fatal(diags)
	}
	imported := schema.TestResourceDataRaw(t, r.Schema, nil)
	imported.SetId("42")
	if _, err := r.Importer.StateContext(ctx, imported, owner); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(ctx, imported, owner); diags.HasError() {
		t.Fatal(diags)
	}
	for name := range r.Schema {
		if name == "secret_scanning_delegated_bypass_options" {
			actual := d.Get(name).([]any)[0].(map[string]any)["reviewers"].(*schema.Set)
			restored := imported.Get(name).([]any)[0].(map[string]any)["reviewers"].(*schema.Set)
			if !actual.Equal(restored) {
				t.Errorf("reviewers not restored by import: %v != %v", actual.List(), restored.List())
			}
			continue
		}
		if fmt.Sprint(d.Get(name)) != fmt.Sprint(imported.Get(name)) {
			t.Errorf("all-settings import mismatch for %s: %v != %v", name, d.Get(name), imported.Get(name))
		}
	}
	updateRaw := make(map[string]any, len(raw))
	for name, value := range raw {
		updateRaw[name] = value
	}
	updateRaw["secret_scanning_delegated_bypass_options"] = []any{map[string]any{"reviewers": []any{}}}
	diff, err := r.Diff(ctx, d.State(), terraform.NewResourceConfigRaw(updateRaw), nil)
	if err != nil {
		t.Fatal(err)
	}
	state, diags := r.Apply(ctx, d.State(), diff, owner)
	if diags.HasError() {
		t.Fatal(diags)
	}
	updated := r.Data(state)
	options := updated.Get("secret_scanning_delegated_bypass_options").([]any)[0].(map[string]any)
	if options["reviewers"].(*schema.Set).Len() != 0 {
		t.Fatal("cleared reviewers remained in state")
	}
	reviewerSchema := r.Schema["secret_scanning_delegated_bypass_options"].Elem.(*schema.Resource).Schema["reviewers"].Elem.(*schema.Resource).Schema
	if !reviewerSchema["reviewer_id"].ValidateDiagFunc(0, nil).HasError() {
		t.Error("accepted nonpositive reviewer ID")
	}
	if !reviewerSchema["reviewer_type"].ValidateDiagFunc("USER", nil).HasError() {
		t.Error("accepted unsupported reviewer type")
	}
}

func TestCodeSecurityConfigurationErrors(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"message":"failure"}`)
			})
			for _, r := range []*schema.Resource{resourceGithubCodeSecurityConfiguration(), resourceGithubCodeSecurityConfigurationDefault(), resourceGithubCodeSecurityConfigurationRepository()} {
				d := schema.TestResourceDataRaw(t, r.Schema, nil)
				id := "42"
				if _, ok := r.Schema["repository_id"]; ok {
					id = "42:99"
				}
				d.SetId(id)
				diags := r.ReadContext(context.Background(), d, owner)
				if status == http.StatusNotFound {
					if diags.HasError() || d.Id() != "" {
						t.Fatalf("404 read: %v %s", diags, d.Id())
					}
				} else if !diags.HasError() || d.Id() != id {
					t.Fatalf("non-404 read lost state: %v %s", diags, d.Id())
				}
				d.SetId(id)
				diags = r.DeleteContext(context.Background(), d, owner)
				if diags.HasError() != (status != http.StatusNotFound) {
					t.Fatalf("delete status %d: %v", status, diags)
				}
			}
		})
	}
}

func TestCodeSecurityConfigurationSchemaAndIDs(t *testing.T) {
	for _, r := range []*schema.Resource{resourceGithubCodeSecurityConfiguration(), resourceGithubCodeSecurityConfigurationDefault(), resourceGithubCodeSecurityConfigurationRepository()} {
		if err := r.InternalValidate(nil, true); err != nil {
			t.Fatal(err)
		}
		for name, field := range r.Schema {
			if field.Description == "" {
				t.Errorf("%s has no description", name)
			}
			if field.ValidateDiagFunc != nil && field.Type == schema.TypeString && name != "description" {
				if diags := field.ValidateDiagFunc("", nil); !diags.HasError() {
					t.Errorf("%s accepted empty value", name)
				}
				for _, config := range []map[string]any{
					{"name": "test", "advanced_security": "enabled", "code_security": "enabled"},
					{"name": "test", "advanced_security": "enabled", "secret_protection": "enabled"},
				} {
					if diags := resourceGithubCodeSecurityConfiguration().Validate(terraform.NewResourceConfigRaw(config)); !diags.HasError() {
						t.Errorf("accepted mutually exclusive product settings: %#v", config)
					}
				}
			}
		}
		d := schema.TestResourceDataRaw(t, r.Schema, nil)
		for _, id := range []string{"", "abc", "0", "-1", "42:0", "42:99:1"} {
			d.SetId(id)
			if _, err := r.Importer.StateContext(context.Background(), d, &Owner{IsOrganization: true}); err == nil {
				t.Errorf("accepted invalid import %q", id)
			}
		}
		if diags := r.CreateContext(context.Background(), d, &Owner{name: "user"}); !diags.HasError() {
			t.Error("accepted non-organization owner")
		}
	}
}

func TestAccGithubCodeSecurityConfiguration(t *testing.T) {
	if os.Getenv("GITHUB_CODE_SECURITY_CONFIGURATION_ACCEPTANCE") != "1" {
		t.Skip("requires explicit opt-in: organization code security configuration permissions and licensing")
	}
	name := fmt.Sprintf("tf-acc-code-security-%d", time.Now().UnixNano())
	config := func(description string) string {
		return fmt.Sprintf(`resource "github_code_security_configuration" "test" {
  name = %q
  description = %q
  dependency_graph = "enabled"
  enforcement = "unenforced"
}`, name, description)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { skipUnlessHasOrgs(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config("created"), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("github_code_security_configuration.test", tfjsonpath.New("name"), knownvalue.StringExact(name)),
			}},
			{ResourceName: "github_code_security_configuration.test", ImportState: true, ImportStateVerify: true},
			{Config: config("updated"), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("github_code_security_configuration.test", tfjsonpath.New("description"), knownvalue.StringExact("updated")),
			}},
		},
	})
}

func TestAccGithubCodeSecurityConfigurationRelationships(t *testing.T) {
	if os.Getenv("GITHUB_CODE_SECURITY_CONFIGURATION_RELATIONSHIPS_ACCEPTANCE") != "1" {
		t.Skip("requires explicit opt-in: attaches a repository and changes organization new-public-repository defaults")
	}
	name := fmt.Sprintf("tf-acc-code-security-%d", time.Now().UnixNano())
	config := func(scope string) string {
		return fmt.Sprintf(`
	resource "github_code_security_configuration" "test" {
	  name = %q
	  description = "Acceptance test configuration"
	  enforcement = "unenforced"
	}
	resource "github_repository" "test" {
	  name = %q
	  visibility = "private"
	}
	resource "github_code_security_configuration_default" "test" {
	  configuration_id = github_code_security_configuration.test.id
	  default_for_new_repos = %q
	}
	resource "github_code_security_configuration_repository" "test" {
	  configuration_id = github_code_security_configuration.test.id
	  repository_id = github_repository.test.repo_id
	}`, name, name, scope)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { skipUnlessHasOrgs(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{Config: config("none"), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("github_code_security_configuration_default.test", tfjsonpath.New("default_for_new_repos"), knownvalue.StringExact("none")),
			}},
			{ResourceName: "github_code_security_configuration_default.test", ImportState: true, ImportStateVerify: true},
			{ResourceName: "github_code_security_configuration_repository.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"status"}},
			{Config: config("public"), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("github_code_security_configuration_default.test", tfjsonpath.New("default_for_new_repos"), knownvalue.StringExact("public")),
			}},
			{Config: config("none"), ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("github_code_security_configuration_default.test", tfjsonpath.New("default_for_new_repos"), knownvalue.StringExact("none")),
			}},
		},
	})
}

func TestCodeSecurityConfigurationCanceledContext(t *testing.T) {
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("canceled request reached server")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, r := range []*schema.Resource{resourceGithubCodeSecurityConfiguration(), resourceGithubCodeSecurityConfigurationDefault(), resourceGithubCodeSecurityConfigurationRepository()} {
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test", "configuration_id": 42, "repository_id": 99, "default_for_new_repos": "all"})
		if diags := r.CreateContext(ctx, d, owner); !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "context canceled") {
			t.Fatalf("expected cancellation diagnostic, got %v", diags)
		}
	}
}
