package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func copilotContentExclusionsTestOwner(t *testing.T, handler http.HandlerFunc) *Owner {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/orgs/test-org/copilot/content_exclusion" {
			t.Errorf("unexpected endpoint %s", req.URL.Path)
		}
		handler(w, req)
	}))
	t.Cleanup(server.Close)
	baseURL := server.URL + "/"
	client, err := github.NewClient(github.WithHTTPClient(server.Client()), github.WithURLs(&baseURL, &baseURL))
	if err != nil {
		t.Fatal(err)
	}
	return &Owner{name: "test-org", IsOrganization: true, v3client: client}
}

func copilotContentExclusionsTestRule(repository string, paths ...string) map[string]any {
	values := make([]any, len(paths))
	for i, path := range paths {
		values[i] = path
	}
	return map[string]any{"repository": repository, "paths": values}
}

func TestGithubOrganizationCopilotContentExclusionsLifecycle(t *testing.T) {
	r := resourceGithubOrganizationCopilotContentExclusions()
	if err := (&schema.Provider{ResourcesMap: map[string]*schema.Resource{"github_test": r}}).InternalValidate(); err != nil {
		t.Fatal(err)
	}
	policy := github.CopilotOrganizationContentExclusionDetails{}
	var methods []string
	meta := copilotContentExclusionsTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		methods = append(methods, req.Method)
		switch req.Method {
		case http.MethodPut:
			if got := req.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			var body github.CopilotOrganizationContentExclusionDetails
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body == nil {
				t.Error("sent null instead of a policy object")
			}
			policy = body
			fmt.Fprint(w, `{"message":"Content exclusion rules updated successfully"}`)
		case http.MethodGet:
			if err := json.NewEncoder(w).Encode(policy); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected method %s", req.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	config := map[string]any{"rule": []any{
		copilotContentExclusionsTestRule("*", "*.env", "/secret/**", "*.env"),
		copilotContentExclusionsTestRule("https://github.com/test-org/example.git", "/private/**"),
	}}
	d := schema.TestResourceDataRaw(t, r.Schema, config)
	if diags := r.CreateContext(t.Context(), d, meta); diags.HasError() || d.Id() != meta.name {
		t.Fatalf("create: %v, ID %q", diags, d.Id())
	}
	want := github.CopilotOrganizationContentExclusionDetails{
		"*": {"*.env", "/secret/**"}, "https://github.com/test-org/example.git": {"/private/**"},
	}
	if !reflect.DeepEqual(policy, want) {
		t.Fatalf("create body = %#v; want %#v", policy, want)
	}
	imported := schema.TestResourceDataRaw(t, r.Schema, nil)
	imported.SetId("TEST-ORG")
	if _, err := r.Importer.StateContext(t.Context(), imported, meta); err != nil {
		t.Fatal(err)
	}
	if len(methods) != 1 {
		t.Fatalf("import unexpectedly called the API: %v", methods)
	}
	if diags := r.ReadContext(t.Context(), imported, meta); diags.HasError() {
		t.Fatal(diags)
	}
	got, err := expandOrganizationCopilotContentExclusions(imported.Get("rule").(*schema.Set))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("import read = %#v, %v", got, err)
	}
	// Reordered API keys and paths must retain the same Terraform set hash.
	before := imported.Get("rule").(*schema.Set)
	policy["*"] = []string{"/secret/**", "*.env"}
	if diags := r.ReadContext(t.Context(), imported, meta); diags.HasError() || !before.Equal(imported.Get("rule").(*schema.Set)) {
		t.Fatalf("nondeterministic read: %v", diags)
	}
	if err := d.Set("rule", []any{copilotContentExclusionsTestRule("example", "/new/**")}); err != nil {
		t.Fatal(err)
	}
	if diags := r.UpdateContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if !reflect.DeepEqual(policy, github.CopilotOrganizationContentExclusionDetails{"example": {"/new/**"}}) {
		t.Fatalf("update did not replace the complete policy: %#v", policy)
	}
	if err := d.Set("rule", []any{}); err != nil {
		t.Fatal(err)
	}
	if diags := r.UpdateContext(t.Context(), d, meta); diags.HasError() || len(policy) != 0 {
		t.Fatalf("empty update: %v, policy %#v", diags, policy)
	}
	if diags := r.ReadContext(t.Context(), imported, meta); diags.HasError() || imported.Get("rule").(*schema.Set).Len() != 0 {
		t.Fatalf("empty read retained old rules: %v", diags)
	}
	policy["old-repository"] = []string{"/old/**"}
	if diags := r.DeleteContext(t.Context(), d, meta); diags.HasError() || d.Id() != "" || policy == nil || len(policy) != 0 {
		t.Fatalf("delete must clear all exclusions with {}: %v, ID %q, policy %#v", diags, d.Id(), policy)
	}
	if !reflect.DeepEqual(methods, []string{"PUT", "GET", "GET", "PUT", "PUT", "GET", "PUT"}) {
		t.Fatalf("unexpected requests (including read-after-write): %v", methods)
	}
}

func TestGithubOrganizationCopilotContentExclusionsValidation(t *testing.T) {
	r := resourceGithubOrganizationCopilotContentExclusions()
	meta := copilotContentExclusionsTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		var policy map[string][]string
		if err := json.NewDecoder(req.Body).Decode(&policy); err != nil {
			t.Error(err)
		}
		if policy == nil || len(policy) != 0 {
			t.Errorf("empty create body = %#v, want {}", policy)
		}
		fmt.Fprint(w, `{"message":"updated"}`)
	})
	empty := schema.TestResourceDataRaw(t, r.Schema, nil)
	if diags := r.CreateContext(t.Context(), empty, meta); diags.HasError() {
		t.Fatalf("empty create: %v", diags)
	}
	duplicate := map[string]any{"rule": []any{
		copilotContentExclusionsTestRule("*", "/one/**"),
		copilotContentExclusionsTestRule("*", "/two/**"),
	}}
	for _, state := range []*terraform.InstanceState{nil, empty.State()} {
		if _, err := r.Diff(t.Context(), state, terraform.NewResourceConfigRaw(duplicate), meta); err == nil {
			t.Fatal("duplicate keys accepted at plan time")
		}
	}
	blocked := copilotContentExclusionsTestOwner(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("invalid configuration reached the API")
	})
	for _, operation := range []func(context.Context, *schema.ResourceData, any) diag.Diagnostics{r.CreateContext, r.UpdateContext} {
		d := schema.TestResourceDataRaw(t, r.Schema, duplicate)
		if diags := operation(t.Context(), d, blocked); !diags.HasError() {
			t.Fatal("duplicate keys accepted at apply time")
		}
	}
	for _, config := range []map[string]any{
		{"rule": []any{copilotContentExclusionsTestRule("", "/valid")}},
		{"rule": []any{copilotContentExclusionsTestRule("repo", "")}},
	} {
		if diags := r.Validate(terraform.NewResourceConfigRaw(config)); !diags.HasError() {
			t.Errorf("invalid config passed schema validation: %#v", config)
		}
		d := schema.TestResourceDataRaw(t, r.Schema, config)
		if diags := r.CreateContext(t.Context(), d, blocked); !diags.HasError() {
			t.Errorf("invalid config passed apply validation: %#v", config)
		}
	}
	for _, repository := range []string{"*", "repo", "owner/repo", "https://github.com/owner/repo", "git@github.com:owner/repo.git"} {
		config := map[string]any{"rule": []any{copilotContentExclusionsTestRule(repository, "/private/**")}}
		if diags := r.Validate(terraform.NewResourceConfigRaw(config)); diags.HasError() {
			t.Errorf("repository key %q rejected: %v", repository, diags)
		}
		if _, err := r.Diff(t.Context(), nil, terraform.NewResourceConfigRaw(config), nil); err != nil {
			t.Errorf("repository key %q rejected at plan: %v", repository, err)
		}
	}
	unknownRules := make([]cty.Value, 0, 2)
	for _, path := range []string{"/one/**", "/two/**"} {
		unknownRules = append(unknownRules, cty.ObjectVal(map[string]cty.Value{
			"repository": cty.UnknownVal(cty.String),
			"paths":      cty.SetVal([]cty.Value{cty.StringVal(path)}),
		}))
	}
	rawUnknown := cty.ObjectVal(map[string]cty.Value{
		"rule": cty.SetVal(unknownRules),
	})
	unknown := terraform.NewResourceConfigShimmed(rawUnknown, r.CoreConfigSchema())
	if _, err := r.Diff(t.Context(), &terraform.InstanceState{RawConfig: rawUnknown}, unknown, nil); err != nil {
		t.Fatalf("unknown repository keys must defer duplicate validation until apply: %v", err)
	}
}

func TestGithubOrganizationCopilotContentExclusionsErrors(t *testing.T) {
	r := resourceGithubOrganizationCopilotContentExclusions()
	for _, status := range []int{401, 403, 404, 413, 422, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			meta := copilotContentExclusionsTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"message":"failure"}`)
			})
			for name, operation := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
				"create": r.CreateContext, "update": r.UpdateContext, "read": r.ReadContext, "delete": r.DeleteContext,
			} {
				d := schema.TestResourceDataRaw(t, r.Schema, nil)
				d.SetId(meta.name)
				diags := operation(t.Context(), d, meta)
				wantError := status != 404 || (name != "read" && name != "delete")
				if diags.HasError() != wantError {
					t.Errorf("%s: %v", name, diags)
				}
				if !wantError && d.Id() != "" {
					t.Errorf("%s 404 did not clear state", name)
				}
				if wantError && d.Id() != meta.name {
					t.Errorf("%s error incorrectly removed state", name)
				}
			}
		})
	}
	for _, response := range []string{"not JSON", `{"message":false}`} {
		meta := copilotContentExclusionsTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, response)
		})
		d := schema.TestResourceDataRaw(t, r.Schema, nil)
		if diags := r.CreateContext(t.Context(), d, meta); !diags.HasError() {
			t.Errorf("invalid typed PUT response accepted: %q", response)
		}
	}
	meta := copilotContentExclusionsTestOwner(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("canceled operation reached the API")
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	for _, operation := range []func(context.Context, *schema.ResourceData, any) diag.Diagnostics{r.CreateContext, r.ReadContext, r.UpdateContext, r.DeleteContext} {
		if diags := operation(ctx, d, meta); !diags.HasError() {
			t.Fatal("canceled context was ignored")
		}
	}
}

func TestGithubOrganizationCopilotContentExclusionsOwnerAndImport(t *testing.T) {
	r := resourceGithubOrganizationCopilotContentExclusions()
	meta := copilotContentExclusionsTestOwner(t, func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("invalid owner or import reached the API")
	})
	for _, tc := range []struct {
		name, owner, id string
		isOrg, valid    bool
	}{
		{"valid", "test-org", "test-org", true, true},
		{"case_insensitive", "test-org", "TEST-ORG", true, true},
		{"empty_id", "test-org", "", true, false},
		{"other_org", "test-org", "other-org", true, false},
		{"composite", "test-org", "test-org:repo", true, false},
		{"empty_owner", "", "test-org", true, false},
		{"user_owner", "test-org", "test-org", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta.name, meta.IsOrganization = tc.owner, tc.isOrg
			d := schema.TestResourceDataRaw(t, r.Schema, nil)
			d.SetId(tc.id)
			data, err := r.Importer.StateContext(t.Context(), d, meta)
			if (err == nil) != tc.valid {
				t.Fatalf("import: %v", err)
			}
			if tc.valid && (len(data) != 1 || d.Id() != meta.name) {
				t.Fatal("import did not normalize owner ID")
			}
			if !tc.valid && tc.id != "" {
				for _, operation := range []func(context.Context, *schema.ResourceData, any) diag.Diagnostics{r.CreateContext, r.ReadContext, r.UpdateContext, r.DeleteContext} {
					if diags := operation(t.Context(), d, meta); !diags.HasError() {
						t.Fatal("invalid owner accepted by CRUD")
					}
				}
			}
		})
	}
}

func TestAccGithubOrganizationCopilotContentExclusions(t *testing.T) {
	if os.Getenv("TF_ACC_COPILOT_CONTENT_EXCLUSIONS") != "1" {
		t.Skip("requires TF_ACC_COPILOT_CONTENT_EXCLUSIONS=1 on a disposable Copilot organization: replaces all exclusions, removes comments, and destroy clears all rules")
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { skipUnlessHasOrgs(t) },
		ProviderFactories: map[string]func() (*schema.Provider, error){
			"github": func() (*schema.Provider, error) {
				p := NewProvider("acctest", "none")()
				p.ResourcesMap["github_organization_copilot_content_exclusions"] = resourceGithubOrganizationCopilotContentExclusions()
				return p, nil
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `resource "github_organization_copilot_content_exclusions" "test" {
  rule {
    repository = "*"
    paths      = ["/terraform-acceptance-test/**"]
  }
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_organization_copilot_content_exclusions.test", tfjsonpath.New("rule"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.ObjectExact(map[string]knownvalue.Check{
							"repository": knownvalue.StringExact("*"),
							"paths":      knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("/terraform-acceptance-test/**")}),
						}),
					})),
				},
			},
			{ResourceName: "github_organization_copilot_content_exclusions.test", ImportState: true, ImportStateVerify: true},
			{
				Config: `resource "github_organization_copilot_content_exclusions" "test" {}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_organization_copilot_content_exclusions.test", tfjsonpath.New("rule"), knownvalue.SetSizeExact(0)),
				},
			},
		},
	})
}
