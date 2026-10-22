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
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	testingterraform "github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const organizationCustomPatternFixture = `{"id":42,"name":"test-pattern","pattern":"token_[0-9]{16}","slug":"test-pattern","state":"unpublished","push_protection_enabled":false,"start_delimiter":"\\A|[^0-9A-Za-z]","end_delimiter":"\\z|[^0-9A-Za-z]","must_match":["[0-9]"],"must_not_match":["example"],"custom_pattern_version":"latest"}`

func organizationCustomPatternTestOwner(t *testing.T, handler http.HandlerFunc) *Owner {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	baseURL := server.URL + "/"
	client, err := github.NewClient(github.WithHTTPClient(server.Client()), github.WithURLs(&baseURL, &baseURL))
	if err != nil {
		t.Fatal(err)
	}
	return &Owner{name: "test-org", IsOrganization: true, v3client: client}
}

func organizationCustomPatternTestBody(t *testing.T, req *http.Request, want string) {
	t.Helper()
	var got, expected any
	if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("request body = %#v; want %#v", got, expected)
	}
}

func TestGithubOrganizationSecretScanningCustomPatternLifecycle(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	if err := r.InternalValidate(nil, true); err != nil {
		t.Fatal(err)
	}
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{
		"name": "test-pattern", "pattern": "token_[0-9]{16}", "must_match": []any{"[0-9]"}, "must_not_match": []any{"example"},
	})
	var calls []string
	meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		switch req.Method {
		case http.MethodPost:
			organizationCustomPatternTestBody(t, req, `{"patterns":[{"name":"test-pattern","pattern":"token_[0-9]{16}","must_match":["[0-9]"],"must_not_match":["example"]}]}`)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"created_patterns":[%s]}`, organizationCustomPatternFixture)
		case http.MethodGet:
			fmt.Fprintf(w, `[%s]`, organizationCustomPatternFixture)
		case http.MethodPatch:
			organizationCustomPatternTestBody(t, req, `{"pattern":"token_[0-9]{16}","must_match":["[0-9]"],"must_not_match":["example"],"custom_pattern_version":"latest"}`)
			fmt.Fprint(w, organizationCustomPatternFixture)
		case http.MethodDelete:
			organizationCustomPatternTestBody(t, req, `{"patterns":[{"pattern_id":42,"custom_pattern_version":"latest"}],"post_delete_action":"resolve_alerts"}`)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
	})
	if diags := r.CreateContext(t.Context(), d, meta); diags.HasError() || d.Id() != "test-org:42" {
		t.Fatalf("create: %v, ID %q", diags, d.Id())
	}
	if len(calls) != 1 || d.Get("start_delimiter") != `\A|[^0-9A-Za-z]` || d.Get("state") != "unpublished" || d.Get("custom_pattern_version") != "latest" {
		t.Fatalf("create failed to persist server defaults without a read: %v", d.State())
	}
	if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if err := d.Set("custom_pattern_version", "stale"); err != nil {
		t.Fatal(err)
	}
	if diags := r.UpdateContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if diags := r.DeleteContext(t.Context(), d, meta); diags.HasError() || d.Id() != "" {
		t.Fatalf("delete: %v, ID %q", diags, d.Id())
	}
	base := "/orgs/test-org/secret-scanning/custom-patterns"
	want := []string{"POST " + base, "GET " + base, "GET " + base, "PATCH " + base + "/42", "GET " + base, "DELETE " + base}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v; want %v (no read-after-write)", calls, want)
	}
}

func TestGithubOrganizationSecretScanningCustomPatternEmptyArrays(t *testing.T) {
	for _, clear := range []string{"must_match", "must_not_match", "both"} {
		t.Run(clear, func(t *testing.T) {
			r := resourceGithubOrganizationSecretScanningCustomPattern()
			old := schema.TestResourceDataRaw(t, r.Schema, map[string]any{
				"name": "test-pattern", "pattern": "token_[0-9]{16}",
				"must_match": []any{"[0-9]"}, "must_not_match": []any{"example"},
			})
			old.SetId("test-org:42")
			config := map[string]any{
				"name": "test-pattern", "pattern": "token_[0-9]{16}",
				"must_match": []any{"[0-9]"}, "must_not_match": []any{"example"},
			}
			if clear != "must_not_match" {
				config["must_match"] = []any{}
			}
			if clear != "must_match" {
				config["must_not_match"] = []any{}
			}
			diff, err := r.Diff(t.Context(), old.State(), terraform.NewResourceConfigRaw(config), nil)
			if err != nil {
				t.Fatal(err)
			}
			var methods []string
			meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
				methods = append(methods, req.Method)
				if req.Method == http.MethodGet {
					fmt.Fprintf(w, `[%s]`, organizationCustomPatternFixture)
					return
				}
				want := map[string]any{"custom_pattern_version": "latest"}
				if clear != "must_not_match" {
					want["must_match"] = []any{}
				}
				if clear != "must_match" {
					want["must_not_match"] = []any{}
				}
				body, err := json.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				organizationCustomPatternTestBody(t, req, string(body))
				var response map[string]any
				if err := json.Unmarshal([]byte(organizationCustomPatternFixture), &response); err != nil {
					t.Fatal(err)
				}
				for key, value := range want {
					response[key] = value
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Fatal(err)
				}
			})
			state, diags := r.Apply(t.Context(), old.State(), diff, meta)
			if diags.HasError() {
				t.Fatal(diags)
			}
			for _, key := range []string{"must_match", "must_not_match"} {
				if clear == key || clear == "both" {
					if state.Attributes[key+".#"] != "0" {
						t.Errorf("%s not cleared: %v", key, state.Attributes)
					}
				}
			}
			if !reflect.DeepEqual(methods, []string{"GET", "PATCH"}) {
				t.Fatalf("calls: %v", methods)
			}
		})
	}
}

func TestGithubOrganizationSecretScanningCustomPatternPaginationImportDrift(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	var pages []string
	meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		pages = append(pages, req.URL.Query().Get("page"))
		if req.URL.Query().Get("page") != "2" {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=2>; rel="next"`, req.Host, req.URL.Path))
			fmt.Fprint(w, `[{"id":7,"name":"test-pattern"}]`)
			return
		}
		fmt.Fprintf(w, `[%s]`, organizationCustomPatternFixture)
	})
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	d.SetId("TEST-ORG:42")
	if _, err := r.Importer.StateContext(t.Context(), d, meta); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if d.Id() != "test-org:42" || d.Get("name") != "test-pattern" || d.Get("pattern") != "token_[0-9]{16}" || d.Get("post_delete_action") != "resolve_alerts" {
		t.Fatalf("imported state: %v", d.State())
	}
	if !reflect.DeepEqual(pages, []string{"", "2"}) {
		t.Fatalf("pagination: %v", pages)
	}
	if err := d.Set("pattern", "out-of-band"); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() || d.Get("pattern") != "token_[0-9]{16}" {
		t.Fatalf("drift refresh: %v", diags)
	}
	for _, id := range []string{"", "42", "other-org:42", "test-org:0", "test-org:-1", "test-org:bad", "test-org:42:extra"} {
		d.SetId(id)
		if _, err := r.Importer.StateContext(t.Context(), d, meta); err == nil {
			t.Errorf("accepted invalid import ID %q", id)
		}
	}
	meta.IsOrganization = false
	d.SetId("test-org:42")
	if _, err := r.Importer.StateContext(t.Context(), d, meta); err == nil {
		t.Fatal("accepted user owner")
	}
	meta.IsOrganization = true
	meta.name = ""
	if diags := r.CreateContext(t.Context(), d, meta); !diags.HasError() {
		t.Fatal("accepted implicit owner")
	}
}

func TestGithubOrganizationSecretScanningCustomPatternErrors(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusPreconditionFailed, http.StatusUnprocessableEntity, http.StatusInternalServerError} {
		for _, failWrite := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/write=%t", status, failWrite), func(t *testing.T) {
				meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
					if failWrite && req.Method == http.MethodGet {
						fmt.Fprintf(w, `[%s]`, organizationCustomPatternFixture)
						return
					}
					w.WriteHeader(status)
					fmt.Fprint(w, `{"message":"failure"}`)
				})
				for name, operation := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
					"create": r.CreateContext, "read": r.ReadContext, "update": r.UpdateContext, "delete": r.DeleteContext,
				} {
					d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test-pattern", "pattern": "changed"})
					if name != "create" {
						d.SetId("test-org:42")
					}
					diags := operation(t.Context(), d, meta)
					wantError := status != http.StatusNotFound || name == "create" || name == "update"
					if failWrite && name == "read" {
						wantError = false
					}
					if diags.HasError() != wantError {
						t.Errorf("%s error = %t; want %t: %v", name, diags.HasError(), wantError, diags)
					}
					if status == http.StatusNotFound && name == "delete" && d.Id() != "" {
						t.Error("delete 404 did not clear state")
					}
				}
			})
		}
	}
}

func TestGithubOrganizationSecretScanningCustomPatternMissingAndMalformed(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	for _, response := range []string{`[]`, `[null]`} {
		meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodGet {
				t.Errorf("unexpected write to absent pattern: %s", req.Method)
			}
			fmt.Fprint(w, response)
		})
		for name, operation := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
			"read": r.ReadContext, "update": r.UpdateContext, "delete": r.DeleteContext,
		} {
			d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test-pattern", "pattern": "changed"})
			d.SetId("test-org:42")
			diags := operation(t.Context(), d, meta)
			if diags.HasError() != (name == "update") {
				t.Fatalf("%s: %v", name, diags)
			}
			if name != "update" && d.Id() != "" {
				t.Errorf("%s did not remove missing pattern", name)
			}
		}
	}
	for _, response := range []string{`null`, `{}`, `{"created_patterns":[]}`, `{"created_patterns":[null]}`, `{"created_patterns":[{"id":0}]}`} {
		meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, response)
		})
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test-pattern", "pattern": "token"})
		if diags := r.CreateContext(t.Context(), d, meta); !diags.HasError() || d.Id() != "" {
			t.Errorf("accepted malformed create response %s: %v", response, diags)
		}
	}
}

func TestGithubOrganizationSecretScanningCustomPatternDelimitersAndDeleteAction(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{
		"name": "test-pattern", "pattern": `token_(?i:[a-z]){32}`,
		"start_delimiter": "[ ]", "end_delimiter": "[;]",
		"post_delete_action": "delete_alerts",
	})
	meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			organizationCustomPatternTestBody(t, req, `{"patterns":[{"name":"test-pattern","pattern":"token_(?i:[a-z]){32}","start_delimiter":"[ ]","end_delimiter":"[;]"}]}`)
			fmt.Fprintf(w, `{"created_patterns":[%s]}`, organizationCustomPatternFixture)
		case http.MethodGet:
			fmt.Fprintf(w, `[%s]`, organizationCustomPatternFixture)
		case http.MethodPatch:
			organizationCustomPatternTestBody(t, req, `{"start_delimiter":"[;]","end_delimiter":"[ ]","custom_pattern_version":"latest"}`)
			fmt.Fprint(w, organizationCustomPatternFixture)
		case http.MethodDelete:
			organizationCustomPatternTestBody(t, req, `{"patterns":[{"pattern_id":42,"custom_pattern_version":"latest"}],"post_delete_action":"delete_alerts"}`)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method %s", req.Method)
		}
	})
	if diags := r.CreateContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	old := schema.TestResourceDataRaw(t, r.Schema, map[string]any{
		"name": "test-pattern", "pattern": "token_[0-9]{16}",
		"start_delimiter": "[ ]", "end_delimiter": "[;]",
	})
	old.SetId("test-org:42")
	diff, err := r.Diff(t.Context(), old.State(), terraform.NewResourceConfigRaw(map[string]any{
		"name": "test-pattern", "pattern": "token_[0-9]{16}",
		"start_delimiter": "[;]", "end_delimiter": "[ ]",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, diags := r.Apply(t.Context(), old.State(), diff, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if diags := r.DeleteContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
}

func TestGithubOrganizationSecretScanningCustomPatternValidationAndLocalUpdate(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	if !r.Schema["name"].ForceNew || !r.Schema["state"].Computed || !r.Schema["push_protection_enabled"].Computed {
		t.Fatal("immutable name or read-only publication schema changed")
	}
	for _, key := range []string{"name", "pattern"} {
		if !r.Schema[key].ValidateDiagFunc("", nil).HasError() {
			t.Errorf("empty %s accepted", key)
		}
	}
	// This is intentionally not a Go RE2 expression.
	if diags := r.Schema["pattern"].ValidateDiagFunc(`secret_(?!example)[A-Z]{32}`, nil); diags.HasError() {
		t.Fatalf("validated GitHub regex with the wrong engine: %v", diags)
	}
	if !r.Schema["post_delete_action"].ValidateDiagFunc("discard", nil).HasError() {
		t.Fatal("invalid deletion action accepted")
	}
	old := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test-pattern", "pattern": "token"})
	old.SetId("test-org:42")
	diff, err := r.Diff(t.Context(), old.State(), terraform.NewResourceConfigRaw(map[string]any{
		"name": "test-pattern", "pattern": "token", "post_delete_action": "delete_alerts",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("local deletion action update made API call: %s", req.Method)
		w.WriteHeader(http.StatusInternalServerError)
	})
	state, diags := r.Apply(t.Context(), old.State(), diff, meta)
	if diags.HasError() || state.Attributes["post_delete_action"] != "delete_alerts" {
		t.Fatalf("local action update: %v, %v", diags, state)
	}
}

func TestGithubOrganizationSecretScanningCustomPatternCancellation(t *testing.T) {
	r := resourceGithubOrganizationSecretScanningCustomPattern()
	meta := organizationCustomPatternTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("cancelled request reached server: %s", req.Method)
		w.WriteHeader(http.StatusInternalServerError)
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for name, operation := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
		"create": r.CreateContext, "read": r.ReadContext, "update": r.UpdateContext, "delete": r.DeleteContext,
	} {
		d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"name": "test-pattern", "pattern": "changed"})
		if name != "create" {
			d.SetId("test-org:42")
		}
		if diags := operation(ctx, d, meta); !diags.HasError() {
			t.Errorf("%s ignored context cancellation", name)
		}
	}
}

func TestAccGithubOrganizationSecretScanningCustomPattern(t *testing.T) {
	if os.Getenv("TF_ACC_ORGANIZATION_SECRET_SCANNING_CUSTOM_PATTERN") != "1" {
		t.Skip("requires TF_ACC_ORGANIZATION_SECRET_SCANNING_CUSTOM_PATTERN=1 and a secret-scanning-enabled organization; creates and deletes a custom detection pattern")
	}
	const address = "github_organization_secret_scanning_custom_pattern.test"
	name := fmt.Sprintf("terraform-acceptance-%s", acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum))
	var provider *schema.Provider
	config := func(pattern string) string {
		return fmt.Sprintf(`resource "github_organization_secret_scanning_custom_pattern" "test" {
  name = %q
  pattern = %q
  must_match = []
  must_not_match = []
}`, name, pattern)
	}
	resource.Test(t, resource.TestCase{
		PreCheck: func() { skipUnlessHasPaidOrgs(t) },
		ProviderFactories: map[string]func() (*schema.Provider, error){
			"github": func() (*schema.Provider, error) {
				p := NewProvider("acctest", "none")()
				p.ResourcesMap["github_organization_secret_scanning_custom_pattern"] = resourceGithubOrganizationSecretScanningCustomPattern()
				provider = p
				return p, nil
			},
		},
		CheckDestroy: func(state *testingterraform.State) error {
			for _, instance := range state.RootModule().Resources {
				if instance.Type != "github_organization_secret_scanning_custom_pattern" {
					continue
				}
				d := schema.TestResourceDataRaw(t, resourceGithubOrganizationSecretScanningCustomPattern().Schema, nil)
				d.SetId(instance.Primary.ID)
				meta, id, err := organizationSecretScanningCustomPatternOwner(d, provider.Meta())
				if err != nil {
					return err
				}
				pattern, err := organizationSecretScanningCustomPatternFind(t.Context(), meta, id)
				if err != nil && !organizationSecretScanningCustomPatternNotFound(err) {
					return err
				}
				if pattern != nil {
					return fmt.Errorf("custom pattern %s still exists after destroy", d.Id())
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: config("terraform_test_[0-9A-Z]{24}"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("name"), knownvalue.StringExact(name)),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("post_delete_action"), knownvalue.StringExact("resolve_alerts")),
				},
			},
			{ResourceName: address, ImportState: true, ImportStateVerify: true},
			{
				Config: config("terraform_test_[0-9A-Z]{32}"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("pattern"), knownvalue.StringExact("terraform_test_[0-9A-Z]{32}")),
				},
			},
		},
	})
}
