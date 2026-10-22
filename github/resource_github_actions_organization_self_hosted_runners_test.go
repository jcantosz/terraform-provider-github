package github

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestGithubActionsOrganizationSelfHostedRunnersWrite(t *testing.T) {
	r := resourceGithubActionsOrganizationSelfHostedRunners()
	for _, tc := range []struct {
		name, oldPolicy, policy string
		ids                     []any
	}{
		{"create_selected", "", "selected", []any{9, 2}},
		{"create_all", "", "all", nil},
		{"selected_empty_update", "selected", "selected", []any{}},
		{"all_to_selected_empty", "all", "selected", []any{}},
		{"none_to_selected", "none", "selected", []any{2}},
		{"selected_to_all", "selected", "all", nil},
		{"selected_to_none", "selected", "none", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := map[string]any{"enabled_repositories": tc.oldPolicy}
			if tc.oldPolicy == "selected" {
				old["selected_repository_ids"] = []any{5}
			}
			var state *terraform.InstanceState
			if tc.oldPolicy != "" {
				initial := schema.TestResourceDataRaw(t, r.Schema, old)
				initial.SetId("test-org")
				state = initial.State()
			}
			diff, err := r.Diff(t.Context(), state, terraform.NewResourceConfigRaw(map[string]any{
				"enabled_repositories": tc.policy, "selected_repository_ids": tc.ids,
			}), nil)
			if err != nil {
				t.Fatal(err)
			}
			var paths []string
			meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != "PUT" {
					t.Errorf("unexpected method %s", req.Method)
				}
				paths = append(paths, req.URL.Path)
				if req.URL.Path == "/orgs/test-org/actions/permissions/self-hosted-runners" {
					organizationActionsPolicyTestBody(t, req, fmt.Sprintf(`{"enabled_repositories":%q}`, tc.policy))
				} else if req.URL.Path == "/orgs/test-org/actions/permissions/self-hosted-runners/repositories" {
					body := `{"selected_repository_ids":[]}`
					if len(tc.ids) == 2 {
						body = `{"selected_repository_ids":[2,9]}`
					} else if len(tc.ids) == 1 {
						body = `{"selected_repository_ids":[2]}`
					}
					organizationActionsPolicyTestBody(t, req, body)
				} else {
					t.Errorf("unexpected path %s", req.URL.Path)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			result, diags := r.Apply(t.Context(), state, diff, meta)
			if diags.HasError() || result == nil || result.ID != meta.name {
				t.Fatalf("write: %v, state %#v", diags, result)
			}
			want := []string{}
			if tc.oldPolicy == "" || tc.oldPolicy != tc.policy {
				want = append(want, "/orgs/test-org/actions/permissions/self-hosted-runners")
			}
			if tc.policy == "selected" {
				want = append(want, "/orgs/test-org/actions/permissions/self-hosted-runners/repositories")
			}
			if !reflect.DeepEqual(paths, want) {
				t.Errorf("requests = %v, want %v", paths, want)
			}
		})
	}
}

func TestGithubActionsOrganizationSelfHostedRunnersReadImportAndDelete(t *testing.T) {
	r := resourceGithubActionsOrganizationSelfHostedRunners()
	policy := "selected"
	listCalls := 0
	meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == "PUT":
			organizationActionsPolicyTestBody(t, req, `{"enabled_repositories":"none"}`)
			w.WriteHeader(http.StatusNoContent)
		case req.URL.Path == "/orgs/test-org/actions/permissions/self-hosted-runners":
			fmt.Fprintf(w, `{"enabled_repositories":%q}`, policy)
		case req.URL.Path == "/orgs/test-org/actions/permissions/self-hosted-runners/repositories":
			listCalls++
			if req.URL.Query().Get("per_page") != "100" {
				t.Error("missing per_page=100")
			}
			if req.URL.Query().Get("page") == "2" {
				fmt.Fprint(w, `{"repositories":[{"id":2},{"id":9}]}`)
			} else {
				w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?per_page=100&page=2>; rel="next"`, req.Host, req.URL.Path))
				fmt.Fprint(w, `{"repositories":[{"id":9}]}`)
			}
		default:
			t.Errorf("unexpected request %s", req.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	d.SetId(meta.name)
	if _, err := r.Importer.StateContext(t.Context(), d, meta); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	ids := d.Get("selected_repository_ids").(*schema.Set)
	if listCalls != 2 || ids.Len() != 2 || !ids.Contains(2) || !ids.Contains(9) || d.Get("enabled_repositories") != "selected" {
		t.Fatalf("pagination/state: calls=%d ids=%v", listCalls, ids.List())
	}
	for _, value := range []string{"all", "none"} {
		policy = value
		if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() || d.Get("selected_repository_ids").(*schema.Set).Len() != 0 {
			t.Fatalf("read %s: %v", value, diags)
		}
	}
	if listCalls != 2 {
		t.Fatal("listed repositories for non-selected policy")
	}
	if diags := r.DeleteContext(t.Context(), d, meta); diags.HasError() || d.Id() != "" {
		t.Fatalf("delete: %v", diags)
	}
	d.SetId("other-org")
	if _, err := r.Importer.StateContext(t.Context(), d, meta); err == nil {
		t.Fatal("mismatched import owner accepted")
	}
}

func TestGithubActionsOrganizationSelfHostedRunnersValidation(t *testing.T) {
	r := resourceGithubActionsOrganizationSelfHostedRunners()
	p := &schema.Provider{ResourcesMap: map[string]*schema.Resource{"github_test": r}}
	if err := p.InternalValidate(); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"selected", "all", "none"} {
		for _, ids := range [][]any{nil, {}, {1}} {
			config := map[string]any{"enabled_repositories": policy, "selected_repository_ids": ids}
			_, err := r.Diff(t.Context(), nil, terraform.NewResourceConfigRaw(config), nil)
			wantError := policy != "selected" && len(ids) != 0
			if (err != nil) != wantError {
				t.Errorf("plan %s %v: %v", policy, ids, err)
			}
			d := schema.TestResourceDataRaw(t, r.Schema, config)
			meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
				if wantError {
					t.Error("invalid config reached API")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			d.MarkNewResource()
			if diags := r.CreateContext(t.Context(), d, meta); diags.HasError() != wantError {
				t.Errorf("apply %s %v: %v", policy, ids, diags)
			}
		}
	}
	for _, config := range []map[string]any{
		{"enabled_repositories": "invalid"},
		{"enabled_repositories": "selected", "selected_repository_ids": []any{0}},
		{"enabled_repositories": "selected", "selected_repository_ids": []any{-1}},
	} {
		if diags := r.Validate(terraform.NewResourceConfigRaw(config)); !diags.HasError() {
			t.Errorf("invalid schema config accepted: %v", config)
		}
	}
}

func TestGithubActionsOrganizationSelfHostedRunnersErrors(t *testing.T) {
	r := resourceGithubActionsOrganizationSelfHostedRunners()
	for _, status := range []int{403, 404, 500} {
		for _, failSelected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/selected=%t", status, failSelected), func(t *testing.T) {
				meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
					if failSelected && req.URL.Path == "/orgs/test-org/actions/permissions/self-hosted-runners" {
						if req.Method == "GET" {
							fmt.Fprint(w, `{"enabled_repositories":"selected"}`)
						} else {
							w.WriteHeader(http.StatusNoContent)
						}
						return
					}
					w.WriteHeader(status)
					fmt.Fprint(w, `{"message":"failure"}`)
				})
				for name, op := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
					"create": r.CreateContext, "update": r.UpdateContext, "read": r.ReadContext, "delete": r.DeleteContext,
				} {
					d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"enabled_repositories": "selected", "selected_repository_ids": []any{2}})
					if name == "create" {
						d.MarkNewResource()
					} else {
						d.SetId(meta.name)
					}
					diags := op(t.Context(), d, meta)
					wantError := !(status == 404 && (name == "read" || name == "delete")) && !(name == "delete" && failSelected)
					if diags.HasError() != wantError {
						t.Errorf("%s: %v", name, diags)
					}
					if !wantError && d.Id() != "" {
						t.Errorf("%s did not clear state", name)
					}
					if failSelected && name == "create" && d.Id() == "" {
						t.Error("partial create lost policy ID")
					}
				}
			})
		}
	}
}

func TestAccGithubActionsOrganizationSelfHostedRunners(t *testing.T) {
	if os.Getenv("TF_ACC_ORGANIZATION_ACTIONS_POLICY") != "1" {
		t.Skip("requires TF_ACC_ORGANIZATION_ACTIONS_POLICY=1: changes organization-wide policy and destroy disables self-hosted runners")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { skipUnlessHasOrgs(t) },
		ProviderFactories: organizationActionsPolicyAcceptanceFactories("github_actions_organization_self_hosted_runners", resourceGithubActionsOrganizationSelfHostedRunners),
		Steps: []resource.TestStep{
			{
				Config: `resource "github_actions_organization_self_hosted_runners" "test" {
  enabled_repositories = "none"
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_actions_organization_self_hosted_runners.test", tfjsonpath.New("enabled_repositories"), knownvalue.StringExact("none")),
				},
			},
			{
				Config: `resource "github_actions_organization_self_hosted_runners" "test" {
  enabled_repositories = "selected"
  selected_repository_ids = []
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_actions_organization_self_hosted_runners.test", tfjsonpath.New("selected_repository_ids"), knownvalue.SetSizeExact(0)),
				},
			},
			{ResourceName: "github_actions_organization_self_hosted_runners.test", ImportState: true, ImportStateVerify: true},
		},
	})
}
