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
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func organizationActionsPolicyTestOwner(t *testing.T, handler http.HandlerFunc) *Owner {
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

func organizationActionsPolicyTestBody(t *testing.T, r *http.Request, want string) {
	t.Helper()
	var got, expected any
	if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
		t.Error(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("body = %#v; want %#v", got, expected)
	}
}

func TestGithubActionsOrganizationForkPRWorkflowsCRUD(t *testing.T) {
	r := resourceGithubActionsOrganizationForkPRWorkflows()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"run_workflows_from_fork_pull_requests": true})
	var methods []string
	meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		methods = append(methods, req.Method)
		if req.URL.Path != "/orgs/test-org/actions/permissions/fork-pr-workflows-private-repos" {
			t.Errorf("unexpected path %s", req.URL.Path)
		}
		if req.Method == http.MethodGet {
			fmt.Fprint(w, `{"run_workflows_from_fork_pull_requests":true}`)
			return
		}
		value := `{"run_workflows_from_fork_pull_requests":false}`
		if len(methods) == 1 {
			value = `{"run_workflows_from_fork_pull_requests":true}`
		}
		organizationActionsPolicyTestBody(t, req, value)
		w.WriteHeader(http.StatusNoContent)
	})
	if diags := r.CreateContext(t.Context(), d, meta); diags.HasError() || d.Id() != meta.name {
		t.Fatalf("create: %v, ID %q", diags, d.Id())
	}
	if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() || !d.Get("run_workflows_from_fork_pull_requests").(bool) {
		t.Fatalf("read: %v", diags)
	}
	if err := d.Set("run_workflows_from_fork_pull_requests", false); err != nil {
		t.Fatal(err)
	}
	if diags := r.UpdateContext(t.Context(), d, meta); diags.HasError() {
		t.Fatal(diags)
	}
	if diags := r.DeleteContext(t.Context(), d, meta); diags.HasError() || d.Id() != "" {
		t.Fatalf("delete: %v, ID %q", diags, d.Id())
	}
	if !reflect.DeepEqual(methods, []string{"PUT", "GET", "PUT", "PUT"}) {
		t.Fatalf("unexpected calls (including read-after-write): %v", methods)
	}
}

func TestGithubActionsOrganizationForkPRWorkflowsErrorsAndImport(t *testing.T) {
	r := resourceGithubActionsOrganizationForkPRWorkflows()
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"message":"failure"}`)
			})
			for name, operation := range map[string]func(context.Context, *schema.ResourceData, any) diag.Diagnostics{
				"create": r.CreateContext, "read": r.ReadContext, "update": r.UpdateContext, "delete": r.DeleteContext,
			} {
				d := schema.TestResourceDataRaw(t, r.Schema, nil)
				d.SetId(meta.name)
				diags := operation(t.Context(), d, meta)
				wantError := status != http.StatusNotFound || name == "create" || name == "update"
				if diags.HasError() != wantError {
					t.Errorf("%s: %v", name, diags)
				}
				if !wantError && d.Id() != "" {
					t.Errorf("%s: 404 did not clear state", name)
				}
			}
		})
	}
	meta := organizationActionsPolicyTestOwner(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"run_workflows_from_fork_pull_requests":true}`)
	})
	for _, id := range []string{"test-org", "TEST-ORG", "other-org", "", "test-org:invalid", "test-org/invalid"} {
		d := schema.TestResourceDataRaw(t, r.Schema, nil)
		d.SetId(id)
		_, err := r.Importer.StateContext(t.Context(), d, meta)
		valid := id == "test-org" || id == "TEST-ORG"
		if (err == nil) != valid {
			t.Errorf("import %q: %v", id, err)
		}
		if valid {
			if diags := r.ReadContext(t.Context(), d, meta); diags.HasError() || !d.Get("run_workflows_from_fork_pull_requests").(bool) {
				t.Fatalf("import read: %v", diags)
			}
		}
	}
	meta.IsOrganization = false
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	if diags := r.CreateContext(t.Context(), d, meta); !diags.HasError() {
		t.Fatal("user owner accepted")
	}
	if _, err := r.Importer.StateContext(t.Context(), d, meta); err == nil {
		t.Fatal("user owner import accepted")
	}
	meta.IsOrganization = true
	d.SetId("other-org")
	if diags := r.ReadContext(t.Context(), d, meta); !diags.HasError() {
		t.Fatal("mismatched owner accepted")
	}
}

func organizationActionsPolicyAcceptanceFactories(name string, factory func() *schema.Resource) map[string]func() (*schema.Provider, error) {
	return map[string]func() (*schema.Provider, error){
		"github": func() (*schema.Provider, error) {
			p := NewProvider("acctest", "none")()
			p.ResourcesMap[name] = factory()
			return p, nil
		},
	}
}

func TestAccGithubActionsOrganizationForkPRWorkflows(t *testing.T) {
	if os.Getenv("TF_ACC_ORGANIZATION_ACTIONS_POLICY") != "1" {
		t.Skip("requires TF_ACC_ORGANIZATION_ACTIONS_POLICY=1: changes organization-wide policy and destroy disables fork PR workflows")
	}
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { skipUnlessHasPaidOrgs(t) },
		ProviderFactories: organizationActionsPolicyAcceptanceFactories("github_actions_organization_fork_pr_workflows", resourceGithubActionsOrganizationForkPRWorkflows),
		Steps: []resource.TestStep{
			{
				Config: `resource "github_actions_organization_fork_pr_workflows" "test" {
  run_workflows_from_fork_pull_requests = false
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_actions_organization_fork_pr_workflows.test", tfjsonpath.New("run_workflows_from_fork_pull_requests"), knownvalue.Bool(false)),
				},
			},
			{
				Config: `resource "github_actions_organization_fork_pr_workflows" "test" {
  run_workflows_from_fork_pull_requests = true
}`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("github_actions_organization_fork_pr_workflows.test", tfjsonpath.New("run_workflows_from_fork_pull_requests"), knownvalue.Bool(true)),
				},
			},
			{ResourceName: "github_actions_organization_fork_pr_workflows.test", ImportState: true, ImportStateVerify: true},
		},
	})
}
