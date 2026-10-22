package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestCodeSecurityConfigurationDefaultRoundTrip(t *testing.T) {
	scope := "public"
	writes := 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPut {
			if req.URL.Path != "/orgs/test-org/code-security/configurations/42/defaults" {
				t.Errorf("unexpected PUT path %s", req.URL.Path)
			}
			var body struct {
				Scope string `json:"default_for_new_repos"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			scope = body.Scope
			writes++
			fmt.Fprintf(w, `{"configuration":{"id":42},"default_for_new_repos":%q}`, scope)
			return
		}
		if req.URL.Path == "/orgs/test-org/code-security/configurations/42" {
			fmt.Fprint(w, `{"id":42,"name":"test"}`)
			return
		}
		if req.URL.Path != "/orgs/test-org/code-security/configurations/defaults" {
			t.Errorf("unexpected GET path %s", req.URL.Path)
		}
		if scope == "none" {
			fmt.Fprint(w, `[]`)
		} else {
			fmt.Fprintf(w, `[{"configuration":{"id":7},"default_for_new_repos":"private_and_internal"},{"configuration":{"id":42},"default_for_new_repos":%q}]`, scope)
		}
	})
	r := resourceGithubCodeSecurityConfigurationDefault()
	ctx := context.Background()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"configuration_id": 42, "default_for_new_repos": "public"})
	if diags := r.CreateContext(ctx, d, owner); diags.HasError() || writes != 1 {
		t.Fatalf("create: %v", diags)
	}
	imported := schema.TestResourceDataRaw(t, r.Schema, nil)
	imported.SetId("42")
	if _, err := r.Importer.StateContext(ctx, imported, owner); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(ctx, imported, owner); diags.HasError() || imported.Get("configuration_id") != 42 || imported.Get("default_for_new_repos") != "public" {
		t.Fatalf("import: %v %#v", diags, imported.State())
	}
	if err := d.Set("default_for_new_repos", "private_and_internal"); err != nil {
		t.Fatal(err)
	}
	if diags := r.UpdateContext(ctx, d, owner); diags.HasError() || scope != "private_and_internal" {
		t.Fatalf("update: %v", diags)
	}
	scope = "none"
	if diags := r.ReadContext(ctx, d, owner); diags.HasError() || d.Id() != "42" || d.Get("default_for_new_repos") != "none" {
		t.Fatalf("default removal drift: %v", diags)
	}
	if diags := r.DeleteContext(ctx, d, owner); diags.HasError() || scope != "none" || d.Id() != "" {
		t.Fatalf("delete: %v", diags)
	}
}
