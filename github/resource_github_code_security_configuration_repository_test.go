package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestCodeSecurityConfigurationRepositoryRoundTrip(t *testing.T) {
	attached := true
	requests, pages, detaches := 0, 0, 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.Method == http.MethodPost {
			if req.URL.Path != "/orgs/test-org/code-security/configurations/42/attach" {
				t.Errorf("unexpected attach path %s", req.URL.Path)
			}
			var body struct {
				Scope string  `json:"scope"`
				IDs   []int64 `json:"selected_repository_ids"`
			}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Scope != "selected" || len(body.IDs) != 1 || body.IDs[0] != 99 {
				t.Errorf("unexpected attachment body: %#v", body)
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method == http.MethodDelete {
			detaches++
			if req.URL.Path != "/orgs/test-org/code-security/configurations/detach" {
				t.Errorf("unexpected detach path %s", req.URL.Path)
			}
			var body map[string][]int64
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if ids := body["selected_repository_ids"]; len(ids) != 1 || ids[0] != 99 {
				t.Errorf("unexpected detach body: %v", body)
			}
			attached = false
			w.WriteHeader(http.StatusAccepted)
			return
		}
		pages++
		if req.URL.Query().Get("per_page") != "100" {
			t.Errorf("missing page size: %s", req.URL)
		}
		if req.URL.Query().Get("after") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?per_page=100&after=cursor>; rel="next"`, req.Host, req.URL.Path))
			fmt.Fprint(w, `[{"status":"attached","repository":{"id":7}}]`)
			return
		}
		if attached {
			fmt.Fprint(w, `[{"status":"attached","repository":{"id":99}}]`)
		} else {
			fmt.Fprint(w, `[]`)
		}
	})
	r := resourceGithubCodeSecurityConfigurationRepository()
	ctx := context.Background()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"configuration_id": 42, "repository_id": 99})
	if diags := r.CreateContext(ctx, d, owner); diags.HasError() || requests != 3 || d.Id() != "42:99" || d.Get("status") != "attached" {
		t.Fatalf("create must wait for attachment: %v requests=%d", diags, requests)
	}
	imported := schema.TestResourceDataRaw(t, r.Schema, nil)
	imported.SetId("42:99")
	if _, err := r.Importer.StateContext(ctx, imported, owner); err != nil {
		t.Fatal(err)
	}
	if diags := r.ReadContext(ctx, imported, owner); diags.HasError() || pages != 4 || imported.Get("repository_id") != 99 || imported.Get("configuration_id") != 42 || imported.Get("status") != "attached" {
		t.Fatalf("paginated import read: %v pages=%d", diags, pages)
	}

	if diags := r.DeleteContext(ctx, d, owner); diags.HasError() || detaches != 1 || d.Id() != "" {
		t.Fatalf("delete: %v detaches=%d", diags, detaches)
	}
	imported.SetId("42:99")
	if diags := r.DeleteContext(ctx, imported, owner); diags.HasError() || detaches != 1 {
		t.Fatalf("must not detach reassigned or absent repository: %v", diags)
	}
	imported.SetId("42:99")
	if diags := r.ReadContext(ctx, imported, owner); diags.HasError() || imported.Id() != "" {
		t.Fatalf("attachment removal drift: %v", diags)
	}
}

func TestCodeSecurityConfigurationRepositoryQueued(t *testing.T) {
	reads := 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		reads++
		switch reads {
		case 1:
			fmt.Fprint(w, `[]`)
		case 2:
			fmt.Fprint(w, `[{"status":"attaching","repository":{"id":99}}]`)
		case 3:
			fmt.Fprint(w, `[{"status":"updating","repository":{"id":99}}]`)
		default:
			fmt.Fprint(w, `[{"status":"enforced","repository":{"id":99}}]`)
		}
	})
	r := resourceGithubCodeSecurityConfigurationRepository()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"configuration_id": 42, "repository_id": 99})
	if diags := r.CreateContext(context.Background(), d, owner); diags.HasError() || d.Id() != "42:99" || d.Get("status") != "enforced" || reads != 4 {
		t.Fatalf("queued create lost relationship: %v, reads=%d state=%#v", diags, reads, d.State())
	}
}

func TestCodeSecurityConfigurationRepositoryPendingRefresh(t *testing.T) {
	reads := 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		reads++
		if reads == 1 {
			fmt.Fprint(w, `[]`)
		} else {
			fmt.Fprint(w, `[{"status":"enterprise_enforced","repository":{"id":99}}]`)
		}
	})
	r := resourceGithubCodeSecurityConfigurationRepository()
	d := schema.TestResourceDataRaw(t, r.Schema, map[string]any{"status": "attaching"})
	d.SetId("42:99")
	if diags := r.ReadContext(context.Background(), d, owner); diags.HasError() || d.Id() == "" || d.Get("status") != "enterprise_enforced" {
		t.Fatalf("refresh cleared queued relationship: %v %#v", diags, d.State())
	}
}

func TestCodeSecurityConfigurationRepositoryWaitFailures(t *testing.T) {
	for _, status := range []string{"failed", "removed_by_enterprise", "attaching", "missing"} {
		t.Run(status, func(t *testing.T) {
			owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
				if status == "missing" {
					fmt.Fprint(w, `[]`)
					return
				}
				fmt.Fprintf(w, `[{"status":%q,"repository":{"id":99}}]`, status)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if _, err := codeSecurityRepositoryWait(ctx, owner, 42, 99, false, time.Second); err == nil {
				t.Fatal("expected terminal-state or context diagnostic")
			}
		})
	}
}

func TestCodeSecurityConfigurationRepositoryRemoved(t *testing.T) {
	for _, status := range []string{"detached", "removed", "removed_by_enterprise"} {
		t.Run(status, func(t *testing.T) {
			owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					t.Error("must not detach an already removed relationship")
				}
				fmt.Fprintf(w, `[{"status":%q,"repository":{"id":99}}]`, status)
			})
			r := resourceGithubCodeSecurityConfigurationRepository()
			d := schema.TestResourceDataRaw(t, r.Schema, nil)
			d.SetId("42:99")
			if diags := r.ReadContext(context.Background(), d, owner); diags.HasError() || d.Id() != "" {
				t.Fatalf("removed relationship retained state: %v", diags)
			}
			d.SetId("42:99")
			if diags := r.DeleteContext(context.Background(), d, owner); diags.HasError() || d.Id() != "" {
				t.Fatalf("delete removed relationship: %v", diags)
			}
		})
	}
}
func TestCodeSecurityConfigurationRepositoryFailed(t *testing.T) {
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `[{"status":"failed","repository":{"id":99}}]`)
	})
	r := resourceGithubCodeSecurityConfigurationRepository()
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	d.SetId("42:99")
	diags := r.ReadContext(context.Background(), d, owner)
	if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "failed to attach") || d.Id() == "" {
		t.Fatalf("failed attachment must be actionable: %v", diags)
	}
}

func TestCodeSecurityConfigurationRepositoryQueuedImport(t *testing.T) {
	for _, terminal := range []string{"attached", "failed"} {
		t.Run(terminal, func(t *testing.T) {
			reads := 0
			owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
				reads++
				status := terminal
				if reads == 1 {
					status = "queued"
				}
				fmt.Fprintf(w, `[{"status":%q,"repository":{"id":99}}]`, status)
			})
			r := resourceGithubCodeSecurityConfigurationRepository()
			d := schema.TestResourceDataRaw(t, r.Schema, nil)
			d.SetId("42:99")
			if _, err := r.Importer.StateContext(context.Background(), d, owner); err != nil {
				t.Fatal(err)
			}
			diags := r.ReadContext(context.Background(), d, owner)
			if d.Id() != "42:99" || reads != 2 {
				t.Fatalf("queued import must wait and retain its ID: %v reads=%d", diags, reads)
			}
			if terminal == "failed" {
				if !diags.HasError() || !strings.Contains(fmt.Sprint(diags), "failed to attach") {
					t.Fatalf("failed queued import lacked actionable diagnostic: %v", diags)
				}
			} else if diags.HasError() || d.Get("status") != "attached" {
				t.Fatalf("queued import did not reach attachment: %v %#v", diags, d.State())
			}
		})
	}
}

func TestCodeSecurityConfigurationRepositoryIncompleteDetach(t *testing.T) {
	detaches, reads := 0, 0
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodDelete {
			detaches++
			w.WriteHeader(http.StatusAccepted)
			return
		}
		reads++
		status := "attached"
		if detaches > 0 {
			status = "queued"
		}
		fmt.Fprintf(w, `[{"status":%q,"repository":{"id":99}}]`, status)
	})
	r := resourceGithubCodeSecurityConfigurationRepository()
	d := schema.TestResourceDataRaw(t, r.Schema, nil)
	d.SetId("42:99")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	diags := r.DeleteContext(ctx, d, owner)
	if !diags.HasError() || d.Id() != "42:99" || detaches != 1 || reads < 2 {
		t.Fatalf("incomplete detach must fail without clearing state: %v state=%#v reads=%d detaches=%d", diags, d.State(), reads, detaches)
	}
}

func TestCodeSecurityConfigurationRepositoryWaitTimeout(t *testing.T) {
	owner := codeSecurityTestOwner(t, func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	})
	start := time.Now()
	if _, err := codeSecurityRepositoryWait(context.Background(), owner, 42, 99, false, 50*time.Millisecond); err == nil {
		t.Fatal("expected timeout diagnostic")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("polling exceeded bounded timeout: %s", elapsed)
	}
}
