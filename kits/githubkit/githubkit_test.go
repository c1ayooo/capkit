package githubkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/auditlog"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/runtime"
)

func TestGithubKitThroughRuntime(t *testing.T) {
	reg := capkit.NewRegistry()
	kit := New(capkit.Deps{})
	if err := reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: gates.StaticScope("example.com"), Approval: gates.AutoApprove(),
		Limiter: gates.NewLimiter(), Audit: auditlog.NewMemory(),
		Fetcher:  &fakeFetcher{resp: &capkit.Response{Status: 200, Body: []byte(sampleJSON)}},
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{
		"template_id": "org-aws", "org": "acme", "domain": "example.com",
	})
	res, err := rt.Call(context.Background(), "github_secret_search", input, capkit.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data SearchResult
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Items) != 1 || data.Items[0].SecretType != "aws_access_key" {
		t.Fatalf("data = %+v", data)
	}
}

func TestGithubKitScopeDenied(t *testing.T) {
	reg := capkit.NewRegistry()
	kit := New(capkit.Deps{})
	if err := reg.Add(capkit.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: gates.StaticScope("example.com"), Approval: gates.AutoApprove(),
		Limiter: gates.NewLimiter(), Audit: auditlog.NewMemory(),
		Fetcher:  &fakeFetcher{resp: &capkit.Response{Status: 200, Body: []byte(sampleJSON)}},
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"template_id": "org-aws", "org": "acme", "domain": "evil.com"})
	_, err = rt.Call(context.Background(), "github_secret_search", input, capkit.CallContext{ProjectID: 1})
	if err == nil || !strings.Contains(err.Error(), capkit.CodeScopeDenied) {
		t.Fatalf("err = %v", err)
	}
}

// TestSearchReportsPagination covers §5.5.4 for the one tool whose result set is
// genuinely unbounded: the envelope must carry the true total and a cursor.
func TestSearchReportsPagination(t *testing.T) {
	fetcher := &fakeFetcher{resp: &capkit.Response{Status: 200, Body: []byte(
		`{"total_count":250,"incomplete_results":false,"items":[` +
			`{"path":"a.go","html_url":"https://github.com/o/r/blob/main/a.go",` +
			`"repository":{"full_name":"o/r","html_url":"https://github.com/o/r","stargazers_count":1},` +
			`"text_matches":[{"fragment":"token=x"}]}]}`)}}
	kit := New(capkit.Deps{
		Fetcher:  fetcher,
		Settings: fakeSettings{m: map[string]string{"github.token": "ghp_test"}},
	})
	ctx := context.Background()

	res, err := kit.Call(ctx, capkit.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"token","per_page":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != capkit.StatusSuccess {
		t.Fatalf("status = %q %s", res.Status, res.Summary)
	}
	if res.Page == nil || res.Page.Total != 250 || !res.Page.HasMore || res.Page.Cursor == "" {
		t.Fatalf("page = %+v", res.Page)
	}
	if !strings.Contains(fetcher.last.URL, "page=1") {
		t.Fatalf("first request = %s", fetcher.last.URL)
	}

	// The cursor resumes at the next API page.
	if _, err := kit.Call(ctx, capkit.Call{
		Tool:  "github_secret_search",
		Input: json.RawMessage(`{"query":"token","per_page":2,"cursor":"` + res.Page.Cursor + `"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fetcher.last.URL, "page=2") {
		t.Fatalf("resumed request = %s", fetcher.last.URL)
	}

	// A garbled cursor is rejected rather than silently restarted.
	bad, _ := kit.Call(ctx, capkit.Call{
		Tool: "github_secret_search", Input: json.RawMessage(`{"query":"token","cursor":"nope"}`),
	})
	if bad.Error == nil || bad.Error.Code != capkit.CodeInvalidInput {
		t.Fatalf("bad cursor = %+v", bad)
	}
}
