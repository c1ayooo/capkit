package verifykit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/auditlog"
	"github.com/c1ayooo/capkit/all"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/runtime"
)

type fakeFP struct{ products []string }

func (f *fakeFP) Fingerprint(context.Context, capkit.Target) ([]capkit.Fingerprint, error) {
	out := make([]capkit.Fingerprint, 0, len(f.products))
	for _, p := range f.products {
		out = append(out, capkit.Fingerprint{Product: p, Source: "fake"})
	}
	return out, nil
}

type fakeCatalog struct{ refs map[string]capkit.TemplateRef }

func (f *fakeCatalog) Search(_ context.Context, q capkit.TemplateQuery) ([]capkit.TemplateRef, error) {
	var out []capkit.TemplateRef
	for _, ref := range f.refs {
		if len(q.Products) == 0 {
			out = append(out, ref)
			continue
		}
		for _, p := range q.Products {
			if strings.Contains(strings.ToLower(ref.Meta["products"]), strings.ToLower(p)) {
				out = append(out, ref)
				break
			}
		}
	}
	return out, nil
}

func (f *fakeCatalog) Get(_ context.Context, id string) (capkit.TemplateRef, bool, error) {
	ref, ok := f.refs[id]
	return ref, ok, nil
}

type fakeEngine struct {
	kind  string
	calls int
}

func (f *fakeEngine) Kind() string { return f.kind }
func (f *fakeEngine) Execute(_ context.Context, refs []capkit.TemplateRef, _ capkit.Target, _ map[string]any) (capkit.Result, error) {
	f.calls++
	return capkit.TextResult("executed " + strings.Join(ids(refs), ",")), nil
}

func ids(refs []capkit.TemplateRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.ID)
	}
	return out
}

func newRuntime(t *testing.T, engine *fakeEngine) *runtime.Runtime {
	t.Helper()
	reg := capkit.NewRegistry()
	if err := all.RegisterVerify(reg); err != nil {
		t.Fatal(err)
	}
	scope := gates.StaticScope("127.0.0.1")
	lim := gates.NewLimiter()
	audit := auditlog.NewMemory()
	catalog := &fakeCatalog{refs: map[string]capkit.TemplateRef{
		"t1": {ID: "t1", Name: "T1", Kind: "http", Engine: "http", Meta: map[string]string{"products": "nginx"}},
	}}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: lim, Audit: audit,
		Fingerprints: &fakeFP{products: []string{"nginx"}}, Templates: catalog,
		TemplateEngines: map[string]capkit.TemplateEngine{"http": engine},
	}, reg)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestVerifyPlan(t *testing.T) {
	rt := newRuntime(t, &fakeEngine{kind: "http"})
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1"})
	res, err := rt.Call(context.Background(), "verify_plan", input, capkit.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	var data struct {
		Fingerprints []capkit.Fingerprint `json:"fingerprints"`
		Candidates   []struct {
			ID string `json:"id"`
		} `json:"candidates"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Fingerprints) != 1 || data.Fingerprints[0].Product != "nginx" {
		t.Fatalf("fingerprints = %+v", data.Fingerprints)
	}
	if data.Count != 1 || data.Candidates[0].ID != "t1" {
		t.Fatalf("candidates = %+v", data.Candidates)
	}
}

func TestVerifyExecute(t *testing.T) {
	engine := &fakeEngine{kind: "http"}
	rt := newRuntime(t, engine)
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1", "template_ids": []string{"t1"}})
	res, err := rt.Call(context.Background(), "verify_execute", input, capkit.CallContext{ProjectID: 1, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("result = %+v", res)
	}
	if engine.calls != 1 {
		t.Fatalf("engine calls = %d", engine.calls)
	}
}

func TestVerifyExecuteMissingTemplate(t *testing.T) {
	rt := newRuntime(t, &fakeEngine{kind: "http"})
	input, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1", "template_ids": []string{"nope"}})
	res, err := rt.Call(context.Background(), "verify_execute", input, capkit.CallContext{ProjectID: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error == nil || res.Error.Code != capkit.CodeNotFound {
		t.Fatalf("result = %+v", res)
	}
}
