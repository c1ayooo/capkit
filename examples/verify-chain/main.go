// Command verify-chain demonstrates the fingerprint -> template -> verify
// pipeline end to end, entirely offline: a local HTTP server is the target, a
// stub fingerprint provider stands in for the host's scanner, and a stub
// template engine stands in for nuclei. It shows the Result envelope the agent
// sees at each step.
//
// Run: go run ./examples/verify-chain
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/auditlog"
	"github.com/c1ayooo/capkit/adapters/httpx"
	"github.com/c1ayooo/capkit/adapters/sealer"
	"github.com/c1ayooo/capkit/adapters/settings"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/templatekit"
	"github.com/c1ayooo/capkit/kits/verifykit"
	"github.com/c1ayooo/capkit/runtime"
)

// stubFingerprints is a FingerprintProvider the host would normally back with a
// real scanner. Here it always reports nginx so the catalog match is visible.
type stubFingerprints struct{}

func (stubFingerprints) Fingerprint(context.Context, capkit.Target) ([]capkit.Fingerprint, error) {
	return []capkit.Fingerprint{{Product: "nginx", Version: "1.18.0", Category: "web-server", Confidence: 90}}, nil
}

// stubEngine is a TemplateEngine. It reports a finding for each template,
// standing in for nuclei/http execution.
type stubEngine struct{}

func (stubEngine) Kind() string { return "http" }

func (stubEngine) Execute(_ context.Context, refs []capkit.TemplateRef, target capkit.Target, _ map[string]any) (capkit.Result, error) {
	findings := make([]capkit.Finding, 0, len(refs))
	for _, r := range refs {
		findings = append(findings, capkit.Finding{
			Target: target, Kind: "template:" + r.ID, Confirmed: true,
			Fingerprint: r.ID + "|" + target.Key(), Source: "verify-chain-example",
		})
	}
	res := capkit.NewResult(capkit.StatusSuccess, fmt.Sprintf("执行 %d 个模板，命中 %d 项", len(refs), len(findings)))
	res.Findings = findings
	if next, err := plannerSuggest(findings...); err == nil {
		res.Next = next
	}
	return res, nil
}

// Suggest is a tiny helper so the example can call the planner without noise.
func plannerSuggest(fs ...capkit.Finding) ([]capkit.NextStep, error) {
	var out []capkit.NextStep
	for _, f := range fs {
		steps, err := capkit.DefaultPlanner().Suggest(context.Background(), f)
		if err != nil {
			return nil, err
		}
		out = append(out, steps...)
	}
	return out, nil
}

func main() {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte("verify-chain example target"))
	}))
	defer target.Close()

	// Host-side template catalog with one http template.
	catalog := templatekit.NewCatalog()
	pack := &templatekit.Pack{
		Manifest: templatekit.PackManifest{Name: "example", Version: "1"},
		Templates: []templatekit.Template{{
			ID: "example-nginx-version", Name: "nginx version disclosure", Kind: templatekit.KindHTTP,
			Severity: "low", Product: []string{"nginx"},
			Request:  &templatekit.RequestSpec{Method: "GET", Path: "/"},
			Matchers: []templatekit.Matcher{{Type: "word", Part: "header", Words: []string{"nginx"}}},
		}},
	}
	if err := catalog.AddPack(pack); err != nil {
		log.Fatalf("add pack: %v", err)
	}

	scope := gates.StaticScope("127.0.0.1")
	limiter := gates.NewLimiter()
	audit := auditlog.NewMemory()
	seal, err := sealer.New([]byte("example-key"))
	if err != nil {
		log.Fatal(err)
	}

	reg := capkit.NewRegistry()
	spec := capkit.Spec{Manifest: verifykit.Manifest(), New: verifykit.NewCapability}
	if err := reg.Add(spec); err != nil {
		log.Fatal(err)
	}

	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: limiter, Audit: audit,
		HTTP: httpx.New(scope, limiter, audit), Settings: settings.New(nil), Sealer: seal,
		Fingerprints: stubFingerprints{}, Templates: catalog,
		TemplateEngines: map[string]capkit.TemplateEngine{"http": stubEngine{}},
	}, reg)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	cc := capkit.CallContext{ProjectID: 1, Actor: "example"}

	planIn, _ := json.Marshal(map[string]any{"target": target.URL})
	plan, err := rt.Call(ctx, "verify_plan", planIn, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("== verify_plan ==")
	fmt.Println("status:", plan.Status)
	fmt.Println("summary:", plan.Summary)
	printJSON(plan.Data)

	execIn, _ := json.Marshal(map[string]any{"target": target.URL, "template_ids": []string{"example-nginx-version"}})
	exec, err := rt.Call(ctx, "verify_execute", execIn, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n== verify_execute ==")
	fmt.Println("status:", exec.Status)
	fmt.Println("summary:", exec.Summary)
	fmt.Println("meta.tool:", exec.Meta.Tool, "duration_ms:", exec.Meta.DurationMS, "gate_trace:", exec.Meta.GateTrace)
	printJSON(exec.Data)
}

func printJSON(raw json.RawMessage) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Println(string(raw))
		return
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
