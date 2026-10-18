package verifykit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/c1ayooo/capkit"
)

// Kit composes fingerprinting, template search and engine execution through
// capkit interfaces only. It never imports fingerprintkit/templatekit/httpkit
// or any concrete engine.
type Kit struct {
	fingerprints capkit.FingerprintProvider
	catalog      capkit.TemplateCatalog
	engines      map[string]capkit.TemplateEngine
}

func New(deps capkit.Deps) (*Kit, error) {
	if deps.Fingerprints == nil {
		return nil, fmt.Errorf("verifykit: fingerprint provider is required")
	}
	if deps.Templates == nil {
		return nil, fmt.Errorf("verifykit: template catalog is required")
	}
	if len(deps.TemplateEngines) == 0 {
		return nil, fmt.Errorf("verifykit: at least one template engine is required")
	}
	return &Kit{fingerprints: deps.Fingerprints, catalog: deps.Templates, engines: deps.TemplateEngines}, nil
}

func NewCapability(deps capkit.Deps) (capkit.Capability, error) { return New(deps) }

func (k *Kit) Manifest() capkit.Manifest { return Manifest() }

// Manifest is the static declaration, usable before providers are available.
func Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "verifykit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "fingerprints", "templates", "template_engines"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "verify_plan",
				Description: "Fingerprint the target, then search the predefined template catalog for matching products/CVEs. Returns a plan only; it does not execute anything.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"URL/host/domain/IP"},
    "products":{"type":"array","items":{"type":"string"},"description":"override fingerprint products"},
    "cve":{"type":"string"},
    "tags":{"type":"array","items":{"type":"string"}},
    "severity":{"type":"array","items":{"type":"string"}},
    "kind":{"type":"string","description":"http | nuclei | shell | chain"},
    "limit":{"type":"integer","description":"max candidates (default 50)"}
  },
  "required":["target"]
}`),
				Risk:         capkit.RiskLow,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"plan_id":{"type":"string"},"target":{"type":"object"},"fingerprints":{"type":"array","items":{"type":"object"}},"templates":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    capkit.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 2},
				ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
					var in planInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					t, err := capkit.TargetFromString(0, in.Target)
					if err != nil {
						return nil, err
					}
					return []capkit.Target{t}, nil
				},
			},
			{
				Name:        "verify_execute",
				Description: "Execute selected predefined template IDs against the target through the matching engine (kind). High risk: the runtime requires approval and scope validation.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "target":{"type":"string","description":"URL/host/domain/IP"},
    "template_ids":{"type":"array","items":{"type":"string"},"description":"IDs returned by verify_plan"},
    "options":{"type":"object","description":"engine-specific options"}
  },
  "required":["target","template_ids"]
}`),
				Risk:         capkit.RiskHigh,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"plan_id":{"type":"string"},"status":{"type":"string"},"results":{"type":"array","items":{"type":"object"}}}}`),
				RateLimit:    capkit.RateLimitSpec{PerSecond: 2, Burst: 1, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
					var in executeInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					t, err := capkit.TargetFromString(0, in.Target)
					if err != nil {
						return nil, err
					}
					return []capkit.Target{t}, nil
				},
			},
		},
	}
}

type planInput struct {
	Target   string   `json:"target"`
	Products []string `json:"products"`
	CVE      string   `json:"cve"`
	Tags     []string `json:"tags"`
	Severity []string `json:"severity"`
	Kind     string   `json:"kind"`
	Limit    int      `json:"limit"`
}

type executeInput struct {
	Target      string         `json:"target"`
	TemplateIDs []string       `json:"template_ids"`
	Options     map[string]any `json:"options"`
}

func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "verify_plan":
		return k.plan(ctx, call)
	case "verify_execute":
		return k.execute(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) plan(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in planInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	target, err := capkit.TargetFromString(call.Context.ProjectID, in.Target)
	if err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	fps, err := k.fingerprints.Fingerprint(ctx, target)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	products := append([]string(nil), in.Products...)
	if len(products) == 0 {
		for _, fp := range fps {
			if fp.Product != "" {
				products = append(products, fp.Product)
			}
		}
	}
	q := capkit.TemplateQuery{
		Products: unique(products), CVE: in.CVE, Tags: in.Tags,
		Severity: in.Severity, Kind: in.Kind, Limit: in.Limit,
	}
	refs, err := k.catalog.Search(ctx, q)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	type candidate struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		Engine string `json:"engine,omitempty"`
	}
	cands := make([]candidate, 0, len(refs))
	for _, ref := range refs {
		cands = append(cands, candidate{ID: ref.ID, Name: ref.Name, Kind: ref.Kind, Engine: ref.Engine})
	}
	out := map[string]any{
		"target": target, "fingerprints": fps, "products": unique(products),
		"candidates": cands, "count": len(cands),
	}
	res, _ := capkit.DataResult(out)
	return res, nil
}

func (k *Kit) execute(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in executeInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	if len(in.TemplateIDs) == 0 {
		return capkit.FailResult(capkit.InvalidInput("template_ids is required")), nil
	}
	target, err := capkit.TargetFromString(call.Context.ProjectID, in.Target)
	if err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	byKind := map[string][]capkit.TemplateRef{}
	var missing []string
	for _, id := range in.TemplateIDs {
		ref, ok, err := k.catalog.Get(ctx, id)
		if err != nil {
			return capkit.FailResult(err), nil
		}
		if !ok {
			missing = append(missing, id)
			continue
		}
		kind := ref.Kind
		if ref.Engine != "" {
			kind = ref.Engine
		}
		byKind[kind] = append(byKind[kind], ref)
	}
	if len(missing) > 0 {
		return capkit.FailResult(capkit.NotFound("templates not found: " + strings.Join(missing, ", "))), nil
	}
	results := make([]map[string]any, 0, len(byKind))
	for kind, refs := range byKind {
		engine, ok := k.engines[kind]
		if !ok {
			return capkit.FailResult(capkit.Unavailable("no template engine for kind " + kind)), nil
		}
		res, err := engine.Execute(ctx, refs, target, in.Options)
		if err != nil {
			return capkit.FailResult(err), nil
		}
		results = append(results, map[string]any{"kind": kind, "result": res})
	}
	out, _ := capkit.DataResult(map[string]any{"target": target, "results": results, "engine_count": len(results)})
	return out, nil
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[strings.ToLower(v)] {
			continue
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	return out
}
