package nucleikit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// Kit wraps the nuclei execution engine. Execution scheduling, process
// management, concurrency and JSONL parsing belong here; template indexing is
// delegated to a TemplateCatalog implementation (wired by the host later).
type Kit struct {
	Processes capkit.ProcessRunner
	Binaries  capkit.BinaryManager
	Settings  capkit.Settings
	Evidence  capkit.EvidenceSink
}

func New(deps capkit.Deps) *Kit {
	return &Kit{Processes: deps.Processes, Binaries: deps.Binaries, Settings: deps.Settings, Evidence: deps.Evidence}
}

func NewCapability(deps capkit.Deps) (capkit.Capability, error) { return New(deps), nil }

func (k *Kit) Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "nucleikit", Version: "0.1.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "process", "binary"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "nuclei_scan",
				Description: "Run nuclei against one or more in-scope targets and parse JSONL output. Execution is gated by scope, approval, rate limiting and audit at the runtime layer.",
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "targets":{"type":"array","items":{"type":"string"},"description":"in-scope URLs/hosts"},
    "templates":{"type":"array","items":{"type":"string"},"description":"template IDs or relative paths"},
    "tags":{"type":"array","items":{"type":"string"}},
    "severity":{"type":"array","items":{"type":"string"}},
    "timeout_sec":{"type":"integer","description":"per-target timeout (default 120)"}
  },
  "required":["targets"]
}`),
				Risk:         capkit.RiskHigh,
				OutputSchema: json.RawMessage(`{"type":"object","properties":{"status":{"type":"integer"},"findings":{"type":"array","items":{"type":"object"}},"duration_ms":{"type":"integer"},"binary":{"type":"string"}}}`),
				RateLimit:    capkit.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 1},
				ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
					var in scanInput
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					return capkit.TargetsFromStrings(0, in.Targets)
				},
			},
			{
				Name:           "nuclei_status",
				Description:    "Report the managed nuclei binary status (version/path/updated_at).",
				InputSchema:    json.RawMessage(`{"type":"object","properties":{}}`),
				Risk:           capkit.RiskLow,
				OutputSchema:   json.RawMessage(`{"type":"object","properties":{"installed":{"type":"boolean"},"version":{"type":"string"},"path":{"type":"string"}}}`),
				ExtractTargets: func(json.RawMessage) ([]capkit.Target, error) { return nil, nil },
			},
		},
	}
}

type scanInput struct {
	Targets    []string `json:"targets"`
	Templates  []string `json:"templates"`
	Tags       []string `json:"tags"`
	Severity   []string `json:"severity"`
	TimeoutSec int      `json:"timeout_sec"`
}

func (k *Kit) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "nuclei_scan":
		return k.scan(ctx, call)
	case "nuclei_status":
		return k.status(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (k *Kit) status(ctx context.Context, _ capkit.Call) (capkit.Result, error) {
	if k.Binaries == nil {
		return capkit.FailResult(capkit.Unavailable("binary manager is not configured")), nil
	}
	st, err := k.Binaries.Status(ctx, "nuclei")
	if err != nil {
		return capkit.FailResult(err), nil
	}
	res, _ := capkit.DataResult(st)
	return res, nil
}

func (k *Kit) scan(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in scanInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	if len(in.Targets) == 0 {
		return capkit.FailResult(capkit.InvalidInput("targets is required")), nil
	}
	if k.Binaries == nil || k.Processes == nil {
		return capkit.FailResult(capkit.Unavailable("nuclei binary/process runner is not configured")), nil
	}
	version := "3.11.1"
	if k.Settings != nil {
		if v, ok := k.Settings.GetString(ctx, "nuclei.version"); ok && strings.TrimSpace(v) != "" {
			version = v
		}
	}
	path, _, err := k.Binaries.Ensure(ctx, "nuclei", version)
	if err != nil {
		return capkit.FailResult(err), nil
	}
	timeout := time.Duration(in.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}

	targets, err := capkit.TargetsFromStrings(call.Context.ProjectID, in.Targets)
	if err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	var hits []any
	var rawLines []string
	for i, raw := range in.Targets {
		args := []string{"-u", raw, "-jsonl", "-silent", "-no-color"}
		for _, t := range in.Templates {
			args = append(args, "-t", t)
		}
		if len(in.Tags) > 0 {
			args = append(args, "-tags", strings.Join(in.Tags, ","))
		}
		if len(in.Severity) > 0 {
			args = append(args, "-severity", strings.Join(in.Severity, ","))
		}
		proc, err := k.Processes.Run(ctx, capkit.ProcessSpec{
			Path: path, Args: args, Timeout: timeout, Targets: []capkit.Target{targets[i]},
			RateLimit: capkit.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 1},
		})
		if err != nil {
			return capkit.FailResult(err), nil
		}
		rawLines = append(rawLines, string(proc.Stdout))
		hits = append(hits, parseJSONL(proc.Stdout)...)
		if proc.ExitCode != 0 {
			return capkit.FailResult(capkit.NewError(capkit.CodeInternal,
				fmt.Sprintf("nuclei exited %d: %s", proc.ExitCode, truncate(string(proc.Stderr), 500)))), nil
		}
	}
	out := map[string]any{
		"hits": hits, "hit_count": len(hits), "target_count": len(in.Targets),
		"raw_lines": len(strings.Split(strings.TrimSpace(strings.Join(rawLines, "\n")), "\n")),
	}
	result, _ := capkit.DataResult(out)
	if k.Evidence != nil {
		id, err := k.Evidence.Record(ctx, capkit.Evidence{
			Kind: "nuclei", Title: fmt.Sprintf("nuclei scan (%d targets)", len(in.Targets)),
			Data: json.RawMessage(mustJSON(out)), CreatedAt: time.Now(),
		})
		if err == nil && id != "" {
			result.EvidenceIDs = []string{id}
		}
	}
	return result, nil
}

func parseJSONL(data []byte) []any {
	var out []any
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
