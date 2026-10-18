package playbookkit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// Capability exposes deterministic playbook execution as an agent tool. Scripts
// live in the host; this tool loads and runs one by ID, enforcing scope per
// step and returning a structured verdict.
type Capability struct {
	deps capkit.Deps
}

// NewCapability builds the playbook capability.
func NewCapability(deps capkit.Deps) (capkit.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the playbook tools.
func Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: "playbookkit", Version: "0.2.0", APIVersion: "v1",
		Requires: []string{"scope", "limiter", "audit", "http"},
		Tools: []capkit.ToolSpec{
			{
				Name:        "playbook_run",
				Description: "确定性执行一条剧本：步骤严格串行、断言失败即停、重定向限同 host。按 ID 加载预设或按 path 加载宿主脚本，返回 verdict/evidence。host 变量必填，scope 每步校验。",
				Risk:        capkit.RiskHigh,
				RateLimit:   capkit.RateLimitSpec{PerSecond: 2, Burst: 1, Concurrency: 1},
				InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "id":{"type":"string","description":"预设剧本 ID"},
    "path":{"type":"string","description":"宿主脚本路径（与 id 二选一）"},
    "vars":{"type":"object","description":"渲染变量，host 必填"},
    "base_url":{"type":"string"},
    "timeout_ms":{"type":"integer"}
  }
}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "verdict":{"type":"string"},
    "reason":{"type":"string"},
    "steps":{"type":"array","items":{"type":"object"}},
    "requests":{"type":"integer"}
  }
}`),
				ExtractTargets: func(input json.RawMessage) ([]capkit.Target, error) {
					var in struct {
						Vars map[string]string `json:"vars"`
					}
					if err := json.Unmarshal(input, &in); err != nil {
						return nil, err
					}
					host := strings.TrimSpace(in.Vars["host"])
					if host == "" {
						return nil, fmt.Errorf("vars.host 必填")
					}
					t, err := capkit.TargetFromString(0, host)
					if err != nil {
						return nil, err
					}
					return []capkit.Target{t}, nil
				},
			},
			{
				Name:        "playbook_list",
				Description: "列出已加载的内置预设剧本（ID/名称/描述/所需变量）。只读，不执行。",
				Risk:        capkit.RiskLow,
				InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
				OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{"count":{"type":"integer"},"playbooks":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"requires_vars":{"type":"array","items":{"type":"string"}}}}}}
}`),
			},
		},
	}
}

// Manifest implements capkit.Capability.
func (c *Capability) Manifest() capkit.Manifest { return Manifest() }

// Call dispatches the playbook tools.
func (c *Capability) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "playbook_run":
		return c.run(ctx, call)
	case "playbook_list":
		return c.list(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

func (c *Capability) list(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	presets, errs := EmbeddedPresets()
	if len(errs) > 0 && len(presets) == 0 {
		return capkit.FailResult(capkit.Unavailable(fmt.Sprintf("%d 个预设剧本加载失败", len(errs)))), nil
	}
	out := make([]map[string]any, 0, len(presets))
	for id, pb := range presets {
		out = append(out, map[string]any{
			"id": id, "name": pb.Name, "description": pb.Note, "requires_vars": pb.VarsRequired,
		})
	}
	res, _ := capkit.SuccessResult(fmt.Sprintf("已加载 %d 条预设剧本", len(out)), map[string]any{
		"count": len(out), "playbooks": out,
	})
	if len(errs) > 0 {
		res.Summary = capkit.ClampSummary(res.Summary + "（有 " + fmt.Sprintf("%d", len(errs)) + " 个解析错误）")
	}
	return res, nil
}

func (c *Capability) run(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in struct {
		ID        string            `json:"id"`
		Path      string            `json:"path"`
		Vars      map[string]string `json:"vars"`
		BaseURL   string            `json:"base_url"`
		TimeoutMS int               `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	var pb *Playbook
	var loadErr error
	switch {
	case strings.TrimSpace(in.ID) != "":
		presets, perrs := EmbeddedPresets()
		found, ok := presets[in.ID]
		switch {
		case ok:
			pb = found
		default:
			loadErr = fmt.Errorf("未知剧本 ID: %s", in.ID)
		}
		_ = perrs
	case strings.TrimSpace(in.Path) != "":
		raw, rerr := os.ReadFile(in.Path)
		if rerr != nil {
			return capkit.FailResult(capkit.InvalidInput("读取剧本失败: " + rerr.Error())), nil
		}
		pb, loadErr = LoadPlaybookFromBytes(raw)
	default:
		return capkit.FailResult(capkit.InvalidInput("id 或 path 必填其一")), nil
	}
	if loadErr != nil {
		return capkit.FailResult(capkit.InvalidInput(loadErr.Error())), nil
	}
	opts := RunOptions{
		Vars:    in.Vars,
		BaseURL: in.BaseURL,
		Scope:   c.deps.Scope,
		Timeout: time.Duration(in.TimeoutMS) * time.Millisecond,
	}
	rr, err := Run(ctx, pb, opts)
	if err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	res, _ := capkit.DataResult(rr)
	res.Summary = capkit.ClampSummary("剧本 " + pb.ID + " 结论 " + rr.Verdict + "：" + rr.Reason)
	return res, nil
}
