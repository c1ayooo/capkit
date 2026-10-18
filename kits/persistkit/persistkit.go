// Package persistkit covers persistence placement (docs §4.8, phase P3).
//
// It is deliberately split into three tools so a destructive-ish action is
// never a single call:
//
//	persist_enum   read-only: what persistence already exists on the target
//	persist_plan   builds the exact steps for one technique; executes nothing
//	persist_apply  runs a plan through the session (high risk, needs confirm)
//
// The *mechanism* (cron line, systemd unit, Run key, ...) is built inside this
// library; the *payload* it invokes is host-provided and stays outside it
// ("识别与决策在库内，成品载荷在库外", docs §6). Nothing here downloads or
// builds an implant.
//
// Everything runs THROUGH a capkit.Session resolved from capkit.Deps.Sessions,
// so a SSH, WinRM, WebShell or CLI foothold is used identically.
package persistkit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

const (
	kitName    = "persistkit"
	kitVersion = "0.1.0"
	apiVersion = "v1"

	defaultTimeout = 20 * time.Second
	maxTimeout     = 2 * time.Minute
	perCmdTimeout  = 10 * time.Second
)

// Capability exposes the persistence tools. It depends only on the injected
// capkit.Deps, never on a concrete transport or a sibling kit.
type Capability struct {
	deps capkit.Deps
}

// NewCapability builds the persistence capability.
func NewCapability(deps capkit.Deps) (capkit.Capability, error) {
	return &Capability{deps: deps}, nil
}

// Manifest declares the persistence tool surface.
func Manifest() capkit.Manifest {
	return capkit.Manifest{
		Name: kitName, Version: kitVersion, APIVersion: apiVersion,
		Requires: []string{"scope", "limiter", "audit", "sessions"},
		Tools: []capkit.ToolSpec{
			enumSpec(),
			planSpec(),
			applySpec(),
		},
	}
}

// Manifest implements capkit.Capability.
func (c *Capability) Manifest() capkit.Manifest { return Manifest() }

// Call dispatches the persistence tools.
func (c *Capability) Call(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	switch call.Tool {
	case "persist_enum":
		return c.enum(ctx, call)
	case "persist_plan":
		return c.plan(ctx, call)
	case "persist_apply":
		return c.apply(ctx, call)
	default:
		return capkit.FailResult(capkit.NotFound("unknown tool: " + call.Tool)), nil
	}
}

// ---- session helper ----

func (c *Capability) session(id string) (capkit.Session, *capkit.Error) {
	if c.deps.Sessions == nil {
		return nil, capkit.ToolMissing("SessionManager 未注入（宿主需提供 capkit.Deps.Sessions）")
	}
	if strings.TrimSpace(id) == "" {
		return nil, capkit.InvalidInput("session_id 必填")
	}
	s, ok := c.deps.Sessions.Get(id)
	if !ok {
		return nil, capkit.NotFound("会话不存在: " + id)
	}
	return s, nil
}

func (c *Capability) run(ctx context.Context, s capkit.Session, cmd string, timeout time.Duration) (capkit.Output, bool) {
	out, err := s.Exec(ctx, cmd, capkit.ExecOpts{Timeout: timeout, MaxOutput: 128 << 10})
	if err != nil {
		return capkit.Output{Command: cmd}, false
	}
	return out, true
}

// detectPlatform resolves the session platform, probing with `uname -s` when
// Info().OS is unset.
func detectPlatform(ctx context.Context, c *Capability, s capkit.Session, to time.Duration) string {
	if os := strings.ToLower(strings.TrimSpace(s.Info().OS)); os != "" {
		if strings.Contains(os, "win") {
			return "windows"
		}
		return "linux"
	}
	if out, ok := c.run(ctx, s, "uname -s", to); ok && strings.TrimSpace(out.Stdout) != "" {
		return "linux"
	}
	return "windows"
}

// enumResult is one inspection command's outcome.
type enumResult struct {
	Label    string `json:"label"`
	Command  string `json:"command"`
	Output   string `json:"output,omitempty"`
	ExitCode int    `json:"exit_code"`
	OK       bool   `json:"ok"`
}

// ---- inputs ----

type planInput struct {
	SessionID string `json:"session_id"`
	Platform  string `json:"platform"` // auto | linux | windows
	Technique string `json:"technique"`
	// Payload is what the persistence mechanism invokes (a command or a path).
	// It is host-provided; persistkit never builds or downloads it.
	Payload   string `json:"payload"`
	Name      string `json:"name"`
	User      string `json:"user"`
	Schedule  string `json:"schedule"`
	PublicKey string `json:"public_key"`
	Path      string `json:"path"`
	TimeoutMS int    `json:"timeout_ms"`
	Confirm   bool   `json:"confirm"`
}

func (in *planInput) validate() *capkit.Error {
	if strings.TrimSpace(in.Technique) == "" {
		return capkit.InvalidInput("technique 必填")
	}
	t, ok := techniques[strings.ToLower(strings.TrimSpace(in.Technique))]
	if !ok {
		return capkit.InvalidInput("未知 technique: " + in.Technique)
	}
	if t.needsPayload() && strings.TrimSpace(in.Payload) == "" {
		return capkit.InvalidInput("technique " + t.ID + " 需要 payload（宿主提供的命令或路径）")
	}
	if t.ID == "linux-ssh-key" && strings.TrimSpace(in.PublicKey) == "" {
		return capkit.InvalidInput("linux-ssh-key 需要 public_key")
	}
	if strings.TrimSpace(in.Name) != "" && strings.ContainsAny(in.Name, "\n\r") {
		return capkit.InvalidInput("name 不能含换行")
	}
	return nil
}

// ---- tool specs ----

func enumSpec() capkit.ToolSpec {
	return capkit.ToolSpec{
		Name:        "persist_enum",
		Description: "只读枚举会话目标（Linux/Windows）上已存在的权限维持点：cron、systemd 单元、authorized_keys、.bashrc、ld.so.preload、PAM（Linux）；计划任务、服务、Run 注册表、WMI 订阅、COM 劫持（Windows）。不修改任何东西。",
		Risk:        capkit.RiskLow,
		RateLimit:   capkit.RateLimitSpec{PerSecond: 2, Burst: 2, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"],"description":"默认 auto，按 session.Info().OS 判定"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string"},
    "commands":{"type":"array","items":{"type":"object"}},
    "signals":{"type":"object"}
  }
}`),
	}
}

func planSpec() capkit.ToolSpec {
	return capkit.ToolSpec{
		Name:        "persist_plan",
		Description: "为选定技术生成精确的落地步骤（命令、产物内容、回滚步骤、目标路径），不执行任何修改。平台支持 linux（cron、systemd、ssh-key、bashrc、ldpreload、pam）与 windows（schtasks、service、registry-run、wmi-subscription、com-hijack）。payload 由宿主提供，库内不生成载荷。",
		Risk:        capkit.RiskMedium,
		RateLimit:   capkit.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 2},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "technique":{"type":"string","description":"见描述中的技术清单"},
    "payload":{"type":"string","description":"维持点执行的命令或路径（宿主提供）"},
    "name":{"type":"string","description":"单元/任务/注册表值名称"},
    "user":{"type":"string"},
    "schedule":{"type":"string","description":"cron 表达式或 schtasks 间隔"},
    "public_key":{"type":"string","description":"linux-ssh-key 的公钥内容"},
    "path":{"type":"string","description":"产物落盘路径覆盖（可选）"}
  },
  "required":["session_id","technique"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "technique":{"type":"string"},
    "platform":{"type":"string"},
    "steps":{"type":"array","items":{"type":"object"}},
    "revert":{"type":"array","items":{"type":"object"}},
    "artifact_path":{"type":"string"}
  }
}`),
	}
}

func applySpec() capkit.ToolSpec {
	return capkit.ToolSpec{
		Name:        "persist_apply",
		Description: "在会话目标上执行 persist_plan 生成的步骤。高风险：runtime 会强制审批与范围校验；要求显式 confirm=true。返回每步的 exit_code 与输出。",
		Risk:        capkit.RiskHigh,
		RateLimit:   capkit.RateLimitSpec{PerSecond: 1, Burst: 1, Concurrency: 1},
		InputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "session_id":{"type":"string"},
    "platform":{"type":"string","enum":["auto","linux","windows"]},
    "technique":{"type":"string"},
    "payload":{"type":"string"},
    "name":{"type":"string"},
    "user":{"type":"string"},
    "schedule":{"type":"string"},
    "public_key":{"type":"string"},
    "path":{"type":"string"},
    "confirm":{"type":"boolean","description":"必须为 true；否则返回 need_human"},
    "timeout_ms":{"type":"integer"}
  },
  "required":["session_id","technique","confirm"]
}`),
		OutputSchema: json.RawMessage(`{
  "type":"object",
  "properties":{
    "technique":{"type":"string"},
    "platform":{"type":"string"},
    "applied":{"type":"boolean"},
    "steps":{"type":"array","items":{"type":"object"}}
  }
}`),
	}
}

// ---- handlers ----

func (c *Capability) enum(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in struct {
		SessionID string `json:"session_id"`
		Platform  string `json:"platform"`
		TimeoutMS int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return capkit.FailResult(e), nil
	}
	to := capkit.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, to)
	}
	cmds := enumCommands(platform)
	if len(cmds) == 0 {
		return capkit.FailResult(capkit.InvalidInput("不支持的平台: " + platform)), nil
	}
	outs := make([]enumResult, 0, len(cmds))
	var raws []capkit.Output
	fail := 0
	for _, cm := range cmds {
		o, ok := c.run(ctx, s, cm.Command, perCmdTimeout)
		if !ok {
			fail++
		}
		raws = append(raws, o)
		outs = append(outs, enumResult{Label: cm.Label, Command: cm.Command, Output: capkit.Truncate(o.Stdout, 4096), ExitCode: o.ExitCode, OK: ok})
	}
	signals := buildSignals(platform, outs2map(outs))
	status := capkit.StatusSuccess
	summary := fmt.Sprintf("%s 平台枚举 %d 项维持点命令", platform, len(cmds))
	if fail > 0 {
		status = capkit.StatusPartial
		summary = fmt.Sprintf("枚举完成：%d/%d 命令失败（多因目标无该组件或权限不足）", fail, len(cmds))
	}
	data, _ := capkit.DataResult(map[string]any{
		"session_id": in.SessionID, "platform": platform,
		"commands": outs, "signals": signals,
	})
	data.Status = status
	data.OK = status == capkit.StatusSuccess
	data.Summary = capkit.ClampSummary(summary)
	data.Evidence = capkit.EvidenceRefs(raws...)
	return data, nil
}

func (c *Capability) plan(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in planInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return capkit.FailResult(e), nil
	}
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, capkit.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout))
	}
	in.Platform = platform
	pl, e := buildPlan(in)
	if e != nil {
		return capkit.FailResult(e), nil
	}
	res, _ := capkit.SuccessResult(fmt.Sprintf("已生成 %s 落地计划（%d 步，未执行）", pl.Technique, len(pl.Steps)), pl)
	res.Next = []capkit.NextStep{{
		Tool:          "persist_apply",
		Reason:        "如需落地该维持点，用 confirm=true 执行本计划；高风险动作需人工审批",
		Risk:          capkit.RiskHigh,
		Preconditions: []string{"session." + pl.Technique, "approval.granted"},
	}}
	return res, nil
}

func (c *Capability) apply(ctx context.Context, call capkit.Call) (capkit.Result, error) {
	var in planInput
	if err := json.Unmarshal(call.Input, &in); err != nil {
		return capkit.FailResult(capkit.InvalidInput(err.Error())), nil
	}
	s, e := c.session(in.SessionID)
	if e != nil {
		return capkit.FailResult(e), nil
	}
	if !in.Confirm {
		return capkit.FailResult(capkit.NeedHuman("persist_apply 需要 confirm=true（高风险维持动作，须人工确认）")), nil
	}
	platform := strings.ToLower(strings.TrimSpace(in.Platform))
	if platform == "" || platform == "auto" {
		platform = detectPlatform(ctx, c, s, capkit.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout))
	}
	in.Platform = platform
	pl, e := buildPlan(in)
	if e != nil {
		return capkit.FailResult(e), nil
	}
	to := capkit.TimeoutFromMS(in.TimeoutMS, defaultTimeout, maxTimeout)
	type stepOut struct {
		Command  string `json:"command"`
		ExitCode int    `json:"exit_code"`
		Stdout   string `json:"stdout,omitempty"`
		Stderr   string `json:"stderr,omitempty"`
		OK       bool   `json:"ok"`
	}
	results := make([]stepOut, 0, len(pl.Steps))
	var raws []capkit.Output
	failed := 0
	for _, step := range pl.Steps {
		o, ok := c.run(ctx, s, step.Command, to)
		if !ok || o.ExitCode != 0 {
			failed++
		}
		raws = append(raws, o)
		results = append(results, stepOut{Command: step.Command, ExitCode: o.ExitCode, Stdout: capkit.Truncate(o.Stdout, 2048), Stderr: capkit.Truncate(o.Stderr, 2048), OK: ok && o.ExitCode == 0})
	}
	status := capkit.StatusSuccess
	summary := fmt.Sprintf("已落地 %s（%d 步）", pl.Technique, len(pl.Steps))
	if failed > 0 {
		status = capkit.StatusPartial
		summary = fmt.Sprintf("落地 %s：%d/%d 步失败", pl.Technique, failed, len(pl.Steps))
	}
	data, _ := capkit.DataResult(map[string]any{
		"technique": pl.Technique, "platform": platform,
		"applied": failed == 0, "steps": results,
	})
	data.Status = status
	data.OK = status == capkit.StatusSuccess
	data.Summary = capkit.ClampSummary(summary)
	data.Evidence = capkit.EvidenceRefs(raws...)
	if failed == 0 {
		data.Findings = []capkit.Finding{{
			Target:      sessionTarget(s),
			Kind:        "persistence:" + pl.Technique,
			Confirmed:   true,
			Fingerprint: "persist|" + pl.Technique + "|" + s.Info().Host,
			Source:      "persistkit",
		}}
		data.Next = []capkit.NextStep{{
			Tool:   "persist_enum",
			Reason: "复验维持点是否生效，并纳入清理清单",
			Risk:   capkit.RiskLow,
		}}
	}
	return data, nil
}

func outs2map(outs []enumResult) map[string]string {
	m := map[string]string{}
	for _, o := range outs {
		m[o.Label] = o.Output
	}
	return m
}

func sessionTarget(s capkit.Session) capkit.Target {
	if t, err := capkit.TargetFromString(0, s.Info().Host); err == nil {
		return t
	}
	return capkit.Target{}
}
