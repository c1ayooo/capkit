package containerkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
)

// fakeSession answers each EscapeCheck with a canned verdict line. It embeds the
// exact `"ok <id>"` / `"no <id>"` string its command would print, so matching is
// unambiguous.
type fakeSession struct {
	info     capkit.SessionInfo
	verdicts map[string]string
}

func newFakeSession(info capkit.SessionInfo, hits ...string) *fakeSession {
	hit := map[string]bool{}
	for _, h := range hits {
		hit[h] = true
	}
	verdicts := map[string]string{}
	for _, c := range EscapeChecks {
		if hit[c.ID] {
			verdicts[c.ID] = "ok " + c.ID
		} else {
			verdicts[c.ID] = "no " + c.ID
		}
	}
	return &fakeSession{info: info, verdicts: verdicts}
}

func (f *fakeSession) Exec(_ context.Context, cmd string, _ capkit.ExecOpts) (capkit.Output, error) {
	for id, line := range f.verdicts {
		if strings.Contains(cmd, `"ok `+id+`"`) || strings.Contains(cmd, `"no `+id+`"`) {
			return capkit.Output{Command: cmd, Stdout: line + "\n", ExitCode: 0}, nil
		}
	}
	return capkit.Output{Command: cmd}, nil
}

func (f *fakeSession) Info() capkit.SessionInfo { return f.info }
func (f *fakeSession) Close() error             { return nil }

// fakeManager is a minimal capkit.SessionManager for hermetic tests.
type fakeManager struct {
	sessions map[string]capkit.Session
	infos    []capkit.SessionInfo
}

func newFakeManager() *fakeManager { return &fakeManager{sessions: map[string]capkit.Session{}} }

func (m *fakeManager) add(id string, s capkit.Session) {
	m.sessions[id] = s
	m.infos = append(m.infos, s.Info())
}

func (m *fakeManager) Open(context.Context, capkit.SessionSpec) (capkit.SessionInfo, error) {
	return capkit.SessionInfo{}, nil
}
func (m *fakeManager) Get(id string) (capkit.Session, bool) { s, ok := m.sessions[id]; return s, ok }
func (m *fakeManager) List() []capkit.SessionInfo           { return m.infos }
func (m *fakeManager) Close(string) error                   { return nil }

func escapeSurfaceFromResult(t *testing.T, res capkit.Result) EscapeSurface {
	t.Helper()
	var s EscapeSurface
	if err := json.Unmarshal(res.Data, &s); err != nil {
		t.Fatalf("decode surface: %v (%s)", err, res.Data)
	}
	return s
}

func TestEscapeCheckHits(t *testing.T) {
	mgr := newFakeManager()
	mgr.add("s1", newFakeSession(
		capkit.SessionInfo{ID: "s1", Kind: "ssh", Host: "10.0.0.9", OS: "linux"},
		"docker_sock", "privileged", "cap_sys_admin", "core_pattern_writable", "host_pid_namespace",
	))

	c := newCap(t, capkit.Deps{Sessions: mgr})
	res := doCall(t, c, "container_escape_check", map[string]any{"session_id": "s1"})
	if res.Status != capkit.StatusSuccess {
		t.Fatalf("status = %q (%s)", res.Status, res.Summary)
	}
	s := escapeSurfaceFromResult(t, res)
	if !s.DockerSock || !s.Privileged || !s.CapSysAdmin || !s.CorePatternWritable || !s.HostPID {
		t.Fatalf("surface = %+v", s)
	}
	if s.SessionID != "s1" || s.Host != "10.0.0.9" {
		t.Fatalf("surface meta = %+v", s)
	}
	if s.HitCount() < 5 {
		t.Fatalf("HitCount = %d", s.HitCount())
	}
	if len(res.Findings) < 5 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if res.Findings[0].Source != "containerkit" || res.Findings[0].Fingerprint == "" {
		t.Fatalf("finding = %+v", res.Findings[0])
	}
	if len(res.Next) == 0 {
		t.Fatal("escape hits must suggest container_escape_plan")
	}
	if res.Meta.Tool != "container_escape_check" || res.Meta.Target != "10.0.0.9" {
		t.Fatalf("meta = %+v", res.Meta)
	}
}

func TestEscapeCheckClean(t *testing.T) {
	mgr := newFakeManager()
	mgr.add("s1", newFakeSession(capkit.SessionInfo{ID: "s1", Kind: "ssh", Host: "h"}))

	c := newCap(t, capkit.Deps{Sessions: mgr})
	res := doCall(t, c, "container_escape_check", map[string]any{"session_id": "s1"})
	s := escapeSurfaceFromResult(t, res)
	if s.HitCount() != 0 {
		t.Fatalf("surface = %+v", s)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Next) != 0 {
		t.Fatalf("clean surface must not suggest next steps: %+v", res.Next)
	}
}

func TestEscapeCheckSessionNotFound(t *testing.T) {
	c := newCap(t, capkit.Deps{Sessions: newFakeManager()})
	res := doCall(t, c, "container_escape_check", map[string]any{"session_id": "nope"})
	if res.Status != capkit.StatusFailed || res.Error == nil || res.Error.Code != capkit.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
}

func TestEscapeCheckNoManager(t *testing.T) {
	c := newCap(t, capkit.Deps{})
	res := doCall(t, c, "container_escape_check", map[string]any{"session_id": "s1"})
	if res.Error == nil || res.Error.Code != capkit.CodeToolMissing {
		t.Fatalf("res = %+v", res)
	}
	if res.Status != capkit.StatusUnavailable {
		t.Fatalf("status = %q", res.Status)
	}
}

func TestEscapeCheckMissingSessionID(t *testing.T) {
	c := newCap(t, capkit.Deps{Sessions: newFakeManager()})
	res := doCall(t, c, "container_escape_check", map[string]any{})
	if res.Error == nil || res.Error.Code != capkit.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
}

func TestEscapePlanFromSurface(t *testing.T) {
	surface := EscapeSurface{
		Host: "10.0.0.9", DockerSock: true, Privileged: true,
		CapSysAdmin: true, CapDacReadSearch: true,
	}
	c := newCap(t, capkit.Deps{})
	res := doCall(t, c, "container_escape_plan", map[string]any{"surface": surface})
	data := decodeData(t, res)
	techniques, _ := data["techniques"].([]any)
	if len(techniques) < 4 {
		t.Fatalf("techniques = %v", data["techniques"])
	}
	if len(res.Next) != len(techniques) {
		t.Fatalf("res.Next=%d techniques=%d", len(res.Next), len(techniques))
	}
	if res.Next[0].Tool != "docker_run_privileged" {
		t.Fatalf("first technique = %q (want most reliable primitive first)", res.Next[0].Tool)
	}
	for _, step := range res.Next {
		if step.Reason == "" {
			t.Fatalf("technique without reason: %+v", step)
		}
		if !step.Risk.AtLeast(capkit.RiskMedium) {
			t.Fatalf("technique risk too low: %+v", step)
		}
	}
}

func TestEscapePlanDacReadSearchOnly(t *testing.T) {
	c := newCap(t, capkit.Deps{})
	res := doCall(t, c, "container_escape_plan", map[string]any{
		"surface": EscapeSurface{CapDacReadSearch: true},
	})
	found := false
	for _, step := range res.Next {
		if step.Tool == "open_by_handle_at" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected open_by_handle_at, got %+v", res.Next)
	}
}

func TestEscapePlanFromSession(t *testing.T) {
	mgr := newFakeManager()
	mgr.add("s1", newFakeSession(capkit.SessionInfo{ID: "s1", Host: "h"}, "privileged"))
	c := newCap(t, capkit.Deps{Sessions: mgr})
	res := doCall(t, c, "container_escape_plan", map[string]any{"session_id": "s1"})
	if len(res.Next) == 0 {
		t.Fatal("privileged surface must yield techniques")
	}
	// The plan nests the surface under data.surface.
	var wrapper struct {
		Surface EscapeSurface `json:"surface"`
	}
	if err := json.Unmarshal(res.Data, &wrapper); err != nil {
		t.Fatalf("decode plan data: %v", err)
	}
	if !wrapper.Surface.Privileged {
		t.Fatalf("surface = %+v", wrapper.Surface)
	}
}

func TestEscapePlanSessionNotFound(t *testing.T) {
	c := newCap(t, capkit.Deps{Sessions: newFakeManager()})
	res := doCall(t, c, "container_escape_plan", map[string]any{"session_id": "nope"})
	if res.Error == nil || res.Error.Code != capkit.CodeNotFound {
		t.Fatalf("res = %+v", res)
	}
}

func TestEscapePlanInvalidInput(t *testing.T) {
	c := newCap(t, capkit.Deps{Sessions: newFakeManager()})
	res := doCall(t, c, "container_escape_plan", map[string]any{})
	if res.Error == nil || res.Error.Code != capkit.CodeInvalidInput {
		t.Fatalf("res = %+v", res)
	}
}

func TestEscapePlanEmptySurface(t *testing.T) {
	c := newCap(t, capkit.Deps{})
	res := doCall(t, c, "container_escape_plan", map[string]any{"surface": EscapeSurface{}})
	if len(res.Next) != 0 {
		t.Fatalf("empty surface must yield no techniques: %+v", res.Next)
	}
	if res.Summary == "" {
		t.Fatal("summary must be set")
	}
}

func TestEscapePlanCgroupWhenPrivileged(t *testing.T) {
	c := newCap(t, capkit.Deps{})
	res := doCall(t, c, "container_escape_plan", map[string]any{
		"surface": EscapeSurface{Privileged: true},
	})
	want := map[string]bool{"cgroup_release_agent": false, "core_pattern": false}
	for _, step := range res.Next {
		if _, ok := want[step.Tool]; ok {
			want[step.Tool] = true
		}
	}
	for tool, seen := range want {
		if !seen {
			t.Fatalf("privileged surface missing %s: %+v", tool, res.Next)
		}
	}
}
