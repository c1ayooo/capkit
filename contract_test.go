package capkit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/all"
)

// registeredSpecs returns every tool spec across the full registry, so the
// contract invariants are checked against real declarations, not fixtures.
func registeredSpecs(t *testing.T) []capkit.ToolSpec {
	t.Helper()
	reg := capkit.NewRegistry()
	if err := all.RegisterFull(reg); err != nil {
		t.Fatalf("RegisterFull: %v", err)
	}
	var out []capkit.ToolSpec
	for _, spec := range reg.Specs() {
		for _, tool := range spec.Manifest.Tools {
			// give each tool a unique owner so duplicates surface as test failures
			out = append(out, tool)
		}
	}
	return out
}

// TestEveryToolHasValidSchemas is the §8 gate: each registered tool declares a
// non-empty, valid JSON Schema for both input and output.
func TestEveryToolHasValidSchemas(t *testing.T) {
	specs := registeredSpecs(t)
	if len(specs) == 0 {
		t.Fatal("no tools registered")
	}
	seen := map[string]bool{}
	for _, tool := range specs {
		if seen[tool.Name] {
			t.Fatalf("duplicate tool name across kits: %s", tool.Name)
		}
		seen[tool.Name] = true
		if strings.TrimSpace(tool.Description) == "" {
			t.Errorf("%s: empty description", tool.Name)
		}
		if !tool.Risk.Valid() {
			t.Errorf("%s: invalid risk %q", tool.Name, tool.Risk)
		}
		for label, raw := range map[string]json.RawMessage{
			"input_schema":  tool.InputSchema,
			"output_schema": tool.OutputSchema,
		} {
			if len(raw) == 0 {
				t.Errorf("%s: empty %s", tool.Name, label)
				continue
			}
			var v map[string]any
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Errorf("%s: %s is not valid JSON: %v", tool.Name, label, err)
				continue
			}
			if v["type"] != "object" {
				t.Errorf("%s: %s type = %v, want object", tool.Name, label, v["type"])
			}
		}
	}
}

// TestResultContractFilesExistAndParse verifies the published contract files.
func TestResultContractFilesExistAndParse(t *testing.T) {
	for _, name := range []string{"result.json", "output.json", "tool.json", "target.json"} {
		path := filepath.Join("contracts", name)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s is not valid JSON: %v", path, err)
		}
	}
}

// TestStatusForErrorMapping locks the code->status contract from §5.5.2/§5.5.3.
func TestStatusForErrorMapping(t *testing.T) {
	cases := map[string]capkit.Status{
		capkit.CodeScopeDenied:         capkit.StatusBlocked,
		capkit.CodeApprovalRequired:    capkit.StatusBlocked,
		capkit.CodeRateLimited:         capkit.StatusBlocked,
		capkit.CodeUnavailable:         capkit.StatusUnavailable,
		capkit.CodeToolMissing:         capkit.StatusUnavailable,
		capkit.CodeNeedHuman:           capkit.StatusNeedHuman,
		capkit.CodeTargetUnreachable:   capkit.StatusFailed,
		capkit.CodeTimeout:             capkit.StatusFailed,
		capkit.CodeInvalidInput:        capkit.StatusFailed,
		capkit.CodeInternal:            capkit.StatusFailed,
		capkit.CodeEvidenceWriteFailed: capkit.StatusFailed,
	}
	for code, want := range cases {
		if got := capkit.StatusForError(capkit.NewError(code, "x")); got != want {
			t.Errorf("StatusForError(%s) = %s, want %s", code, got, want)
		}
	}
	// scope_denied must never be retryable: the agent must not loop on it.
	if e := capkit.ScopeDenied("x"); e.Retryable {
		t.Error("scope_denied must not be retryable")
	}
	if e := capkit.NewError(capkit.CodeApprovalRequired, "x"); e.Retryable {
		t.Error("approval_required must not be retryable")
	}
}

// TestSummaryClamp keeps Summary within the agent-readable bound.
func TestSummaryClamp(t *testing.T) {
	long := strings.Repeat("测", 500)
	got := capkit.ClampSummary(long)
	if len([]rune(got)) > capkit.MaxSummaryRunes {
		t.Fatalf("clamped summary = %d runes", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("clamped summary should end with ellipsis: %q", got)
	}
	if capkit.ClampSummary("short") != "short" {
		t.Fatal("short summary must pass through unchanged")
	}
}

// TestFailResultCarriesStatus ensures error atoms map to the right status.
func TestFailResultCarriesStatus(t *testing.T) {
	res := capkit.FailResult(capkit.ScopeDenied("out of scope"))
	if res.Status != capkit.StatusBlocked || res.OK {
		t.Fatalf("status/ok = %s/%v", res.Status, res.OK)
	}
	if res.Summary == "" || res.Error == nil {
		t.Fatal("blocked result needs summary and error")
	}
}
