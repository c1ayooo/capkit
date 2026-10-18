package nucleikit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// Kind implements capkit.TemplateEngine for kind=nuclei.
func (k *Kit) Kind() string { return "nuclei" }

type engineResult struct {
	ID    string `json:"id"`
	Hits  []any  `json:"hits,omitempty"`
	Error string `json:"error,omitempty"`
}

// Execute writes each template artifact to a temporary file and runs nuclei
// against the single target. Scope/rate/audit are enforced by the injected
// ProcessRunner and the runtime gates.
func (k *Kit) Execute(ctx context.Context, refs []capkit.TemplateRef, target capkit.Target, opts map[string]any) (capkit.Result, error) {
	if k.Binaries == nil || k.Processes == nil {
		return capkit.FailResult(capkit.Unavailable("nuclei binary/process runner is not configured")), nil
	}
	targetURL := strings.TrimSpace(target.URL)
	if targetURL == "" {
		host := target.Host
		if host == "" {
			host = target.IP
		}
		if host == "" {
			return capkit.FailResult(capkit.InvalidInput("target has no URL/host")), nil
		}
		targetURL = "http://" + host
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
	timeout := 120 * time.Second
	if v, ok := opts["timeout_sec"].(float64); ok && v > 0 {
		timeout = time.Duration(v) * time.Second
	}
	results := make([]engineResult, 0, len(refs))
	totalHits := 0
	for _, ref := range refs {
		res := engineResult{ID: ref.ID}
		artifact := ref.Artifact
		if len(artifact) == 0 {
			res.Error = "template artifact is empty"
			results = append(results, res)
			continue
		}
		dir, derr := os.MkdirTemp("", "capkit-nuclei-*")
		if derr != nil {
			res.Error = "temp dir: " + derr.Error()
			results = append(results, res)
			continue
		}
		name := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(ref.ID)
		if name == "" {
			name = "template"
		}
		tplPath := filepath.Join(dir, name+".yaml")
		if werr := os.WriteFile(tplPath, artifact, 0o600); werr != nil {
			_ = os.RemoveAll(dir)
			res.Error = "write template: " + werr.Error()
			results = append(results, res)
			continue
		}
		proc, rerr := k.Processes.Run(ctx, capkit.ProcessSpec{
			Path:    path,
			Args:    []string{"-u", targetURL, "-t", tplPath, "-jsonl", "-silent", "-no-color"},
			Timeout: timeout, Targets: []capkit.Target{target},
			RateLimit: capkit.RateLimitSpec{PerSecond: 5, Burst: 2, Concurrency: 1},
		})
		_ = os.RemoveAll(dir)
		if rerr != nil {
			res.Error = rerr.Error()
			results = append(results, res)
			continue
		}
		res.Hits = parseJSONL(proc.Stdout)
		totalHits += len(res.Hits)
		if proc.ExitCode != 0 {
			res.Error = fmt.Sprintf("nuclei exited %d: %s", proc.ExitCode, truncate(string(proc.Stderr), 300))
		}
		results = append(results, res)
	}
	out, _ := capkit.DataResult(map[string]any{
		"target": target, "results": results, "template_count": len(refs), "hit_count": totalHits,
	})
	return out, nil
}
