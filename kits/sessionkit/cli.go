package sessionkit

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/c1ayooo/capkit"
)

// CLIOpener runs commands as a local process through the host's ProcessRunner
// port. It is the reference adapter: it needs no credentials and no network, so
// it makes the Session contract testable end to end and is useful for local
// agent-side tasks.
//
// Routing through ProcessRunner (never os/exec) keeps the "kits never spawn a
// subprocess themselves" boundary intact (docs §6.4): the host decides whether
// local execution is gated, audited and sandboxed. A host that wants a fully
// gated local transport passes adapters/exec.New(scope, limiter, audit); one
// that only needs host-side local commands passes adapters/exec.NewLocal().
type CLIOpener struct {
	// Runner is required: CLIOpener holds no execution path of its own.
	Runner capkit.ProcessRunner
	// AllowedCommands, when non-empty, restricts the first token of every
	// command. Empty means unrestricted (host's responsibility).
	AllowedCommands []string
	// DefaultShell overrides the detected shell interpreter.
	DefaultShell string
}

// Open returns a CLI session. spec.Host is ignored; "local" is conventional.
func (o *CLIOpener) Open(_ context.Context, spec capkit.SessionSpec) (capkit.Session, error) {
	if o.Runner == nil {
		return nil, capkit.Unavailable("cli opener requires a process runner")
	}
	info := capkit.SessionInfo{
		Kind: "cli", Host: capkit.FirstNonEmpty(spec.Host, "local"),
		OS: osName(), Arch: runtime.GOARCH, Labels: spec.Labels,
		Meta: map[string]string{"cwd": capkit.FirstNonEmpty(cwd(), "")},
	}
	if u := hostUser(); u != "" {
		info.User = u
		info.Meta["user"] = u
	}
	if isElevated() {
		info.Elevated = true
	}
	return &CLISession{info: info, allowed: o.AllowedCommands, shell: o.DefaultShell, runner: o.Runner}, nil
}

// CLISession is a local-process Session.
type CLISession struct {
	info    capkit.SessionInfo
	allowed []string
	shell   string
	runner  capkit.ProcessRunner
}

func (s *CLISession) Info() capkit.SessionInfo { return s.info }

func (s *CLISession) Close() error { return nil }

func (s *CLISession) Exec(ctx context.Context, cmd string, opts capkit.ExecOpts) (capkit.Output, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return capkit.Output{}, fmt.Errorf("命令为空")
	}
	if len(s.allowed) > 0 {
		first := strings.Fields(cmd)
		if len(first) == 0 || !containsStr(s.allowed, first[0]) {
			return capkit.Output{}, fmt.Errorf("命令 %q 不在白名单内", first)
		}
	}
	shell := opts.Shell
	if shell == "" {
		shell = s.shell
	}
	if shell == "" {
		shell = "sh"
	}
	args := []string{"-c", cmd}
	if opts.TTY {
		args = []string{"-i", "-c", cmd}
	}
	spec := capkit.ProcessSpec{
		Path:    shell,
		Args:    args,
		Dir:     capkit.FirstNonEmpty(opts.Dir, s.info.Meta["cwd"]),
		Env:     envList(opts.Env),
		Stdin:   opts.Stdin,
		Timeout: opts.Timeout,
	}
	started := time.Now()
	pr, err := s.runner.Run(ctx, spec)
	dur := time.Since(started)
	if err != nil {
		return capkit.OutputFor(cmd, "", err.Error(), -1, dur, opts.MaxOutput), err
	}
	return capkit.OutputFor(cmd, string(pr.Stdout), string(pr.Stderr), pr.ExitCode, dur, opts.MaxOutput), nil
}

// envList renders extra environment entries. The runner owns the base
// environment; a session only contributes its overrides.
func envList(extra map[string]string) []string {
	if len(extra) == 0 {
		return nil
	}
	out := make([]string, 0, len(extra))
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

func osName() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return runtime.GOOS
	}
}

func hostUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

func cwd() string {
	d, err := os.Getwd()
	if err != nil {
		return ""
	}
	return d
}

func isElevated() bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return false
	}
	return os.Geteuid() == 0
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
