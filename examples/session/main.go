// Command session demonstrates the Session contract end to end: a
// sessionkit.Manager tracks live sessions, the CLI opener supplies a real
// (local) transport, and shellkit's session tools drive it through the same
// contract SSH/WinRM/WebShell use. Every session is closed at the end.
//
// Run: go run ./examples/session
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"

	"github.com/c1ayooo/capkit/adapters/auditlog"
	execport "github.com/c1ayooo/capkit/adapters/exec"
	"github.com/c1ayooo/capkit/adapters/settings"
	"github.com/c1ayooo/capkit/core"
	"github.com/c1ayooo/capkit/gates"
	"github.com/c1ayooo/capkit/kits/sessionkit"
	"github.com/c1ayooo/capkit/kits/shellkit"
	"github.com/c1ayooo/capkit/runtime"
)

func main() {
	if _, err := exec.LookPath("sh"); err != nil {
		log.Fatalf("this example needs a POSIX shell in PATH: %v", err)
	}

	// The host owns the SessionManager and chooses which openers exist. Here
	// only the local CLI transport is registered; a real deployment adds
	// "ssh"/"webshell"/"winrm" openers with host-injected credentials. Local
	// shells run through the ProcessRunner port, so the shared audit sink sees
	// them like any other host-side process.
	audit := auditlog.NewMemory()
	manager := sessionkit.NewManager(nil, nil)
	manager.RegisterOpener("cli", &sessionkit.CLIOpener{Runner: execport.NewLocal(audit), AllowedCommands: []string{"echo", "uname", "id"}})

	scope := gates.StaticScope("local")
	reg := core.NewRegistry()
	if err := reg.Add(core.Spec{Manifest: shellkit.Manifest(), New: shellkit.NewCapability}); err != nil {
		log.Fatal(err)
	}

	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: gates.NewLimiter(),
		Audit: audit, Settings: settings.New(nil), Sessions: manager,
	}, reg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = manager.CloseAll() }()

	ctx := context.Background()
	cc := core.CallContext{ProjectID: 1, Actor: "example"}

	// 1. Open a session.
	openIn, _ := json.Marshal(map[string]any{"kind": "cli", "host": "local", "timeout_ms": 5000})
	opened, err := rt.Call(ctx, "session_open", openIn, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("== session_open ==")
	fmt.Println("status:", opened.Status, "| summary:", opened.Summary)
	printJSON(opened.Data)
	if opened.Status != core.StatusSuccess {
		log.Fatalf("session_open did not succeed: %s", opened.Error.Message)
	}
	var openData struct {
		SessionID string `json:"session_id"`
	}
	_ = json.Unmarshal(opened.Data, &openData)
	if openData.SessionID == "" {
		log.Fatal("session_open returned no session_id")
	}

	// 2. Run a command inside it.
	execIn, _ := json.Marshal(map[string]any{"session_id": openData.SessionID, "command": "echo hello-from-capkit"})
	ran, err := rt.Call(ctx, "session_exec", execIn, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n== session_exec ==")
	fmt.Println("status:", ran.Status, "| summary:", ran.Summary)
	fmt.Println("meta.tool:", ran.Meta.Tool, "duration_ms:", ran.Meta.DurationMS, "gate_trace:", ran.Meta.GateTrace)
	printJSON(ran.Data)

	// 3. List live sessions.
	listed, err := rt.Call(ctx, "session_list", json.RawMessage(`{}`), cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n== session_list ==")
	fmt.Println("status:", listed.Status, "| summary:", listed.Summary)

	// 4. Close it. Closing again is idempotent by contract.
	closeIn, _ := json.Marshal(map[string]any{"session_id": openData.SessionID})
	closed, err := rt.Call(ctx, "session_close", closeIn, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\n== session_close ==")
	fmt.Println("status:", closed.Status, "| summary:", closed.Summary)
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
