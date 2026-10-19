// Command identity-login demonstrates the M2 identity half: the host assembles
// one site login, and the Identity it produces injects its own session cookies
// into every subsequent request.
//
//	identity_login  the agent-facing tool, running the host's registered form flow
//	Identity.Headers()  the host-side path: the cookie jar hands back the session
//	                    cookie without the caller tracking it
//
// It runs against a local in-process target (examples/lab) that binds to
// loopback only. Point it at a real target with
//
//	go run ./examples/identity-login -base http://127.0.0.1:PORT
//
// Nothing in this example reaches the network beyond loopback.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
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
	"github.com/c1ayooo/capkit/kits/identitykit"
	"github.com/c1ayooo/capkit/runtime"
)

func main() {
	base := flag.String("base", "", "target base URL; default: the local in-process lab")
	loginPath := flag.String("login-path", "/login", "form login path")
	userinfoPath := flag.String("userinfo-path", "/private/userinfo", "protected page path")
	username := flag.String("user", "", "username; default: the lab account")
	password := flag.String("password", "", "password; default: the lab account")
	flag.Parse()

	ctx := context.Background()
	cc := core.CallContext{ProjectID: 1, Actor: "identity-login-example"}

	var target, user, pass string
	if *base != "" {
		target = *base
		if *username == "" || *password == "" {
			log.Fatal("-user and -password are required for a real target")
		}
		user, pass = *username, *password
	} else {
		l, err := lab.New()
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		target = l.BaseURL()
		user, pass = l.Credentials()
	}
	loginURL := target + *loginPath
	userinfoURL := target + *userinfoPath
	fmt.Printf("target: %s\nlogin:  %s\n\n", target, loginURL)

	scope := gates.StaticScope(hostOf(target))
	limiter := gates.NewLimiter()
	audit := auditlog.NewMemory()
	httpDoer := httpx.New(scope, limiter, audit)

	// ---- the host assembles the site login (one line) ----
	flows := identitykit.NewAuthFlowRegistry()
	if err := flows.RegisterFormSite(identitykit.FormFlow{
		LoginURL:     loginURL,
		Target:       target,
		HTTP:         httpDoer,
		CSRFRequired: true, // the login page carries a hidden csrf_token
		Scope: core.IdentityScope{
			Hosts: []string{hostOf(target)}, User: user, Label: "example-site",
		},
	}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("registered flow kinds:", flows.Kinds())

	reg := core.NewRegistry()
	if err := all.RegisterIdentity(reg, flows); err != nil {
		log.Fatal(err)
	}
	rt, err := runtime.New(runtime.Config{
		Scope: scope, Approval: gates.AutoApprove(), Limiter: limiter, Audit: audit,
		HTTP: httpDoer, Settings: settings.New(nil),
	}, reg)
	if err != nil {
		log.Fatal(err)
	}

	// ---- 1. the agent-facing tool ----
	fmt.Println("\n== 1. identity_login (agent path) ==")
	loginInput, _ := json.Marshal(map[string]any{
		"target": target, "kind": "form", "username": user, "password": pass,
	})
	res, err := rt.Call(ctx, "identity_login", loginInput, cc)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("status:", res.Status, "| summary:", res.Summary)
	if res.Status != core.StatusSuccess {
		fatalf("identity_login failed: %s / %+v", res.Summary, res.Error)
	}
	var out struct {
		User  string   `json:"user"`
		Hosts []string `json:"hosts"`
		Label string   `json:"label"`
	}
	_ = json.Unmarshal(res.Data, &out)
	fmt.Printf("identity: user=%q hosts=%v label=%q\n", out.User, out.Hosts, out.Label)
	// The password must not come back anywhere in the envelope.
	if strings.Contains(res.Summary, pass) || strings.Contains(string(res.Data), pass) {
		fatalf("the password leaked into the tool result")
	}

	// ---- 2. the host path: Identity.Headers() carries the session ----
	fmt.Println("\n== 2. Identity.Headers() -> a protected page (host path) ==")
	flow, ok := flows.Lookup("form")
	if !ok {
		fatalf("form flow vanished from the registry")
	}
	id, err := flow.Login(ctx, core.Credentials{Username: user, Password: pass})
	if err != nil {
		fatalf("host-side login failed: %v", err)
	}
	headers, err := id.Headers(ctx)
	if err != nil {
		fatalf("Identity.Headers: %v", err)
	}
	cookie := headers.Get("Cookie")
	fmt.Println("headers:", headerShape(headers))
	if cookie == "" {
		fatalf("Identity.Headers() did not inject a Cookie header")
	}
	fmt.Println("cookie names:", cookieNames(cookie))

	// The proof that the cookie is the real session: the protected page accepts
	// it. Nothing here passes the cookie explicitly — it comes from Headers().
	probe, err := httpDoer.Do(ctx, core.Request{
		Method: http.MethodGet, URL: userinfoURL,
		Headers: flatten(headers), Timeout: 20 * time.Second,
	})
	if err != nil {
		fatalf("protected request failed: %v", err)
	}
	fmt.Printf("GET %s -> %d %s\n", userinfoURL, probe.Status, strings.TrimSpace(string(probe.Body)))
	if probe.Status != http.StatusOK {
		fatalf("the server did not recognise the injected cookie as a logged-in session (status %d)", probe.Status)
	}

	// ---- 3. the counter-example: no cookie, no access ----
	fmt.Println("\n== 3. control: the same page without the identity ==")
	anon, err := httpDoer.Do(ctx, core.Request{Method: http.MethodGet, URL: userinfoURL, Timeout: 20 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("GET %s (anonymous) -> %d\n", userinfoURL, anon.Status)
	if anon.Status == http.StatusOK {
		fatalf("the protected page answered without a session cookie")
	}

	fmt.Println("\nidentity chain complete: identity_login / Identity.Headers() -> protected page")
}

func headerShape(h http.Header) string {
	parts := make([]string, 0, len(h))
	for k, vs := range h {
		parts = append(parts, fmt.Sprintf("%s: %d value(s)", k, len(vs)))
	}
	return strings.Join(parts, ", ")
}

func cookieNames(cookie string) string {
	var names []string
	for _, pair := range strings.Split(cookie, ";") {
		if name, _, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

func flatten(h http.Header) map[string]string {
	out := map[string]string{}
	for k, vs := range h {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

func fatalf(format string, args ...any) {
	fmt.Printf("FATAL: "+format+"\n", args...)
	os.Exit(1)
}
