// Package lab is a deliberately vulnerable in-process target for the examples.
//
// It exists so `go run ./examples/webshell-chain` can demonstrate the whole
// chain — command injection, shell drop, session takeover — with no Docker and
// no network, and so the same example can be pointed at the real PHP container
// described in STATE.md with just -base/-dir.
//
// It is a fixture, not a product. Every route is intentionally insecure, it
// binds to loopback only, and it must never be exposed or reused as a real
// server. The "PHP" it serves is a toy subset: it recognises the payload
// template's own shape (a pass literal and a cmd parameter) rather than
// interpreting PHP. That is enough to prove the chain moved real bytes to a real
// file, which is what the example is for; the real evidence run uses PHP.
package lab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Lab is a running vulnerable target plus the state its routes share.
type Lab struct {
	// Dir is the writable "web root" the injection point can write into and the
	// fallback handler serves from. A dropped shell lands here.
	Dir string

	Server *httptest.Server

	mu       sync.Mutex
	users    map[string]string // username -> password
	sessions map[string]string // cookie value -> username
	csrf     string
}

// New starts the lab on a loopback port.
func New() (*Lab, error) {
	if _, err := exec.LookPath("sh"); err != nil {
		return nil, fmt.Errorf("the lab runs commands through a POSIX shell: %w", err)
	}
	dir, err := os.MkdirTemp("", "capkit-lab-")
	if err != nil {
		return nil, err
	}
	l := &Lab{
		Dir:      dir,
		users:    map[string]string{"alice": "correct-horse-battery"},
		sessions: map[string]string{},
		csrf:     randomToken(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/exec.php", l.handleCmdInjection)
	mux.HandleFunc("/login", l.handleLogin)
	mux.HandleFunc("/private/userinfo", l.handleUserInfo)
	mux.HandleFunc("/", l.handleDropped)
	l.Server = httptest.NewServer(mux)
	return l, nil
}

// Close stops the server and removes the web root.
func (l *Lab) Close() {
	l.Server.Close()
	_ = os.RemoveAll(l.Dir)
}

// BaseURL is the lab's origin, e.g. http://127.0.0.1:41234.
func (l *Lab) BaseURL() string { return l.Server.URL }

// ShellURL is where a dropped file named name is served.
func (l *Lab) ShellURL(name string) string { return l.Server.URL + "/" + name }

// ---- command injection ----

// handleCmdInjection is the vulnerable endpoint: it concatenates the ip
// parameter into a shell command line, so `1;id` runs id. This is the classic
// shape cmdi_probe looks for, and the primitive webshell_deploy writes through.
func (l *Lab) handleCmdInjection(rw http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	out, _ := exec.Command("sh", "-c", "echo PING "+ip).CombinedOutput() //nolint:gosec // intentionally vulnerable
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = rw.Write(out)
}

// ---- dropped shell ----

// payloadPassRE matches the generated PHP template's pass comparison, and
// payloadCmdRE its cmd parameter name.
var (
	payloadPassRE = regexp.MustCompile(`\$_REQUEST\['pass'\]\s*===\s*'([A-Za-z0-9_]+)'`)
	payloadCmdRE  = regexp.MustCompile(`\$c\s*=\s*\$_REQUEST\['([A-Za-z0-9_]+)'\]`)
)

// handleDropped serves the web root. A file that carries the payload template's
// shape is executed as a shell; anything else is served verbatim.
func (l *Lab) handleDropped(rw http.ResponseWriter, r *http.Request) {
	name := path.Base(r.URL.Path)
	if name == "/" || name == "." || name == "" {
		http.NotFound(rw, r)
		return
	}
	body, err := os.ReadFile(filepath.Join(l.Dir, name))
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	pass := payloadPassRE.FindSubmatch(body)
	if len(pass) != 2 {
		_, _ = rw.Write(body) // a plain file, not a shell
		return
	}
	if r.URL.Query().Get("pass") != string(pass[1]) {
		http.Error(rw, "denied", http.StatusForbidden)
		return
	}
	cmdParam := "cmd"
	if m := payloadCmdRE.FindSubmatch(body); len(m) == 2 {
		cmdParam = string(m[1])
	}
	cmd := r.URL.Query().Get(cmdParam)
	if cmd == "" {
		http.Error(rw, "missing command", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput() //nolint:gosec // intentionally vulnerable
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = rw.Write(out)
}

// ---- login ----

func (l *Lab) handleLogin(rw http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(rw, `<!doctype html><html><body>
<form method="post" action="/login">
<input type="hidden" name="csrf_token" value="%s">
<input name="username"><input name="password" type="password">
<button type="submit">login</button>
</form></body></html>`, l.csrf)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("csrf_token") != l.csrf {
		http.Error(rw, "bad csrf", http.StatusForbidden)
		return
	}
	user := r.PostFormValue("username")
	if l.users[user] == "" || l.users[user] != r.PostFormValue("password") {
		http.Error(rw, "bad credentials", http.StatusUnauthorized)
		return
	}
	sid := randomToken()
	l.mu.Lock()
	l.sessions[sid] = user
	l.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{Name: "labsid", Value: sid, Path: "/"})
	fmt.Fprint(rw, "logged in as "+user)
}

// handleUserInfo is the protected page: it answers only for a valid session
// cookie, which is how the identity example proves Headers() carried it.
func (l *Lab) handleUserInfo(rw http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("labsid")
	if err != nil {
		http.Error(rw, "no session cookie", http.StatusUnauthorized)
		return
	}
	l.mu.Lock()
	user := l.sessions[c.Value]
	l.mu.Unlock()
	if user == "" {
		http.Error(rw, "unknown session", http.StatusUnauthorized)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(rw, `{"authorized":true,"user":%q}`, user)
}

// LoginURL and UserInfoURL are the routes the identity example uses.
func (l *Lab) LoginURL() string    { return l.Server.URL + "/login" }
func (l *Lab) UserInfoURL() string { return l.Server.URL + "/private/userinfo" }

// Credentials are the lab's known-good account.
func (l *Lab) Credentials() (user, password string) { return "alice", "correct-horse-battery" }

// QueryEscape is a convenience for building inject payloads in the example.
func QueryEscape(s string) string { return url.QueryEscape(s) }

func randomToken() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "fallbacktoken"
	}
	return strings.TrimSpace(hex.EncodeToString(b))
}
