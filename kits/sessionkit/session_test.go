package sessionkit_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/adapters/exec"
	"github.com/c1ayooo/capkit/kits/sessionkit"
	"golang.org/x/crypto/ssh"
)

// ---- fake session exercises the contract shape ----

type fakeSession struct {
	info   capkit.SessionInfo
	closed bool
	last   string
}

func (f *fakeSession) Exec(_ context.Context, cmd string, _ capkit.ExecOpts) (capkit.Output, error) {
	f.last = cmd
	return capkit.Output{Command: cmd, Stdout: "ok:" + cmd, ExitCode: 0}, nil
}
func (f *fakeSession) Info() capkit.SessionInfo { return f.info }
func (f *fakeSession) Close() error             { f.closed = true; return nil }

type fakeOpener struct{ s *fakeSession }

func (o fakeOpener) Open(context.Context, capkit.SessionSpec) (capkit.Session, error) {
	return o.s, nil
}

// Compile-time proof that the manager satisfies the host port.
var _ capkit.SessionManager = (*sessionkit.Manager)(nil)

func TestManagerOpenGetListClose(t *testing.T) {
	m := sessionkit.NewManager(nil, nil)
	s := &fakeSession{info: capkit.SessionInfo{ID: "s1", Kind: "fake", Host: "10.0.0.1"}}
	m.RegisterOpener("fake", fakeOpener{s: s})

	info, err := m.Open(context.Background(), capkit.SessionSpec{Kind: "fake", Host: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == "" || info.Host != "10.0.0.1" {
		t.Fatalf("info = %+v", info)
	}
	got, ok := m.Get(info.ID)
	if !ok {
		t.Fatal("session not tracked")
	}
	out, err := got.Exec(context.Background(), "id", capkit.ExecOpts{})
	if err != nil || !strings.Contains(out.Stdout, "id") {
		t.Fatalf("exec = %+v, %v", out, err)
	}
	if len(m.List()) != 1 {
		t.Fatalf("list = %d", len(m.List()))
	}
	if err := m.Close(info.ID); err != nil {
		t.Fatal(err)
	}
	if !s.closed {
		t.Fatal("Close was not propagated to the session")
	}
	// Closing an unknown id is idempotent (agents retry).
	if err := m.Close("nope"); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
}

func TestManagerUnknownKind(t *testing.T) {
	m := sessionkit.NewManager(nil, nil)
	if _, err := m.Open(context.Background(), capkit.SessionSpec{Kind: "winrm", Host: "h"}); err == nil {
		t.Fatal("expected missing opener error")
	}
	if _, err := m.Open(context.Background(), capkit.SessionSpec{Kind: "", Host: "h"}); err == nil {
		t.Fatal("expected kind-required error")
	}
	if _, err := m.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: ""}); err == nil {
		t.Fatal("expected host-required error")
	}
}

func TestManagerCloseAll(t *testing.T) {
	m := sessionkit.NewManager(nil, nil)
	a := &fakeSession{info: capkit.SessionInfo{ID: "a"}}
	b := &fakeSession{info: capkit.SessionInfo{ID: "b"}}
	m.RegisterOpener("x", fakeOpener{s: a})
	m.RegisterOpener("y", fakeOpener{s: b})
	_, _ = m.Open(context.Background(), capkit.SessionSpec{Kind: "x", Host: "h1"})
	_, _ = m.Open(context.Background(), capkit.SessionSpec{Kind: "y", Host: "h2"})
	if err := m.CloseAll(); err != nil {
		t.Fatal(err)
	}
	if !a.closed || !b.closed {
		t.Fatal("CloseAll must close every session")
	}
	if len(m.List()) != 0 {
		t.Fatalf("list after CloseAll = %d", len(m.List()))
	}
}

// ---- CLI adapter: real local execution ----

func TestCLIOpenerRequiresRunner(t *testing.T) {
	o := &sessionkit.CLIOpener{}
	if _, err := o.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: "local"}); err == nil {
		t.Fatal("a CLI opener with no process runner must fail closed")
	}
}

func TestCLISessionExec(t *testing.T) {
	o := &sessionkit.CLIOpener{Runner: exec.NewLocal(nil)}
	m := sessionkit.NewManager(nil, nil)
	m.RegisterOpener("cli", o)
	info, err := m.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: "local"})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := m.Get(info.ID)
	out, err := s.Exec(context.Background(), "echo sessionkit-ok", capkit.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Stdout, "sessionkit-ok") {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	if out.DurationMS < 0 {
		t.Fatal("duration must be set")
	}
	if !info.Elevated && info.OS == "" {
		t.Fatal("info must carry OS")
	}
}

func TestCLISessionNonZeroExit(t *testing.T) {
	o := &sessionkit.CLIOpener{Runner: exec.NewLocal(nil)}
	s, err := o.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: "local"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Exec(context.Background(), "exit 3", capkit.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", out.ExitCode)
	}
}

func TestCLISessionAllowList(t *testing.T) {
	o := &sessionkit.CLIOpener{Runner: exec.NewLocal(nil), AllowedCommands: []string{"echo"}}
	s, _ := o.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: "local"})
	if _, err := s.Exec(context.Background(), "id", capkit.ExecOpts{}); err == nil {
		t.Fatal("expected allowlist rejection")
	}
	if _, err := s.Exec(context.Background(), "echo hi", capkit.ExecOpts{}); err != nil {
		t.Fatalf("allowed command rejected: %v", err)
	}
	if _, err := s.Exec(context.Background(), "  ", capkit.ExecOpts{}); err == nil {
		t.Fatal("empty command must be rejected")
	}
}

func TestCLISessionMaxOutput(t *testing.T) {
	o := &sessionkit.CLIOpener{Runner: exec.NewLocal(nil)}
	s, _ := o.Open(context.Background(), capkit.SessionSpec{Kind: "cli", Host: "local"})
	out, err := s.Exec(context.Background(), "printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", capkit.ExecOpts{MaxOutput: 8})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || len(out.Stdout) > 8 {
		t.Fatalf("truncation = %v len=%d", out.Truncated, len(out.Stdout))
	}
}

// ---- SSH adapter against an in-process SSH server ----

func startSSHServer(t *testing.T, password string) (addr string, cleanup func()) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == password {
				return nil, nil
			}
			return nil, io.ErrUnexpectedEOF
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHConn(conn, cfg)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveSSHConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			_ = newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				switch req.Type {
				case "exec":
					cmd := ""
					if len(req.Payload) >= 4 {
						n := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
						if 4+n <= len(req.Payload) {
							cmd = string(req.Payload[4 : 4+n])
						}
					}
					req.Reply(true, nil)
					// Drain stdin so a real Upload does not block, then echo
					// what we received back as the command output.
					if _, err := io.Copy(io.Discard, ch); err != nil {
						_ = err
					}
					_, _ = ch.Write([]byte("SSH-EXEC:" + cmd))
					_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					_ = ch.Close()
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}

func TestSSHSessionExec(t *testing.T) {
	addr, cleanup := startSSHServer(t, "pw")
	defer cleanup()
	host, portStr, _ := net.SplitHostPort(addr)

	m := sessionkit.NewManager(nil, nil)
	m.RegisterOpener("ssh", &sessionkit.SSHOwner{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	info, err := m.Open(ctx, capkit.SessionSpec{Kind: "ssh", Host: host, Port: port, User: "u", Secret: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "ssh" || info.Host != host {
		t.Fatalf("info = %+v", info)
	}
	s, _ := m.Get(info.ID)
	out, err := s.Exec(ctx, "whoami", capkit.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Stdout, "SSH-EXEC:whoami") {
		t.Fatalf("stdout = %q", out.Stdout)
	}

	// Uploader capability is present on the SSH session.
	up, ok := s.(capkit.Uploader)
	if !ok {
		t.Fatal("SSH session must implement Uploader")
	}
	if err := up.Upload(ctx, bytes.NewReader([]byte("data")), "/tmp/x"); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if _, ok := s.(capkit.Tunneler); !ok {
		t.Fatal("SSH session must implement Tunneler")
	}
	_ = m.Close(info.ID)
}

func TestSSHBadPassword(t *testing.T) {
	addr, cleanup := startSSHServer(t, "pw")
	defer cleanup()
	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	m := sessionkit.NewManager(nil, nil)
	m.RegisterOpener("ssh", &sessionkit.SSHOwner{})
	_, err = m.Open(context.Background(), capkit.SessionSpec{Kind: "ssh", Host: host, Port: port, User: "u", Secret: "wrong"})
	if err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestSSHMissingSecret(t *testing.T) {
	o := &sessionkit.SSHOwner{}
	_, err := o.Open(context.Background(), capkit.SessionSpec{Kind: "ssh", Host: "127.0.0.1", Port: 1, User: "u"})
	if err == nil || !strings.Contains(err.Error(), "密码或私钥") {
		t.Fatalf("err = %v", err)
	}
}
