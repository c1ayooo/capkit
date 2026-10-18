package session_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/c1ayooo/capkit"
	"github.com/c1ayooo/capkit/kits/shellkit/session"
)

type fakeExec struct {
	last  string
	lastF session.FileOp
}

func (f *fakeExec) Exec(_ context.Context, _ session.Session, cmd string) (*session.ExecResult, error) {
	f.last = cmd
	return &session.ExecResult{Output: "R:" + cmd, HTTPStatus: 200, TrafficID: "ev"}, nil
}

func (f *fakeExec) File(_ context.Context, _ session.Session, op session.FileOp) (*session.ExecResult, error) {
	f.lastF = op
	if op.Action == "read" {
		return &session.ExecResult{Output: "aGVsbG8=", HTTPStatus: 200}, nil // "hello"
	}
	return &session.ExecResult{Output: "ok", HTTPStatus: 200}, nil
}

var _ capkit.Session = (*session.CapabilitySession)(nil)
var _ capkit.Uploader = (*session.CapabilitySession)(nil)
var _ capkit.Downloader = (*session.CapabilitySession)(nil)

func newSession(exec session.Executor) *session.CapabilitySession {
	return &session.CapabilitySession{
		Shell:    session.Session{ID: 7, URL: "http://h/s.php", ShellType: "godzilla", Protocol: "http"},
		Executor: exec,
	}
}

func TestAdapterExec(t *testing.T) {
	f := &fakeExec{}
	s := newSession(f)
	out, err := s.Exec(context.Background(), "id", capkit.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "R:id" || out.ExitCode != 0 {
		t.Fatalf("out = %+v", out)
	}
	if out.EvidenceID != "ev" {
		t.Fatalf("evidence = %q", out.EvidenceID)
	}
	// dir is prepended
	_, _ = s.Exec(context.Background(), "ls", capkit.ExecOpts{Dir: "/tmp"})
	if !strings.HasPrefix(f.last, "cd /tmp &&") {
		t.Fatalf("dir not applied: %q", f.last)
	}
	// empty command rejected
	if _, err := s.Exec(context.Background(), "  ", capkit.ExecOpts{}); err == nil {
		t.Fatal("expected empty-command error")
	}
}

func TestAdapterInfo(t *testing.T) {
	info := newSession(&fakeExec{}).Info()
	if info.Kind != "webshell" {
		t.Fatalf("kind = %q", info.Kind)
	}
	if info.ID != "webshell-7" || info.Host != "h" {
		t.Fatalf("info = %+v", info)
	}
	if info.Meta["shell_type"] != "godzilla" {
		t.Fatalf("meta = %v", info.Meta)
	}
	if err := newSession(&fakeExec{}).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterUpload(t *testing.T) {
	f := &fakeExec{}
	s := newSession(f)
	if err := s.Upload(context.Background(), strings.NewReader("payload"), "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if f.lastF.Action != "write" || f.lastF.Path != "/tmp/x" || string(f.lastF.Content) != "payload" {
		t.Fatalf("file op = %+v", f.lastF)
	}
	if err := s.Upload(context.Background(), strings.NewReader("x"), ""); err == nil {
		t.Fatal("expected empty-path error")
	}
}

func TestAdapterDownload(t *testing.T) {
	s := newSession(&fakeExec{})
	rc, err := s.Download(context.Background(), "/tmp/x")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello" {
		t.Fatalf("body = %q (base64 should be decoded)", body)
	}
}

func TestAdapterNilExecutor(t *testing.T) {
	s := &session.CapabilitySession{}
	if _, err := s.Exec(context.Background(), "id", capkit.ExecOpts{}); err == nil {
		t.Fatal("expected executor-missing error")
	}
	if err := s.Upload(context.Background(), strings.NewReader("x"), "/y"); err == nil {
		t.Fatal("expected executor-missing error")
	}
	if _, err := s.Download(context.Background(), "/y"); err == nil {
		t.Fatal("expected executor-missing error")
	}
}
