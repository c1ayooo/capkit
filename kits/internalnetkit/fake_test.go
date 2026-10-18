package internalnetkit

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/c1ayooo/capkit"
)

// This file provides the fake Session and fake SessionManager the tests drive.
// Nothing here touches the real network: every command returns a canned output
// scripted by the test, so the whole suite is hermetic.

var (
	_ capkit.Session        = (*scriptedSession)(nil)
	_ capkit.SessionManager = (*fakeManager)(nil)
)

// rule maps a command (matched by substring, first match wins) to an output.
type rule struct {
	match      string
	stdout     string
	stderr     string
	exit       int
	evidenceID string
	err        error
}

// scriptedSession is a capkit.Session that answers from a rule table. It is
// safe for concurrent Exec calls, matching the Session contract.
type scriptedSession struct {
	info  capkit.SessionInfo
	rules []rule

	mu     sync.Mutex
	calls  []string
	closed bool
}

func (s *scriptedSession) Exec(_ context.Context, cmd string, _ capkit.ExecOpts) (capkit.Output, error) {
	s.mu.Lock()
	s.calls = append(s.calls, cmd)
	rules := s.rules
	s.mu.Unlock()
	for _, r := range rules {
		if strings.Contains(cmd, r.match) {
			if r.err != nil {
				return capkit.Output{Command: cmd}, r.err
			}
			return capkit.Output{
				Command: cmd, Stdout: r.stdout, Stderr: r.stderr,
				ExitCode: r.exit, EvidenceID: r.evidenceID,
			}, nil
		}
	}
	return capkit.Output{Command: cmd, ExitCode: 0}, nil
}

func (s *scriptedSession) Info() capkit.SessionInfo { return s.info }

func (s *scriptedSession) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *scriptedSession) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// fakeManager is a capkit.SessionManager backed by an in-memory map.
type fakeManager struct {
	sessions map[string]capkit.Session
	infos    map[string]capkit.SessionInfo
}

func newFakeManager() *fakeManager {
	return &fakeManager{sessions: map[string]capkit.Session{}, infos: map[string]capkit.SessionInfo{}}
}

func (m *fakeManager) add(s *scriptedSession) {
	m.sessions[s.info.ID] = s
	m.infos[s.info.ID] = s.info
}

func (m *fakeManager) Open(context.Context, capkit.SessionSpec) (capkit.SessionInfo, error) {
	return capkit.SessionInfo{}, errors.New("not implemented")
}

func (m *fakeManager) Get(id string) (capkit.Session, bool) {
	s, ok := m.sessions[id]
	return s, ok
}

func (m *fakeManager) List() []capkit.SessionInfo {
	out := make([]capkit.SessionInfo, 0, len(m.infos))
	for _, i := range m.infos {
		out = append(out, i)
	}
	return out
}

func (m *fakeManager) Close(id string) error {
	delete(m.sessions, id)
	delete(m.infos, id)
	return nil
}

// capWith builds a capability wired to the given manager, or a bare one when
// manager is nil (the missing-port path).
func capWith(manager capkit.SessionManager) *Capability {
	c, err := NewCapability(capkit.Deps{Sessions: manager})
	if err != nil {
		panic(err)
	}
	return c.(*Capability)
}
