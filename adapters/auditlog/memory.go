package auditlog

import (
	"context"
	"sync"

	"github.com/c1ayooo/capkit"
)

// Memory is an in-memory AuditSink for tests and examples.
type Memory struct {
	mu     sync.Mutex
	events []capkit.AuditEvent
}

func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Record(_ context.Context, ev capkit.AuditEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *Memory) Events() []capkit.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]capkit.AuditEvent, len(m.events))
	copy(out, m.events)
	return out
}
