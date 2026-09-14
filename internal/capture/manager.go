package capture

import (
	"context"
	"sort"
	"sync"

	"github.com/yohnark/tadori/internal/model"
)

// Manager keeps capture sessions process-local and bounds the number of
// browser processes/proxies a local UI can create at once.
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	released map[string]bool
	capacity chan struct{}
	closed   bool
	options  Options
	newID    func() string
}

// ManagerOptions configures a capture manager.
type ManagerOptions struct {
	Capture               Options
	MaxConcurrentSessions int
	NewID                 func() string
}

// NewManager creates a bounded in-memory capture manager.
func NewManager(opts ManagerOptions) *Manager {
	maxConcurrent := opts.MaxConcurrentSessions
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	newIDFunc := opts.NewID
	if newIDFunc == nil {
		newIDFunc = newID
	}
	return &Manager{
		sessions: make(map[string]*Session),
		released: make(map[string]bool),
		capacity: make(chan struct{}, maxConcurrent),
		options:  opts.Capture,
		newID:    newIDFunc,
	}
}

// Start starts a browser capture with the requested browser. Empty browser
// selects the configured/default Edge browser.
func (m *Manager) Start(ctx context.Context, browser Browser) (Snapshot, error) {
	select {
	case m.capacity <- struct{}{}:
	default:
		return Snapshot{}, ErrBusy
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		<-m.capacity
		return Snapshot{}, ErrClosed
	}
	id := m.newID()
	opts := m.options
	if browser != "" {
		opts.Browser = browser
	}
	m.mu.Unlock()

	session, err := Start(ctx, id, opts)
	if err != nil {
		<-m.capacity
		return Snapshot{}, err
	}
	session.setOnStop(func() { m.release(id) })
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		session.Stop()
		return Snapshot{}, ErrClosed
	}
	m.sessions[id] = session
	m.mu.Unlock()
	return session.Snapshot(), nil
}

// Get returns a live session snapshot.
func (m *Manager) Get(id string) (Snapshot, error) {
	session, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	return session.Snapshot(), nil
}

// Report returns the canonical browser-capture report projection.
func (m *Manager) Report(id string) (model.BrowserCaptureReport, error) {
	session, err := m.lookup(id)
	if err != nil {
		return model.BrowserCaptureReport{}, err
	}
	return session.CanonicalReport(), nil
}

// FQDNs returns the deterministic sorted set of observed requested hostnames.
// It is intentionally hostname-only: no wildcard or broader policy scope is
// inferred from the observed names.
func (m *Manager) FQDNs(id string) ([]string, error) {
	session, err := m.lookup(id)
	if err != nil {
		return nil, err
	}
	snapshot := session.Snapshot()
	seen := make(map[string]struct{}, len(snapshot.Destinations))
	for _, destination := range snapshot.Destinations {
		if destination.RequestedHostname != "" {
			seen[destination.RequestedHostname] = struct{}{}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

// Stop terminates a capture session and returns its final snapshot.
func (m *Manager) Stop(id string) (Snapshot, error) {
	session, err := m.lookup(id)
	if err != nil {
		return Snapshot{}, err
	}
	return session.Stop(), nil
}

// Close stops all sessions and rejects future starts.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		session.Stop()
	}
}

func (m *Manager) lookup(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return session, nil
}

func (m *Manager) release(id string) {
	m.mu.Lock()
	if m.released[id] {
		m.mu.Unlock()
		return
	}
	m.released[id] = true
	m.mu.Unlock()
	<-m.capacity
}
