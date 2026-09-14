package capture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

const (
	DefaultMaxConcurrentConnections = 64
	DefaultMaxHeaderBytes           = 64 << 10
	DefaultMaxBodyBytes             = 16 << 20
	DefaultMaxSessionDuration       = 15 * time.Minute
	DefaultRequestTimeout           = 30 * time.Second
	DefaultReadHeaderTimeout        = 10 * time.Second

	// The local proxy must be bounded even when the browser keeps a connection
	// open indefinitely. The session lifetime is the outer bound; this timeout
	// bounds one request or tunnel operation.
	DefaultTunnelTimeout = 2 * time.Minute
)

var (
	ErrBusy            = errors.New("browser capture capacity is full")
	ErrClosed          = errors.New("browser capture manager is closed")
	ErrNotFound        = errors.New("browser capture session not found")
	ErrBrowserNotFound = errors.New("supported browser executable was not found")
	ErrInvalidBrowser  = errors.New("browser must be edge or chrome")
)

// Browser identifies the browser executable used for the dedicated profile.
type Browser string

const (
	BrowserEdge   Browser = "edge"
	BrowserChrome Browser = "chrome"
)

// Process is the small process lifecycle surface needed by Session. It keeps
// browser-launch tests deterministic without requiring a browser installation.
type Process interface {
	Wait() error
	Kill() error
}

// Launcher starts a browser with the supplied dedicated profile and proxy
// arguments.
type Launcher func(context.Context, string, []string) (Process, error)

// LookupIPFunc and DialContextFunc are injectable only to make local tests
// deterministic. Production uses the operating system resolver and dialer.
type LookupIPFunc func(context.Context, string) ([]net.IP, error)
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Options configures one browser capture. All zero values select bounded
// local defaults.
type Options struct {
	Browser                  Browser
	BrowserPath              string
	MaxConcurrentConnections int
	MaxHeaderBytes           int
	MaxBodyBytes             int64
	MaxSessionDuration       time.Duration
	RequestTimeout           time.Duration
	TunnelTimeout            time.Duration
	Launcher                 Launcher
	LookupIP                 LookupIPFunc
	DialContext              DialContextFunc
	Now                      func() time.Time
}

type normalizedOptions struct {
	Options
	browser Browser
	lookup  LookupIPFunc
	dial    DialContextFunc
	now     func() time.Time
}

func normalizeOptions(opts Options) (normalizedOptions, error) {
	browser := opts.Browser
	if browser == "" {
		browser = BrowserEdge
	}
	if browser != BrowserEdge && browser != BrowserChrome {
		return normalizedOptions{}, ErrInvalidBrowser
	}
	if opts.MaxConcurrentConnections <= 0 {
		opts.MaxConcurrentConnections = DefaultMaxConcurrentConnections
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.MaxSessionDuration <= 0 {
		opts.MaxSessionDuration = DefaultMaxSessionDuration
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = DefaultRequestTimeout
	}
	if opts.TunnelTimeout <= 0 {
		opts.TunnelTimeout = DefaultTunnelTimeout
	}
	lookup := opts.LookupIP
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	dial := opts.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return normalizedOptions{Options: opts, browser: browser, lookup: lookup, dial: dial, now: now}, nil
}

// Snapshot is the live machine-readable state exposed by the UI API. The
// canonical completed projection is available through CanonicalReport.
type Snapshot struct {
	ID                     string                            `json:"id"`
	Browser                Browser                           `json:"browser"`
	State                  model.BrowserCaptureState         `json:"state"`
	ProxyAddress           string                            `json:"proxy_address"`
	StartedAt              time.Time                         `json:"started_at"`
	StoppedAt              *time.Time                        `json:"stopped_at,omitempty"`
	Destinations           []model.BrowserCaptureDestination `json:"destinations"`
	UniqueDestinationCount uint64                            `json:"unique_destination_count"`
	UniqueAddressCount     uint64                            `json:"unique_address_count"`
	ObservationCount       uint64                            `json:"observation_count"`
	FailureCount           uint64                            `json:"failure_count"`
	Error                  string                            `json:"error,omitempty"`
}

type destinationResult struct {
	host                string
	authority           string
	port                uint16
	mechanism           model.BrowserCaptureMechanism
	resolvedCandidates  []string
	connectedEndpoint   string
	connectedAddress    string
	outcome             model.BrowserCaptureOutcome
	failureReason       string
	connectionAttempted bool
}

type destinationAccumulator struct {
	value model.BrowserCaptureDestination
}

// Session owns one loopback listener, one temporary browser profile, and all
// in-memory destination observations for that browser workflow.
type Session struct {
	mu             sync.RWMutex
	id             string
	opts           normalizedOptions
	ctx            context.Context
	cancel         context.CancelFunc
	listener       net.Listener
	server         *http.Server
	proxyAddress   string
	profileDir     string
	process        Process
	processDone    chan struct{}
	processErr     error
	serverDone     chan struct{}
	state          model.BrowserCaptureState
	startedAt      time.Time
	stoppedAt      *time.Time
	lastError      string
	destinations   map[string]*destinationAccumulator
	active         map[net.Conn]struct{}
	connectionGate chan struct{}
	stopOnce       sync.Once
	stopDone       chan struct{}
	onStop         func()
}

// Start creates a loopback-only capture session and launches the selected
// browser with a temporary profile and explicit proxy configuration.
func Start(ctx context.Context, id string, opts Options) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := normalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(id) == "" {
		id = newID()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for browser capture: %w", err)
	}
	profileDir, err := os.MkdirTemp("", "tadori-browser-capture-")
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("create browser profile: %w", err)
	}
	baseCtx, cancel := context.WithCancel(ctx)
	s := &Session{
		id:             id,
		opts:           normalized,
		ctx:            baseCtx,
		cancel:         cancel,
		listener:       listener,
		proxyAddress:   listener.Addr().String(),
		profileDir:     profileDir,
		processDone:    make(chan struct{}),
		serverDone:     make(chan struct{}),
		stopDone:       make(chan struct{}),
		state:          model.BrowserCaptureStateStarting,
		startedAt:      normalized.now().UTC(),
		destinations:   make(map[string]*destinationAccumulator),
		active:         make(map[net.Conn]struct{}),
		connectionGate: make(chan struct{}, normalized.MaxConcurrentConnections),
	}
	s.server = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       normalized.RequestTimeout,
		WriteTimeout:      normalized.RequestTimeout,
		MaxHeaderBytes:    normalized.MaxHeaderBytes,
	}
	go s.serve()

	browserPath := normalized.BrowserPath
	if browserPath == "" {
		browserPath, err = FindBrowser(normalized.browser)
		if err != nil {
			_ = s.shutdownStartup()
			return nil, err
		}
	}
	launcher := normalized.Launcher
	if launcher == nil {
		launcher = defaultLauncher
	}
	args := BrowserArguments(normalized.browser, profileDir, s.proxyAddress)
	process, err := launcher(baseCtx, browserPath, args)
	if err != nil {
		_ = s.shutdownStartup()
		return nil, fmt.Errorf("launch %s: %w", normalized.browser, err)
	}
	s.mu.Lock()
	s.process = process
	s.state = model.BrowserCaptureStateRunning
	s.mu.Unlock()
	go s.waitForProcess(process)
	go func() {
		timer := time.NewTimer(normalized.MaxSessionDuration)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.Stop()
		case <-s.ctx.Done():
		}
	}()
	return s, nil
}

func (s *Session) serve() {
	err := s.server.Serve(s.listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.mu.Lock()
		if s.state == model.BrowserCaptureStateRunning {
			s.lastError = err.Error()
			s.state = model.BrowserCaptureStateFailed
		}
		s.mu.Unlock()
	}
	close(s.serverDone)
}

func (s *Session) waitForProcess(process Process) {
	err := process.Wait()
	s.mu.Lock()
	s.processErr = err
	close(s.processDone)
	s.mu.Unlock()
}

func (s *Session) shutdownStartup() error {
	s.cancel()
	_ = s.server.Close()
	select {
	case <-s.serverDone:
	case <-time.After(2 * time.Second):
	}
	_ = os.RemoveAll(s.profileDir)
	return nil
}

// Stop tears down the browser process, proxy listener, active tunnels, and
// temporary profile. It is idempotent and returns the final live snapshot.
func (s *Session) Stop() Snapshot {
	s.stopOnce.Do(func() {
		go s.stop()
	})
	<-s.stopDone
	return s.Snapshot()
}

func (s *Session) stop() {
	s.mu.Lock()
	if s.state != model.BrowserCaptureStateCompleted && s.state != model.BrowserCaptureStateFailed && s.state != model.BrowserCaptureStateCancelled {
		s.state = model.BrowserCaptureStateStopping
	}
	process := s.process
	s.cancel()
	listener := s.listener
	server := s.server
	active := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		active = append(active, conn)
	}
	s.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if server != nil {
		_ = server.Close()
	}
	for _, conn := range active {
		_ = conn.Close()
	}
	if process != nil {
		_ = process.Kill()
		select {
		case <-s.processDone:
		case <-time.After(2 * time.Second):
		}
	}
	select {
	case <-s.serverDone:
	case <-time.After(2 * time.Second):
	}
	_ = os.RemoveAll(s.profileDir)

	now := s.opts.now().UTC()
	s.mu.Lock()
	s.stoppedAt = &now
	if s.state == model.BrowserCaptureStateStopping || s.state == model.BrowserCaptureStateStarting || s.state == model.BrowserCaptureStateRunning {
		if s.ctx.Err() != nil && s.state == model.BrowserCaptureStateStopping {
			s.state = model.BrowserCaptureStateCompleted
		} else {
			s.state = model.BrowserCaptureStateCompleted
		}
	}
	onStop := s.onStop
	s.onStop = nil
	close(s.stopDone)
	s.mu.Unlock()
	if onStop != nil {
		onStop()
	}
}

func (s *Session) setOnStop(callback func()) {
	s.mu.Lock()
	stopped := s.stoppedAt != nil
	if !stopped {
		s.onStop = callback
	}
	s.mu.Unlock()
	if stopped && callback != nil {
		callback()
	}
}

// Snapshot returns a detached point-in-time view of the session.
func (s *Session) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	observation := s.observationLocked()
	return Snapshot{
		ID:                     s.id,
		Browser:                s.opts.browser,
		State:                  s.state,
		ProxyAddress:           s.proxyAddress,
		StartedAt:              s.startedAt,
		StoppedAt:              cloneTime(s.stoppedAt),
		Destinations:           observation.Destinations,
		UniqueDestinationCount: observation.UniqueDestinationCount,
		UniqueAddressCount:     observation.UniqueAddressCount,
		ObservationCount:       observation.ObservationCount,
		FailureCount:           observation.FailureCount,
		Error:                  s.lastError,
	}
}

// CanonicalReport returns a detached report under the shared observations
// envelope. It is suitable for JSON export while the session is running or
// after it has completed.
func (s *Session) CanonicalReport() model.BrowserCaptureReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	observation := s.observationLocked()
	return model.BrowserCaptureReport{
		SchemaVersion: model.BrowserCaptureSchemaVersion,
		SessionID:     s.id,
		Browser:       string(s.opts.browser),
		State:         s.state,
		StartedAt:     s.startedAt,
		StoppedAt:     cloneTime(s.stoppedAt),
		Observations:  model.Observations{BrowserCapture: &observation},
	}
}

func (s *Session) observationLocked() model.BrowserCaptureObservation {
	destinations := make([]model.BrowserCaptureDestination, 0, len(s.destinations))
	uniqueAddresses := make(map[string]struct{})
	var observationCount, failureCount uint64
	for _, accumulator := range s.destinations {
		value := accumulator.value
		destinations = append(destinations, value)
		observationCount += value.ObservationCount
		failureCount += value.FailureCount
		for _, address := range value.ResolvedAddressCandidates {
			uniqueAddresses[address] = struct{}{}
		}
		for _, address := range value.ConnectedEndpoints {
			host, _, err := net.SplitHostPort(address)
			if err == nil {
				uniqueAddresses[host] = struct{}{}
			} else if address != "" {
				uniqueAddresses[address] = struct{}{}
			}
		}
	}
	sort.Slice(destinations, func(i, j int) bool {
		if destinations[i].RequestedHostname != destinations[j].RequestedHostname {
			return destinations[i].RequestedHostname < destinations[j].RequestedHostname
		}
		if destinations[i].Port != destinations[j].Port {
			return destinations[i].Port < destinations[j].Port
		}
		return destinations[i].Mechanism < destinations[j].Mechanism
	})
	return model.BrowserCaptureObservation{
		SessionID:              s.id,
		Browser:                string(s.opts.browser),
		State:                  s.state,
		ProxyAddress:           s.proxyAddress,
		StartedAt:              s.startedAt,
		StoppedAt:              cloneTime(s.stoppedAt),
		Destinations:           destinations,
		UniqueDestinationCount: uint64(len(destinations)),
		UniqueAddressCount:     uint64(len(uniqueAddresses)),
		ObservationCount:       observationCount,
		FailureCount:           failureCount,
		Limitations: []string{
			"HTTPS is represented by CONNECT authority; TLS payloads are not decrypted.",
			"Only destination metadata, timestamps, outcomes, counts, and provenance are retained.",
			"Capture reflects the dedicated browser profile through its explicit proxy; DoH, QUIC, bypass rules, and browser background traffic can affect coverage.",
		},
		Error: s.lastError,
	}
}

func (s *Session) record(result destinationResult, observedAt time.Time) {
	if result.host == "" || result.port == 0 {
		return
	}
	key := destinationKey(result.host, result.port)
	s.mu.Lock()
	defer s.mu.Unlock()
	accumulator := s.destinations[key]
	if accumulator == nil {
		accumulator = &destinationAccumulator{value: model.BrowserCaptureDestination{
			RequestedHostname:  result.host,
			RequestedAuthority: result.authority,
			Port:               result.port,
			Mechanism:          result.mechanism,
			FirstSeen:          observedAt.UTC(),
			Provenance:         "browser_capture",
		}}
		s.destinations[key] = accumulator
	}
	value := &accumulator.value
	value.LastSeen = observedAt.UTC()
	value.ObservationCount++
	if value.Mechanism == "" {
		value.Mechanism = result.mechanism
	}
	appendUniqueMechanism(&value.Mechanisms, result.mechanism)
	for _, candidate := range result.resolvedCandidates {
		appendUnique(&value.ResolvedAddressCandidates, candidate)
	}
	if result.connectionAttempted {
		value.ConnectionCount++
	}
	if result.connectedEndpoint != "" {
		appendUnique(&value.ConnectedEndpoints, result.connectedEndpoint)
		value.ConnectedEndpoint = result.connectedEndpoint
		value.ConnectedAddress = result.connectedAddress
	}
	if result.failureReason != "" {
		appendUnique(&value.FailureReasons, result.failureReason)
		if value.FailureReason == "" {
			value.FailureReason = result.failureReason
		}
		if len(value.FailureReasons) >= maxFailureReasons {
			value.FailureReasons = value.FailureReasons[:maxFailureReasons]
		}
		value.FailureCount++
	} else {
		value.SuccessCount++
	}
	if value.SuccessCount > 0 && value.FailureCount > 0 {
		value.Outcome = model.BrowserCaptureOutcomeMixed
	} else if value.SuccessCount > 0 {
		value.Outcome = model.BrowserCaptureOutcomeConnected
	} else {
		value.Outcome = result.outcome
	}
}

func appendUnique(values *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func appendUniqueMechanism(values *[]model.BrowserCaptureMechanism, value model.BrowserCaptureMechanism) {
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func destinationKey(host string, port uint16) string {
	return strings.ToLower(host) + ":" + fmt.Sprint(port)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func newID() string {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return "capture-" + hex.EncodeToString(bytes[:])
	}
	return fmt.Sprintf("capture-%d", time.Now().UnixNano())
}

func defaultLauncher(ctx context.Context, path string, args []string) (Process, error) {
	command := exec.CommandContext(ctx, path, args...)
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &commandProcess{command: command}, nil
}

type commandProcess struct {
	command *exec.Cmd
}

func (process *commandProcess) Wait() error {
	return process.command.Wait()
}

func (process *commandProcess) Kill() error {
	if process.command.Process == nil {
		return nil
	}
	return process.command.Process.Kill()
}

// FindBrowser resolves the platform's conventional Edge or Chrome executable.
func FindBrowser(browser Browser) (string, error) {
	if browser != BrowserEdge && browser != BrowserChrome {
		return "", ErrInvalidBrowser
	}
	candidates := browserCandidates(browser, runtime.GOOS)
	for _, candidate := range candidates {
		if strings.ContainsRune(candidate, os.PathSeparator) {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("%w: install Microsoft Edge or Google Chrome, or configure a browser path", ErrBrowserNotFound)
}

func browserCandidates(browser Browser, operatingSystem string) []string {
	if browser == BrowserEdge {
		switch operatingSystem {
		case "windows":
			return appendWindowsCandidates([]string{"msedge.exe", "msedge"}, "Microsoft", "Edge", "msedge.exe")
		case "darwin":
			return []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "microsoft-edge"}
		default:
			return []string{"microsoft-edge", "microsoft-edge-stable", "msedge"}
		}
	}
	switch operatingSystem {
	case "windows":
		return appendWindowsCandidates([]string{"chrome.exe", "chrome"}, "Google", "Chrome", "chrome.exe")
	case "darwin":
		return []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome"}
	default:
		return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
	}
}

func appendWindowsCandidates(candidates []string, vendor, product, executable string) []string {
	roots := []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")}
	for _, root := range roots {
		if root == "" {
			continue
		}
		candidates = append(candidates, filepath.Join(root, vendor, product, "Application", executable))
	}
	return candidates
}

// BrowserArguments returns the explicit profile/proxy arguments used for a
// launched browser. Proxy bounds are enforced by the local capture server.
func BrowserArguments(browser Browser, profileDir string, proxyAddress string) []string {
	proxyURL := "http://" + proxyAddress
	args := []string{
		"--user-data-dir=" + profileDir,
		"--proxy-server=" + proxyURL,
		"--proxy-bypass-list=<-loopback>",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-quic",
		"about:blank",
	}
	if browser == BrowserChrome || browser == BrowserEdge {
		return args
	}
	return nil
}
