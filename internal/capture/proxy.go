package capture

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yohnark/tadori/internal/model"
)

const (
	maxResolvedCandidates = 32
	maxFailureReasons     = 16
)

var proxyHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (s *Session) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case s.connectionGate <- struct{}{}:
		defer func() { <-s.connectionGate }()
	case <-s.ctx.Done():
		http.Error(w, "browser capture is stopping", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(s.ctx, s.opts.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxBodyBytes)
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Session) handleConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.RequestURI
	}
	host, port, err := parseProxyAuthority(authority, 443)
	if err != nil {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	candidates, err := s.resolve(r.Context(), host)
	if err != nil {
		s.record(destinationResult{
			host:          host,
			authority:     authority,
			port:          port,
			mechanism:     model.BrowserCaptureMechanismCONNECT,
			outcome:       model.BrowserCaptureOutcomeDNSFailed,
			failureReason: "name_resolution_failed",
		}, s.opts.now())
		http.Error(w, "could not resolve CONNECT destination", http.StatusBadGateway)
		return
	}
	upstream, endpoint, err := s.dial(r.Context(), candidates, port)
	if err != nil {
		s.record(destinationResult{
			host:                host,
			authority:           authority,
			port:                port,
			mechanism:           model.BrowserCaptureMechanismCONNECT,
			resolvedCandidates:  candidates,
			outcome:             model.BrowserCaptureOutcomeFailed,
			failureReason:       "upstream_connection_failed",
			connectionAttempted: true,
		}, s.opts.now())
		http.Error(w, "could not connect to destination", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		s.record(destinationResult{
			host:                host,
			authority:           authority,
			port:                port,
			mechanism:           model.BrowserCaptureMechanismCONNECT,
			resolvedCandidates:  candidates,
			connectedEndpoint:   endpoint,
			connectedAddress:    endpointHost(endpoint),
			outcome:             model.BrowserCaptureOutcomeProxyRejected,
			failureReason:       "proxy_hijack_unsupported",
			connectionAttempted: true,
		}, s.opts.now())
		http.Error(w, "CONNECT is not supported by this server", http.StatusNotImplemented)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		s.record(destinationResult{
			host:                host,
			authority:           authority,
			port:                port,
			mechanism:           model.BrowserCaptureMechanismCONNECT,
			resolvedCandidates:  candidates,
			connectedEndpoint:   endpoint,
			connectedAddress:    endpointHost(endpoint),
			outcome:             model.BrowserCaptureOutcomeProxyRejected,
			failureReason:       "proxy_hijack_failed",
			connectionAttempted: true,
		}, s.opts.now())
		return
	}

	s.track(client)
	s.track(upstream)
	s.record(destinationResult{
		host:                host,
		authority:           authority,
		port:                port,
		mechanism:           model.BrowserCaptureMechanismCONNECT,
		resolvedCandidates:  candidates,
		connectedEndpoint:   endpoint,
		connectedAddress:    endpointHost(endpoint),
		outcome:             model.BrowserCaptureOutcomeConnected,
		connectionAttempted: true,
	}, s.opts.now())

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		s.untrack(client)
		s.untrack(upstream)
		return
	}
	if err := buffered.Flush(); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		s.untrack(client)
		s.untrack(upstream)
		return
	}
	s.tunnel(client, buffered.Reader, upstream)
}

func (s *Session) handleHTTP(w http.ResponseWriter, r *http.Request) {
	authority := r.URL.Host
	if authority == "" {
		authority = r.Host
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host, port, err := parseProxyAuthority(authority, defaultPort(scheme))
	if err != nil {
		http.Error(w, "invalid proxy destination", http.StatusBadRequest)
		return
	}
	base := destinationResult{
		host:      host,
		authority: authority,
		port:      port,
		mechanism: model.BrowserCaptureMechanismHTTP,
		outcome:   model.BrowserCaptureOutcomeUnknown,
	}
	if scheme != "http" {
		base.outcome = model.BrowserCaptureOutcomeUnsupported
		base.failureReason = "unsupported_proxy_scheme"
		s.record(base, s.opts.now())
		http.Error(w, "HTTPS must use CONNECT through the capture proxy", http.StatusNotImplemented)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		base.outcome = model.BrowserCaptureOutcomeUnsupported
		base.failureReason = "websocket_upgrade_not_supported"
		s.record(base, s.opts.now())
		http.Error(w, "websocket upgrades are not supported by this capture lane; use CONNECT", http.StatusNotImplemented)
		return
	}
	candidates, err := s.resolve(r.Context(), host)
	if err != nil {
		base.resolvedCandidates = nil
		base.outcome = model.BrowserCaptureOutcomeDNSFailed
		base.failureReason = "name_resolution_failed"
		s.record(base, s.opts.now())
		http.Error(w, "could not resolve proxy destination", http.StatusBadGateway)
		return
	}
	base.resolvedCandidates = candidates

	var connectedEndpoint string
	var connectedAddress string
	var connectionAttempted bool
	var connectedConn net.Conn
	transport := &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: s.opts.RequestTimeout,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			connectionAttempted = true
			conn, endpoint, dialErr := s.dial(ctx, candidates, port)
			if dialErr == nil {
				connectedEndpoint = endpoint
				connectedAddress = endpointHost(endpoint)
				connectedConn = conn
				s.track(conn)
			}
			return conn, dialErr
		},
	}
	defer func() {
		transport.CloseIdleConnections()
		if connectedConn != nil {
			s.untrack(connectedConn)
		}
	}()

	request := r.Clone(r.Context())
	request.URL.Scheme = scheme
	request.URL.Host = authority
	request.RequestURI = ""
	request.Host = authority
	stripProxyHeaders(request.Header)
	response, err := (&http.Client{
		Transport:     transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(request)
	if err != nil {
		base.connectedEndpoint = connectedEndpoint
		base.connectedAddress = connectedAddress
		base.outcome = model.BrowserCaptureOutcomeFailed
		base.failureReason = "upstream_request_failed"
		base.connectionAttempted = connectionAttempted
		s.record(base, s.opts.now())
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	base.connectedEndpoint = connectedEndpoint
	base.connectedAddress = connectedAddress
	base.outcome = model.BrowserCaptureOutcomeConnected
	base.connectionAttempted = connectionAttempted
	s.record(base, s.opts.now())
	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (s *Session) resolve(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	addresses, err := s.opts.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address == nil {
			continue
		}
		canonical := address.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
		if len(result) >= maxResolvedCandidates {
			break
		}
	}
	if len(result) == 0 {
		return nil, errors.New("name resolution returned no addresses")
	}
	return result, nil
}

func (s *Session) dial(ctx context.Context, candidates []string, port uint16) (net.Conn, string, error) {
	var lastErr error
	for _, candidate := range candidates {
		address := net.JoinHostPort(candidate, strconv.Itoa(int(port)))
		conn, err := s.opts.dial(ctx, "tcp", address)
		if err == nil {
			endpoint := address
			if remote := conn.RemoteAddr(); remote != nil && remote.String() != "" {
				endpoint = remote.String()
			}
			return conn, endpoint, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no address candidates")
	}
	return nil, "", lastErr
}

func (s *Session) tunnel(client net.Conn, buffered *bufio.Reader, upstream net.Conn) {
	deadline := time.Now().Add(s.opts.TunnelTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	clientReader := &bufferedConn{Conn: client, Reader: buffered}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(upstream, clientReader)
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(client, upstream)
	}()
	wait.Wait()
	_ = client.Close()
	_ = upstream.Close()
	s.untrack(client)
	s.untrack(upstream)
}

type bufferedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (conn *bufferedConn) Read(value []byte) (int, error) {
	return conn.Reader.Read(value)
}

func (s *Session) track(conn net.Conn) {
	s.mu.Lock()
	stopping := s.ctx.Err() != nil
	if !stopping {
		s.active[conn] = struct{}{}
	}
	s.mu.Unlock()
	if stopping {
		_ = conn.Close()
	}
}

func (s *Session) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.active, conn)
	s.mu.Unlock()
}

func parseProxyAuthority(authority string, fallbackPort uint16) (string, uint16, error) {
	if authority == "" || strings.TrimSpace(authority) != authority || strings.ContainsAny(authority, "/?#@") {
		return "", 0, errors.New("invalid authority")
	}
	for _, character := range authority {
		if character < 0x20 || character == 0x7f {
			return "", 0, errors.New("invalid authority")
		}
	}
	host := authority
	portText := ""
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", 0, errors.New("invalid IPv6 authority")
		}
		host = authority[1:end]
		rest := authority[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
				return "", 0, errors.New("invalid authority port")
			}
			portText, hasPort = rest[1:], true
		}
	} else {
		switch strings.Count(authority, ":") {
		case 0:
		case 1:
			parts := strings.SplitN(authority, ":", 2)
			host, portText, hasPort = parts[0], parts[1], true
			if portText == "" {
				return "", 0, errors.New("invalid authority port")
			}
		default:
			return "", 0, errors.New("IPv6 authority must be bracketed")
		}
	}
	if host == "" || strings.Contains(host, "%") {
		return "", 0, errors.New("invalid authority host")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	port := fallbackPort
	if hasPort {
		parsed, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || parsed == 0 {
			return "", 0, errors.New("invalid authority port")
		}
		port = uint16(parsed)
	}
	if port == 0 {
		return "", 0, errors.New("authority has no port")
	}
	return host, port, nil
}

func defaultPort(scheme string) uint16 {
	if scheme == "https" {
		return 443
	}
	return 80
}

func endpointHost(endpoint string) string {
	host, _, err := net.SplitHostPort(endpoint)
	if err == nil {
		return host
	}
	return endpoint
}

func stripProxyHeaders(header http.Header) {
	connectionValues := append([]string(nil), header.Values("Connection")...)
	for _, name := range proxyHopHeaders {
		header.Del(name)
	}
	for _, value := range connectionValues {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
}

func copyResponseHeaders(destination, source http.Header) {
	connectionTokens := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			connectionTokens[strings.ToLower(strings.TrimSpace(token))] = struct{}{}
		}
	}
	for key, values := range source {
		if isHopHeader(key) {
			continue
		}
		if _, hop := connectionTokens[strings.ToLower(key)]; hop {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func isHopHeader(key string) bool {
	for _, candidate := range proxyHopHeaders {
		if strings.EqualFold(key, candidate) {
			return true
		}
	}
	return false
}
