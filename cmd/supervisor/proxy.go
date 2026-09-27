package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyConfig contains settings for the embedded reverse proxy.
type ProxyConfig struct {
	ListenAddr     string        // e.g. ":8080"
	TargetURL      string        // e.g. "http://127.0.0.1:8081"
	ProjectID      string        // GCP Project ID for Cloud Trace correlation
	StartupTimeout time.Duration // Timeout for buffering client requests during boot
	AllowedHosts   []string      // Allowed Host header values (case-insensitive)
	StrictHost     bool          // Whether to enforce AllowedHosts validation
	DomainPath     string        // URL subpath prefix (e.g. "/nxp42")
	AuthTokens     []string      // Allowed secret tokens for administrative endpoints (e.g. /_supervisor/taint)
}

// statusRecorder captures the HTTP response status code and written byte count,
// while preserving http.Hijacker and http.Flusher for WebSockets and streaming.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	bytesCount int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytesCount += int64(n)
	return n, err
}

// Unwrap supports ResponseController in Go 1.20+.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Hijack implements http.Hijacker to allow WebSocket upgrades.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher to support streaming and SSE.
func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// ReverseProxyServer embeds an HTTP reverse proxy, health check handler,
// and in-flight request tracker into the Supervisor.
type ReverseProxyServer struct {
	server         *http.Server
	targetURL      *url.URL
	rp             *httputil.ReverseProxy
	activeRequests atomic.Int64
	isDraining     atomic.Bool
	isReady        atomic.Bool
	isTainted      atomic.Bool
	taintMu        sync.Mutex
	taintHandler   func(ctx context.Context) (*SyncResult, error)
	syncHandler    func(ctx context.Context) (*SyncResult, error)
	readyCh        chan struct{}
	readyOnce      sync.Once
	projectID      string
	startupTimeout time.Duration
	allowedHosts   []string
	strictHost     bool
	domainPath     string
	authTokens     []string
}

// NewReverseProxyServer constructs a ReverseProxyServer.
func NewReverseProxyServer(cfg ProxyConfig) (*ReverseProxyServer, error) {
	target, err := url.Parse(cfg.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy target URL %q: %w", cfg.TargetURL, err)
	}

	startupTimeout := cfg.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = 15 * time.Second
	}

	var allowedHosts []string
	for _, h := range cfg.AllowedHosts {
		if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
			allowedHosts = append(allowedHosts, trimmed)
		}
	}

	var authTokens []string
	for _, t := range cfg.AuthTokens {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			authTokens = append(authTokens, trimmed)
		}
	}

	ps := &ReverseProxyServer{
		targetURL:      target,
		readyCh:        make(chan struct{}),
		projectID:      strings.TrimSpace(cfg.ProjectID),
		startupTimeout: startupTimeout,
		allowedHosts:   allowedHosts,
		strictHost:     cfg.StrictHost && len(allowedHosts) > 0,
		domainPath:     strings.TrimRight(cfg.DomainPath, "/"),
		authTokens:     authTokens,
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host

			// Extract and sanitize client IP
			clientIP := ExtractClientIP(pr.In)
			if clientIP != "" {
				pr.Out.Header.Set("X-Real-IP", clientIP)
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}

			// Forward protocol (Cloud Run always terminates HTTPS externally)
			proto := pr.In.Header.Get("X-Forwarded-Proto")
			if proto == "" {
				if pr.In.TLS != nil {
					proto = "https"
				} else {
					proto = "http"
				}
			}
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("reverse proxy backend forwarding failed",
				"component", "proxy      ",
				"error", err,
				"url", r.URL.String(),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "bad_gateway",
				"message": "Vaultwarden backend service is unavailable",
			})
		},
	}
	ps.rp = rp

	ps.server = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           ps,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return ps, nil
}

// RegisterTaintHandler sets the callback to execute when /_supervisor/taint is invoked.
func (ps *ReverseProxyServer) RegisterTaintHandler(fn func(ctx context.Context) (*SyncResult, error)) {
	ps.taintMu.Lock()
	defer ps.taintMu.Unlock()
	ps.taintHandler = fn
}

// RegisterSyncHandler sets the callback to execute when /_supervisor/sync is invoked.
func (ps *ReverseProxyServer) RegisterSyncHandler(fn func(ctx context.Context) (*SyncResult, error)) {
	ps.taintMu.Lock()
	defer ps.taintMu.Unlock()
	ps.syncHandler = fn
}

// IsTainted returns whether the proxy has entered tainted maintenance mode.
func (ps *ReverseProxyServer) IsTainted() bool {
	return ps.isTainted.Load()
}

// SetTainted sets the tainted status explicitly.
func (ps *ReverseProxyServer) SetTainted(v bool) {
	ps.isTainted.Store(v)
}

// MarkReady signals that the backend service (Vaultwarden) is fully operational.
func (ps *ReverseProxyServer) MarkReady() {
	ps.readyOnce.Do(func() {
		ps.isReady.Store(true)
		close(ps.readyCh)
		slog.Info("reverse proxy marked ready; accepting live traffic", "component", "proxy      ")
	})
}

// IsReady returns whether the backend service is ready.
func (ps *ReverseProxyServer) IsReady() bool {
	return ps.isReady.Load()
}

// Start begins listening on the configured address in a non-blocking goroutine.
func (ps *ReverseProxyServer) Start() error {
	ln, err := net.Listen("tcp", ps.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy listener on %s: %w", ps.server.Addr, err)
	}

	slog.Info("reverse proxy listening",
		"component", "proxy      ",
		"addr", ln.Addr().String(),
		"target", ps.targetURL.String(),
	)

	go func() {
		if err := ps.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("reverse proxy server error", "component", "proxy      ", "error", err)
		}
	}()

	return nil
}

// Drain marks the proxy as shutting down, stops accepting new requests,
// and blocks until all in-flight requests complete or the timeout expires.
func (ps *ReverseProxyServer) Drain(timeout time.Duration) {
	ps.isDraining.Store(true)
	slog.Info("initiating reverse proxy drain", "component", "proxy      ", "timeout", timeout)

	deadline := time.Now().Add(timeout)
	for {
		active := ps.activeRequests.Load()
		if active <= 0 {
			slog.Info("all in-flight requests drained cleanly", "component", "proxy      ")
			return
		}
		if time.Now().After(deadline) {
			slog.Warn("drain timed out with active requests remaining",
				"component", "proxy      ",
				"remaining_active", active,
			)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Shutdown gracefully shuts down the HTTP server listener.
func (ps *ReverseProxyServer) Shutdown(ctx context.Context) error {
	return ps.server.Shutdown(ctx)
}

// ServeHTTP routes incoming traffic to health checks or the reverse proxy.
func (ps *ReverseProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Supervisor Administrative and Health Check endpoints
	// Support both root paths (/ready, /healthz, /alive) and custom subpath prefixes (/nxp42/ready, etc.)
	probePath := r.URL.Path
	if ps.domainPath != "" && strings.HasPrefix(probePath, ps.domainPath) {
		trimmed := strings.TrimPrefix(probePath, ps.domainPath)
		if trimmed == "" || strings.HasPrefix(trimmed, "/") {
			probePath = trimmed
			if !strings.HasPrefix(probePath, "/") {
				probePath = "/" + probePath
			}
		}
	}

	switch probePath {
	case "/healthz", "/alive":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if ps.isTainted.Load() {
			_, _ = w.Write([]byte(`{"status":"healthy","tainted":true}` + "\n"))
		} else {
			_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
		}
		return

	case "/ready":
		w.Header().Set("Content-Type", "application/json")
		if ps.isTainted.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"tainted","ready":false}` + "\n"))
			return
		}
		if ps.isReady.Load() && !ps.isDraining.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ready"}` + "\n"))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"warming_up"}` + "\n"))
		}
		return

	case "/_supervisor/status":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		status := "warming_up"
		if ps.isTainted.Load() {
			status = "tainted"
		} else if ps.isDraining.Load() {
			status = "draining"
		} else if ps.isReady.Load() {
			status = "ready"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":          status,
			"ready":           ps.isReady.Load() && !ps.isTainted.Load() && !ps.isDraining.Load(),
			"tainted":         ps.isTainted.Load(),
			"draining":        ps.isDraining.Load(),
			"active_requests": ps.activeRequests.Load(),
		})
		return

	case "/_supervisor/taint":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		ps.handleTaint(w, r)
		return

	case "/_supervisor/sync":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		ps.handleSync(w, r)
		return
	}

	// 2. Strict Host Validation (if enabled)
	if ps.strictHost && len(ps.allowedHosts) > 0 {
		reqHost := extractHostname(r.Host)
		allowed := false
		for _, ah := range ps.allowedHosts {
			if reqHost == ah {
				allowed = true
				break
			}
		}

		if !allowed {
			slog.Warn("rejected request with disallowed Host header",
				"component", "proxy      ",
				"host", r.Host,
				"method", r.Method,
				"path", r.URL.Path,
				"client_ip", ExtractClientIP(r),
			)
			// Stealth rejection: 404 Not Found without response body
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	// 2.5. Custom Path Prefix Validation: If domainPath is configured, reject requests outside the prefix
	if ps.domainPath != "" {
		if r.URL.Path == ps.domainPath {
			target := ps.domainPath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}

		if !strings.HasPrefix(r.URL.Path, ps.domainPath+"/") {
			slog.Warn("rejected request outside custom path prefix",
				"component", "proxy      ",
				"host", r.Host,
				"method", r.Method,
				"path", r.URL.Path,
				"client_ip", ExtractClientIP(r),
			)
			// Stealth rejection: 404 Not Found without response body
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	// 3. Reject new requests if tainted or draining
	if ps.isTainted.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "service_unavailable",
			"message": "instance is tainted and undergoing maintenance; please retry",
		})
		return
	}

	if ps.isDraining.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "service_unavailable",
			"message": "container is shutting down",
		})
		return
	}

	// 4. Connection Buffering: If backend not ready yet, wait for readyCh
	if !ps.isReady.Load() {
		select {
		case <-ps.readyCh:
			// Backend is now ready, proceed to forward
		case <-time.After(ps.startupTimeout):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGatewayTimeout)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "gateway_timeout",
				"message": "backend service took too long to warm up",
			})
			return
		case <-r.Context().Done():
			return
		}
	}

	// 5. In-flight request tracking
	ps.activeRequests.Add(1)
	defer ps.activeRequests.Add(-1)

	// 6. Cloud Trace Context extraction
	traceID, spanID := ParseCloudTraceContext(r.Header.Get("X-Cloud-Trace-Context"))

	start := time.Now()
	rec := &statusRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // default if WriteHeader not called explicitly
	}

	// 7. Forward to Vaultwarden backend
	ps.rp.ServeHTTP(rec, r)

	// 8. Structured access log with query sanitization & Cloud Trace correlation
	duration := time.Since(start)
	uri := SanitizeURI(r.URL)
	logAttrs := []any{
		slog.String("component", "proxy      "),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("uri", uri),
		slog.Int("status", rec.statusCode),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.Int64("bytes", rec.bytesCount),
	}

	if traceID != "" && ps.projectID != "" {
		logAttrs = append(logAttrs,
			slog.String("logging.googleapis.com/trace", fmt.Sprintf("projects/%s/traces/%s", ps.projectID, traceID)),
		)
		if spanID != "" {
			logAttrs = append(logAttrs,
				slog.String("logging.googleapis.com/spanId", spanID),
			)
		}
	}

	msg := fmt.Sprintf("%s %s %d (%dms)", r.Method, uri, rec.statusCode, duration.Milliseconds())
	if rec.statusCode >= 500 {
		slog.Error(msg, logAttrs...)
	} else if rec.statusCode >= 400 {
		slog.Warn(msg, logAttrs...)
	} else {
		slog.Info(msg, logAttrs...)
	}
}

// extractHostname returns the lowercased hostname without port from a host string.
func extractHostname(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

// sensitiveQueryKeys defines query parameter names that must be redacted in logs.
var sensitiveQueryKeys = map[string]bool{
	"access_token": true,
	"token":        true,
	"key":          true,
	"secret":       true,
	"password":     true,
	"auth":         true,
	"api_key":      true,
}

// SanitizeURI returns a sanitized representation of the URL with sensitive query parameter values redacted.
func SanitizeURI(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawQuery == "" {
		return u.Path
	}

	lowerQuery := strings.ToLower(u.RawQuery)
	containsSensitive := false
	for k := range sensitiveQueryKeys {
		if strings.Contains(lowerQuery, k) {
			containsSensitive = true
			break
		}
	}
	if !containsSensitive {
		return u.RequestURI()
	}

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.Path + "?[REDACTED]"
	}

	for k := range values {
		if sensitiveQueryKeys[strings.ToLower(k)] {
			values[k] = []string{"[REDACTED]"}
		}
	}

	encoded := values.Encode()
	encoded = strings.ReplaceAll(encoded, "%5BREDACTED%5D", "[REDACTED]")
	return u.Path + "?" + encoded
}

// ParseCloudTraceContext parses the X-Cloud-Trace-Context header.
// Format: TRACE_ID/SPAN_ID;o=TRACE_TRUE
func ParseCloudTraceContext(header string) (traceID string, spanID string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}

	// Split options if present
	parts := strings.SplitN(header, ";", 2)
	traceAndSpan := parts[0]

	slashIdx := strings.IndexByte(traceAndSpan, '/')
	if slashIdx == -1 {
		return traceAndSpan, ""
	}

	traceID = traceAndSpan[:slashIdx]
	spanID = traceAndSpan[slashIdx+1:]
	return traceID, spanID
}

// ExtractClientIP sanitizes incoming proxy headers to find the trusted client IP.
func ExtractClientIP(r *http.Request) string {
	// 1. Check X-Forwarded-For (Google Cloud Run GFE sets/appends client IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, rawIP := range ips {
			cleanIP := strings.TrimSpace(rawIP)
			if parsed := net.ParseIP(cleanIP); parsed != nil {
				// Reject loopback from being treated as external client IP
				if !parsed.IsLoopback() {
					return cleanIP
				}
			}
		}
	}

	// 2. Check X-Real-IP
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if parsed := net.ParseIP(xri); parsed != nil && !parsed.IsLoopback() {
			return xri
		}
	}

	// 3. Fallback to RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			return host
		}
	}

	return ""
}

func (ps *ReverseProxyServer) verifyAuth(r *http.Request) bool {
	if len(ps.authTokens) == 0 {
		return false
	}
	token := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	} else if supToken := r.Header.Get("X-Supervisor-Token"); supToken != "" {
		token = supToken
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	for _, at := range ps.authTokens {
		if at != "" && token == at {
			return true
		}
	}
	return false
}

func (ps *ReverseProxyServer) handleTaint(w http.ResponseWriter, r *http.Request) {
	if !ps.verifyAuth(r) {
		slog.Warn("unauthorized attempt to access taint endpoint", "component", "proxy      ", "client_ip", ExtractClientIP(r))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "unauthorized",
			"message": "valid Bearer token or X-Supervisor-Token required",
		})
		return
	}

	ps.taintMu.Lock()
	defer ps.taintMu.Unlock()

	if ps.isTainted.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "already_tainted",
			"message": "instance is already tainted and disarmed",
		})
		return
	}

	slog.Info("TAINT request received; disarming instance and freezing writes", "component", "proxy      ", "client_ip", ExtractClientIP(r))

	// 1. Mark as tainted and draining so new client requests get 503 and /ready returns 503
	ps.isTainted.Store(true)
	ps.isDraining.Store(true)

	// 2. Drain active in-flight proxy requests
	ps.Drain(3 * time.Second)

	// 3. Execute taint callback (stop Vaultwarden, sync S3, stop Litestream)
	var syncRes *SyncResult
	var syncErr error
	if ps.taintHandler != nil {
		syncRes, syncErr = ps.taintHandler(r.Context())
	}

	w.Header().Set("Content-Type", "application/json")
	if syncErr != nil {
		slog.Error("taint teardown sync encountered error", "component", "proxy      ", "error", syncErr)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "tainted_with_error",
			"error":   syncErr.Error(),
			"message": "Vaultwarden stopped, but Litestream S3 sync reported an error",
		})
		return
	}

	resp := map[string]any{
		"status":  "tainted",
		"message": "Vaultwarden stopped, Litestream synced to S3 and stopped. Instance is disarmed and holding.",
	}
	if syncRes != nil {
		resp["txid"] = syncRes.TxID
		resp["replica_txid"] = syncRes.ReplicaTxID
		resp["latency_ms"] = syncRes.DurationMS
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (ps *ReverseProxyServer) handleSync(w http.ResponseWriter, r *http.Request) {
	if !ps.verifyAuth(r) {
		slog.Warn("unauthorized attempt to access sync endpoint", "component", "proxy      ", "client_ip", ExtractClientIP(r))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "unauthorized",
			"message": "valid Bearer token or X-Supervisor-Token required",
		})
		return
	}

	slog.Info("explicit sync requested via /_supervisor/sync", "component", "proxy      ", "client_ip", ExtractClientIP(r))

	ps.taintMu.Lock()
	syncFn := ps.syncHandler
	ps.taintMu.Unlock()

	var syncRes *SyncResult
	var syncErr error
	if syncFn != nil {
		syncRes, syncErr = syncFn(r.Context())
	} else {
		syncErr = fmt.Errorf("sync handler not registered")
	}

	w.Header().Set("Content-Type", "application/json")
	if syncErr != nil {
		slog.Error("explicit sync failed", "component", "proxy      ", "error", syncErr)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "sync_failed",
			"message": syncErr.Error(),
		})
		return
	}

	resp := map[string]any{
		"status":  "synchronized",
		"message": "WAL frames successfully replicated and durable in remote S3",
	}
	if syncRes != nil {
		resp["db_path"] = syncRes.DBPath
		resp["txid"] = syncRes.TxID
		resp["replica_txid"] = syncRes.ReplicaTxID
		resp["duration_ms"] = syncRes.DurationMS
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
