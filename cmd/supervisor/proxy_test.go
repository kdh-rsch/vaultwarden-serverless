package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseCloudTraceContext(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		expectTraceID string
		expectSpanID  string
	}{
		{
			name:          "standard GCP trace header with options",
			header:        "4bf92f3577b34da6a3ce929d0e0e4736/00f067aa0ba902b7;o=1",
			expectTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			expectSpanID:  "00f067aa0ba902b7",
		},
		{
			name:          "trace header without options",
			header:        "4bf92f3577b34da6a3ce929d0e0e4736/12345",
			expectTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			expectSpanID:  "12345",
		},
		{
			name:          "trace header without span ID",
			header:        "4bf92f3577b34da6a3ce929d0e0e4736",
			expectTraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
			expectSpanID:  "",
		},
		{
			name:          "empty header",
			header:        "",
			expectTraceID: "",
			expectSpanID:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			traceID, spanID := ParseCloudTraceContext(tc.header)
			if traceID != tc.expectTraceID {
				t.Errorf("traceID mismatch: expected %q, got %q", tc.expectTraceID, traceID)
			}
			if spanID != tc.expectSpanID {
				t.Errorf("spanID mismatch: expected %q, got %q", tc.expectSpanID, spanID)
			}
		})
	}
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		req        *http.Request
		expectedIP string
	}{
		{
			name: "single IP in X-Forwarded-For",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Forwarded-For", "203.0.113.195")
				return r
			}(),
			expectedIP: "203.0.113.195",
		},
		{
			name: "multiple IPs in X-Forwarded-For, skips loopback",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Forwarded-For", "127.0.0.1, 203.0.113.195, 70.41.3.18")
				return r
			}(),
			expectedIP: "203.0.113.195",
		},
		{
			name: "fallback to X-Real-IP",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Real-IP", "198.51.100.1")
				return r
			}(),
			expectedIP: "198.51.100.1",
		},
		{
			name: "fallback to RemoteAddr",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = "192.0.2.1:54321"
				return r
			}(),
			expectedIP: "192.0.2.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := ExtractClientIP(tc.req)
			if ip != tc.expectedIP {
				t.Errorf("expected IP %q, got %q", tc.expectedIP, ip)
			}
		})
	}
}

func TestReverseProxy_HealthzAndReady(t *testing.T) {
	InitLogger()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		TargetURL:  "http://127.0.0.1:9999",
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	// 1. /healthz must always return 200 OK
	reqHealthz := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealthz := httptest.NewRecorder()
	ps.ServeHTTP(recHealthz, reqHealthz)

	if recHealthz.Code != http.StatusOK {
		t.Errorf("expected /healthz to return 200, got %d", recHealthz.Code)
	}

	// 2. /ready must return 503 before MarkReady()
	reqReady1 := httptest.NewRequest(http.MethodGet, "/ready", nil)
	recReady1 := httptest.NewRecorder()
	ps.ServeHTTP(recReady1, reqReady1)

	if recReady1.Code != http.StatusServiceUnavailable {
		t.Errorf("expected /ready before ready to return 503, got %d", recReady1.Code)
	}

	// 3. Mark ready
	ps.MarkReady()

	// 4. /ready must now return 200 OK
	reqReady2 := httptest.NewRequest(http.MethodGet, "/ready", nil)
	recReady2 := httptest.NewRecorder()
	ps.ServeHTTP(recReady2, reqReady2)

	if recReady2.Code != http.StatusOK {
		t.Errorf("expected /ready after ready to return 200, got %d", recReady2.Code)
	}
}

func TestReverseProxy_StartupBufferingAndForwarding(t *testing.T) {
	InitLogger()

	// Mock Vaultwarden backend server
	var receivedRealIP string
	var receivedProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRealIP = r.Header.Get("X-Real-IP")
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"vaultwarden":"online"}`))
	}))
	defer backend.Close()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetURL:      backend.URL,
		ProjectID:      "test-gcp-project",
		StartupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	// Send request BEFORE backend is ready
	req := httptest.NewRequest(http.MethodGet, "/api/sync", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.Header.Set("X-Cloud-Trace-Context", "trace12345/span99;o=1")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		ps.ServeHTTP(rec, req)
		close(done)
	}()

	// Verify request is waiting (buffered and blocked)
	select {
	case <-done:
		t.Fatal("request should be buffered and blocked, but returned immediately")
	case <-time.After(50 * time.Millisecond):
		// Expected: still waiting for backend to be ready
	}

	// Mark backend ready
	ps.MarkReady()

	select {
	case <-done:
		// Expected: finished forwarding
	case <-time.After(2 * time.Second):
		t.Fatal("request timed out waiting for backend")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK after ready, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, `"vaultwarden":"online"`) {
		t.Errorf("expected response from mock backend, got: %s", body)
	}

	if receivedRealIP != "203.0.113.50" {
		t.Errorf("expected backend to receive X-Real-IP=203.0.113.50, got %s", receivedRealIP)
	}
	if receivedProto != "http" {
		t.Errorf("expected backend to receive X-Forwarded-Proto=http, got %s", receivedProto)
	}
}

func TestReverseProxy_DrainInFlightRequests(t *testing.T) {
	InitLogger()

	// Slow backend (simulates a 150ms write operation)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"saved":true}`))
	}))
	defer backend.Close()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		TargetURL:  backend.URL,
	})
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	ps.MarkReady()

	// Launch in-flight request
	req := httptest.NewRequest(http.MethodPost, "/api/ciphers", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	inFlightDone := make(chan struct{})
	go func() {
		ps.ServeHTTP(rec, req)
		close(inFlightDone)
	}()

	// Wait 30ms to ensure the request is in-flight
	time.Sleep(30 * time.Millisecond)
	if ps.activeRequests.Load() != 1 {
		t.Errorf("expected 1 active request, got %d", ps.activeRequests.Load())
	}

	// Trigger Drain in background
	drainDone := make(chan struct{})
	go func() {
		ps.Drain(1 * time.Second)
		close(drainDone)
	}()

	// Wait until drain has started
	for !ps.isDraining.Load() {
		time.Sleep(5 * time.Millisecond)
	}

	// Attempt a new request while draining -> must be rejected with 503
	reqRejected := httptest.NewRequest(http.MethodGet, "/api/ciphers", nil)
	recRejected := httptest.NewRecorder()
	ps.ServeHTTP(recRejected, reqRejected)

	if recRejected.Code != http.StatusServiceUnavailable {
		t.Errorf("expected new request during drain to receive 503, got %d", recRejected.Code)
	}

	// In-flight request must succeed
	select {
	case <-inFlightDone:
		// finished
	case <-time.After(1 * time.Second):
		t.Fatal("in-flight request timed out")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("expected in-flight request to complete with 200, got %d", rec.Code)
	}

	// Drain must finish cleanly
	select {
	case <-drainDone:
		// success
	case <-time.After(1 * time.Second):
		t.Fatal("drain timed out")
	}

	if ps.activeRequests.Load() != 0 {
		t.Errorf("expected 0 active requests after drain, got %d", ps.activeRequests.Load())
	}
}

func TestStatusRecorder_ImplementsHijackerAndFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{
		ResponseWriter: rec,
		statusCode:     http.StatusOK,
	}

	// Verify type assertions for WebSockets and SSE streaming
	if _, ok := any(sr).(http.Hijacker); !ok {
		t.Errorf("statusRecorder must implement http.Hijacker for WebSocket support")
	}
	if _, ok := any(sr).(http.Flusher); !ok {
		t.Errorf("statusRecorder must implement http.Flusher for SSE / streaming support")
	}
}

func TestSanitizeURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "path only",
			input:    "http://example.com/api/sync",
			expected: "/api/sync",
		},
		{
			name:     "clean query params",
			input:    "http://example.com/api/ciphers?page=1&limit=20",
			expected: "/api/ciphers?page=1&limit=20",
		},
		{
			name:     "access_token redacted",
			input:    "http://example.com/notifications/hub?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "/notifications/hub?access_token=[REDACTED]",
		},
		{
			name:     "multiple sensitive query params",
			input:    "http://example.com/test?token=abc&user=alice&secret=xyz&password=123",
			expected: "/test?password=[REDACTED]&secret=[REDACTED]&token=[REDACTED]&user=alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tc.input, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			actual := SanitizeURI(req.URL)
			if actual != tc.expected {
				t.Errorf("SanitizeURI mismatch:\nexpected: %s\ngot:      %s", tc.expected, actual)
			}
		})
	}

	// Nil URL check
	if res := SanitizeURI(nil); res != "" {
		t.Errorf("expected empty string for nil URL, got %q", res)
	}
}

func TestReverseProxy_StrictHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"from_backend"}`))
	}))
	defer backend.Close()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr:   ":0",
		TargetURL:    backend.URL,
		AllowedHosts: []string{"vault.example.com", "myvault.org"},
		StrictHost:   true,
	})
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}
	ps.MarkReady()

	// 1. Health checks must ALWAYS pass regardless of Host header
	for _, path := range []string{"/healthz", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "malicious-scanner.com"
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected health check %s to bypass strict host and return 200, got %d", path, rec.Code)
		}
	}

	// 2. Allowed host (with or without port) must succeed
	for _, host := range []string{"vault.example.com", "vault.example.com:443", "MYVAULT.ORG"} {
		req := httptest.NewRequest(http.MethodGet, "/api/sync", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected allowed host %q to return 200, got %d", host, rec.Code)
		}
	}

	// 3. Disallowed host must be rejected with 404 Not Found without response body
	for _, badHost := range []string{"malicious-scanner.com", "1.2.3.4", "example.com"} {
		req := httptest.NewRequest(http.MethodGet, "/api/sync", nil)
		req.Host = badHost
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected disallowed host %q to return 404, got %d", badHost, rec.Code)
		}
		if rec.Body.Len() > 0 {
			t.Errorf("expected empty body for disallowed host, got %s", rec.Body.String())
		}
	}
}

func TestReverseProxy_CustomPathPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend ok"))
	}))
	defer backend.Close()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr:   ":0",
		TargetURL:    backend.URL,
		AllowedHosts: []string{"vault.example.com"},
		StrictHost:   true,
		DomainPath:   "/nxp42",
	})
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}
	ps.MarkReady()

	// 1. Probes (root and subpath prefixed) should succeed
	for _, p := range []string{"/ready", "/healthz", "/nxp42/ready", "/nxp42/healthz"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "127.0.0.1"
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected probe %s to return 200, got %d", p, rec.Code)
		}
	}

	// 2. Request matching custom path prefix without trailing slash should redirect with 301
	for _, tc := range []struct {
		path     string
		expected string
	}{
		{"/nxp42", "/nxp42/"},
		{"/nxp42?param=1", "/nxp42/?param=1"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = "vault.example.com"
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected bare path %s to return 301, got %d", tc.path, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != tc.expected {
			t.Errorf("expected Location header %s, got %s", tc.expected, loc)
		}
	}

	// 2.1. Request matching custom path prefix with trailing slash or subpath should succeed
	for _, p := range []string{"/nxp42/", "/nxp42/api/sync"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "vault.example.com"
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected path %s to return 200, got %d", p, rec.Code)
		}
	}

	// 3. Request outside custom path prefix should be rejected with 404 and empty body
	for _, p := range []string{"/", "/admin", "/api/sync", "/robots.txt", "/nxp42fake"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "vault.example.com"
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected path %s outside prefix to return 404, got %d", p, rec.Code)
		}
		if rec.Body.Len() > 0 {
			t.Errorf("expected empty body for path %s, got %s", p, rec.Body.String())
		}
	}
}

func TestReverseProxy_SupervisorStatus(t *testing.T) {
	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr: ":0",
		TargetURL:  "http://127.0.0.1:8081",
	})
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}

	// 1. Initial warming up state
	req := httptest.NewRequest(http.MethodGet, "/_supervisor/status", nil)
	rec := httptest.NewRecorder()
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for status, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"warming_up"`) {
		t.Errorf("expected warming_up status, got %s", rec.Body.String())
	}

	// 2. Ready state
	ps.MarkReady()
	rec = httptest.NewRecorder()
	ps.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"status":"ready"`) {
		t.Errorf("expected ready status, got %s", rec.Body.String())
	}

	// 3. Tainted state
	ps.SetTainted(true)
	rec = httptest.NewRecorder()
	ps.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"status":"tainted"`) {
		t.Errorf("expected tainted status, got %s", rec.Body.String())
	}
}

func TestReverseProxy_TaintAuthAndBehavior(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"backend_ok"}`))
	}))
	defer backend.Close()

	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr: ":0",
		TargetURL:  backend.URL,
		AuthTokens: []string{"secret-litestream-key", "argon2-admin-token"},
	})
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}
	ps.MarkReady()

	handlerCalled := false
	ps.RegisterTaintHandler(func(ctx context.Context) (*SyncResult, error) {
		handlerCalled = true
		return &SyncResult{DBPath: "/data/db.sqlite3", TxID: 101, ReplicaTxID: 101, DurationMS: 15}, nil
	})

	// 1. Unauthorized requests (missing or invalid tokens)
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/_supervisor/taint", nil),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/_supervisor/taint", nil)
			r.Header.Set("Authorization", "Bearer invalid-token")
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/_supervisor/taint", nil)
			r.Header.Set("X-Supervisor-Token", "wrong-secret")
			return r
		}(),
	} {
		rec := httptest.NewRecorder()
		ps.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for bad auth, got %d", rec.Code)
		}
	}

	if handlerCalled {
		t.Errorf("taint handler should not have been called on unauthorized request")
	}

	// 2. Successful taint request with Bearer token
	req := httptest.NewRequest(http.MethodPost, "/_supervisor/taint", nil)
	req.Header.Set("Authorization", "Bearer secret-litestream-key")
	rec := httptest.NewRecorder()
	ps.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid taint request, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !handlerCalled {
		t.Errorf("expected taint callback handler to be invoked")
	}
	if !strings.Contains(rec.Body.String(), `"status":"tainted"`) || !strings.Contains(rec.Body.String(), `"txid":101`) {
		t.Errorf("expected taint response to contain status and sync result, got %s", rec.Body.String())
	}

	if !ps.IsTainted() {
		t.Errorf("expected proxy.IsTainted() to be true")
	}

	// 3. Probes behavior while tainted
	// /ready must return 503
	readyRec := httptest.NewRecorder()
	ps.ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected /ready to return 503 when tainted, got %d", readyRec.Code)
	}

	// /healthz must return 200 OK
	healthRec := httptest.NewRecorder()
	ps.ServeHTTP(healthRec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthRec.Code != http.StatusOK {
		t.Errorf("expected /healthz to return 200 when tainted, got %d", healthRec.Code)
	}
	if !strings.Contains(healthRec.Body.String(), `"tainted":true`) {
		t.Errorf("expected /healthz body to indicate tainted: true, got %s", healthRec.Body.String())
	}

	// 4. Normal client requests must be rejected with 503 and Retry-After: 5
	clientRec := httptest.NewRecorder()
	ps.ServeHTTP(clientRec, httptest.NewRequest(http.MethodGet, "/api/sync", nil))
	if clientRec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected client request to return 503 when tainted, got %d", clientRec.Code)
	}
	if clientRec.Header().Get("Retry-After") != "5" {
		t.Errorf("expected Retry-After header of 5, got %q", clientRec.Header().Get("Retry-After"))
	}

	// 5. Subsequent taint call returns already_tainted
	subsequentRec := httptest.NewRecorder()
	subsequentReq := httptest.NewRequest(http.MethodPost, "/_supervisor/taint", nil)
	subsequentReq.Header.Set("X-Supervisor-Token", "argon2-admin-token")
	ps.ServeHTTP(subsequentRec, subsequentReq)
	if subsequentRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for already tainted, got %d", subsequentRec.Code)
	}
	if !strings.Contains(subsequentRec.Body.String(), `"already_tainted"`) {
		t.Errorf("expected already_tainted status, got %s", subsequentRec.Body.String())
	}
}

func TestReverseProxy_SyncEndpoint(t *testing.T) {
	ps, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr: ":0",
		TargetURL:  "http://127.0.0.1:8081",
		AuthTokens: []string{"test-secret-key"},
	})
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}
	ps.MarkReady()

	syncCalled := false
	ps.RegisterSyncHandler(func(ctx context.Context) (*SyncResult, error) {
		syncCalled = true
		return &SyncResult{
			DBPath:      "/data/db.sqlite3",
			TxID:        205,
			ReplicaTxID: 205,
			DurationMS:  32,
		}, nil
	})

	// 1. Unauthorized request without header -> 401
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_supervisor/sync", nil)
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// 2. Unauthorized request with wrong token -> 401
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/_supervisor/sync", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}

	// 3. Method Not Allowed for GET -> 405
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/_supervisor/sync", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key")
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed for GET, got %d", rec.Code)
	}

	// 4. Authorized request with Bearer token -> 200 OK
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/_supervisor/sync", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key")
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	if !syncCalled {
		t.Errorf("expected syncHandler to be called")
	}
	if !strings.Contains(rec.Body.String(), `"status":"synchronized"`) || !strings.Contains(rec.Body.String(), `"txid":205`) {
		t.Errorf("expected response to contain synchronized status and txid 205, got %s", rec.Body.String())
	}

	// 5. Authorized request with X-Supervisor-Token -> 200 OK
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/_supervisor/sync", nil)
	req.Header.Set("X-Supervisor-Token", "test-secret-key")
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK with X-Supervisor-Token, got %d", rec.Code)
	}

	// 6. Sync handler error -> 500
	ps.RegisterSyncHandler(func(ctx context.Context) (*SyncResult, error) {
		return nil, fmt.Errorf("simulated S3 connection error")
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/_supervisor/sync", nil)
	req.Header.Set("Authorization", "Bearer test-secret-key")
	ps.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 InternalServerError on sync error, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "simulated S3 connection error") {
		t.Errorf("expected error message in response, got %s", rec.Body.String())
	}
}



