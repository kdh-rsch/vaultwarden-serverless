package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLoadConfig_MissingEnv(t *testing.T) {
	t.Setenv("REPLICA_BUCKET", "")
	t.Setenv("REPLICA_ENDPOINT", "")
	t.Setenv("LITESTREAM_ACCESS_KEY_ID", "")
	t.Setenv("LITESTREAM_SECRET_ACCESS_KEY", "")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error when required environment variables are missing, got nil")
	}
	if !strings.Contains(err.Error(), "REPLICA_BUCKET") {
		t.Errorf("expected error to mention REPLICA_BUCKET, got %v", err)
	}
}

func TestLoadConfig_Success(t *testing.T) {
	t.Setenv("REPLICA_BUCKET", "my-bucket")
	t.Setenv("REPLICA_ENDPOINT", "s3.us-west-004.backblazeb2.com")
	t.Setenv("LITESTREAM_ACCESS_KEY_ID", "key123")
	t.Setenv("LITESTREAM_SECRET_ACCESS_KEY", "secret456")
	t.Setenv("RSA_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	if cfg.ReplicaBucket != "my-bucket" {
		t.Errorf("expected ReplicaBucket=my-bucket, got %s", cfg.ReplicaBucket)
	}
	if cfg.DBPath != "/data/db.sqlite3" {
		t.Errorf("expected DBPath=/data/db.sqlite3, got %s", cfg.DBPath)
	}
	if cfg.SocketPath != "/tmp/litestream.sock" {
		t.Errorf("expected SocketPath=/tmp/litestream.sock, got %s", cfg.SocketPath)
	}
	if cfg.SyncInterval != "1s" {
		t.Errorf("expected SyncInterval=1s, got %s", cfg.SyncInterval)
	}
	if cfg.SnapshotInterval != "12h" {
		t.Errorf("expected SnapshotInterval=12h, got %s", cfg.SnapshotInterval)
	}
	if cfg.ShutdownTimeoutSeconds != 10*time.Second {
		t.Errorf("expected ShutdownTimeout=10s, got %v", cfg.ShutdownTimeoutSeconds)
	}
	if cfg.StartupTimeout != 30*time.Second {
		t.Errorf("expected StartupTimeout=30s, got %v", cfg.StartupTimeout)
	}
}

func TestLoadConfig_StartupTimeout(t *testing.T) {
	t.Setenv("REPLICA_BUCKET", "my-bucket")
	t.Setenv("REPLICA_ENDPOINT", "s3.us-west-004.backblazeb2.com")
	t.Setenv("LITESTREAM_ACCESS_KEY_ID", "key123")
	t.Setenv("LITESTREAM_SECRET_ACCESS_KEY", "secret456")

	// Custom valid timeout
	t.Setenv("STARTUP_TIMEOUT", "45s")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}
	if cfg.StartupTimeout != 45*time.Second {
		t.Errorf("expected StartupTimeout=45s, got %v", cfg.StartupTimeout)
	}

	// Invalid timeout fallback to default 30s
	t.Setenv("STARTUP_TIMEOUT", "invalid-duration")
	cfgInvalid, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}
	if cfgInvalid.StartupTimeout != 30*time.Second {
		t.Errorf("expected fallback StartupTimeout=30s, got %v", cfgInvalid.StartupTimeout)
	}
}

func TestLoadConfig_WebsocketOptions(t *testing.T) {
	t.Setenv("REPLICA_BUCKET", "my-bucket")
	t.Setenv("REPLICA_ENDPOINT", "s3.us-west-004.backblazeb2.com")
	t.Setenv("LITESTREAM_ACCESS_KEY_ID", "key123")
	t.Setenv("LITESTREAM_SECRET_ACCESS_KEY", "secret456")

	// 1. Default (unset) -> WebsocketEnabled=false, WebsocketDisabledCode=404
	t.Setenv("WEBSOCKET_ENABLED", "")
	t.Setenv("WEBSOCKET_DISABLED_STATUS_CODE", "")
	cfgDefault, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}
	if cfgDefault.WebsocketEnabled {
		t.Errorf("expected WebsocketEnabled=false by default, got true")
	}
	if cfgDefault.WebsocketDisabledCode != http.StatusNotFound {
		t.Errorf("expected WebsocketDisabledCode=404 by default, got %d", cfgDefault.WebsocketDisabledCode)
	}

	// 2. Explicitly enabled with "true"
	t.Setenv("WEBSOCKET_ENABLED", "true")
	cfgTrue, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgTrue.WebsocketEnabled {
		t.Errorf("expected WebsocketEnabled=true, got false")
	}

	// 3. Explicitly enabled with "1"
	t.Setenv("WEBSOCKET_ENABLED", "1")
	cfgOne, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgOne.WebsocketEnabled {
		t.Errorf("expected WebsocketEnabled=true for '1', got false")
	}

	// 4. Explicitly disabled with "false"
	t.Setenv("WEBSOCKET_ENABLED", "false")
	cfgFalse, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgFalse.WebsocketEnabled {
		t.Errorf("expected WebsocketEnabled=false, got true")
	}

	// 5. Custom status code (403 Forbidden)
	t.Setenv("WEBSOCKET_DISABLED_STATUS_CODE", "403")
	cfg403, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg403.WebsocketDisabledCode != http.StatusForbidden {
		t.Errorf("expected WebsocketDisabledCode=403, got %d", cfg403.WebsocketDisabledCode)
	}

	// 6. Invalid status code fallback to 404
	t.Setenv("WEBSOCKET_DISABLED_STATUS_CODE", "not-a-number")
	cfgInvalid, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgInvalid.WebsocketDisabledCode != http.StatusNotFound {
		t.Errorf("expected fallback WebsocketDisabledCode=404, got %d", cfgInvalid.WebsocketDisabledCode)
	}
}

func TestLoadConfig_StrictHost(t *testing.T) {
	t.Setenv("REPLICA_BUCKET", "my-bucket")
	t.Setenv("REPLICA_ENDPOINT", "s3.us-west-004.backblazeb2.com")
	t.Setenv("LITESTREAM_ACCESS_KEY_ID", "key123")
	t.Setenv("LITESTREAM_SECRET_ACCESS_KEY", "secret456")

	// 1. Default: strict host disabled
	t.Setenv("STRICT_HOST", "")
	t.Setenv("ALLOWED_HOSTS", "")
	t.Setenv("DOMAIN", "")
	cfgDefault, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgDefault.StrictHost {
		t.Errorf("expected StrictHost=false by default, got true")
	}

	if cfgDefault.DomainPath != "" {
		t.Errorf("expected empty DomainPath by default, got %q", cfgDefault.DomainPath)
	}

	// 2. ALLOWED_HOSTS enables strict host
	t.Setenv("ALLOWED_HOSTS", "vault1.example.com, VAULT2.EXAMPLE.COM ")
	cfgHosts, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgHosts.StrictHost {
		t.Errorf("expected StrictHost=true when ALLOWED_HOSTS is set, got false")
	}
	if len(cfgHosts.AllowedHosts) != 2 || cfgHosts.AllowedHosts[0] != "vault1.example.com" || cfgHosts.AllowedHosts[1] != "vault2.example.com" {
		t.Errorf("expected [vault1.example.com, vault2.example.com], got %v", cfgHosts.AllowedHosts)
	}

	// 3. STRICT_HOST=true with DOMAIN parses domain hostname and subpath
	t.Setenv("ALLOWED_HOSTS", "")
	t.Setenv("STRICT_HOST", "true")
	t.Setenv("DOMAIN", "https://vault.mycorp.org:8443/secret-vault/")
	cfgDomain, err := loadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgDomain.StrictHost {
		t.Errorf("expected StrictHost=true with STRICT_HOST=true, got false")
	}
	if len(cfgDomain.AllowedHosts) != 1 || cfgDomain.AllowedHosts[0] != "vault.mycorp.org" {
		t.Errorf("expected [vault.mycorp.org], got %v", cfgDomain.AllowedHosts)
	}
	if cfgDomain.DomainPath != "/secret-vault" {
		t.Errorf("expected DomainPath '/secret-vault', got %q", cfgDomain.DomainPath)
	}
}

func TestGenerateLitestreamConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "litestream.yml")
	socketPath := filepath.Join(tmpDir, "test.sock")

	cfg := &Config{
		ReplicaBucket:    "my-test-bucket",
		ReplicaEndpoint:  "https://test.r2.cloudflarestorage.com",
		ReplicaRegion:    "auto",
		ReplicaPath:      "v-db",
		DBPath:           filepath.Join(tmpDir, "db.sqlite3"),
		ConfigPath:       configPath,
		SocketPath:       socketPath,
		SyncInterval:     "2s",
		SnapshotInterval: "6h",
		Retention:        "72h",
	}

	if err := generateLitestreamConfig(cfg); err != nil {
		t.Fatalf("failed to generate litestream config: %v", err)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	yamlStr := string(content)
	expectedSubstrings := []string{
		"socket:",
		"enabled: true",
		"path: " + socketPath,
		"path: " + cfg.DBPath,
		"bucket: my-test-bucket",
		"endpoint: https://test.r2.cloudflarestorage.com",
		"region: auto",
		"path: v-db",
		"sync-interval: 2s",
		"snapshot-interval: 6h",
		"retention: 72h",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(yamlStr, sub) {
			t.Errorf("expected config to contain %q, but got:\n%s", sub, yamlStr)
		}
	}
}

func TestSetupRSAKey_InjectedEnv(t *testing.T) {
	tmpDir := t.TempDir()
	pemContent := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s3Client := NewS3Client(server.URL, "us-east-1", "test-key", "test-secret")
	cfg := &Config{
		DataFolder:          tmpDir,
		RsaPrivateKeyPEM:    pemContent,
		ReplicaBucket:       "test-bucket",
		ReplicaPath:         "vaultwarden-db",
		LitestreamSecretKey: "litestream-secret-123",
	}

	if err := setupRSAKey(t.Context(), cfg, s3Client); err != nil {
		t.Fatalf("failed to setup RSA key: %v", err)
	}

	keyFile := filepath.Join(tmpDir, "rsa_key.pem")
	stat, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("failed to stat rsa key file: %v", err)
	}

	if stat.Mode().Perm() != 0600 {
		t.Errorf("expected file mode 0600, got %o", stat.Mode().Perm())
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("failed to read rsa key file: %v", err)
	}

	if strings.TrimSpace(string(data)) != pemContent {
		t.Errorf("file content mismatch: expected %q, got %q", pemContent, string(data))
	}
}

func TestSetupRSAKey_GenerateAndRestoreFromS3(t *testing.T) {
	storage := make(map[string][]byte)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			data, _ := io.ReadAll(r.Body)
			storage[r.URL.Path] = data
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			data, ok := storage[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		}
	}))
	defer server.Close()

	s3Client := NewS3Client(server.URL, "us-east-1", "test-key", "test-secret")

	// Phase 1: First boot without existing key -> Should generate new RSA key, write to disk, encrypt and upload to S3
	dataFolder1 := t.TempDir()
	cfg1 := &Config{
		DataFolder:          dataFolder1,
		ReplicaBucket:       "test-bucket",
		ReplicaPath:         "vaultwarden-db",
		LitestreamSecretKey: "secret-master-key",
	}

	if err := setupRSAKey(t.Context(), cfg1, s3Client); err != nil {
		t.Fatalf("phase 1 failed: %v", err)
	}

	keyFile1 := filepath.Join(dataFolder1, "rsa_key.pem")
	generatedKey1, err := os.ReadFile(keyFile1)
	if err != nil {
		t.Fatalf("failed to read generated key in phase 1: %v", err)
	}

	if !strings.HasPrefix(string(generatedKey1), "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("expected valid RSA PEM in phase 1, got %s", string(generatedKey1))
	}

	// Verify that S3 has the encrypted object
	s3Path := "/test-bucket/vaultwarden-db/rsa_key.pem.enc"
	if _, ok := storage[s3Path]; !ok {
		t.Fatalf("expected encrypted RSA key to be saved at %s in S3", s3Path)
	}

	// Phase 2: Second container cold start with fresh empty data folder -> Should restore from S3 and decrypt
	dataFolder2 := t.TempDir()
	cfg2 := &Config{
		DataFolder:          dataFolder2,
		ReplicaBucket:       "test-bucket",
		ReplicaPath:         "vaultwarden-db",
		LitestreamSecretKey: "secret-master-key",
	}

	if err := setupRSAKey(t.Context(), cfg2, s3Client); err != nil {
		t.Fatalf("phase 2 failed to restore from S3: %v", err)
	}

	keyFile2 := filepath.Join(dataFolder2, "rsa_key.pem")
	restoredKey2, err := os.ReadFile(keyFile2)
	if err != nil {
		t.Fatalf("failed to read restored key in phase 2: %v", err)
	}

	if string(restoredKey2) != string(generatedKey1) {
		t.Errorf("restored key from S3 does not match original generated key!\nExpected:\n%s\nGot:\n%s",
			string(generatedKey1), string(restoredKey2))
	}
}

func TestWaitForSocket_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	procDone := make(chan error, 1)

	// Simulate daemon creating socket after 50ms
	go func() {
		time.Sleep(50 * time.Millisecond)
		l, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Errorf("failed to listen on socket: %v", err)
			return
		}
		defer l.Close()
		time.Sleep(500 * time.Millisecond)
	}()

	if err := waitForSocket(socketPath, procDone, 1*time.Second); err != nil {
		t.Fatalf("waitForSocket failed: %v", err)
	}
}

func TestWaitForSocket_PrematureExit(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	procDone := make(chan error, 1)
	procDone <- fmt.Errorf("crash on startup")

	err := waitForSocket(socketPath, procDone, 1*time.Second)
	if err == nil {
		t.Fatal("expected error when process exits prematurely, got nil")
	}
	if !strings.Contains(err.Error(), "crash on startup") {
		t.Errorf("expected error message to contain 'crash on startup', got %v", err)
	}
}

func TestExecuteExplicitSync_NoDB(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{
		DBPath: filepath.Join(tmpDir, "nonexistent.db"),
	}

	res, err := executeExplicitSync(context.Background(), cfg, 5)
	if err != nil {
		t.Fatalf("expected nil error when db does not exist, got %v", err)
	}
	if res != nil {
		t.Errorf("expected nil result when db does not exist, got %v", res)
	}
}

func TestStopProcess_CleanExit(t *testing.T) {
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	err := stopProcess(cmd, done, syscall.SIGTERM, 2*time.Second)
	// Process was killed by SIGTERM, so error is expected (signal: terminated)
	if err == nil {
		t.Log("process exited with nil error")
	}
}

func TestStopProcess_TimeoutForceKill(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessIgnoreTerm")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_IGNORE_TERM=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start trapped command: %v", err)
	}
	// Wait until child has registered its SIGTERM handler
	buf := make([]byte, 5)
	_, _ = stdout.Read(buf)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	err = stopProcess(cmd, done, syscall.SIGTERM, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error on timed-out process kill, got nil")
	}
	if !strings.Contains(err.Error(), "killed after timeout") {
		t.Errorf("expected error to mention 'killed after timeout', got %v", err)
	}
}

func TestHelperProcessIgnoreTerm(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_IGNORE_TERM") != "1" {
		return
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	go func() {
		for range sigChan {
			// ignore SIGTERM
		}
	}()
	fmt.Println("READY")
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func setupMockBinaries(t *testing.T, tmpDir string) (string, string) {
	testBin := os.Args[0]

	mockLSPath := filepath.Join(tmpDir, "mock-litestream")
	lsScript := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_MOCK_LITESTREAM=1\nexec %q -test.run=TestHelperMockLitestream -- \"$@\"\n", testBin)
	if err := os.WriteFile(mockLSPath, []byte(lsScript), 0755); err != nil {
		t.Fatalf("failed to write mock litestream: %v", err)
	}

	mockVWPath := filepath.Join(tmpDir, "mock-vaultwarden")
	vwScript := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_MOCK_VAULTWARDEN=1\nexec %q -test.run=TestHelperMockVaultwarden -- \"$@\"\n", testBin)
	if err := os.WriteFile(mockVWPath, []byte(vwScript), 0755); err != nil {
		t.Fatalf("failed to write mock vaultwarden: %v", err)
	}

	return mockLSPath, mockVWPath
}

func TestRunDualProcess_SignalHandling(t *testing.T) {
	tmpDir := t.TempDir()
	mockLS, mockVW := setupMockBinaries(t, tmpDir)

	dbPath := filepath.Join(tmpDir, "db.sqlite3")
	_ = os.WriteFile(dbPath, []byte("test db content"), 0644)

	socketPath := filepath.Join(tmpDir, "litestream.sock")
	t.Setenv("LITESTREAM_SOCKET_PATH", socketPath)

	mockPort := "8095"
	cfg := &Config{
		DBPath:                 dbPath,
		SocketPath:             socketPath,
		ConfigPath:             filepath.Join(tmpDir, "litestream.yml"),
		LitestreamBin:          mockLS,
		VaultwardenBin:         mockVW,
		PublicPort:             "8094",
		InternalPort:           mockPort,
		ShutdownTimeoutSeconds: 10 * time.Second,
	}

	proxyServer, _ := NewReverseProxyServer(ProxyConfig{
		ListenAddr: "127.0.0.1:8094",
		TargetURL:  "http://127.0.0.1:" + mockPort,
	})
	_ = proxyServer.Start()
	defer proxyServer.Shutdown(context.Background())

	go func() {
		// Wait for both processes to be operational (proxy marked ready)
		for i := 0; i < 100; i++ {
			if proxyServer.IsReady() {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	exitCode := runDualProcess(context.Background(), cfg, proxyServer)
	if exitCode != 0 {
		t.Errorf("expected exitCode=0 on graceful shutdown, got %d", exitCode)
	}
}

func TestRunDualProcess_LitestreamCrash(t *testing.T) {
	tmpDir := t.TempDir()
	_, mockVW := setupMockBinaries(t, tmpDir)

	// Litestream mock that crashes immediately after creating socket
	mockCrashLSPath := filepath.Join(tmpDir, "mock-crash-litestream")
	lsScript := fmt.Sprintf("#!/bin/sh\nexport GO_WANT_MOCK_CRASH_LITESTREAM=1\nexec %q -test.run=TestHelperMockCrashLitestream -- \"$@\"\n", os.Args[0])
	if err := os.WriteFile(mockCrashLSPath, []byte(lsScript), 0755); err != nil {
		t.Fatalf("failed to write mock crash litestream: %v", err)
	}

	socketPath := filepath.Join(tmpDir, "litestream.sock")
	t.Setenv("LITESTREAM_SOCKET_PATH", socketPath)

	cfg := &Config{
		DBPath:                 filepath.Join(tmpDir, "db.sqlite3"),
		SocketPath:             socketPath,
		ConfigPath:             filepath.Join(tmpDir, "litestream.yml"),
		LitestreamBin:          mockCrashLSPath,
		VaultwardenBin:         mockVW,
		PublicPort:             "8096",
		InternalPort:           "8097",
		ShutdownTimeoutSeconds: 2 * time.Second,
	}

	exitCode := runDualProcess(context.Background(), cfg, nil)
	if exitCode != 1 {
		t.Errorf("expected exitCode=1 on litestream crash (fail-closed), got %d", exitCode)
	}
}

func TestHelperMockLitestream(t *testing.T) {
	if os.Getenv("GO_WANT_MOCK_LITESTREAM") != "1" {
		return
	}

	// Check if this is a sync call
	for _, arg := range os.Args {
		if arg == "sync" {
			fmt.Println(`{"db_path":"/tmp/test.db","txid":42,"replica_txid":42,"duration_ms":12}`)
			os.Exit(0)
		}
	}

	socketPath := os.Getenv("LITESTREAM_SOCKET_PATH")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on socket %s: %v\n", socketPath, err)
		os.Exit(1)
	}
	defer l.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	<-sigChan
	os.Exit(0)
}

func TestHelperMockCrashLitestream(t *testing.T) {
	if os.Getenv("GO_WANT_MOCK_CRASH_LITESTREAM") != "1" {
		return
	}
	socketPath := os.Getenv("LITESTREAM_SOCKET_PATH")
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		os.Exit(1)
	}
	_ = l.Close()
	// Simulate unexpected crash after socket creation
	time.Sleep(100 * time.Millisecond)
	os.Exit(2)
}

func TestHelperMockVaultwarden(t *testing.T) {
	if os.Getenv("GO_WANT_MOCK_VAULTWARDEN") != "1" {
		return
	}
	port := os.Getenv("ROCKET_PORT")
	if port != "" {
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err == nil {
			mux := http.NewServeMux()
			mux.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"alive"}`))
			})
			srv := &http.Server{Handler: mux}
			go srv.Serve(l)
			defer srv.Close()
		}
	}
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	<-sigChan
	os.Exit(0)
}

