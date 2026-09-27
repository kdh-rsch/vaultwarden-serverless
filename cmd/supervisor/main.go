package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config holds runtime configuration gathered from environment variables.
type Config struct {
	ReplicaBucket          string
	ReplicaEndpoint        string
	ReplicaRegion          string
	ReplicaPath            string
	LitestreamAccessKeyID  string
	LitestreamSecretKey    string
	RsaPrivateKeyPEM       string
	RsaPassphrase          string
	DBPath                 string
	DataFolder             string
	ConfigPath             string
	SocketPath             string
	LitestreamBin          string
	VaultwardenBin         string
	SyncInterval           string
	SnapshotInterval       string
	Retention              string
	ShutdownTimeoutSeconds time.Duration
	StartupTimeout         time.Duration
	AllowedHosts           []string
	StrictHost             bool
	DomainPath             string
	PublicPort             string
	InternalPort           string
	ProjectID              string
}

// SyncResult represents the machine-readable JSON output of 'litestream sync -json'.
type SyncResult struct {
	DBPath      string `json:"db_path"`
	TxID        int64  `json:"txid"`
	ReplicaTxID int64  `json:"replica_txid"`
	DurationMS  int64  `json:"duration_ms"`
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return defaultValue
}

func parseDurationOrDefault(key, defaultValue string) string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return defaultValue
	}
	if _, err := time.ParseDuration(val); err != nil {
		slog.Warn("invalid duration format, falling back to default", "component", "supervisor", "key", key, "value", val, "default", defaultValue)
		return defaultValue
	}
	return val
}

func loadConfig() (*Config, error) {
	bucket := strings.TrimSpace(os.Getenv("REPLICA_BUCKET"))
	endpoint := strings.TrimSpace(os.Getenv("REPLICA_ENDPOINT"))
	accessKey := strings.TrimSpace(os.Getenv("LITESTREAM_ACCESS_KEY_ID"))
	secretKey := strings.TrimSpace(os.Getenv("LITESTREAM_SECRET_ACCESS_KEY"))

	var missing []string
	if bucket == "" {
		missing = append(missing, "REPLICA_BUCKET")
	}
	if endpoint == "" {
		missing = append(missing, "REPLICA_ENDPOINT")
	}
	if accessKey == "" {
		missing = append(missing, "LITESTREAM_ACCESS_KEY_ID")
	}
	if secretKey == "" {
		missing = append(missing, "LITESTREAM_SECRET_ACCESS_KEY")
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}

	timeoutStr := getEnvOrDefault("SHUTDOWN_TIMEOUT", "10s")
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		slog.Warn("invalid SHUTDOWN_TIMEOUT, defaulting to 10s", "component", "supervisor", "input", timeoutStr)
		timeout = 10 * time.Second
	}

	startupTimeoutStr := getEnvOrDefault("STARTUP_TIMEOUT", "30s")
	startupTimeout, err := time.ParseDuration(startupTimeoutStr)
	if err != nil {
		slog.Warn("invalid STARTUP_TIMEOUT, defaulting to 30s", "component", "supervisor", "input", startupTimeoutStr)
		startupTimeout = 30 * time.Second
	}

	// Strict Host / Domain validation
	domainStr := strings.TrimSpace(os.Getenv("DOMAIN"))
	strictHostStr := strings.ToLower(strings.TrimSpace(os.Getenv("STRICT_HOST")))
	strictHost := strictHostStr == "true" || strictHostStr == "1"

	var allowedHosts []string
	if rawHosts := os.Getenv("ALLOWED_HOSTS"); rawHosts != "" {
		strictHost = true
		for _, h := range strings.Split(rawHosts, ",") {
			if trimmed := strings.ToLower(strings.TrimSpace(h)); trimmed != "" {
				allowedHosts = append(allowedHosts, trimmed)
			}
		}
	}

	var domainPath string
	if domainStr != "" {
		dHost := domainStr
		if !strings.Contains(dHost, "://") {
			dHost = "https://" + dHost
		}
		if u, err := url.Parse(dHost); err == nil {
			if u.Path != "" && u.Path != "/" {
				domainPath = strings.TrimRight(u.Path, "/")
			}
			if (strictHost || len(allowedHosts) > 0) && u.Hostname() != "" {
				h := strings.ToLower(u.Hostname())
				exists := false
				for _, ah := range allowedHosts {
					if ah == h {
						exists = true
						break
					}
				}
				if !exists {
					allowedHosts = append(allowedHosts, h)
				}
			}
		}
	}

	return &Config{
		ReplicaBucket:          bucket,
		ReplicaEndpoint:        endpoint,
		ReplicaRegion:          strings.TrimSpace(os.Getenv("REPLICA_REGION")),
		ReplicaPath:            getEnvOrDefault("REPLICA_PATH", "vaultwarden-db"),
		LitestreamAccessKeyID:  accessKey,
		LitestreamSecretKey:    secretKey,
		RsaPrivateKeyPEM:       strings.TrimSpace(os.Getenv("RSA_PRIVATE_KEY_PEM")),
		RsaPassphrase:          strings.TrimSpace(os.Getenv("RSA_PASSPHRASE")),
		DBPath:                 getEnvOrDefault("DB_PATH", "/data/db.sqlite3"),
		DataFolder:             getEnvOrDefault("DATA_FOLDER", "/data"),
		ConfigPath:             getEnvOrDefault("LITESTREAM_CONFIG_PATH", "/etc/litestream.yml"),
		SocketPath:             getEnvOrDefault("LITESTREAM_SOCKET_PATH", "/tmp/litestream.sock"),
		LitestreamBin:          getEnvOrDefault("LITESTREAM_BIN", "litestream"),
		VaultwardenBin:         getEnvOrDefault("VAULTWARDEN_BIN", "/vaultwarden"),
		SyncInterval:           parseDurationOrDefault("SYNC_INTERVAL", "1s"),
		SnapshotInterval:       parseDurationOrDefault("SNAPSHOT_INTERVAL", "12h"),
		Retention:              parseDurationOrDefault("RETENTION", "168h"),
		ShutdownTimeoutSeconds: timeout,
		StartupTimeout:         startupTimeout,
		AllowedHosts:           allowedHosts,
		StrictHost:             strictHost && len(allowedHosts) > 0,
		DomainPath:             domainPath,
		PublicPort:             getEnvOrDefault("PORT", "8080"),
		InternalPort:           getEnvOrDefault("INTERNAL_PORT", "8081"),
		ProjectID: func() string {
			for _, k := range []string{"GCP_PROJECT", "GOOGLE_CLOUD_PROJECT", "PROJECT_ID"} {
				if v := strings.TrimSpace(os.Getenv(k)); v != "" {
					return v
				}
			}
			return ""
		}(),
	}, nil
}

func ensureDirectories(cfg *Config) error {
	dirs := []string{
		cfg.DataFolder,
		filepath.Dir(cfg.DBPath),
		filepath.Dir(cfg.ConfigPath),
		filepath.Dir(cfg.SocketPath),
	}
	for _, dir := range dirs {
		if dir == "" || dir == "." || dir == "/" {
			continue
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %q: %w", dir, err)
		}
	}
	return nil
}

func setupRSAKey(ctx context.Context, cfg *Config, s3 *S3Client) error {
	keyPath := filepath.Join(cfg.DataFolder, "rsa_key.pem")

	passphrase := cfg.RsaPassphrase
	if passphrase == "" {
		passphrase = cfg.LitestreamSecretKey
		slog.Info("RSA_PASSPHRASE not set; deriving encryption key from LITESTREAM_SECRET_ACCESS_KEY", "component", "supervisor")
	} else {
		slog.Info("using explicit RSA_PASSPHRASE for RSA key encryption", "component", "supervisor")
	}

	s3Key := path.Clean(cfg.ReplicaPath + "/rsa_key.pem.enc")

	// 1. If local key file already exists (e.g. persistent volume or warm restart)
	if data, err := os.ReadFile(keyPath); err == nil && len(data) > 0 {
		slog.Info("found existing RSA private key", "component", "supervisor", "path", keyPath)
		_ = os.Chmod(keyPath, 0600)
		return nil
	}

	// 2. If explicit RSA_PRIVATE_KEY_PEM environment variable is provided
	if cfg.RsaPrivateKeyPEM != "" {
		pemBytes := []byte(strings.TrimSpace(cfg.RsaPrivateKeyPEM) + "\n")
		if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
			return fmt.Errorf("failed to write injected RSA key to %s: %w", keyPath, err)
		}
		slog.Info("injected RSA private key from RSA_PRIVATE_KEY_PEM", "component", "supervisor", "path", keyPath)

		// Upload encrypted copy to S3 for backup
		encrypted, err := EncryptAESGCM(passphrase, pemBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt RSA key for S3 backup: %w", err)
		}
		if err := s3.PutObject(ctx, cfg.ReplicaBucket, s3Key, encrypted); err != nil {
			slog.Warn("failed to upload encrypted RSA key backup to S3", "component", "supervisor", "error", err)
		} else {
			slog.Info("successfully backed up encrypted RSA key to S3", "component", "supervisor", "bucket", cfg.ReplicaBucket, "key", s3Key)
		}
		return nil
	}

	// 3. Try to restore encrypted key from S3
	slog.Info("checking remote S3 for existing encrypted RSA key", "component", "supervisor", "bucket", cfg.ReplicaBucket, "key", s3Key)
	encData, statusCode, err := s3.GetObject(ctx, cfg.ReplicaBucket, s3Key)
	if err == nil {
		decryptedPEM, err := DecryptAESGCM(passphrase, encData)
		if err != nil {
			return fmt.Errorf("failed to decrypt RSA key from S3 (check RSA_PASSPHRASE or secret key): %w", err)
		}

		if err := os.WriteFile(keyPath, decryptedPEM, 0600); err != nil {
			return fmt.Errorf("failed to write decrypted RSA key to %s: %w", keyPath, err)
		}

		slog.Info("successfully restored and decrypted RSA private key from S3", "component", "supervisor", "path", keyPath)
		return nil
	}

	if errors.Is(err, ErrObjectNotFound) || statusCode == http.StatusNotFound {
		// 4. Not found in S3 -> Generate fresh 2048-bit RSA key natively in Go
		slog.Info("no existing RSA key found in S3; generating fresh 2048-bit RSA key", "component", "supervisor")
		newPEM, err := GenerateRSAKeyPEM()
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}

		if err := os.WriteFile(keyPath, newPEM, 0600); err != nil {
			return fmt.Errorf("failed to write new RSA key to %s: %w", keyPath, err)
		}
		slog.Info("generated new RSA private key", "component", "supervisor", "path", keyPath)

		// Encrypt and upload to S3
		encrypted, err := EncryptAESGCM(passphrase, newPEM)
		if err != nil {
			return fmt.Errorf("failed to encrypt newly generated RSA key: %w", err)
		}

		if err := s3.PutObject(ctx, cfg.ReplicaBucket, s3Key, encrypted); err != nil {
			return fmt.Errorf("failed to store encrypted RSA key in S3: %w", err)
		}

		slog.Info("successfully uploaded encrypted RSA key to S3", "component", "supervisor", "bucket", cfg.ReplicaBucket, "key", s3Key)
		return nil
	}

	// 5. Fail-closed on network/credentials/server error
	return fmt.Errorf("failed to retrieve RSA key from S3 (HTTP status %d): %w", statusCode, err)
}

func generateLitestreamConfig(cfg *Config) error {
	var sb strings.Builder
	sb.WriteString("# Generated dynamically by vaultwarden-serverless supervisor\n")
	sb.WriteString("socket:\n")
	sb.WriteString("  enabled: true\n")
	sb.WriteString(fmt.Sprintf("  path: %s\n", cfg.SocketPath))
	sb.WriteString("dbs:\n")
	sb.WriteString(fmt.Sprintf("  - path: %s\n", cfg.DBPath))
	sb.WriteString("    replicas:\n")
	sb.WriteString("      - type: s3\n")
	sb.WriteString(fmt.Sprintf("        bucket: %s\n", cfg.ReplicaBucket))
	sb.WriteString(fmt.Sprintf("        path: %s\n", cfg.ReplicaPath))
	sb.WriteString(fmt.Sprintf("        endpoint: %s\n", cfg.ReplicaEndpoint))
	if cfg.ReplicaRegion != "" {
		sb.WriteString(fmt.Sprintf("        region: %s\n", cfg.ReplicaRegion))
	}
	sb.WriteString(fmt.Sprintf("        sync-interval: %s\n", cfg.SyncInterval))
	sb.WriteString(fmt.Sprintf("        snapshot-interval: %s\n", cfg.SnapshotInterval))
	sb.WriteString(fmt.Sprintf("        retention: %s\n", cfg.Retention))

	if err := os.WriteFile(cfg.ConfigPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write litestream config to %q: %w", cfg.ConfigPath, err)
	}

	slog.Info("generated Litestream configuration", "component", "supervisor", "path", cfg.ConfigPath)
	return nil
}

func restoreDatabase(ctx context.Context, cfg *Config) error {
	slog.Info("checking remote replica and restoring database if present", "component", "supervisor", "db_path", cfg.DBPath)

	cmd := exec.CommandContext(ctx, cfg.LitestreamBin, "restore",
		"-if-replica-exists",
		"-if-db-not-exists",
		"-config", cfg.ConfigPath,
		cfg.DBPath,
	)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("litestream restore failed to start: %w", err)
	}

	go PipeProcessLogs(ctx, stdoutPipe, "litestream", false)
	go PipeProcessLogs(ctx, stderrPipe, "litestream", true)

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("litestream restore failed with error: %w", err)
	}

	if _, err := os.Stat(cfg.DBPath); err == nil {
		slog.Info("database is ready (restored or existing)", "component", "supervisor", "db_path", cfg.DBPath)
	} else {
		slog.Info("no existing replica found in remote storage, will initialize new db", "component", "supervisor")
	}

	return nil
}

// executeExplicitSync forces an immediate WAL-to-LTX conversion and remote S3 replication.
// It blocks until the remote storage acknowledges durability and returns the confirmed transaction IDs.
func executeExplicitSync(ctx context.Context, cfg *Config, timeoutSec int) (*SyncResult, error) {
	if _, err := os.Stat(cfg.DBPath); os.IsNotExist(err) {
		slog.Info("database file does not exist; skipping explicit sync", "component", "supervisor", "db_path", cfg.DBPath)
		return nil, nil
	}

	timeoutStr := strconv.Itoa(timeoutSec)
	cmd := exec.CommandContext(ctx, cfg.LitestreamBin, "sync",
		"-wait",
		"-timeout", timeoutStr,
		"-socket", cfg.SocketPath,
		"-json",
		cfg.DBPath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if errStr != "" {
			ProcessLine(ctx, slog.Default(), errStr, "litestream", true)
		}
		return nil, fmt.Errorf("sync command failed (%w): %s", err, errStr)
	}

	var res SyncResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("failed to parse sync output %q: %w", stdout.String(), err)
	}

	return &res, nil
}

func waitForSocket(socketPath string, procDone <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-procDone:
			return fmt.Errorf("daemon exited prematurely while waiting for socket: %w", err)
		default:
		}

		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s waiting for socket %s", timeout, socketPath)
}

func stopProcess(cmd *exec.Cmd, done <-chan error, sig os.Signal, timeout time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if err := cmd.Process.Signal(sig); err != nil {
		if errors.Is(err, os.ErrProcessDone) || strings.Contains(err.Error(), "process already finished") {
			return nil
		}
		return fmt.Errorf("failed to signal PID %d: %w", cmd.Process.Pid, err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case err := <-done:
		return err
	case <-timer.C:
		slog.Warn("process timed out; escalating to SIGKILL", "component", "supervisor", "pid", cmd.Process.Pid, "timeout", timeout.String())
		_ = cmd.Process.Kill()
		<-done
		return fmt.Errorf("process PID %d killed after timeout %s", cmd.Process.Pid, timeout)
	}
}

func waitForBackendAlive(aliveURL string, procDone <-chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}

	for {
		select {
		case err := <-procDone:
			if err == nil {
				return errors.New("backend process exited unexpectedly with status 0")
			}
			return fmt.Errorf("backend process exited prematurely: %w", err)
		default:
		}

		resp, err := client.Get(aliveURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %v waiting for %s", timeout, aliveURL)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func gracefulShutdown(cfg *Config, vwCmd *exec.Cmd, vwDone <-chan error, lsCmd *exec.Cmd, lsDone <-chan error, proxy *ReverseProxyServer) int {
	deadline := time.Now().Add(cfg.ShutdownTimeoutSeconds)
	exitCode := 0

	// Phase 0: Drain in-flight HTTP requests from reverse proxy
	if proxy != nil {
		slog.Info("draining in-flight HTTP requests from reverse proxy", "component", "supervisor", "phase", "0/3")
		proxy.Drain(5 * time.Second)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = proxy.Shutdown(shutdownCtx)
		cancel()
	}

	// Phase 1: Graceful stop Vaultwarden (Freeze Writes)
	slog.Info("stopping Vaultwarden to freeze SQLite writes", "component", "supervisor", "phase", "1/3", "pid", vwCmd.Process.Pid)
	vwTimeout := cfg.ShutdownTimeoutSeconds / 3
	if vwTimeout < 2*time.Second {
		vwTimeout = 2 * time.Second
	}
	if vwTimeout > 5*time.Second {
		vwTimeout = 5 * time.Second
	}
	if err := stopProcess(vwCmd, vwDone, syscall.SIGTERM, vwTimeout); err != nil {
		slog.Warn("Vaultwarden did not stop cleanly within timeout", "component", "supervisor", "timeout", vwTimeout.String(), "error", err)
	} else {
		slog.Info("Vaultwarden stopped cleanly; SQLite writes are frozen", "component", "supervisor", "phase", "1/3")
	}

	// Phase 2: Explicit Sync to remote S3
	remaining := time.Until(deadline) - 1500*time.Millisecond
	syncSec := int(remaining.Seconds())
	if syncSec < 2 {
		syncSec = 2
	}
	slog.Info("executing explicit Litestream sync", "component", "supervisor", "phase", "2/3", "timeout_sec", syncSec)
	syncRes, err := executeExplicitSync(context.Background(), cfg, syncSec)
	if err != nil {
		slog.Error("explicit sync failed", "component", "supervisor", "phase", "2/3", "error", err)
		exitCode = 1
	} else if syncRes != nil {
		if syncRes.TxID != syncRes.ReplicaTxID {
			slog.Warn("txid mismatch after sync", "component", "supervisor", "phase", "2/3", "txid", syncRes.TxID, "replica_txid", syncRes.ReplicaTxID)
			exitCode = 1
		} else {
			slog.Info("replication confirmed durable in remote S3", "component", "supervisor", "phase", "2/3",
				"txid", syncRes.TxID, "replica_txid", syncRes.ReplicaTxID, "latency_ms", syncRes.DurationMS)
		}
	}

	// Phase 3: Graceful stop Litestream daemon
	slog.Info("stopping Litestream daemon", "component", "supervisor", "phase", "3/3", "pid", lsCmd.Process.Pid)
	lsTimeout := time.Until(deadline)
	if lsTimeout < 1*time.Second {
		lsTimeout = 1 * time.Second
	}
	if err := stopProcess(lsCmd, lsDone, syscall.SIGTERM, lsTimeout); err != nil {
		slog.Warn("Litestream daemon did not stop cleanly", "component", "supervisor", "error", err)
		if exitCode == 0 {
			exitCode = 1
		}
	} else {
		slog.Info("Litestream daemon terminated cleanly; teardown complete", "component", "supervisor", "phase", "3/3")
	}

	return exitCode
}

func runDualProcess(ctx context.Context, cfg *Config, proxy *ReverseProxyServer) int {
	// Clean up stale socket file if it exists
	_ = os.Remove(cfg.SocketPath)

	// 1. Start Litestream replication daemon
	slog.Info("starting Litestream daemon", "component", "supervisor", "bin", cfg.LitestreamBin, "config", cfg.ConfigPath)
	lsCmd := exec.CommandContext(ctx, cfg.LitestreamBin, "replicate", "-config", cfg.ConfigPath)
	lsCmd.Stdin = os.Stdin
	lsStdout, err := lsCmd.StdoutPipe()
	if err != nil {
		slog.Error("failed to create Litestream stdout pipe", "component", "supervisor", "error", err)
		return 1
	}
	lsStderr, err := lsCmd.StderrPipe()
	if err != nil {
		slog.Error("failed to create Litestream stderr pipe", "component", "supervisor", "error", err)
		return 1
	}
	lsCmd.Env = os.Environ()

	if err := lsCmd.Start(); err != nil {
		slog.Error("failed to start Litestream daemon", "component", "supervisor", "error", err)
		return 1
	}
	slog.Info("Litestream daemon started; waiting for control socket", "component", "supervisor", "pid", lsCmd.Process.Pid)

	go PipeProcessLogs(ctx, lsStdout, "litestream", false)
	go PipeProcessLogs(ctx, lsStderr, "litestream", true)

	lsDone := make(chan error, 1)
	go func() {
		lsDone <- lsCmd.Wait()
	}()

	if err := waitForSocket(cfg.SocketPath, lsDone, 5*time.Second); err != nil {
		slog.Error("Litestream control socket failed to initialize", "component", "supervisor", "error", err)
		_ = lsCmd.Process.Kill()
		return 1
	}
	slog.Info("Litestream control socket ready", "component", "supervisor", "socket", cfg.SocketPath)

	// 2. Start Vaultwarden web server on internal loopback port
	slog.Info("starting Vaultwarden on internal loopback", "component", "supervisor", "bin", cfg.VaultwardenBin, "port", cfg.InternalPort)
	vwCmd := exec.CommandContext(ctx, cfg.VaultwardenBin)
	vwCmd.Stdin = os.Stdin
	vwStdout, err := vwCmd.StdoutPipe()
	if err != nil {
		slog.Error("failed to create Vaultwarden stdout pipe", "component", "supervisor", "error", err)
		_ = stopProcess(lsCmd, lsDone, syscall.SIGTERM, 2*time.Second)
		return 1
	}
	vwStderr, err := vwCmd.StderrPipe()
	if err != nil {
		slog.Error("failed to create Vaultwarden stderr pipe", "component", "supervisor", "error", err)
		_ = stopProcess(lsCmd, lsDone, syscall.SIGTERM, 2*time.Second)
		return 1
	}
	// Route Vaultwarden to internal loopback port and configure client IP extraction
	vwCmd.Env = append(os.Environ(),
		fmt.Sprintf("ROCKET_PORT=%s", cfg.InternalPort),
		"ROCKET_ADDRESS=127.0.0.1",
		"IP_HEADER=X-Real-IP",
	)

	if err := vwCmd.Start(); err != nil {
		slog.Error("failed to start Vaultwarden", "component", "supervisor", "error", err)
		_ = stopProcess(lsCmd, lsDone, syscall.SIGTERM, 2*time.Second)
		return 1
	}
	slog.Info("Vaultwarden started; waiting for internal readiness probe", "component", "supervisor", "pid", vwCmd.Process.Pid)

	go PipeProcessLogs(ctx, vwStdout, "vaultwarden", false)
	go PipeProcessLogs(ctx, vwStderr, "vaultwarden", true)

	vwDone := make(chan error, 1)
	go func() {
		vwDone <- vwCmd.Wait()
	}()

	// Wait for Vaultwarden's internal /alive probe (accounting for DOMAIN subpath if set)
	probePath := path.Join("/", cfg.DomainPath, "alive")
	aliveURL := fmt.Sprintf("http://127.0.0.1:%s%s", cfg.InternalPort, probePath)
	if err := waitForBackendAlive(aliveURL, vwDone, 10*time.Second); err != nil {
		slog.Error("Vaultwarden failed to become ready", "component", "supervisor", "error", err)
		_ = vwCmd.Process.Kill()
		_ = stopProcess(lsCmd, lsDone, syscall.SIGTERM, 2*time.Second)
		return 1
	}
	slog.Info("Vaultwarden backend is ready on internal port; all services operational", "component", "supervisor", "url", aliveURL)
	if proxy != nil {
		proxy.MarkReady()
	}

	// Register TAINT handler so external deployers can disarm this instance safely
	taintCh := make(chan struct{})
	if proxy != nil {
		proxy.RegisterTaintHandler(func(taintCtx context.Context) (*SyncResult, error) {
			slog.Info("executing taint teardown sequence", "component", "supervisor")

			// Phase 1: Stop Vaultwarden to freeze writes
			slog.Info("stopping Vaultwarden to freeze SQLite writes (TAINT phase 1)", "component", "supervisor")
			vwTimeout := cfg.ShutdownTimeoutSeconds / 3
			if vwTimeout < 2*time.Second {
				vwTimeout = 2 * time.Second
			}
			if vwTimeout > 5*time.Second {
				vwTimeout = 5 * time.Second
			}
			if err := stopProcess(vwCmd, vwDone, syscall.SIGTERM, vwTimeout); err != nil {
				slog.Warn("Vaultwarden did not stop cleanly during taint", "component", "supervisor", "error", err)
			} else {
				slog.Info("Vaultwarden stopped cleanly for taint; SQLite writes frozen", "component", "supervisor")
			}

			// Phase 2: Explicit S3 sync
			slog.Info("executing explicit Litestream sync to remote S3 (TAINT phase 2)", "component", "supervisor")
			syncRes, err := executeExplicitSync(context.Background(), cfg, 10)
			if err != nil {
				slog.Error("explicit sync failed during taint", "component", "supervisor", "error", err)
			} else if syncRes != nil {
				slog.Info("replication confirmed durable in remote S3 during taint", "component", "supervisor",
					"txid", syncRes.TxID, "replica_txid", syncRes.ReplicaTxID, "latency_ms", syncRes.DurationMS)
			}

			// Phase 3: Stop Litestream daemon
			slog.Info("stopping Litestream daemon (TAINT phase 3)", "component", "supervisor")
			if err := stopProcess(lsCmd, lsDone, syscall.SIGTERM, 5*time.Second); err != nil {
				slog.Warn("Litestream daemon did not stop cleanly during taint", "component", "supervisor", "error", err)
			} else {
				slog.Info("Litestream daemon stopped cleanly for taint", "component", "supervisor")
			}

			close(taintCh)
			return syncRes, err
		})

		proxy.RegisterSyncHandler(func(syncCtx context.Context) (*SyncResult, error) {
			slog.Info("triggering on-demand Litestream sync to remote S3 via API", "component", "supervisor")
			return executeExplicitSync(syncCtx, cfg, 10)
		})
	}

	// 3. Monitor signals and process exits
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	select {
	case sig := <-sigChan:
		slog.Info("received shutdown signal; initiating 3-phase graceful teardown", "component", "supervisor", "signal", sig.String())
		return gracefulShutdown(cfg, vwCmd, vwDone, lsCmd, lsDone, proxy)

	case <-taintCh:
		slog.Info("instance successfully tainted and disarmed; entering holding state for Cloud Run SIGTERM", "component", "supervisor")

	case err := <-vwDone:
		if proxy != nil && proxy.IsTainted() {
			slog.Info("Vaultwarden process stopped cleanly for taint", "component", "supervisor")
		} else {
			slog.Info("Vaultwarden process exited; triggering final sync and teardown", "component", "supervisor", "status", err)
			_, _ = executeExplicitSync(context.Background(), cfg, 5)
			_ = stopProcess(lsCmd, lsDone, syscall.SIGTERM, 3*time.Second)
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					return exitErr.ExitCode()
				}
				return 1
			}
			return 0
		}

	case err := <-lsDone:
		if proxy != nil && proxy.IsTainted() {
			slog.Info("Litestream daemon stopped cleanly for taint", "component", "supervisor")
		} else {
			slog.Error("Litestream replication daemon terminated unexpectedly (FAIL-CLOSED)", "component", "supervisor", "error", err)
			slog.Error("halting Vaultwarden immediately to prevent un-replicated data writes", "component", "supervisor")
			_ = stopProcess(vwCmd, vwDone, syscall.SIGTERM, 2*time.Second)
			return 1
		}
	}

	// If tainted, hold in disarmed sentinel state until SIGTERM arrives from Cloud Run (or watchdog expires)
	if proxy != nil && proxy.IsTainted() {
		slog.Info("holding in disarmed state (returning 503 to traffic); waiting for SIGTERM from Cloud Run", "component", "supervisor")
		watchdog := time.NewTimer(5 * time.Minute)
		defer watchdog.Stop()

		select {
		case sig := <-sigChan:
			slog.Info("received termination signal in tainted state; exiting cleanly", "component", "supervisor", "signal", sig.String())
			return 0
		case <-watchdog.C:
			slog.Info("taint holding watchdog expired (5m); exiting cleanly to free Cloud Run slot", "component", "supervisor")
			return 0
		}
	}

	return 0
}

func main() {
	InitLogger()
	slog.Info("initializing Vaultwarden-Litestream Serverless Container Supervisor (PID 1)", "component", "supervisor")

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("fatal configuration error", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	slog.Info("configuration loaded successfully", "component", "supervisor",
		"bucket", cfg.ReplicaBucket, "endpoint", cfg.ReplicaEndpoint, "db_path", cfg.DBPath,
		"public_port", cfg.PublicPort, "internal_port", cfg.InternalPort,
		"sync_interval", cfg.SyncInterval, "snapshot_interval", cfg.SnapshotInterval,
		"startup_timeout", cfg.StartupTimeout.String(), "shutdown_timeout", cfg.ShutdownTimeoutSeconds.String(),
		"strict_host", cfg.StrictHost, "allowed_hosts", strings.Join(cfg.AllowedHosts, ","))

	if err := ensureDirectories(cfg); err != nil {
		slog.Error("failed to initialize directories", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	// Assemble administrative authorization tokens for /_supervisor/taint
	var authTokens []string
	if cfg.LitestreamSecretKey != "" {
		authTokens = append(authTokens, cfg.LitestreamSecretKey)
	}
	if adminToken := strings.TrimSpace(os.Getenv("ADMIN_TOKEN")); adminToken != "" {
		authTokens = append(authTokens, adminToken)
	}
	if supToken := strings.TrimSpace(os.Getenv("SUPERVISOR_TOKEN")); supToken != "" {
		authTokens = append(authTokens, supToken)
	}

	// Start Reverse Proxy server immediately on public port so Cloud Run gets 200 OK for probes
	proxyServer, err := NewReverseProxyServer(ProxyConfig{
		ListenAddr:     fmt.Sprintf(":%s", cfg.PublicPort),
		TargetURL:      fmt.Sprintf("http://127.0.0.1:%s", cfg.InternalPort),
		ProjectID:      cfg.ProjectID,
		StartupTimeout: cfg.StartupTimeout,
		AllowedHosts:   cfg.AllowedHosts,
		StrictHost:     cfg.StrictHost,
		AuthTokens:     authTokens,
	})
	if err != nil {
		slog.Error("failed to create reverse proxy", "component", "supervisor", "error", err)
		os.Exit(1)
	}
	if err := proxyServer.Start(); err != nil {
		slog.Error("failed to start reverse proxy", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	s3Client := NewS3Client(cfg.ReplicaEndpoint, cfg.ReplicaRegion, cfg.LitestreamAccessKeyID, cfg.LitestreamSecretKey)

	if err := setupRSAKey(ctx, cfg, s3Client); err != nil {
		slog.Error("failed to configure RSA key", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	if err := generateLitestreamConfig(cfg); err != nil {
		slog.Error("failed to generate Litestream configuration", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	if err := restoreDatabase(ctx, cfg); err != nil {
		slog.Error("database restore failed (FAIL-CLOSED); halting container to prevent empty DB overwrite", "component", "supervisor", "error", err)
		os.Exit(1)
	}

	exitCode := runDualProcess(ctx, cfg, proxyServer)
	os.Exit(exitCode)
}
