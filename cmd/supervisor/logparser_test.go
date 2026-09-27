package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestParseVaultwardenLog_Success(t *testing.T) {
	line := "[2026-09-27 02:44:26.033][start][INFO] Rocket has launched from http://0.0.0.0:8080"
	record, ok := ParseVaultwardenLog(line)
	if !ok {
		t.Fatalf("expected line to parse successfully, got false")
	}

	if record.Level != slog.LevelInfo {
		t.Errorf("expected level INFO, got %v", record.Level)
	}
	if record.Message != "Rocket has launched from http://0.0.0.0:8080" {
		t.Errorf("expected message 'Rocket has launched from http://0.0.0.0:8080', got %q", record.Message)
	}

	attrs := make(map[string]string)
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	if attrs["component"] != "vaultwarden" {
		t.Errorf("expected component=vaultwarden, got %s", attrs["component"])
	}
	if attrs["target"] != "start" {
		t.Errorf("expected target=start, got %s", attrs["target"])
	}
	if _, hasStderr := attrs["stderr"]; hasStderr {
		t.Errorf("parsed log should NOT have 'stderr' attribute, but found: %s", attrs["stderr"])
	}
}

func TestParseVaultwardenLog_ErrorLevel(t *testing.T) {
	line := "[2026-09-27 02:43:57.773][vaultwarden][ERROR] No persistent volume!"
	record, ok := ParseVaultwardenLog(line)
	if !ok {
		t.Fatalf("expected error log to parse successfully, got false")
	}

	if record.Level != slog.LevelError {
		t.Errorf("expected level ERROR, got %v", record.Level)
	}
	if record.Message != "No persistent volume!" {
		t.Errorf("expected message 'No persistent volume!', got %q", record.Message)
	}
}

func TestParseVaultwardenLog_Unparseable(t *testing.T) {
	unparseableLines := []string{
		"/--------------------------------------------------------------------\\",
		"|                        Starting Vaultwarden                        |",
		"########################################################################################",
		"Plain unformatted stdout line",
	}

	for _, line := range unparseableLines {
		_, ok := ParseVaultwardenLog(line)
		if ok {
			t.Errorf("expected line %q to fail parsing, but returned true", line)
		}
	}
}

func TestParseLitestreamLog_Success(t *testing.T) {
	line := `time=2026-09-27T02:44:25.474Z level=INFO msg="control socket listening" system=server path=/tmp/litestream.sock`
	record, ok := ParseLitestreamLog(line)
	if !ok {
		t.Fatalf("expected litestream log to parse successfully, got false")
	}

	if record.Level != slog.LevelInfo {
		t.Errorf("expected level INFO, got %v", record.Level)
	}
	if record.Message != "control socket listening" {
		t.Errorf("expected message 'control socket listening', got %q", record.Message)
	}

	attrs := make(map[string]string)
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	if attrs["component"] != "litestream" {
		t.Errorf("expected component=litestream, got %s", attrs["component"])
	}
	if attrs["system"] != "server" {
		t.Errorf("expected system=server, got %s", attrs["system"])
	}
	if attrs["path"] != "/tmp/litestream.sock" {
		t.Errorf("expected path=/tmp/litestream.sock, got %s", attrs["path"])
	}
	if _, hasStderr := attrs["stderr"]; hasStderr {
		t.Errorf("parsed log should NOT have 'stderr' attribute, but found: %s", attrs["stderr"])
	}
}

func TestParseLitestreamLog_Replicating(t *testing.T) {
	line := `time=2026-09-27T02:44:25.475Z level=INFO msg="replicating to" type=s3 sync-interval=1s bucket=gcp-edge-link path=e2e-sync-test region="" endpoint=s3.us-west-004.backblazeb2.com`
	record, ok := ParseLitestreamLog(line)
	if !ok {
		t.Fatalf("expected replicating log to parse successfully, got false")
	}

	if record.Message != "replicating to" {
		t.Errorf("expected msg 'replicating to', got %q", record.Message)
	}

	attrs := make(map[string]string)
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})

	if attrs["bucket"] != "gcp-edge-link" {
		t.Errorf("expected bucket=gcp-edge-link, got %s", attrs["bucket"])
	}
	if attrs["type"] != "s3" {
		t.Errorf("expected type=s3, got %s", attrs["type"])
	}
}

func TestParseLitestreamLog_Unparseable(t *testing.T) {
	unparseableLines := []string{
		"Error: sync failed: database not found",
		"Signal received",
		"Random banner without msg=",
	}

	for _, line := range unparseableLines {
		_, ok := ParseLitestreamLog(line)
		if ok {
			t.Errorf("expected line %q to fail parsing, but returned true", line)
		}
	}
}

func TestProcessLine_UnparseableDumpsToStderrField(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx := context.Background()

	// 1. Unparseable line from stderr
	rawErrLine := "Error: something crashed unexpectedly in background"
	ProcessLine(ctx, logger, rawErrLine, "vaultwarden", true)

	var entry1 map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry1); err != nil {
		t.Fatalf("failed to parse slog JSON: %v", err)
	}

	if entry1["level"] != "ERROR" {
		t.Errorf("expected level ERROR for stderr unparseable line, got %v", entry1["level"])
	}
	if entry1["stderr"] != rawErrLine {
		t.Errorf("expected 'stderr' field to contain %q, got %v", rawErrLine, entry1["stderr"])
	}
	if entry1["component"] != "vaultwarden" {
		t.Errorf("expected component=vaultwarden, got %v", entry1["component"])
	}

	buf.Reset()

	// 2. Unparseable line from stdout
	stdoutLine := "Notice: custom plugin initialized"
	ProcessLine(ctx, logger, stdoutLine, "vaultwarden", false)

	var entry2 map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry2); err != nil {
		t.Fatalf("failed to parse slog JSON: %v", err)
	}

	if entry2["level"] != "INFO" {
		t.Errorf("expected level INFO for stdout unparseable line, got %v", entry2["level"])
	}
	if entry2["stderr"] != stdoutLine {
		t.Errorf("expected 'stderr' field to contain %q, got %v", stdoutLine, entry2["stderr"])
	}

	buf.Reset()

	// 3. Parseable line: should NOT have 'stderr' field
	validLine := "[2026-09-27 02:44:26.033][start][INFO] Server started"
	ProcessLine(ctx, logger, validLine, "vaultwarden", false)

	var entry3 map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry3); err != nil {
		t.Fatalf("failed to parse slog JSON: %v", err)
	}

	if _, hasStderr := entry3["stderr"]; hasStderr {
		t.Errorf("successfully parsed line must NOT have 'stderr' field, got %v", entry3["stderr"])
	}
	if entry3["msg"] != "Server started" {
		t.Errorf("expected msg 'Server started', got %v", entry3["msg"])
	}
	if entry3["target"] != "start" {
		t.Errorf("expected target 'start', got %v", entry3["target"])
	}
}

func TestPipeProcessLogs(t *testing.T) {
	input := `
[2026-09-27 02:44:26.033][start][INFO] Rocket launched
Unparseable banner 1
time=2026-09-27T02:44:26.034Z level=WARN msg="high memory"
Unparseable banner 2
`

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	PipeProcessLogs(context.Background(), strings.NewReader(input), "vaultwarden", false)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 JSON log lines, got %d:\n%s", len(lines), buf.String())
	}

	// Line 0: Parsed Vaultwarden
	var e0 map[string]interface{}
	_ = json.Unmarshal([]byte(lines[0]), &e0)
	if e0["msg"] != "Rocket launched" || e0["stderr"] != nil {
		t.Errorf("line 0 mismatch: %v", e0)
	}

	// Line 1: Unparseable banner 1 -> dumped to stderr field
	var e1 map[string]interface{}
	_ = json.Unmarshal([]byte(lines[1]), &e1)
	if e1["stderr"] != "Unparseable banner 1" {
		t.Errorf("line 1 should have stderr field, got %v", e1)
	}

	// Line 2: Parsed Litestream logfmt
	var e2 map[string]interface{}
	_ = json.Unmarshal([]byte(lines[2]), &e2)
	if e2["msg"] != "high memory" || e2["stderr"] != nil {
		t.Errorf("line 2 mismatch: %v", e2)
	}

	// Line 3: Unparseable banner 2 -> dumped to stderr field
	var e3 map[string]interface{}
	_ = json.Unmarshal([]byte(lines[3]), &e3)
	if e3["stderr"] != "Unparseable banner 2" {
		t.Errorf("line 3 should have stderr field, got %v", e3)
	}
}

func TestZerologHandler_ComponentFrontAndPadding(t *testing.T) {
	InitLogger()

	var buf bytes.Buffer
	zLogger := zerolog.New(&buf)
	handler := &ZerologHandler{logger: zLogger}
	logger := slog.New(handler)

	// Log with supervisor
	logger.Info("test supervisor log", slog.String("component", "supervisor"), slog.String("key", "val"))
	line1 := strings.TrimSpace(buf.String())
	buf.Reset()

	// Log with vaultwarden
	logger.Info("test vaultwarden log", slog.String("component", "vaultwarden"), slog.String("key", "val"))
	line2 := strings.TrimSpace(buf.String())
	buf.Reset()

	// Log with litestream
	logger.Info("test litestream log", slog.String("component", "litestream"), slog.String("key", "val"))
	line3 := strings.TrimSpace(buf.String())
	buf.Reset()

	// 1. Verify component is padded to 11 characters
	if !strings.Contains(line1, `"component":"supervisor "`) {
		t.Errorf("expected 'supervisor ' padded to 11 chars in line1, got %s", line1)
	}
	if !strings.Contains(line2, `"component":"vaultwarden"`) {
		t.Errorf("expected 'vaultwarden' padded to 11 chars in line2, got %s", line2)
	}
	if !strings.Contains(line3, `"component":"litestream "`) {
		t.Errorf("expected 'litestream ' padded to 11 chars in line3, got %s", line3)
	}

	// 2. Verify Cloud Run standard fields: severity and message
	if !strings.Contains(line1, `"severity":"INFO"`) {
		t.Errorf("expected 'severity':'INFO' in line1, got %s", line1)
	}
	if !strings.Contains(line1, `"message":"test supervisor log"`) {
		t.Errorf("expected 'message':'test supervisor log' in line1, got %s", line1)
	}

	// 3. Verify component appears before key/val and message in the raw JSON string
	idxComp := strings.Index(line1, `"component":`)
	idxKey := strings.Index(line1, `"key":`)
	idxMsg := strings.Index(line1, `"message":`)

	if idxComp == -1 || idxKey == -1 || idxMsg == -1 {
		t.Fatalf("missing expected fields in JSON: %s", line1)
	}
	if idxComp > idxKey || idxComp > idxMsg {
		t.Errorf("component must appear in front of key and message: comp=%d, key=%d, msg=%d in %s",
			idxComp, idxKey, idxMsg, line1)
	}
}

func TestZerologHandler_TimePadding(t *testing.T) {
	InitLogger()

	var buf bytes.Buffer
	zLogger := zerolog.New(&buf)
	handler := &ZerologHandler{logger: zLogger}
	logger := slog.New(handler)

	// Timestamp with 3 decimal places (milliseconds)
	tMilli := time.Date(2026, 9, 27, 5, 47, 4, 33000000, time.UTC)
	recordMilli := slog.NewRecord(tMilli, slog.LevelInfo, "milli test", 0)
	recordMilli.AddAttrs(slog.String("component", "vaultwarden"))
	_ = handler.Handle(context.Background(), recordMilli)

	lineMilli := strings.TrimSpace(buf.String())
	buf.Reset()

	// Timestamp with 9 decimal places (nanoseconds)
	tNano := time.Date(2026, 9, 27, 5, 47, 4, 625329827, time.UTC)
	recordNano := slog.NewRecord(tNano, slog.LevelInfo, "nano test", 0)
	recordNano.AddAttrs(slog.String("component", "supervisor"))
	_ = handler.Handle(context.Background(), recordNano)

	lineNano := strings.TrimSpace(buf.String())

	// Both time strings must be exactly 30 characters (2006-01-02T15:04:05.000000000Z)
	expectedMilliTime := `"time":"2026-09-27T05:47:04.033000000Z"`
	expectedNanoTime := `"time":"2026-09-27T05:47:04.625329827Z"`

	if !strings.Contains(lineMilli, expectedMilliTime) {
		t.Errorf("expected time to be zero-padded to 9 digits %s, got: %s", expectedMilliTime, lineMilli)
	}
	if !strings.Contains(lineNano, expectedNanoTime) {
		t.Errorf("expected time %s, got: %s", expectedNanoTime, lineNano)
	}

	_ = logger
}

func TestPipeProcessLogs_VaultwardenStartupBanner(t *testing.T) {
	bannerInput := `/--------------------------------------------------------------------\
|                        Starting Vaultwarden                        |
|                           Version 1.37.3                           |
|--------------------------------------------------------------------|
| This is an unofficial bitwarden implementation, but it's great!    |
| Please report bugs to the vaultwarden issue tracker.               |
\--------------------------------------------------------------------/
[2026-09-27 02:44:26.033][start][INFO] Rocket has launched from http://0.0.0.0:8080
`
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	PipeProcessLogs(context.Background(), strings.NewReader(bannerInput), "vaultwarden", false)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 log lines (1 for clean banner, 1 for rocket), got %d:\n%s", len(lines), buf.String())
	}

	var e0 map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &e0); err != nil {
		t.Fatalf("failed to unmarshal banner log: %v", err)
	}
	if e0["msg"] != "Starting Vaultwarden (v1.37.3)" {
		t.Errorf("expected clean message 'Starting Vaultwarden (v1.37.3)', got %v", e0["msg"])
	}
	if e0["version"] != "1.37.3" {
		t.Errorf("expected version '1.37.3', got %v", e0["version"])
	}
	if e0["component"] != "vaultwarden" {
		t.Errorf("expected component 'vaultwarden', got %v", e0["component"])
	}
	if _, hasStderr := e0["stderr"]; hasStderr {
		t.Errorf("banner log must NOT have 'stderr' field: %v", e0["stderr"])
	}

	var e1 map[string]interface{}
	if err := json.Unmarshal([]byte(lines[1]), &e1); err != nil {
		t.Fatalf("failed to unmarshal rocket log: %v", err)
	}
	if e1["msg"] != "Rocket has launched from http://0.0.0.0:8080" {
		t.Errorf("expected rocket launch msg, got %v", e1["msg"])
	}
}

