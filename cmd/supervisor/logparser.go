package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

const (
	// componentPadding defines the fixed column width for component names.
	// "vaultwarden" is 11 chars, so 11 ensures "supervisor " and "litestream "
	// align perfectly to the same column width.
	componentPadding = 11
)

var (
	vaultwardenLogRegex = regexp.MustCompile(`^\[([0-9]{4}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?)\]\[([^\]]+)\]\[([A-Za-z]+)\]\s*(.*)$`)
)

// padComponent right-pads the component name with spaces to componentPadding width.
func padComponent(name string) string {
	name = strings.TrimSpace(name)
	if len(name) >= componentPadding {
		return name
	}
	return name + strings.Repeat(" ", componentPadding-len(name))
}

func mapSlogLevelToZerolog(l slog.Level) zerolog.Level {
	switch {
	case l >= slog.LevelError:
		return zerolog.ErrorLevel
	case l >= slog.LevelWarn:
		return zerolog.WarnLevel
	case l >= slog.LevelInfo:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
}

// ZerologHandler implements slog.Handler powered by zerolog.
// It guarantees that "component" is positioned right at the front and padded for alignment.
type ZerologHandler struct {
	logger zerolog.Logger
}

func (h *ZerologHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.logger.GetLevel() <= mapSlogLevelToZerolog(level)
}

func (h *ZerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	subLogger := h.logger.With().Logger()
	for _, a := range attrs {
		if a.Key == "component" {
			subLogger = subLogger.With().Str("component", padComponent(a.Value.String())).Logger()
		} else {
			subLogger = subLogger.With().Any(a.Key, a.Value.Any()).Logger()
		}
	}
	return &ZerologHandler{logger: subLogger}
}

func (h *ZerologHandler) WithGroup(name string) slog.Handler {
	return h
}

func (h *ZerologHandler) Handle(_ context.Context, r slog.Record) error {
	zLevel := mapSlogLevelToZerolog(r.Level)
	evt := h.logger.WithLevel(zLevel)

	if !r.Time.IsZero() {
		evt = evt.Time("time", r.Time.UTC())
	}

	var componentVal string
	var stderrVal string
	otherAttrs := make([]slog.Attr, 0, r.NumAttrs())

	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "component":
			componentVal = a.Value.String()
		case "stderr":
			stderrVal = a.Value.String()
		default:
			otherAttrs = append(otherAttrs, a)
		}
		return true
	})

	if componentVal == "" {
		componentVal = "supervisor"
	}

	// ALWAYS output padded component at the front!
	evt = evt.Str("component", padComponent(componentVal))

	// Add other attributes in order
	for _, a := range otherAttrs {
		evt = evt.Any(a.Key, a.Value.Any())
	}

	// If unparseable stderr string is present, add it
	if stderrVal != "" {
		evt = evt.Str("stderr", stderrVal)
	}

	evt.Msg(r.Message)
	return nil
}

// InitLogger initializes the global logger powered by zerolog.
func InitLogger() {
	logFormat := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_FORMAT")))
	logLevelStr := strings.ToUpper(strings.TrimSpace(os.Getenv("LOG_LEVEL")))

	var zLevel zerolog.Level
	switch logLevelStr {
	case "DEBUG":
		zLevel = zerolog.DebugLevel
	case "WARN", "WARNING":
		zLevel = zerolog.WarnLevel
	case "ERROR":
		zLevel = zerolog.ErrorLevel
	default:
		zLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zLevel)
	// Fixed-width RFC3339 layout with 9-digit zero-padded nanoseconds for pixel-perfect column alignment
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.000000000Z07:00"
	zerolog.TimestampFieldName = "time"
	zerolog.LevelFieldName = "severity"
	zerolog.MessageFieldName = "message"
	zerolog.LevelFieldMarshalFunc = func(l zerolog.Level) string {
		switch l {
		case zerolog.TraceLevel, zerolog.DebugLevel:
			return "DEBUG"
		case zerolog.InfoLevel:
			return "INFO"
		case zerolog.WarnLevel:
			return "WARNING"
		case zerolog.ErrorLevel:
			return "ERROR"
		case zerolog.FatalLevel:
			return "CRITICAL"
		case zerolog.PanicLevel:
			return "EMERGENCY"
		default:
			return "DEFAULT"
		}
	}

	var zLogger zerolog.Logger
	if logFormat == "text" {
		cw := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05.000",
		}
		zLogger = zerolog.New(cw)
	} else {
		// Default to JSON format for Cloud Run and structured log aggregators
		zLogger = zerolog.New(os.Stdout)
	}

	handler := &ZerologHandler{logger: zLogger}
	slog.SetDefault(slog.New(handler))
}

func parseLevel(levelStr string) slog.Level {
	switch strings.ToUpper(levelStr) {
	case "TRACE":
		return slog.LevelDebug - 4
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR", "FATAL":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseVaultwardenLog parses a log line formatted with Vaultwarden's bracket structure.
func ParseVaultwardenLog(line string) (slog.Record, bool) {
	matches := vaultwardenLogRegex.FindStringSubmatch(line)
	if len(matches) != 5 {
		return slog.Record{}, false
	}

	timeStr := matches[1]
	target := matches[2]
	levelStr := matches[3]
	msg := matches[4]

	timestamp, err := time.Parse("2006-01-02 15:04:05.999999999", timeStr)
	if err != nil {
		timestamp, err = time.Parse("2006-01-02 15:04:05", timeStr)
		if err != nil {
			timestamp = time.Now()
		}
	}

	level := parseLevel(levelStr)
	record := slog.NewRecord(timestamp, level, msg, 0)
	record.AddAttrs(
		slog.String("component", "vaultwarden"),
		slog.String("target", target),
	)

	return record, true
}

func parseLogfmt(line string) map[string]string {
	fields := make(map[string]string)
	n := len(line)
	i := 0

	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		keyStart := i
		for i < n && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i >= n || line[i] != '=' {
			break
		}
		key := line[keyStart:i]
		i++ // skip '='

		if i >= n {
			fields[key] = ""
			break
		}

		var val string
		if line[i] == '"' {
			i++
			var sb strings.Builder
			escaped := false
			for i < n {
				c := line[i]
				if escaped {
					sb.WriteByte(c)
					escaped = false
				} else if c == '\\' {
					escaped = true
				} else if c == '"' {
					break
				} else {
					sb.WriteByte(c)
				}
				i++
			}
			if i < n && line[i] == '"' {
				i++
			}
			val = sb.String()
		} else {
			valStart := i
			for i < n && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			val = line[valStart:i]
		}

		if key != "" {
			if key == "level" && fields["level"] != "" && val == "" {
				continue
			}
			fields[key] = val
		}
	}

	return fields
}

// ParseLitestreamLog parses a log line formatted with Litestream's logfmt format.
func ParseLitestreamLog(line string) (slog.Record, bool) {
	fields := parseLogfmt(line)
	msg, hasMsg := fields["msg"]
	if !hasMsg {
		return slog.Record{}, false
	}

	var timestamp time.Time
	if timeStr, ok := fields["time"]; ok {
		var err error
		timestamp, err = time.Parse(time.RFC3339Nano, timeStr)
		if err != nil {
			timestamp, err = time.Parse(time.RFC3339, timeStr)
			if err != nil {
				timestamp = time.Now()
			}
		}
	} else {
		timestamp = time.Now()
	}

	level := slog.LevelInfo
	if levelStr, ok := fields["level"]; ok && levelStr != "" {
		level = parseLevel(levelStr)
	}

	record := slog.NewRecord(timestamp, level, msg, 0)
	record.AddAttrs(slog.String("component", "litestream"))

	keys := make([]string, 0, len(fields))
	for k := range fields {
		if k != "time" && k != "level" && k != "msg" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		record.AddAttrs(slog.String(k, fields[k]))
	}

	return record, true
}

// StreamProcessor tracks multi-line log state (such as the Vaultwarden ASCII banner box).
type StreamProcessor struct {
	component string
	isStderr  bool
	inBanner  bool
	version   string
}

func NewStreamProcessor(component string, isStderr bool) *StreamProcessor {
	return &StreamProcessor{
		component: strings.TrimSpace(component),
		isStderr:  isStderr,
	}
}

func (sp *StreamProcessor) ProcessLine(ctx context.Context, logger *slog.Logger, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	if sp.component == "vaultwarden" {
		// Detect start of Vaultwarden startup ASCII box
		if strings.HasPrefix(line, "/---") || strings.Contains(line, "Starting Vaultwarden") {
			sp.inBanner = true
			return
		}

		if sp.inBanner {
			// Extract version if present, e.g. "|                           Version 1.37.3                           |"
			if idx := strings.Index(line, "Version "); idx != -1 {
				vPart := strings.TrimSpace(line[idx+8:])
				vPart = strings.Trim(vPart, "| ")
				sp.version = vPart
			}

			// Detect end of Vaultwarden startup ASCII box
			if strings.HasPrefix(line, "\\---") || strings.HasSuffix(line, "---/") {
				sp.inBanner = false
				msg := "Starting Vaultwarden"
				attrs := []any{slog.String("component", "vaultwarden")}
				if sp.version != "" {
					msg = fmt.Sprintf("Starting Vaultwarden (v%s)", sp.version)
					attrs = append(attrs, slog.String("version", sp.version))
				}
				logger.Info(msg, attrs...)
				return
			}

			// If next regular bracketed log arrives before banner closed, flush banner first
			if vaultwardenLogRegex.MatchString(line) {
				sp.inBanner = false
				msg := "Starting Vaultwarden"
				attrs := []any{slog.String("component", "vaultwarden")}
				if sp.version != "" {
					msg = fmt.Sprintf("Starting Vaultwarden (v%s)", sp.version)
					attrs = append(attrs, slog.String("version", sp.version))
				}
				logger.Info(msg, attrs...)
				// Continue to process this line below
			} else {
				// Suppress interior disclaimer and border lines of the ASCII box
				return
			}
		}
	}

	// Try regular parsing
	var record slog.Record
	var ok bool

	switch sp.component {
	case "vaultwarden":
		record, ok = ParseVaultwardenLog(line)
		if !ok {
			record, ok = ParseLitestreamLog(line)
		}
	case "litestream":
		record, ok = ParseLitestreamLog(line)
		if !ok {
			record, ok = ParseVaultwardenLog(line)
		}
	default:
		record, ok = ParseVaultwardenLog(line)
		if !ok {
			record, ok = ParseLitestreamLog(line)
		}
	}

	if ok {
		_ = logger.Handler().Handle(ctx, record)
		return
	}

	// Unparseable string: dump into 'stderr' field
	level := slog.LevelInfo
	if sp.isStderr {
		level = slog.LevelError
	}

	unparsedRecord := slog.NewRecord(time.Now(), level, line, 0)
	unparsedRecord.AddAttrs(
		slog.String("component", sp.component),
		slog.String("stderr", line),
	)
	_ = logger.Handler().Handle(ctx, unparsedRecord)
}

func (sp *StreamProcessor) Flush(logger *slog.Logger) {
	if sp.inBanner {
		sp.inBanner = false
		msg := "Starting Vaultwarden"
		attrs := []any{slog.String("component", "vaultwarden")}
		if sp.version != "" {
			msg = fmt.Sprintf("Starting Vaultwarden (v%s)", sp.version)
			attrs = append(attrs, slog.String("version", sp.version))
		}
		logger.Info(msg, attrs...)
	}
}

func ProcessLine(ctx context.Context, logger *slog.Logger, line string, component string, isStderr bool) {
	sp := NewStreamProcessor(component, isStderr)
	sp.ProcessLine(ctx, logger, line)
	sp.Flush(logger)
}

func PipeProcessLogs(ctx context.Context, r io.Reader, component string, isStderr bool) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 256*1024)

	logger := slog.Default()
	sp := NewStreamProcessor(component, isStderr)
	for scanner.Scan() {
		sp.ProcessLine(ctx, logger, scanner.Text())
	}
	sp.Flush(logger)
}
