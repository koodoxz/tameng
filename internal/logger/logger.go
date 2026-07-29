/*
Package logger provides structured logging for SVALINN.
*/
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog for SVALINN
type Logger struct {
	log    zerolog.Logger
	module string
}

// New creates a new logger instance
func New(module string) *Logger {
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	log := zerolog.New(output).
		With().
		Timestamp().
		Str("module", module).
		Logger()

	return &Logger{
		log:    log,
		module: module,
	}
}

// NewWithWriter creates a logger with custom writer
func NewWithWriter(module string, w io.Writer) *Logger {
	log := zerolog.New(w).
		With().
		Timestamp().
		Str("module", module).
		Logger()

	return &Logger{
		log:    log,
		module: module,
	}
}

// WithModule creates a child logger with additional module context
func (l *Logger) WithModule(submodule string) *Logger {
	return &Logger{
		log:    l.log.With().Str("submodule", submodule).Logger(),
		module: l.module + "/" + submodule,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	event := l.log.Debug()
	addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Info logs an info message
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	event := l.log.Info()
	addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	event := l.log.Warn()
	addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	event := l.log.Error()
	addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	event := l.log.Fatal()
	addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Threat logs a security threat event
func (l *Logger) Threat(threatType string, severity string, keysAndValues ...interface{}) {
	event := l.log.Warn().
		Str("event_type", "threat").
		Str("threat_type", threatType).
		Str("severity", severity)
	addFields(event, keysAndValues...)
	event.Msg("Threat detected")
}

// Attack logs an attack event
func (l *Logger) Attack(attackType string, ip string, path string, keysAndValues ...interface{}) {
	event := l.log.Warn().
		Str("event_type", "attack").
		Str("attack_type", attackType).
		Str("source_ip", ip).
		Str("path", path)
	addFields(event, keysAndValues...)
	event.Msg("Attack detected")
}

// Block logs a block action
func (l *Logger) Block(reason string, ip string, duration time.Duration, keysAndValues ...interface{}) {
	event := l.log.Info().
		Str("event_type", "block").
		Str("reason", reason).
		Str("source_ip", ip).
		Dur("duration", duration)
	addFields(event, keysAndValues...)
	event.Msg("IP blocked")
}

// Request logs an HTTP request
func (l *Logger) Request(method string, path string, status int, duration time.Duration, keysAndValues ...interface{}) {
	event := l.log.Info().
		Str("method", method).
		Str("path", path).
		Int("status", status).
		Dur("duration", duration)
	addFields(event, keysAndValues...)
	event.Msg("Request")
}

// addFields adds key-value pairs to a log event
func addFields(event *zerolog.Event, keysAndValues ...interface{}) {
	for i := 0; i < len(keysAndValues)-1; i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			continue
		}
		value := keysAndValues[i+1]
		switch v := value.(type) {
		case string:
			event.Str(key, v)
		case int:
			event.Int(key, v)
		case int64:
			event.Int64(key, v)
		case float64:
			event.Float64(key, v)
		case bool:
			event.Bool(key, v)
		case time.Duration:
			event.Dur(key, v)
		case time.Time:
			event.Time(key, v)
		case error:
			event.Err(v)
		default:
			event.Interface(key, v)
		}
	}
}

// SetLevel sets the global log level
func SetLevel(level string) {
	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
