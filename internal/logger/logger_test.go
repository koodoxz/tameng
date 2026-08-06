package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// captureStdout swaps os.Stdout for a pipe while fn runs and returns whatever
// fn wrote there. NewWithFormat's "json" branch hardcodes os.Stdout, so this
// is the only way to assert that the format argument actually selects a
// different writer -- without it, a NewWithFormat that ignored its format
// argument entirely (i.e. the exact regression REQ
// SVALINN-LOGGING-CONFIG-WIRE-001 exists to prevent) would still pass.
// os.Stdout is read at construction time inside fn, and the pipe is drained
// concurrently so a write larger than the pipe buffer cannot deadlock.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()

	orig := os.Stdout
	// Restore via defer, not a plain assignment: if fn (or an assertion below)
	// aborts the test, leaving os.Stdout pointing at a closed pipe would break
	// every later test in this package rather than just this one.
	defer func() {
		os.Stdout = orig
		w.Close() // no-op if the happy path already closed it
	}()
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	// The reader only unblocks once every write end is closed.
	w.Close()
	return <-done
}

func TestNewWithWriter_ProducesParsableJSONLines(t *testing.T) {
	var buf bytes.Buffer
	log := NewWithWriter("svalinn-json-format-test", &buf)
	log.Info("hello", "key", "value")

	line := strings.TrimSpace(buf.String())
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("expected a single parsable JSON line, got %q: %v", line, err)
	}
	if decoded["message"] != "hello" {
		t.Errorf("message = %v, want %q", decoded["message"], "hello")
	}
	if decoded["module"] != "svalinn-json-format-test" {
		t.Errorf("module = %v, want %q", decoded["module"], "svalinn-json-format-test")
	}
}

func TestNewWithFormat_JSONFormat_WritesRawJSONToStdout(t *testing.T) {
	out := captureStdout(t, func() {
		NewWithFormat("format-json-probe", "json").Info("hello")
	})

	line := strings.TrimSpace(out)
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("format %q must emit raw JSON, got %q: %v", "json", line, err)
	}
	if decoded["message"] != "hello" {
		t.Errorf("message = %v, want %q", decoded["message"], "hello")
	}
	if decoded["module"] != "format-json-probe" {
		t.Errorf("module = %v, want %q", decoded["module"], "format-json-probe")
	}
}

func TestNewWithFormat_ConsoleFormat_WritesNonJSONToStdout(t *testing.T) {
	// The console branch must NOT be raw JSON -- this is what distinguishes it
	// from the "json" branch above and pins the format argument as load-bearing.
	out := captureStdout(t, func() {
		NewWithFormat("format-console-probe", "console").Info("hello")
	})

	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatal("console format produced no output")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err == nil {
		t.Errorf("format %q must emit human-readable ConsoleWriter output, but got parsable JSON: %q", "console", line)
	}
	if !strings.Contains(line, "hello") {
		t.Errorf("console output %q does not contain the logged message", line)
	}
}

func TestNewWithFormat_UnknownFormat_FallsBackToConsole(t *testing.T) {
	// Config validation (validLogFormats) should make this unreachable in
	// production, but the fallback must stay human-readable rather than
	// panicking or emitting nothing.
	out := captureStdout(t, func() {
		NewWithFormat("fallback-probe", "yaml-was-never-a-format").Info("hello")
	})

	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatal("unknown format produced no output")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err == nil {
		t.Errorf("unrecognized format must fall back to ConsoleWriter, but got parsable JSON: %q", line)
	}
	if !strings.Contains(line, "hello") {
		t.Errorf("fallback output %q does not contain the logged message", line)
	}
}

func TestSetLevel_SuppressesBelowThreshold(t *testing.T) {
	// Restore whatever the level actually was, not a hardcoded guess --
	// zerolog's process default is TraceLevel, so restoring InfoLevel here
	// would silently leak a stricter level into every later test in this
	// package and make debug-level assertions order-dependent.
	prev := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(prev)

	var buf bytes.Buffer
	log := NewWithWriter("level-test", &buf)

	SetLevel("warn")
	log.Info("should be suppressed")
	log.Debug("should be suppressed")
	if buf.Len() != 0 {
		t.Fatalf("expected no output below warn level, got %q", buf.String())
	}

	log.Warn("should appear")
	if buf.Len() == 0 {
		t.Fatal("expected warn-level output to appear, got nothing")
	}
}

func TestSetLevel_UnknownLevel_DefaultsToInfo(t *testing.T) {
	prev := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(prev)

	var buf bytes.Buffer
	log := NewWithWriter("level-default-test", &buf)

	SetLevel("not-a-real-level")
	log.Debug("should be suppressed at info default")
	if buf.Len() != 0 {
		t.Fatalf("expected debug suppressed under unknown-level-defaults-to-info, got %q", buf.String())
	}

	log.Info("should appear")
	if buf.Len() == 0 {
		t.Fatal("expected info-level output under the default, got nothing")
	}
}

func TestSetLevel_EachKnownLevel_SetsMatchingGlobalLevel(t *testing.T) {
	prev := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(prev)

	// Pins the level strings to the exact set config validation allows
	// (validLogLevels = debug|info|warn|error). A SetLevel that collapsed any
	// of these to the info default would fail here.
	cases := []struct {
		level string
		want  zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
	}
	for _, tc := range cases {
		SetLevel(tc.level)
		if got := zerolog.GlobalLevel(); got != tc.want {
			t.Errorf("SetLevel(%q) -> GlobalLevel() = %v, want %v", tc.level, got, tc.want)
		}
	}
}
