package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
	"github.com/koodoxz/tameng/internal/logger"
)

// syncBuffer makes bytes.Buffer safe for the concurrent write (from the
// autosave goroutine's logger) + read (from the test's polling loop) that
// TestGrayZoneAutoSave_LogsErrorOnSaveFailure needs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestGrayZoneAutoSave_PersistsOnTick(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gray-zone.json")
	gz := actor.NewGrayZone(10, path)
	gz.Add(actor.GrayZoneEntry{IP: "203.0.113.5", Path: "/probe"})

	stop := make(chan struct{})
	defer close(stop)
	go grayZoneAutoSave(gz, 10*time.Millisecond, stop, logger.New("test"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			var entries []actor.GrayZoneEntry
			if json.Unmarshal(data, &entries) == nil && len(entries) == 1 && entries[0].IP == "203.0.113.5" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("gray zone was not persisted to %s within timeout", path)
}

func TestGrayZoneAutoSave_StopsOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gray-zone.json")
	gz := actor.NewGrayZone(10, path)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		grayZoneAutoSave(gz, 5*time.Millisecond, stop, logger.New("test"))
		close(done)
	}()

	close(stop)
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("grayZoneAutoSave did not exit after stop was closed")
	}
}

func TestGrayZoneAutoSave_LogsErrorOnSaveFailure(t *testing.T) {
	// A directory path (instead of a file) makes os.WriteFile inside
	// SaveToFile fail deterministically, exercising the error branch.
	badPath := t.TempDir()
	gz := actor.NewGrayZone(10, badPath)

	buf := &syncBuffer{}
	log := logger.NewWithWriter("test", buf)

	stop := make(chan struct{})
	defer close(stop)
	go grayZoneAutoSave(gz, 10*time.Millisecond, stop, log)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "Failed to persist gray zone") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected save-failure log message, got: %s", buf.String())
}

func TestShutdown_FlushesGrayZone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gray-zone.json")
	gz := actor.NewGrayZone(10, path)
	gz.Add(actor.GrayZoneEntry{IP: "198.51.100.7", Path: "/shutdown-test"})

	s := &Server{
		log:      logger.New("test"),
		shutdown: make(chan struct{}),
		grayZone: gz,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected gray-zone file to be written on shutdown: %v", err)
	}
	var entries []actor.GrayZoneEntry
	if err := json.Unmarshal(data, &entries); err != nil || len(entries) != 1 || entries[0].IP != "198.51.100.7" {
		t.Fatalf("gray zone was not correctly flushed on shutdown, got: %s", data)
	}
}
