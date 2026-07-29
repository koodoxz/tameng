package actor

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Reproduces the recursive-RLock self-deadlock that SaveToFile() can hit
// once it has real callers running concurrently with Add() on the hot
// request path: SaveToFile takes RLock() then calls GetAll(), which takes
// RLock() again on the same goroutine. If a concurrent Add() (Lock()) is
// queued between those two RLock() calls, Go blocks new readers behind
// the pending writer to prevent writer starvation -- deadlocking the
// SaveToFile goroutine against its own held lock.
func TestGrayZone_ConcurrentAddAndSaveDoesNotDeadlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gray-zone.json")
	gz := NewGrayZone(50, path)

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 200; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				gz.Add(GrayZoneEntry{IP: "203.0.113.1", Path: "/x"})
			}()
			go func() {
				defer wg.Done()
				_ = gz.SaveToFile()
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: concurrent Add()/SaveToFile() did not complete within timeout")
	}
}
