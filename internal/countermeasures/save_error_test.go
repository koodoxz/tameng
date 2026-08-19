package countermeasures

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// REQ SVALINN-COUNTERMEASURES-SAVEERROR-001
//
// Backlog item from the Opus-judge review of REQ
// SVALINN-COUNTERMEASURES-LOG-DURABILITY-001: saveLog's four failure
// branches (MkdirAll, MarshalIndent, WriteFile, and the previously fully
// discarded `_ = os.Rename(...)`) fail silently by design -- this package's
// "best-effort persistence" contract, unchanged here -- but were entirely
// unobservable from outside the package. SaveError() mirrors LoadError()'s
// shape but not its one-shot semantics: saveLog runs on every
// TempBlock/Throttle/SoftIsolate/Unblock/ReverseLastBlock call, so
// SaveError() reflects only the most recent attempt and clears again once
// persistence recovers.

// TestSaveError_NilAfterSuccessfulSave is a regression guard: a normal,
// fully successful save must leave SaveError() nil.
func TestSaveError_NilAfterSuccessfulSave(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")
	c := New(logPath)

	c.TempBlock("203.0.113.40", "test")

	if err := c.SaveError(); err != nil {
		t.Fatalf("SaveError() = %v after a successful save", err)
	}
}

// TestSaveError_ClearsAfterRecoveryFromFailure proves SaveError() reflects
// only the MOST RECENT save attempt, not a permanently-sticky first
// failure -- a transient persistence problem must not leave callers
// believing persistence is still broken after it has actually recovered.
func TestSaveError_ClearsAfterRecoveryFromFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "defense-actions.json")
	c := New(logPath)
	c.TempBlock("203.0.113.41", "baseline") // establishes a real file to rename over

	// Force the next save to fail by blocking the temp-file target with a
	// directory of the same name (same technique as
	// TestSaveLog_FailedWriteDoesNotCorruptExistingFile in
	// log_durability_test.go).
	tmpPath := logPath + ".tmp"
	if err := os.Mkdir(tmpPath, 0755); err != nil {
		t.Fatalf("test setup failed creating blocking directory: %v", err)
	}
	c.TempBlock("203.0.113.42", "should fail to persist")
	if c.SaveError() == nil {
		t.Fatal("test setup did not actually trigger a save failure")
	}

	// Remove the blocker -- the NEXT save should succeed and clear saveErr.
	if err := os.Remove(tmpPath); err != nil {
		t.Fatalf("test cleanup of blocking directory failed: %v", err)
	}
	c.TempBlock("203.0.113.43", "recovered")

	if err := c.SaveError(); err != nil {
		t.Fatalf("SaveError() = %v after a subsequent successful save -- a stale earlier failure must not persist once persistence recovers", err)
	}
}

// TestSaveError_ReportsRenameFailure covers the os.Rename error branch --
// previously fully discarded via `_ = os.Rename(...)`. Forces the rename
// to fail by making the destination itself a pre-existing directory:
// renaming a regular file onto an existing directory fails portably on
// both POSIX (EISDIR) and Windows.
func TestSaveError_ReportsRenameFailure(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "defense-actions.json")
	if err := os.Mkdir(logPath, 0755); err != nil {
		t.Fatalf("test setup failed: %v", err)
	}

	// loadLog also fails here (logPath is a directory, not fs.ErrNotExist)
	// -- unrelated to this test, which targets the Rename branch of
	// saveLog specifically.
	c := New(logPath)
	c.TempBlock("203.0.113.44", "test")

	if c.SaveError() == nil {
		t.Fatal("SaveError() is nil after a save whose os.Rename step failed -- the failure must be observable, not discarded")
	}
}

// TestSaveError_RaceSafeUnderConcurrentAccess proves SaveError() can be
// polled concurrently with the writes that mutate saveErr (every
// TempBlock/Throttle/SoftIsolate/Unblock/ReverseLastBlock call) without a
// data race. Run with -race to verify -- saveErr is guarded by the same
// c.lock as every other mutable field on Countermeasures.
func TestSaveError_RaceSafeUnderConcurrentAccess(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")
	c := New(logPath)

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			c.TempBlock(fmt.Sprintf("203.0.113.%d", n%255), "race-test")
		}(i)
		go func() {
			defer wg.Done()
			_ = c.SaveError()
		}()
	}
	wg.Wait()
}
