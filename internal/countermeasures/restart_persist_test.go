package countermeasures

import (
	"path/filepath"
	"testing"
	"time"
)

// REQ SVALINN-COUNTERMEASURES-RESTART-PERSIST-001
//
// blockedIPs (the map TempBlock/IsBlocked/real enforcement actually use) was
// in-memory only -- no json tag, never touched by saveLog/loadLog. Only
// c.log.Actions (the audit log) is persisted. On every process restart, ALL
// active temp-blocks silently vanished: enforcement stopped for previously
// blocked IPs with nothing logged about it -- fail-open, and triggered on
// every ordinary restart (deploy, crash recovery), not just a high-traffic
// edge case.
//
// Fix: reconstruct blockedIPs at construction time by replaying un-reversed
// TEMP_BLOCK entries from the already-persisted action log (TempBlock's own
// logAction call already records level/duration_ms/reason in Details),
// computing Until = Timestamp + duration_ms and skipping anything already
// expired. No new persistence mechanism -- reuses data already on disk.

// TestNew_RestoresActiveBlock_AfterSimulatedRestart is the core proof: a
// second Countermeasures instance pointed at the same log path (simulating
// a process restart) must see the block WITHOUT ever calling TempBlock
// itself.
func TestNew_RestoresActiveBlock_AfterSimulatedRestart(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	original := before.TempBlock("198.51.100.1", "restart test")

	after := New(logPath)

	entry, blocked := after.IsBlocked("198.51.100.1")
	if !blocked {
		t.Fatal("IP blocked before a simulated restart is NOT blocked after -- the block silently vanished")
	}
	if entry.Level != original.Level {
		t.Fatalf("restored block level = %d, want %d", entry.Level, original.Level)
	}
	if entry.Reason != original.Reason {
		t.Fatalf("restored block reason = %q, want %q", entry.Reason, original.Reason)
	}
	if diff := entry.Until.Sub(original.Until); diff > time.Second || diff < -time.Second {
		t.Fatalf("restored block Until = %v, want ~%v (diff %v)", entry.Until, original.Until, diff)
	}
}

// TestNew_DoesNotResurrectExpiredBlock proves the fix doesn't overshoot:
// a block whose duration already elapsed before the restart must NOT come
// back.
func TestNew_DoesNotResurrectExpiredBlock(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.log.Actions = append(before.log.Actions, ActionEntry{
		ID:         "expired-1",
		Timestamp:  time.Now().Add(-2 * time.Hour),
		Type:       ActionTempBlock,
		Target:     "198.51.100.2",
		Details:    map[string]any{"level": float64(1), "duration_ms": float64(5 * time.Minute.Milliseconds()), "reason": "old"},
		Reversible: true,
		Reversed:   false,
	})
	before.saveLog()

	after := New(logPath)

	if _, blocked := after.IsBlocked("198.51.100.2"); blocked {
		t.Fatal("an already-expired block was resurrected after restart")
	}
}

// TestNew_SkipsReversedBlockEntries proves a block that was already lifted
// before the restart stays lifted.
func TestNew_SkipsReversedBlockEntries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.TempBlock("198.51.100.3", "will be reversed")
	if ok := before.ReverseLastBlock("198.51.100.3"); !ok {
		t.Fatal("test setup failed: ReverseLastBlock did not succeed")
	}

	after := New(logPath)

	if _, blocked := after.IsBlocked("198.51.100.3"); blocked {
		t.Fatal("a block that was reversed before restart came back after restart")
	}
}

// TestNew_KeepsLatestBlockAcrossRepeatOffenses proves reconstruction uses
// the most recent block state per IP, not the first (matching TempBlock's
// own escalation semantics -- a repeat offense creates a new log entry
// without reversing the old one).
func TestNew_KeepsLatestBlockAcrossRepeatOffenses(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.TempBlock("198.51.100.4", "first offense")
	second := before.TempBlock("198.51.100.4", "second offense")

	after := New(logPath)

	entry, blocked := after.IsBlocked("198.51.100.4")
	if !blocked {
		t.Fatal("repeatedly-blocked IP is not blocked after restart")
	}
	if entry.Level != second.Level {
		t.Fatalf("restored level = %d, want the escalated level %d (from the second offense), not the first", entry.Level, second.Level)
	}
}

// TestNew_ReversalOfLatestOffenseSuppressesEarlierEntry guards a subtle
// edge case a naive single-pass "last un-reversed entry wins" reconstruction
// would get wrong: block, escalate (repeat offense, new log entry, old one
// left un-reversed), then reverse -- ReverseLastBlock marks only the LATEST
// entry as reversed in place, without touching the earlier one. A scan that
// skips reversed entries and lets later un-reversed ones overwrite earlier
// ones would incorrectly resurrect the first (already-superseded) offense
// as if it were still an active block.
func TestNew_ReversalOfLatestOffenseSuppressesEarlierEntry(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.TempBlock("198.51.100.7", "first offense")
	before.TempBlock("198.51.100.7", "second offense (escalated)")
	if ok := before.ReverseLastBlock("198.51.100.7"); !ok {
		t.Fatal("test setup failed: ReverseLastBlock did not succeed")
	}

	after := New(logPath)

	if _, blocked := after.IsBlocked("198.51.100.7"); blocked {
		t.Fatal("reversing the escalated (latest) offense incorrectly resurrected the earlier, already-superseded offense after restart")
	}
}

// TestNew_SkipsMalformedLogEntriesGracefully proves a corrupted/malformed
// on-disk entry (missing duration_ms) is skipped rather than panicking or
// resurrecting a bogus block.
func TestNew_SkipsMalformedLogEntriesGracefully(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.log.Actions = append(before.log.Actions, ActionEntry{
		ID:         "malformed-1",
		Timestamp:  time.Now(),
		Type:       ActionTempBlock,
		Target:     "198.51.100.5",
		Details:    map[string]any{"level": "not-a-number"}, // no duration_ms at all
		Reversible: true,
		Reversed:   false,
	})
	before.saveLog()

	after := New(logPath) // must not panic

	if _, blocked := after.IsBlocked("198.51.100.5"); blocked {
		t.Fatal("a malformed log entry (missing duration_ms) resurrected a block that should have been skipped")
	}
}

// TestNew_HandlesFreshInstallGracefully is a baseline regression guard: a
// brand-new logPath with no file at all must not error or panic, and must
// leave blockedIPs empty.
func TestNew_HandlesFreshInstallGracefully(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "does-not-exist-yet.json")

	c := New(logPath) // must not panic

	if _, blocked := c.IsBlocked("198.51.100.6"); blocked {
		t.Fatal("a fresh install with no prior log reported a block that cannot exist")
	}
}

// TestNew_IgnoresNonTempBlockLogEntries proves reconstruction only reads
// TEMP_BLOCK entries -- a THROTTLE (or any other action type) for the same
// IP must never be mistaken for a block.
func TestNew_IgnoresNonTempBlockLogEntries(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.Throttle("198.51.100.8", 2.0, time.Hour)

	after := New(logPath)

	if _, blocked := after.IsBlocked("198.51.100.8"); blocked {
		t.Fatal("a THROTTLE log entry was mistaken for a TEMP_BLOCK and resurrected a block that never existed")
	}
}

// TestNew_DefaultsToLevel1WhenLevelFieldMalformed proves a valid,
// resurrectable block (real duration_ms) with a malformed/missing "level"
// field falls back to level 1 rather than being skipped entirely or
// crashing.
func TestNew_DefaultsToLevel1WhenLevelFieldMalformed(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "defense-actions.json")

	before := New(logPath)
	before.log.Actions = append(before.log.Actions, ActionEntry{
		ID:         "badlevel-1",
		Timestamp:  time.Now(),
		Type:       ActionTempBlock,
		Target:     "198.51.100.9",
		Details:    map[string]any{"duration_ms": float64(time.Hour.Milliseconds()), "level": "not-a-number", "reason": "test"},
		Reversible: true,
		Reversed:   false,
	})
	before.saveLog()

	after := New(logPath)

	entry, blocked := after.IsBlocked("198.51.100.9")
	if !blocked {
		t.Fatal("a block with a malformed (but present) level field should still be resurrected using a default level, not skipped")
	}
	if entry.Level != 1 {
		t.Fatalf("Level = %d, want default 1 when the level field is malformed", entry.Level)
	}
}
