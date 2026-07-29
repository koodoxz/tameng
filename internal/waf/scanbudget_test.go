package waf

import (
	"testing"
	"time"
)

// REQ SVALINN-SCANBUDGET-001
//
// scanWithDeadline is Scan's deadline-injectable real implementation,
// letting these tests force the budget-exceeded path deterministically.

func TestScanWithDeadline_AlreadyPastDeadlineFindsNothing(t *testing.T) {
	e := newDefaultEngine(t)
	result := e.scanWithDeadline("/taxii/collections/default/objects", "", "'; DROP TABLE users;--",
		map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0", time.Now().Add(-time.Second))
	if len(result.Matches) != 0 {
		t.Fatalf("got %d matches with an already-past deadline, want 0 (fail-open: no signatures evaluated): %v", len(result.Matches), acScanSummary(result))
	}
	if result.Blocked {
		t.Fatal("expected Blocked=false when no signatures were evaluated")
	}
}

func TestScanWithDeadline_GenerousDeadlineBehavesLikeUnbudgeted(t *testing.T) {
	e := newDefaultEngine(t)
	result := e.scanWithDeadline("/taxii/collections/default/objects", "", "'; DROP TABLE users;--",
		map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0", time.Now().Add(time.Minute))
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match for a real SQLi payload with a generous deadline")
	}
}

// TestScan_PublicWrapperUsesRealBudget confirms Scan (the public entry
// point real callers use) actually delegates through the budget-aware
// path, not a stale copy -- a real SQLi payload well within the default
// budget must still be caught via the ordinary public API.
func TestScan_PublicWrapperUsesRealBudget(t *testing.T) {
	e := newDefaultEngine(t)
	result := e.Scan("/taxii/collections/default/objects", "", "'; DROP TABLE users;--",
		map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	if len(result.Matches) == 0 {
		t.Fatal("expected the public Scan() to still catch a real SQLi payload within its default budget")
	}
}
