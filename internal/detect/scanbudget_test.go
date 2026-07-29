package detect

import (
	"regexp"
	"testing"
	"time"
)

// REQ SVALINN-SCANBUDGET-001
//
// checkPatternsWithDeadline is the deadline-injectable real implementation
// behind checkPatterns, letting these tests force the budget-exceeded path
// deterministically (an already-past deadline) instead of depending on real
// slow computation or sleep-based flakiness.

func TestCheckPatternsWithDeadline_AlreadyPastDeadlineEvaluatesNothing(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)select.*from`),
		regexp.MustCompile(`(?i)drop\s+table`),
	}
	// A real attack payload that would match both patterns under a normal
	// deadline -- proves the early-exit is real (fail-open), not just a
	// no-op on already-empty input.
	matches := checkPatternsWithDeadline("'; SELECT password FROM users; DROP TABLE users;--", patterns, time.Now().Add(-time.Second))
	if len(matches) != 0 {
		t.Fatalf("got %d matches with an already-past deadline, want 0 (fail-open: no patterns evaluated after deadline)", len(matches))
	}
}

func TestCheckPatternsWithDeadline_GenerousDeadlineBehavesLikeUnbudgeted(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)select.*from`),
		regexp.MustCompile(`(?i)drop\s+table`),
	}
	matches := checkPatternsWithDeadline("'; SELECT password FROM users; DROP TABLE users;--", patterns, time.Now().Add(time.Minute))
	if len(matches) != 2 {
		t.Fatalf("got %d matches with a generous deadline, want 2 (both patterns should be evaluated)", len(matches))
	}
}
