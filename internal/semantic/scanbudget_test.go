package semantic

import (
	"testing"
	"time"
)

// REQ SVALINN-SCANBUDGET-001
//
// analyzeWithDeadline is the deadline-injectable real implementation behind
// Analyze, letting these tests force the budget-exceeded path
// deterministically.

func TestAnalyzeWithDeadline_AlreadyPastDeadlineDetectsNothing(t *testing.T) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: true})
	result := a.analyzeWithDeadline("attempting to bypass amsi and unhook etw before running shellcode", time.Now().Add(-time.Second))
	if result.Detected {
		t.Fatalf("expected Detected=false with an already-past deadline (fail-open: no categories evaluated), got: %v", result.Categories)
	}
}

func TestAnalyzeWithDeadline_GenerousDeadlineBehavesLikeUnbudgeted(t *testing.T) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: true})
	result := a.analyzeWithDeadline("attempting to bypass amsi and unhook etw before running shellcode", time.Now().Add(time.Minute))
	if !result.Detected {
		t.Fatal("expected Detected=true with a generous deadline")
	}
	if len(result.Categories) < 2 {
		t.Fatalf("got %d categories with a generous deadline, want at least 2: %v", len(result.Categories), result.Categories)
	}
}
