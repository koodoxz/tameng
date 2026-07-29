package semantic

import "testing"

// This package had no existing tests. Establishes basic coverage of
// Analyze's real detection behavior (real semantic-intent content is
// detected, benign content is not, a disabled analyzer always returns
// empty). A MatchString-first probe was tried on Analyze's inner pattern
// loop (REQ SVALINN-MATCHFIRST-001, same idea as
// internal/detect/helpers.go's checkPatterns) but benchmarked as providing
// no measurable benefit and reverted; these tests were kept regardless.

func TestAnalyzer_DetectsRealSemanticIntent(t *testing.T) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: true})
	result := a.Analyze("attempting to bypass amsi and unhook etw before running shellcode")
	if !result.Detected {
		t.Fatal("expected Detected=true for content matching evasion_intent and exploit_intent patterns")
	}
	if len(result.Categories) < 2 {
		t.Fatalf("got %d categories, want at least 2 (evasion_intent, exploit_intent): %v", len(result.Categories), result.Categories)
	}
}

func TestAnalyzer_NoDetectionOnBenignContent(t *testing.T) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: true})
	result := a.Analyze("just an ordinary request with no attack intent whatsoever")
	if result.Detected {
		t.Fatalf("expected Detected=false for benign content, got categories: %v", result.Categories)
	}
}

func TestAnalyzer_DisabledReturnsEmptyResult(t *testing.T) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: false})
	result := a.Analyze("exploit shellcode bypass amsi")
	if result.Detected {
		t.Fatal("expected Detected=false when analyzer is disabled, regardless of content")
	}
}
