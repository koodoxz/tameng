package detect

import (
	"regexp"
	"testing"
)

// checkPatterns is the shared hot loop behind 4 of the 6 body-scanning
// detector middlewares (evasion/ad_attack/network_attack/exploitation --
// see server/middleware.go's checkPatterns callers). This package had no
// direct unit tests for checkPatterns itself; these cover its core
// correctness properties (real matches found, benign content produces no
// matches, the FindAllString(_, n) cap is honored, evaluation of later
// patterns isn't affected by earlier non-matching ones). A MatchString-first
// probe was tried here (REQ SVALINN-MATCHFIRST-001) on the theory that it
// would avoid FindAllString's match-position bookkeeping for non-matching
// patterns -- benchmarked and found to provide no measurable benefit
// (RE2 pays the same full-scan cost either way to conclude "no match") and
// reverted; these tests were kept since they add real coverage regardless.

func TestCheckPatterns_FindsRealMatches(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)select.*from`),
		regexp.MustCompile(`(?i)drop\s+table`),
	}
	matches := checkPatterns("'; SELECT password FROM users; DROP TABLE users;--", patterns)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2 (one per matching pattern): %v", len(matches), matches)
	}
}

func TestCheckPatterns_NoMatchesOnBenignContent(t *testing.T) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)select.*from`),
		regexp.MustCompile(`(?i)drop\s+table`),
	}
	matches := checkPatterns("just an ordinary benign request body with no attack content", patterns)
	if len(matches) != 0 {
		t.Fatalf("got %d matches, want 0 for benign content: %v", len(matches), matches)
	}
}

func TestCheckPatterns_RespectsFindAllStringCap(t *testing.T) {
	// The real call site caps at 3 (FindAllString(data, 3)) -- confirm the
	// MatchString-first gate doesn't accidentally change that cap.
	patterns := []*regexp.Regexp{regexp.MustCompile(`a`)}
	matches := checkPatterns("aaaaaaaaaa", patterns)
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3 (FindAllString cap)", len(matches))
	}
}

func TestCheckPatterns_MixOfMatchingAndNonMatchingPatterns(t *testing.T) {
	// Proves the MatchString-first `continue` on a non-matching pattern
	// doesn't skip evaluation of subsequent patterns in the same slice.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)nonexistent_pattern_xyz`),
		regexp.MustCompile(`(?i)union\s+select`),
		regexp.MustCompile(`(?i)another_nonexistent_abc`),
	}
	matches := checkPatterns("1' UNION SELECT username,password FROM users--", patterns)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1 (only the middle pattern matches): %v", len(matches), matches)
	}
}
