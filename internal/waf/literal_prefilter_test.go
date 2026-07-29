package waf

import (
	"reflect"
	"testing"
)

// REQ SVALINN-WAFSCAN-ACPREFILTER-001 -- targeted unit tests for the
// extraction logic itself, covering branches the real 212-signature corpus
// doesn't happen to exercise (invalid syntax, capture-group edge cases,
// below-threshold literals).

func TestRequiredLiterals(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string // nil means "not extractable"
	}{
		{"invalid regex syntax", "(unclosed", nil},
		{"pure literal, long enough", "SELECT", []string{"SELECT"}},
		{"pure literal, too short", "OR", nil},
		{"mandatory alternation of literals with no shared prefix, all long enough",
			"(SELECT|UPDATE|INSERT)", []string{"SELECT", "UPDATE", "INSERT"}},
		{"mandatory alternation, one branch too short overall (min applies to whole set)",
			"(SELECT|OR)", nil}, // minLen across branches is 2 ("OR"), below threshold
		{"known conservative gap: shared-prefix branches get internally " +
			"prefix-factored by regexp/syntax into a nested Concat this " +
			"function doesn't unpack -- correctly returns nil (safe, just " +
			"less complete) rather than guessing. DROP and DELETE both " +
			"start with 'D'; this is real SVALINN-SQLI-003 behavior.",
			"(DROP|DELETE|INSERT)", nil},
		{"alternation with a non-literal branch poisons the whole group",
			"(SELECT|[0-9]+)", nil},
		{"concat with a literal prefix and a non-literal suffix -- literal still required",
			"SELECT.*FROM", []string{"SELECT"}},
		{"concat where only the second member is a usable literal",
			"[0-9]+BENCHMARK", []string{"BENCHMARK"}},
		{"nothing extractable at all: pure character class",
			"[a-zA-Z0-9]+", nil},
		{"empty pattern", "", nil},
		{"capture group wrapping a literal", "(SELECT)", []string{"SELECT"}},
		{"non-capturing group wrapping a literal", "(?:UNION)", []string{"UNION"}},
		{"optional literal is never mandatory", "(?:SELECT)?", nil},
		{"starred literal is never mandatory", "(?:SELECT)*", nil},
		// REQ SVALINN-WAF-NONASCII-GUARD-001 -- N2 from the
		// DETECTPREFILTER-001 review: internal/literalextract (used by
		// detect/malware) already rejects any candidate literal set
		// containing a non-ASCII rune, since the AC automaton here is
		// ASCII-case-insensitive while the real regexes fold full Unicode
		// (?i) -- a cased non-ASCII literal (Cyrillic/Greek/accented) could
		// silently bypass the prefilter otherwise. This package never got
		// that guard. Latent today (the shipped 212-signature corpus is
		// 100% ASCII, no attacker-controlled write path to signatures
		// found), but LoadEvolvedRules means a future non-ASCII signature
		// could silently reopen it -- closing preemptively.
		{"single non-ASCII literal is rejected outright", "ПАРОЛЬ", nil},
		{"non-ASCII concat member is dropped, a separate ASCII member still wins",
			"SELECT.*ПАРОЛЬ", []string{"SELECT"}},
		{"alternation mixing ASCII and non-ASCII branches is rejected as a " +
			"WHOLE candidate, not per-literal -- dropping only the non-ASCII " +
			"branch would let text containing only the non-ASCII alternative " +
			"match the real regex while looking prefilter-absent",
			"(SELECT|ПАРОЛЬ)", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := requiredLiterals(tt.pattern)
			if tt.want == nil {
				if got != nil {
					t.Errorf("requiredLiterals(%q) = %v, want nil", tt.pattern, got)
				}
				return
			}
			// Order isn't guaranteed to matter for correctness, but our
			// implementation is deterministic, so pin it directly.
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requiredLiterals(%q) = %v, want %v", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestMinLiteralLen(t *testing.T) {
	tests := []struct {
		lits []string
		want int
	}{
		{nil, 0},
		{[]string{}, 0},
		{[]string{"a"}, 1},
		{[]string{"abc", "de", "fghij"}, 2},
		{[]string{"same", "size"}, 4},
	}
	for _, tt := range tests {
		if got := minLiteralLen(tt.lits); got != tt.want {
			t.Errorf("minLiteralLen(%v) = %d, want %d", tt.lits, got, tt.want)
		}
	}
}

// TestRequiredLiterals_ContractHoldsOnRealSignatures cross-checks every
// real default signature's extraction result against the function's own
// documented contract: either nil, or a non-empty slice whose shortest
// element is at least minUsefulLiteralLen.
func TestRequiredLiterals_ContractHoldsOnRealSignatures(t *testing.T) {
	e := newDefaultEngine(t)
	for _, sig := range e.signatures {
		lits := requiredLiterals(sig.Pattern)
		if lits == nil {
			continue
		}
		if len(lits) == 0 {
			t.Errorf("%s: requiredLiterals returned non-nil but empty slice", sig.ID)
		}
		if minLiteralLen(lits) < minUsefulLiteralLen {
			t.Errorf("%s: requiredLiterals returned %v with minLen %d, below minUsefulLiteralLen %d",
				sig.ID, lits, minLiteralLen(lits), minUsefulLiteralLen)
		}
	}
}
