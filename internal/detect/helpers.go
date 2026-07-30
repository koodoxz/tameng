package detect

import (
	"fmt"
	"regexp"
	"time"

	"github.com/koodoxz/tameng/internal/scanbudget"
)

// checkPatternsBudget bounds the wall-clock time a single checkPatterns
// call may spend (REQ SVALINN-SCANBUDGET-001): an attacker who defeats
// literal-based prefilter mitigations elsewhere can't force unbounded CPU
// cost by supplying content that requires evaluating many patterns to an
// inconclusive "no match" -- the budget caps that regardless of how many
// patterns are configured. ponytail: ceiling is 100ms, deliberately well
// above the ~6-7ms measured on dev hardware for a real 51-pattern detector
// against an 8KiB benign body -- the production VPS is independently known
// to run ~6x slower single-thread (SVALINN-WAFSCAN-ACPREFILTER-001's own
// cost-attribution work), so a tight budget calibrated only against dev
// hardware risks clipping legitimate traffic on slower/loaded production
// hardware for no attacker-related reason. Verify this margin against real
// VPS timing during any deploy before trusting it further; lower only with
// real production benchmark data, not a guess.
const checkPatternsBudget = 100 * time.Millisecond

func checkPatterns(data string, patterns []*regexp.Regexp) []string {
	return checkPatternsWithDeadline(data, patterns, time.Now().Add(checkPatternsBudget))
}

// checkPatternsFiltered is checkPatterns plus the Aho-Corasick literal
// prefilter (REQ SVALINN-DETECTPREFILTER-001). cand comes from
// literalextract.Groups.Slice; nil means "no prefilter available", which
// reproduces checkPatterns exactly.
func checkPatternsFiltered(data string, patterns []*regexp.Regexp, cand []bool) []string {
	return checkPatternsFilteredWithDeadline(data, patterns, cand, time.Now().Add(checkPatternsBudget))
}

// checkPatternsWithDeadline is checkPatterns' real implementation, taking an
// explicit deadline so tests can force the budget-exceeded path
// deterministically (an already-past deadline) rather than relying on real
// slow computation or sleep-based flakiness. Pattern evaluation order is
// shuffled per call so a budget cutoff can't deterministically favor
// evading the same subset of patterns on every request (REQ
// SVALINN-SCANBUDGET-001; fail-open by design -- see the same REQ's
// decision record -- unevaluated patterns are simply not checked for this
// request, never blocked outright, to avoid denying legitimate traffic
// during a slow moment rather than an actually oversized/adversarial body).
func checkPatternsWithDeadline(data string, patterns []*regexp.Regexp, deadline time.Time) []string {
	return checkPatternsFilteredWithDeadline(data, patterns, nil, deadline)
}

// checkPatternsFilteredWithDeadline is the real implementation behind all
// four entry points.
//
// Composition with SVALINN-SCANBUDGET-001 (deliberate, and tested): the
// deadline check still comes FIRST, so the budget's fail-open guarantee is
// untouched in shape -- patterns not reached before the deadline are still
// simply unevaluated, and the evaluation order is still shuffled per call.
// The prefilter only removes patterns that are PROVEN unable to match this
// data, before the budget is ever spent on them. It can therefore only
// increase how many genuinely-could-match patterns fit inside the same
// budget; it never removes coverage from a pattern that could have matched,
// and it never lets an attacker choose which patterns get skipped (skipping
// requires proving absence of that pattern's own required literals).
//
// cand is defensively ignored unless its length matches patterns exactly:
// a mismatched slice would mean the caller paired the wrong category's
// flags with this pattern list, and evaluating everything is the only safe
// interpretation.
func checkPatternsFilteredWithDeadline(data string, patterns []*regexp.Regexp, cand []bool, deadline time.Time) []string {
	if cand != nil && len(cand) != len(patterns) {
		cand = nil
	}
	matches := []string{}
	for _, i := range scanbudget.ShuffledIndices(len(patterns)) {
		if time.Now().After(deadline) {
			break
		}
		if cand != nil && !cand[i] {
			continue
		}
		found := patterns[i].FindAllString(data, 3)
		if len(found) > 0 {
			matches = append(matches, found...)
		}
	}
	return matches
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(values))
	for _, val := range values {
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		unique = append(unique, val)
	}
	return unique
}

func formatPercent(value float64) string {
	return fmt.Sprintf("%.2f%%", value)
}
