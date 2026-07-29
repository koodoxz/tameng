/*
Package waf -- literal extraction for the Aho-Corasick body-scan prefilter.

REQ SVALINN-WAFSCAN-ACPREFILTER-001. Every regex-combining approach that
doesn't have Aho-Corasick's actual complexity guarantee (e.g. joining
regexes with `|`) was measured to be SLOWER, not faster, than direct
per-signature evaluation (see the reverted SVALINN-WAFSCAN-PREFILTER-001).
Genuine multi-literal search needs literal strings, not regexes -- this file
extracts them soundly from the existing regex patterns, by walking Go's own
parsed regex AST (regexp/syntax), not by pattern-matching on the pattern
text itself.
*/
package waf

import "regexp/syntax"

// minUsefulLiteralLen is the shortest a required literal's shortest
// alternative may be and still be worth prefiltering on. Below this, the
// literal is common enough in ordinary text (a single quote, "OR", "AND")
// that the prefilter would "hit" on nearly all traffic, providing no real
// filtering benefit while still costing a lookup.
const minUsefulLiteralLen = 4

// requiredLiterals returns the most selective (longest shortest-alternative)
// set of literal strings such that: if NONE of them appear anywhere in the
// scanned text, pattern is PROVEN unable to match anywhere in that text
// either. Returns nil if no such set can be proven, or if the best
// candidate found is too short to be a useful filter.
//
// Deliberately conservative: soundness over completeness. A missed
// optimization opportunity costs performance; an unsound extraction costs a
// silent WAF bypass. This is why literals are derived by walking the actual
// parsed AST rather than string-matching the pattern text -- the same
// mistake ("this looks like a keyword alternation") is exactly what a naive
// heuristic could get wrong on a pattern's more complex neighbors.
func requiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()

	var candidates [][]string
	switch re.Op {
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if lits := mandatoryLiteralsOf(sub); lits != nil {
				candidates = append(candidates, lits)
			}
		}
	default:
		if lits := mandatoryLiteralsOf(re); lits != nil {
			candidates = append(candidates, lits)
		}
	}
	// Drop any candidate set containing a non-ASCII rune BEFORE picking the
	// best one (REQ SVALINN-WAF-NONASCII-GUARD-001), so a rejected
	// non-ASCII candidate doesn't deny a perfectly usable ASCII candidate
	// elsewhere in the same pattern. Every signature is compiled with
	// `(?i)`, i.e. full Unicode simple case folding, while the AC automaton
	// this feeds is ASCII-case-insensitive only -- an unguarded non-ASCII
	// literal could let a cased-non-ASCII homoglyph substitution defeat the
	// prefilter while the real regex still matches.
	//
	// The rejection must be whole-set, never per-literal: for an
	// alternation like (Alpha|Alphä), dropping just the non-ASCII branch
	// would leave "Alpha" looking "required" when text containing only
	// "Alphä" still matches the regex -- a false negative (silent WAF
	// bypass). Either the entire proven set survives the ASCII check or the
	// pattern gets no prefilter at all.
	var best []string
	for _, c := range candidates {
		if !allASCII(c) {
			continue
		}
		if best == nil || minLiteralLen(c) > minLiteralLen(best) {
			best = c
		}
	}
	if best == nil || minLiteralLen(best) < minUsefulLiteralLen {
		return nil
	}
	return best
}

// allASCII reports whether every rune of every literal is below 128.
func allASCII(lits []string) bool {
	for _, l := range lits {
		for i := 0; i < len(l); i++ {
			if l[i] >= 0x80 {
				return false
			}
		}
	}
	return true
}

// mandatoryLiteralsOf checks a single AST node (not a concat sequence): is
// it unconditionally literal (or a capture of one), or a pure-literal
// alternation (every branch is itself unconditionally literal, recursively)?
// Anything else -- OpStar/OpQuest/OpPlus/OpCharClass/OpAnyChar/anchors/etc
// -- is either optional (could be skipped in a match) or not a fixed
// literal, and is conservatively rejected: nil, not a guess.
func mandatoryLiteralsOf(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return mandatoryLiteralsOf(re.Sub[0])
		}
		return nil
	case syntax.OpAlternate:
		var lits []string
		for _, branch := range re.Sub {
			l := mandatoryLiteralsOf(branch)
			if l == nil {
				return nil // one non-literal branch poisons the whole alternation
			}
			lits = append(lits, l...)
		}
		return lits
	default:
		return nil
	}
}

// minLiteralLen returns the length of the shortest string in lits.
func minLiteralLen(lits []string) int {
	if len(lits) == 0 {
		return 0
	}
	m := len(lits[0])
	for _, l := range lits[1:] {
		if len(l) < m {
			m = len(l)
		}
	}
	return m
}
