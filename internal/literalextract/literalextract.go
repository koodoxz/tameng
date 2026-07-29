/*
Package literalextract extracts provably-required literal substrings from
regex patterns, so a caller can skip evaluating a pattern entirely when an
Aho-Corasick pass proves none of that pattern's required literals appear in
the scanned text.

REQ SVALINN-DETECTPREFILTER-001. This is the same technique already live in
internal/waf (SVALINN-WAFSCAN-ACPREFILTER-001), applied to the five
detection hot loops that live-VPS pprof measured at ~80% of a benign
request's CPU cost. Every regex-combining approach lacking Aho-Corasick's
actual complexity guarantee (e.g. joining regexes with `|`) was previously
measured to be SLOWER, not faster, than direct per-pattern evaluation (see
the reverted SVALINN-WAFSCAN-PREFILTER-001) -- genuine multi-literal search
needs literal strings, not regexes.

Soundness over completeness, always. A missed optimization costs
performance; an unsound extraction costs a silent detector bypass. Literals
are therefore derived by walking Go's own parsed regex AST (regexp/syntax),
never by pattern-matching on the pattern text itself.
*/
package literalextract

import (
	"regexp/syntax"
	"strings"
)

// MinUsefulLiteralLen is the shortest a required literal's shortest
// alternative may be and still be worth prefiltering on. Below this, the
// literal is common enough in ordinary text ("arp", "bot", "net") that the
// prefilter would "hit" on nearly all traffic, providing no real filtering
// benefit while still costing a lookup.
const MinUsefulLiteralLen = 4

// The only two non-ASCII runes in all of Unicode whose simple-case-fold
// orbit contains an ASCII character. This is not a guess or a spot-check:
// TestFoldTableIsExhaustive sweeps every rune in [128, 0x10FFFF] and fails
// if any third such rune exists, so this table cannot silently rot as Go's
// Unicode tables advance.
//
// They matter because callers compile patterns with `(?i)`, which is Go's
// FULL Unicode simple case folding, while the Aho-Corasick automaton is
// built AsciiCaseInsensitive (ASCII-only). Unhandled, an attacker can
// homoglyph-substitute a required literal -- e.g. "Am<U+017F>iScanBuffer", which
// `(?i)AmsiScanBuffer` genuinely matches -- so the real regex would still
// fire but the ASCII-only prefilter would not find the literal, silently
// skipping the pattern. That is a detector bypass, not a missed
// optimization.
//
// Written with explicit \u escapes rather than the literal glyphs so the
// source itself cannot be misread, mis-copied, or mangled by an
// intermediate tool the same way an attacker's payload could be.
const (
	runeLongS  = '\u017F' // LATIN SMALL LETTER LONG S, folds with s/S
	runeKelvin = '\u212A' // KELVIN SIGN, folds with k/K
)

var unicodeFoldReplacer = strings.NewReplacer(
	string(runeLongS), "s",
	string(runeKelvin), "k",
)

// FoldForASCIISearch returns text with the two non-ASCII case-fold
// equivalents of ASCII letters rewritten to their ASCII counterparts, so an
// ASCII-case-insensitive Aho-Corasick search over the result cannot miss a
// literal that Go's `(?i)` regex folding would have matched.
//
// The result is for the prefilter search ONLY. Callers must never let it
// reach the real regex evaluation or any matched-text/evidence reporting:
// folding those would make a detector report a homoglyph-normalized string
// instead of the attacker's actual bytes, destroying the evidence of a
// genuine homoglyph attack.
//
// Returns text unchanged (no allocation) when neither rune is present,
// which is the overwhelmingly common case for real traffic.
func FoldForASCIISearch(text string) string {
	if !strings.ContainsRune(text, runeLongS) && !strings.ContainsRune(text, runeKelvin) {
		return text
	}
	return unicodeFoldReplacer.Replace(text)
}

// Required returns the most selective (longest shortest-alternative) set of
// literal strings such that: if NONE of them appear anywhere in the scanned
// text, pattern is PROVEN unable to match anywhere in that text either.
// Returns nil if no such set can be proven, if the best candidate found is
// too short to be a useful filter, or if the candidate contains any
// non-ASCII rune.
//
// nil means "no safe optimization available", NOT "no literals" -- callers
// must always evaluate such a pattern directly.
func Required(pattern string) []string {
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
	// best one, so a rejected non-ASCII candidate doesn't deny a perfectly
	// usable ASCII candidate elsewhere in the same pattern.
	//
	// The rejection must be whole-set, never per-literal: for an alternation
	// like (Alpha|Alph<U+00E4>), dropping just the non-ASCII branch would leave
	// "Alpha" looking "required" when text containing only "Alph<U+00E4>" still
	// matches the regex -- a false negative. Either the entire proven set
	// survives the ASCII check or the pattern gets no prefilter at all.
	var best []string
	for _, c := range candidates {
		if !allASCII(c) {
			continue
		}
		if best == nil || minLiteralLen(c) > minLiteralLen(best) {
			best = c
		}
	}
	if best == nil || minLiteralLen(best) < MinUsefulLiteralLen {
		return nil
	}
	return best
}

// mandatoryLiteralsOf checks a single AST node (not a concat sequence): is
// it unconditionally literal (or a capture of one), or a pure-literal
// alternation (every branch itself unconditionally literal, recursively)?
// Anything else -- OpStar/OpQuest/OpPlus/OpCharClass/OpAnyChar/anchors --
// is either optional (could be skipped in a match) or not a fixed literal,
// and is conservatively rejected: nil, not a guess.
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
