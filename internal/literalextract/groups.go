package literalextract

import (
	"regexp"
	"sort"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// Groups is a prefilter over a detector's whole category->patterns map,
// built ONCE at detector-construction time and read-only thereafter (so it
// is safe for concurrent use across requests without locking).
//
// One combined Aho-Corasick automaton spans every category, so a request
// costs a SINGLE O(n) pass over the body rather than one pass per category.
// That matters: the detectors here have 5-8 categories each, and a per-
// category automaton would re-scan the same 8KiB body 5-8 times, spending a
// meaningful share of the savings the prefilter is supposed to deliver.
//
// REQ SVALINN-DETECTPREFILTER-001.
type Groups struct {
	ac ahocorasick.AhoCorasick

	// litToPatterns maps an AC pattern index (the index into the literal
	// slice handed to Build) to every global pattern index requiring it.
	litToPatterns [][]int

	// alwaysEval is the template result: true at every global pattern index
	// whose regex yielded no provable required literal. Those patterns are
	// unaffected by this REQ and are always evaluated directly, exactly as
	// before. Copied per call rather than recomputed.
	alwaysEval []bool

	spans map[string]span
	ready bool
}

type span struct{ start, count int }

// NewGroups builds the combined prefilter. Returns a usable *Groups even
// when nothing could be extracted; Candidates then simply reports nil and
// every caller falls back to full evaluation.
func NewGroups(patterns map[string][]*regexp.Regexp) *Groups {
	names := make([]string, 0, len(patterns))
	for name := range patterns {
		names = append(names, name)
	}
	// Sorted so global indices are deterministic regardless of Go's
	// randomized map iteration order -- otherwise the automaton's layout,
	// and anything that ever gets logged about it, would differ per process.
	sort.Strings(names)

	g := &Groups{spans: make(map[string]span, len(names))}

	litIndex := make(map[string]int)
	var lits []string
	next := 0
	for _, name := range names {
		group := patterns[name]
		g.spans[name] = span{start: next, count: len(group)}
		for _, re := range group {
			idx := next
			next++
			g.alwaysEval = append(g.alwaysEval, false)
			if re == nil {
				g.alwaysEval[idx] = true
				continue
			}
			required := Required(re.String())
			if len(required) == 0 {
				g.alwaysEval[idx] = true
				continue
			}
			for _, lit := range required {
				li, ok := litIndex[lit]
				if !ok {
					li = len(lits)
					litIndex[lit] = li
					lits = append(lits, lit)
					g.litToPatterns = append(g.litToPatterns, nil)
				}
				g.litToPatterns[li] = append(g.litToPatterns[li], idx)
			}
		}
	}

	if len(lits) == 0 {
		return g // ready stays false: no useful literals, never prefilter
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		// ASCII-case-insensitive is SOUND for both kinds of pattern here:
		// for a `(?i)` pattern it mirrors the regex's own folding (with
		// FoldForASCIISearch covering the two non-ASCII fold orbits), and
		// for a case-SENSITIVE pattern it is a strict over-approximation --
		// it can only report a literal present that the regex would not
		// have matched, which costs an unnecessary evaluation, never a
		// missed one.
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		// StandardMatch + IterOverlapping is mandatory, not stylistic.
		// Iter() reports only leftmost non-overlapping matches, so with
		// literals "SELECT" and "SELECTX" both registered, the text
		// "selectx" yields ONLY "SELECT" -- every pattern requiring
		// "SELECTX" would then be wrongly skipped. That is a silent
		// detector bypass. TestIterWouldMissOverlappingLiterals pins this.
		MatchKind: ahocorasick.StandardMatch,
	})
	g.ac = builder.Build(lits)
	g.ready = true
	return g
}

// Candidates returns, per global pattern index, whether that pattern still
// needs its regex evaluated against text. A nil result means "no prefilter
// available -- evaluate everything", the original always-safe behavior.
//
// Sound by construction: an index is false only when the pattern had a
// proven-required literal set and NONE of those literals occur anywhere in
// text, which proves the regex cannot match text.
func (g *Groups) Candidates(text string) []bool {
	// text == "" deliberately falls back to full evaluation: a pattern can
	// legitimately match the empty string, and the prefilter has nothing to
	// prove anything with.
	if g == nil || !g.ready || text == "" {
		return nil
	}

	cand := make([]bool, len(g.alwaysEval))
	copy(cand, g.alwaysEval)

	it := g.ac.IterOverlapping(FoldForASCIISearch(text))
	for m := it.Next(); m != nil; m = it.Next() {
		for _, pi := range g.litToPatterns[m.Pattern()] {
			cand[pi] = true
		}
	}
	return cand
}

// Slice narrows a Candidates result to one category's patterns. Returns nil
// (evaluate everything in that category) for an unknown category or a nil
// cand, so a caller can never accidentally read another category's flags.
func (g *Groups) Slice(cand []bool, name string) []bool {
	if g == nil || cand == nil {
		return nil
	}
	sp, ok := g.spans[name]
	if !ok || sp.count == 0 || sp.start+sp.count > len(cand) {
		return nil
	}
	return cand[sp.start : sp.start+sp.count]
}
