package detect

import (
	"regexp"
	"strings"
	"testing"

	"github.com/koodoxz/tameng/internal/literalextract"
)

// Phase 7 benchmarks for REQ SVALINN-DETECTPREFILTER-001.
//
// Two cases are measured, and BOTH are reported honestly:
//
//   - benign: an ordinary ~8KiB body, the case live-VPS pprof showed these
//     five detectors dominating.
//   - adaptive attacker: a body padded with one copy of EVERY literal the
//     extractor produced, which defeats the prefilter completely by making
//     every pattern a candidate. This is the worst case an attacker can
//     construct on purpose, and it is what SVALINN-SCANBUDGET-001's 100ms
//     ceiling exists to bound.
//
// A prefilter that only ever gets benchmarked on benign input is a
// half-measured prefilter.

func benignBody(size int) string {
	const filler = "The quick brown fox jumps over the lazy dog. " +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do " +
		"eiusmod tempor incididunt ut labore et dolore magna aliqua. "
	return strings.Repeat(filler, size/len(filler)+1)[:size]
}

// allExtractedLiterals gathers every literal the extractor produced across
// all four detectors -- exactly the set an adaptive attacker would need to
// sprinkle into a body to defeat the prefilter.
func allExtractedLiterals() []string {
	maps := []map[string][]*regexp.Regexp{
		NewEvasionDetector(EvasionConfig{Enabled: true}).patterns,
		NewADAttackDetector(ADAttackConfig{Enabled: true}).patterns,
		NewNetworkAttackDetector(NetworkAttackConfig{Enabled: true}).patterns,
		NewExploitationDetector(ExploitationConfig{Enabled: true}).patterns,
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range maps {
		for _, group := range m {
			for _, re := range group {
				for _, lit := range literalextract.Required(re.String()) {
					if _, ok := seen[lit]; ok {
						continue
					}
					seen[lit] = struct{}{}
					out = append(out, lit)
				}
			}
		}
	}
	return out
}

// adaptiveAttackerBody pads a body with one copy of every extracted
// literal, so no pattern can be prefiltered away.
func adaptiveAttackerBody(minSize int) string {
	var b strings.Builder
	for _, lit := range allExtractedLiterals() {
		b.WriteString(lit)
		b.WriteByte(' ')
	}
	for b.Len() < minSize {
		b.WriteString("padding ")
	}
	return b.String()
}

func benchDetectors(b *testing.B, data string, prefilter bool) {
	ev := NewEvasionDetector(EvasionConfig{Enabled: true})
	ad := NewADAttackDetector(ADAttackConfig{Enabled: true})
	na := NewNetworkAttackDetector(NetworkAttackConfig{Enabled: true})
	ex := NewExploitationDetector(ExploitationConfig{Enabled: true})
	if !prefilter {
		ev.prefilter, ad.prefilter, na.prefilter, ex.prefilter = nil, nil, nil, nil
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.Analyze(data)
		ad.Analyze(data)
		na.Analyze(data)
		ex.Analyze(data)
	}
}

func BenchmarkDetectors_Benign8KiB_PrefilterOff(b *testing.B) {
	benchDetectors(b, benignBody(8192), false)
}

func BenchmarkDetectors_Benign8KiB_PrefilterOn(b *testing.B) {
	benchDetectors(b, benignBody(8192), true)
}

func BenchmarkDetectors_Adaptive8KiB_PrefilterOff(b *testing.B) {
	benchDetectors(b, adaptiveAttackerBody(8192), false)
}

func BenchmarkDetectors_Adaptive8KiB_PrefilterOn(b *testing.B) {
	benchDetectors(b, adaptiveAttackerBody(8192), true)
}

// BenchmarkPrefilterCandidatesOnly isolates the per-request prefilter cost
// (one Aho-Corasick pass + the candidate slice) from the regex evaluation it
// replaces, so the allocation delta seen in the full benchmarks can be
// attributed rather than guessed at.
func BenchmarkPrefilterCandidatesOnly(b *testing.B) {
	ev := NewEvasionDetector(EvasionConfig{Enabled: true})
	body := benignBody(8192)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev.prefilter.Candidates(body)
	}
}

// BenchmarkPrefilterBuild measures the one-time construction cost paid per
// detector at startup, to confirm it is not a hidden per-request cost.
func BenchmarkPrefilterBuild(b *testing.B) {
	patterns := NewEvasionDetector(EvasionConfig{Enabled: true}).patterns
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		literalextract.NewGroups(patterns)
	}
}
