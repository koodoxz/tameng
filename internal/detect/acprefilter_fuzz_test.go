package detect

import (
	"strings"
	"testing"
)

// FuzzACPrefilterParity is the differential fuzzer behind REQ
// SVALINN-DETECTPREFILTER-001: for ANY input, all four touched detectors
// must produce identical results with the prefilter enabled and disabled.
// A single disagreement is a false negative introduced by the prefilter.
//
// Seeded with the full deterministic parity corpus so the fuzzer starts
// from inputs already known to exercise every category, then mutates
// outward from there.
func FuzzACPrefilterParity(f *testing.F) {
	for _, c := range parityCorpus() {
		f.Add(c.data)
	}
	// Extra seeds aimed squarely at the prefilter's edges.
	f.Add(string(rune(0x017F)))
	f.Add(string(rune(0x212A)))
	f.Add("AmsiScanBuffer" + string(rune(0x017F)))
	f.Add(strings.Repeat(string(rune(0x017F)), 64))
	f.Add("\xff\xfe\xfd invalid utf8")
	f.Add(adaptiveAttackerBody(256))

	f.Fuzz(func(t *testing.T, data string) {
		// Keep bodies bounded: past a few KiB the run is dominated by regex
		// time, and a body large enough to approach the 100ms scan budget
		// would make the two runs legitimately diverge on budget cutoff
		// rather than on prefilter correctness -- a false alarm, not a bug.
		if len(data) > 8192 {
			data = data[:8192]
		}
		with, without := analyzeBothWays(data)
		for name := range without {
			if with[name] != without[name] {
				t.Fatalf("PREFILTER PARITY BREAK in %s\ninput: %q\nwith:  %s\nwithout: %s",
					name, data, with[name], without[name])
			}
		}
	})
}
