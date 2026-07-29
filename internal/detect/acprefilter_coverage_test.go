package detect

import (
	"regexp"
	"testing"
)

// TestPrefilterActuallySkipsWork guards against the prefilter silently
// degrading into a no-op (extracting nothing, or marking everything a
// candidate). That state would be perfectly SOUND -- every parity and fuzz
// test would still pass -- while delivering zero benefit, so it needs its
// own explicit check. Also reports the real skip rates.
// REQ SVALINN-DETECTPREFILTER-001.
func TestPrefilterActuallySkipsWork(t *testing.T) {
	body := benignBody(8192)

	cases := []struct {
		name     string
		patterns map[string][]*regexp.Regexp
		cand     []bool
	}{}

	ev := NewEvasionDetector(EvasionConfig{Enabled: true})
	cases = append(cases, struct {
		name     string
		patterns map[string][]*regexp.Regexp
		cand     []bool
	}{"evasion", ev.patterns, ev.prefilter.Candidates(body)})

	ad := NewADAttackDetector(ADAttackConfig{Enabled: true})
	cases = append(cases, struct {
		name     string
		patterns map[string][]*regexp.Regexp
		cand     []bool
	}{"ad_attack", ad.patterns, ad.prefilter.Candidates(body)})

	na := NewNetworkAttackDetector(NetworkAttackConfig{Enabled: true})
	cases = append(cases, struct {
		name     string
		patterns map[string][]*regexp.Regexp
		cand     []bool
	}{"network_attack", na.patterns, na.prefilter.Candidates(body)})

	ex := NewExploitationDetector(ExploitationConfig{Enabled: true})
	cases = append(cases, struct {
		name     string
		patterns map[string][]*regexp.Regexp
		cand     []bool
	}{"exploitation", ex.patterns, ex.prefilter.Candidates(body)})

	for _, c := range cases {
		if c.cand == nil {
			t.Errorf("%s: prefilter was not built at all", c.name)
			continue
		}
		total := 0
		for _, g := range c.patterns {
			total += len(g)
		}
		skipped := 0
		for _, ok := range c.cand {
			if !ok {
				skipped++
			}
		}
		if skipped == 0 {
			t.Errorf("%s: prefilter skipped 0 of %d patterns on a benign body; "+
				"it is doing nothing", c.name, total)
		}
		t.Logf("%-15s skipped %d of %d patterns (%.1f%%) on a benign 8KiB body",
			c.name, skipped, total, 100*float64(skipped)/float64(total))
	}
}

// The disabled-detector early return is the only branch of each modified
// Analyze the parity corpus does not reach. REQ SVALINN-DETECTPREFILTER-001.
func TestDetectorsDisabledShortCircuit(t *testing.T) {
	data := "AmsiScanBuffer krbtgt arp spoof VirtualAlloc 0c0c0c0c"

	if r := NewEvasionDetector(EvasionConfig{}).Analyze(data); r.Detected {
		t.Error("disabled evasion detector must not report detections")
	}
	if r := NewADAttackDetector(ADAttackConfig{}).Analyze(data); r.Detected {
		t.Error("disabled AD detector must not report detections")
	}
	if r := NewNetworkAttackDetector(NetworkAttackConfig{}).Analyze(data); r.Detected {
		t.Error("disabled network detector must not report detections")
	}
	if r := NewExploitationDetector(ExploitationConfig{}).Analyze(data); r.Detected {
		t.Error("disabled exploitation detector must not report detections")
	}
}
