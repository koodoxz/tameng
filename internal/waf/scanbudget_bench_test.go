package waf

import (
	"strings"
	"testing"
)

// REQ SVALINN-SCANBUDGET-001 -- Phase 7 (performance/calibration).
//
// Confirms signatureScanBudget (25ms) sits comfortably above real benign
// cost (so it essentially never trips for normal traffic) while genuinely
// bounding the adaptive-attacker case that defeats the AC-prefilter
// (SVALINN-WAFSCAN-ACPREFILTER-001's own finding: ~1337 bytes of literal
// salt drops the prefilter's speedup to ~0.99x).

func BenchmarkScan_Benign8KiB(b *testing.B) {
	e := newDefaultEngine(b)
	body := strings.Repeat("x", 8*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}

// adaptiveSalt8KiB approximates an adaptive attacker's body: real body-AC
// literals repeated to defeat the prefilter, padded to 8KiB (today's cap,
// SVALINN-BODYCAP-REDUCE-001) with benign filler.
func adaptiveSalt8KiB(e *Engine) string {
	var salt strings.Builder
	for _, lit := range e.bodyACPatterns {
		salt.WriteString(lit)
		salt.WriteString(" ")
	}
	body := salt.String()
	if len(body) < 8*1024 {
		body += strings.Repeat("x", 8*1024-len(body))
	}
	return body
}

func BenchmarkScan_AdaptiveAttackerShaped8KiB(b *testing.B) {
	e := newDefaultEngine(b)
	body := adaptiveSalt8KiB(e)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}
