package detect

import (
	"strings"
	"testing"
)

// REQ SVALINN-SCANBUDGET-001 -- Phase 7 (performance/calibration).
//
// Confirms checkPatternsBudget (25ms) sits comfortably above real benign
// cost via EvasionDetector (51 real patterns), so it essentially never
// trips for normal traffic.

func BenchmarkEvasionDetector_Analyze_Benign8KiB(b *testing.B) {
	d := NewEvasionDetector(EvasionConfig{Enabled: true})
	body := strings.Repeat("x", 8*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Analyze(body)
	}
}
