package semantic

import (
	"strings"
	"testing"
)

// REQ SVALINN-SCANBUDGET-001 -- Phase 7 (performance/calibration).
//
// Confirms analyzeBudget (25ms) sits comfortably above real benign cost.

func BenchmarkAnalyzer_Analyze_Benign8KiB(b *testing.B) {
	a := NewAnalyzer(AnalyzerConfig{Enabled: true})
	body := strings.Repeat("x", 8*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Analyze(body)
	}
}
