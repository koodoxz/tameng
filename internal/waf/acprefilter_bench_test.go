package waf

import (
	"strings"
	"testing"
)

// REQ SVALINN-WAFSCAN-ACPREFILTER-001 -- Phase 7 (performance).
//
// Benchmarks the realistic common case: a benign body (RATATOSKR's actual
// "x"-filler shape from round 5), which is the overwhelming majority of
// real traffic. Both benchmarks call the REAL, unmodified Scan() -- on vs.
// reference (prefilter forced off) -- so this measures the actual
// production code path, not an isolated microbenchmark of the AC library
// alone (that isolated number was already validated separately via the
// pre-implementation spike; this benchmark is end-to-end).

func BenchmarkEngineScan_BenignBody50KiB_ACPrefilterOn(b *testing.B) {
	e := newDefaultEngine(b)
	body := strings.Repeat("x", 50*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}

func BenchmarkEngineScan_BenignBody50KiB_ACPrefilterOff(b *testing.B) {
	e := newACReferenceEngine(b)
	body := strings.Repeat("x", 50*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}

// BenchmarkEngineScan_RealAttackBody50KiB measures the other real case: a
// body that DOES contain a genuine attack payload embedded in padding. The
// prefilter must still find it (correctness, proven separately by the
// parity tests) -- this just confirms the "hit" path isn't pathologically
// slower than the pre-optimization baseline.
func BenchmarkEngineScan_RealAttackBody50KiB_ACPrefilterOn(b *testing.B) {
	e := newDefaultEngine(b)
	body := strings.Repeat("x", 25*1024) + "' UNION SELECT username,password FROM users--" + strings.Repeat("x", 25*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}

func BenchmarkEngineScan_RealAttackBody50KiB_ACPrefilterOff(b *testing.B) {
	e := newACReferenceEngine(b)
	body := strings.Repeat("x", 25*1024) + "' UNION SELECT username,password FROM users--" + strings.Repeat("x", 25*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Scan("/taxii/collections/default/objects", "", body, map[string]string{"Content-Type": "application/json"}, "Mozilla/5.0")
	}
}
