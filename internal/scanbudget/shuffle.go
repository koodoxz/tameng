/*
Package scanbudget provides a shared, stdlib-only primitive for bounding the
wall-clock time spent evaluating a set of detection patterns against a
single request, and for randomizing pattern evaluation order so a budget
cutoff doesn't deterministically favor evading the same patterns every time.

REQ SVALINN-SCANBUDGET-001. Zero internal imports, so it can be imported by
internal/detect, internal/semantic, internal/malware, and internal/waf
without creating an import cycle back to internal/server (the same reason
internal/netutil exists as its own package -- see SVALINN-CLIENTIP-SPOOF-002).
*/
package scanbudget

import "math/rand"

// ShuffledIndices returns a random permutation of [0, n). Callers use it to
// iterate a fixed-order pattern slice in a randomized order per call,
// without mutating the shared underlying slice (which is read concurrently
// across requests). math/rand's top-level functions, including Shuffle, are
// safe for concurrent use by multiple goroutines.
func ShuffledIndices(n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	rand.Shuffle(n, func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
	return idx
}
