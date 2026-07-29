package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegis/svalinn/internal/config"
	"github.com/aegis/svalinn/internal/logger"
	"github.com/aegis/svalinn/internal/payload"
)

// REQ SVALINN-BODYSIZE-EARLYGATE-001
//
// Root cause: six body-scanning detector middlewares
// (semantic/malware/exploitation/evasion/networkAttack/adAttack) all run
// BEFORE the only existing size cap (payloadSignatureMiddleware, which reads
// at most 1024*50 bytes and silently discards the rest). A body over that
// cap therefore pays the full cost of all six detectors' regex scans, then
// gets silently truncated, then fails JSON decoding downstream with a
// misleading 400 -- instead of being cheaply and clearly rejected before any
// of that work happens. Found via RATATOSKR round 5 (2026-07-28): a 64KiB
// benign body measured 7,049ms / HTTP 400 against live production, vs. 32ms
// for a bare /health check.
//
// No mocks: real payload.Generator, real payloadSignatureMiddleware, a
// handler that reproduces the exact decode-then-400 pattern used by the real
// TAXII handler (handlers.go:392-397).

func newBodySizeTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		log: logger.New("test"),
		cfg: &config.Config{PayloadSignature: config.PayloadSignatureConfig{Enabled: true}},
		payloadGenerator: payload.NewGenerator(payload.SignatureConfig{
			Enabled: true,
		}),
		stats: &Stats{},
	}
}

// taxiiDecodeStandIn reproduces handlers.go:392-397's exact behavior: decode
// the body as JSON, 400 on failure, 200 on success. It flags whether it was
// ever invoked, so tests can prove the expensive path was skipped entirely
// once the early gate is real.
func taxiiDecodeStandIn(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		var payload interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Invalid STIX bundle"})
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// oversizedValidJSONBody builds a syntactically valid JSON body larger than
// maxScannedBodyBytes -- valid in full, but guaranteed to become invalid
// JSON if truncated mid-string, exactly like payloadSignatureMiddleware does
// today.
func oversizedValidJSONBody(t *testing.T) string {
	t.Helper()
	padding := strings.Repeat("x", maxScannedBodyBytes+8*1024)
	body, err := json.Marshal(map[string]interface{}{
		"type":    "bundle",
		"objects": []interface{}{},
		"padding": padding,
	})
	if err != nil {
		t.Fatalf("failed to build oversized JSON body: %v", err)
	}
	if len(body) <= maxScannedBodyBytes {
		t.Fatalf("test body is %d bytes, must exceed maxScannedBodyBytes (%d)", len(body), maxScannedBodyBytes)
	}
	return string(body)
}

// TestOversizedBody_RejectedBeforeReachingExpensiveDetectorsOrTheHandler is
// the Red/Green pivot test for this REQ. Today (stub gate, passthrough
// only) it fails: the oversized body sails through the gate, gets silently
// truncated by payloadSignatureMiddleware, and the handler is reached with a
// corrupted body, producing 400 instead of the desired 413 -- and (reached
// == true) instead of the desired false. Once bodySizeLimitMiddleware is
// implemented for real, this passes: 413, and the downstream handler (the
// stand-in for all six detectors' cost) is never reached at all.
func TestOversizedBody_RejectedBeforeReachingExpensiveDetectorsOrTheHandler(t *testing.T) {
	s := newBodySizeTestServer(t)
	reached := false
	chain := s.bodySizeLimitMiddleware(s.payloadSignatureMiddleware(taxiiDecodeStandIn(&reached)))

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(oversizedValidJSONBody(t)))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d (PAYLOAD_TOO_LARGE); downstream reached=%v, body=%q",
			rec.Code, http.StatusRequestEntityTooLarge, reached, rec.Body.String())
	}
	if reached {
		t.Error("downstream handler was reached -- the whole point of the gate is to reject before any detector (or the handler) ever sees an oversized body")
	}
}

// TestBodySizeLimitMiddleware_PassesBodyAtOrUnderCapUnchanged proves the
// gate is not just "reject everything" -- a body at exactly the existing
// effective cap must reach the handler byte-for-byte untouched, so nothing
// that works today regresses.
func TestBodySizeLimitMiddleware_PassesBodyAtOrUnderCapUnchanged(t *testing.T) {
	s := newBodySizeTestServer(t)
	original := strings.Repeat("y", maxScannedBodyBytes)

	var gotBody []byte
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 0, maxScannedBodyBytes)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			b = append(b, buf[:n]...)
			if err != nil {
				break
			}
		}
		gotBody = b
		w.WriteHeader(http.StatusOK)
	})
	chain := s.bodySizeLimitMiddleware(handler)

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(original))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a body exactly at the cap", rec.Code)
	}
	if string(gotBody) != original {
		t.Errorf("body reached handler altered: got %d bytes, want %d bytes unchanged", len(gotBody), len(original))
	}
}

// TestBodySizeLimitMiddleware_PassesThroughRequestsWithNoBody guards against
// a regression that would slow down or break the overwhelming majority of
// traffic (GET requests, no body) -- this middleware runs globally, on
// every request through the chain.
func TestBodySizeLimitMiddleware_PassesThroughRequestsWithNoBody(t *testing.T) {
	s := newBodySizeTestServer(t)
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	chain := s.bodySizeLimitMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !called {
		t.Error("downstream handler was not called for a bodyless GET request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestOversizedBody_40KiBRejected_LowerCapBoundary pins REQ
// SVALINN-BODYCAP-REDUCE-001's new, lower ceiling with a body size fixed at
// an absolute 40KiB -- deliberately NOT derived from maxScannedBodyBytes, so
// this test's meaning doesn't drift if the constant changes again. A 40KiB
// body was accepted under the original 50KiB cap (SVALINN-BODYSIZE-
// EARLYGATE-001) but must be rejected under the reduced 8KiB cap: real
// production traffic showed zero genuine external TAXII/body-heavy requests
// in a 24h window (2026-07-29 investigation, see memory), so the reduction
// has no observed functional cost today, while the linear per-byte scan cost
// (~110ms/KiB, RATATOSKR round 5) drops by the same ~6x the cap itself drops
// by.
func TestOversizedBody_40KiBRejected_LowerCapBoundary(t *testing.T) {
	s := newBodySizeTestServer(t)
	chain := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler must not be reached for a 40KiB body under the reduced cap")
	}))

	oversized := strings.Repeat("q", 40*1024)
	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d (PAYLOAD_TOO_LARGE) for a 40KiB body under the reduced cap", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestBodySizeLimitMiddleware_ExactBoundary_8KiBPassesOneByteOverFails pins
// the precise 8KiB boundary with ABSOLUTE byte counts (8*1024, 8*1024+1),
// deliberately not derived from maxScannedBodyBytes. Phase 4 mutation
// testing (REQ SVALINN-BODYCAP-REDUCE-001) found that
// TestBodySizeLimitMiddleware_PassesBodyAtOrUnderCapUnchanged -- which sizes
// its body FROM the constant -- cannot catch an off-by-one on the constant
// itself (shrinking the constant just shrinks that test's body by the same
// amount, so it always trivially passes). This test closes that gap.
func TestBodySizeLimitMiddleware_ExactBoundary_8KiBPassesOneByteOverFails(t *testing.T) {
	s := newBodySizeTestServer(t)

	atCap := strings.Repeat("a", 8*1024)
	chainAtCap := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	reqAtCap := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(atCap))
	recAtCap := httptest.NewRecorder()
	chainAtCap.ServeHTTP(recAtCap, reqAtCap)
	if recAtCap.Code != http.StatusOK {
		t.Errorf("exactly 8KiB: status = %d, want 200", recAtCap.Code)
	}

	overCap := strings.Repeat("a", 8*1024+1)
	chainOverCap := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler must not be reached for a body one byte over the 8KiB cap")
	}))
	reqOverCap := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(overCap))
	recOverCap := httptest.NewRecorder()
	chainOverCap.ServeHTTP(recOverCap, reqOverCap)
	if recOverCap.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("8KiB+1 byte: status = %d, want %d", recOverCap.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestBodySizeLimitMiddleware_RejectionBodyIsWellFormed pins the exact
// response shape so a future refactor can't silently change the client-
// visible contract.
func TestBodySizeLimitMiddleware_RejectionBodyIsWellFormed(t *testing.T) {
	s := newBodySizeTestServer(t)
	chain := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream handler must not be reached for an oversized body")
	}))

	oversized := strings.Repeat("z", maxScannedBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response body is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if decoded["error"] != "PAYLOAD_TOO_LARGE" {
		t.Errorf(`response "error" = %v, want "PAYLOAD_TOO_LARGE"`, decoded["error"])
	}
}
