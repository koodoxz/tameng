package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ SVALINN-BODYSIZE-EARLYGATE-001 -- Phase 7 (performance).
//
// The point of this gate is that rejecting an oversized body must be cheap
// (microseconds), in contrast to the ~110ms-per-KiB cost of letting it reach
// the six detector middlewares first (measured live via RATATOSKR round 5,
// 2026-07-28: a 64KiB body cost 7,049ms end-to-end). This benchmark isolates
// just the gate, not the full chain, since the six detectors are unaffected
// by this change for bodies at or under the cap.

func BenchmarkBodySizeLimitMiddleware_AcceptsBodyAtCap(b *testing.B) {
	s := &Server{stats: &Stats{}}
	body := strings.Repeat("y", maxScannedBodyBytes)
	handler := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkBodySizeLimitMiddleware_RejectsOversizedBody(b *testing.B) {
	s := &Server{stats: &Stats{}}
	body := strings.Repeat("z", maxScannedBodyBytes*2)
	handler := s.bodySizeLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.Fatal("downstream must never be reached for an oversized body")
	}))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects", strings.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
