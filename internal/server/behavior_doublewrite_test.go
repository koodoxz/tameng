package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
	"github.com/koodoxz/tameng/internal/behavior"
	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-BEHAVIOR-DBLWRITE-001
//
// behavioralDetectorMiddleware calls next.ServeHTTP first, letting the whole
// downstream chain commit a complete response, and only THEN evaluates the
// behavioral alert. When the alert score crosses BlockScoreThreshold it used to
// call s.jsonResponse on the same, already-committed ResponseWriter -- appending
// a second top-level JSON document to a response that was already sent.
//
// Real-world signature (production nginx logs, 2026-07-27): external scanners
// hammering 404s received bimodal response sizes -- ~340-361 bytes for a clean
// single-body 404, and ~596-605 bytes when the behavioral 429 body got appended.
//
// The scoring path exercised here is the real one: internal/behavior.detectErrorRate
// scores 40 + (errorRate * 100). A single 404 gives rate 1.0 -> score 140, capped
// to 100, which clears the default BlockScoreThreshold of 85. No mocks, no stubs:
// the detector, the actor tracker and the middleware are all the production types.

const dblWriteScannerIP = "198.51.100.9"

// newBehaviorTestServer builds a Server wired with the REAL behavioral detector
// and the REAL actor tracker. Only the downstream HTTP handler varies per test.
func newBehaviorTestServer(t *testing.T) *Server {
	t.Helper()

	detectorCfg := config.BehavioralDetectorConfig{
		Enabled:             true,
		ErrorRateThreshold:  0.4,
		AlertScoreThreshold: 60,
		BlockScoreThreshold: 85,
		// Long eviction/cleanup intervals keep background goroutines out of the
		// way so assertions are deterministic under -race.
		CleanupInterval: time.Hour,
	}

	detector := behavior.NewDetector(behavior.DetectorConfig{
		Enabled:             detectorCfg.Enabled,
		ErrorRateThreshold:  detectorCfg.ErrorRateThreshold,
		AlertScoreThreshold: detectorCfg.AlertScoreThreshold,
		BlockScoreThreshold: detectorCfg.BlockScoreThreshold,
		CleanupInterval:     detectorCfg.CleanupInterval,
	})
	// behavior.Detector exposes no Stop method; the 1h CleanupInterval above keeps
	// its background loop idle for the lifetime of the test.

	// promotionThreshold 1 so the scanner IP becomes a full Actor quickly; the
	// tests pre-warm it below so AddThreat lands on a real Actor deterministically.
	tracker := actor.NewTracker(1000, 1, time.Hour)
	t.Cleanup(tracker.Stop)

	return &Server{
		log:              logger.New("test"),
		cfg:              &config.Config{BehavioralDetect: detectorCfg},
		behaviorDetector: detector,
		actorTracker:     tracker,
		stats:            &Stats{StartTime: time.Now()},
	}
}

// prewarmActor promotes the IP to a full Actor so AddThreat is observable.
func prewarmActor(t *testing.T, s *Server, ip string) {
	t.Helper()
	for i := 0; i < 3; i++ {
		s.actorTracker.Track(ip)
	}
	if s.actorTracker.Get(ip) == nil {
		t.Fatalf("test setup: actor %s was not promoted", ip)
	}
}

func scannerRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = dblWriteScannerIP + ":54321"
	req.Header.Set("User-Agent", "scanner/1.0")
	return req
}

// notFoundHandler is a realistic committed response: an explicit 404 plus a body,
// exactly what the production mux emits for the scanner traffic in question.
func notFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	})
}

const notFoundBody = `{"error":"not found"}`

// TestBehavioralDetector_NoSecondBodyOnCommittedResponse is the core RED test.
//
// The client must receive exactly the original 404 body -- nothing appended.
func TestBehavioralDetector_NoSecondBodyOnCommittedResponse(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest("/wp-login.php"))

	if got := rec.Body.String(); got != notFoundBody {
		t.Errorf("client received a corrupted body.\n got: %q\nwant: %q", got, notFoundBody)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("got status %d, want %d (first WriteHeader wins)", rec.Code, http.StatusNotFound)
	}
}

// TestBehavioralDetector_NoDetectorStateLeak is the Phase 9 security assertion:
// the behavioral detector's internal scoring state must never reach the client.
//
// Leaking it hands an unauthenticated attacker a threshold-evasion oracle -- they
// read their own live score on every response and tune request rate to stay under
// BlockScoreThreshold.
func TestBehavioralDetector_NoDetectorStateLeak(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest("/.env"))

	body := rec.Body.String()
	// Every one of these is detector internal state that an external caller must
	// never be able to read back.
	leaks := []string{
		"behavioral_detector", // block reason
		"BEHAVIOR-RESP-001",   // alert ID
		"High Error Rate",     // alert name
		"error_rate",          // raw window counter
		"errors",              // raw window counter
		"total",               // raw window counter
		"score",               // the evasion oracle itself
		"blocked",             // block status
	}
	for _, leak := range leaks {
		if strings.Contains(body, leak) {
			t.Errorf("detector state %q leaked to client; body = %q", leak, body)
		}
	}
}

// TestBehavioralDetector_CommittedResponseStaysValidJSON proves the response is a
// single well-formed JSON document, not two concatenated top-level documents.
func TestBehavioralDetector_CommittedResponseStaysValidJSON(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest("/admin"))

	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))

	var first map[string]interface{}
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body = %q)", err, rec.Body.String())
	}

	// A second decodable document means the body is malformed for strict parsers.
	var second map[string]interface{}
	if err := dec.Decode(&second); err != io.EOF {
		t.Errorf("response contains a second JSON document (err=%v, doc=%v); body = %q",
			err, second, rec.Body.String())
	}
}

// TestBehavioralDetector_BookkeepingStillRecordedWhenCommitted verifies the fix
// suppresses only the HTTP write, NOT the detection bookkeeping. Server-side
// telemetry must still record the block decision.
func TestBehavioralDetector_BookkeepingStillRecordedWhenCommitted(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest("/phpmyadmin"))

	if got := atomic.LoadInt64(&s.stats.BlockedRequests); got != 1 {
		t.Errorf("stats.BlockedRequests = %d, want 1 (detection must still be counted)", got)
	}

	a := s.actorTracker.Get(dblWriteScannerIP)
	if a == nil {
		t.Fatal("actor disappeared")
	}
	var found bool
	for _, tt := range a.ThreatTypes {
		if tt == "behavioral_detector" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("actorTracker.AddThreat was not recorded; ThreatTypes = %v", a.ThreatTypes)
	}
	if a.ThreatScore <= 0 {
		t.Errorf("actor ThreatScore = %v, want > 0", a.ThreatScore)
	}
}

// TestBehavioralDetector_PassthroughWhenNoAlert covers integration case (a):
// a clean 200 response produces no alert and must be forwarded untouched.
func TestBehavioralDetector_PassthroughWhenNoAlert(t *testing.T) {
	s := newBehaviorTestServer(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(handler).ServeHTTP(rec, scannerRequest("/"))

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("passthrough body altered: got %q", got)
	}
	if got := atomic.LoadInt64(&s.stats.BlockedRequests); got != 0 {
		t.Errorf("stats.BlockedRequests = %d, want 0 (no alert fired)", got)
	}
}

// TestBehavioralDetector_UncommittedResponseStillBlocks covers integration case
// (d): the reachable "response not yet committed" path.
//
// A handler that neither calls WriteHeader nor Write has committed nothing at the
// moment the middleware inspects the alert (net/http only sends its implicit 200
// later). Here a fresh 429 IS still legitimately sendable, and must still be sent.
//
// Reaching this requires prior error events on the same profile, because the
// current request contributes status 200 to the error-rate window.
func TestBehavioralDetector_UncommittedResponseStillBlocks(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	// Seed the profile with real 404 traffic from the same IP.
	for i := 0; i < 4; i++ {
		s.behavioralDetectorMiddleware(notFoundHandler()).
			ServeHTTP(httptest.NewRecorder(), scannerRequest("/seed"))
	}

	// Handler writes nothing at all -> nothing committed yet.
	silent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(silent).ServeHTTP(rec, scannerRequest("/quiet"))

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("uncommitted response must still be blockable: got status %d, want 429", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "behavioral_detector") {
		t.Errorf("expected the 429 block body, got %q", rec.Body.String())
	}
}

// seedErrors drives n real 404s from the scanner IP through the middleware so the
// error-rate window is primed before the request under test.
func seedErrors(t *testing.T, s *Server, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		s.behavioralDetectorMiddleware(notFoundHandler()).
			ServeHTTP(httptest.NewRecorder(), scannerRequest("/seed"))
	}
}

// TestBehavioralDetector_WriteOnlyHandlerNotDoubleWritten covers a handler that
// never calls WriteHeader and only calls Write. net/http commits an implicit 200
// on that first Write, so the response IS committed even though WriteHeader was
// never invoked -- the wrapper must record that, or the guard misses it.
func TestBehavioralDetector_WriteOnlyHandlerNotDoubleWritten(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)
	seedErrors(t, s, 4)

	writeOnly := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`)) // no WriteHeader call at all
	})

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(writeOnly).ServeHTTP(rec, scannerRequest("/implicit"))

	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("implicit-200 response was double-written.\n got: %q\nwant: %q", got, `{"ok":true}`)
	}
}

// TestBehavioralDetector_HeaderOnlyResponseNotDoubleWritten covers a handler that
// calls WriteHeader and writes no body. The response is committed, so the block
// body must not be appended -- the client must receive an empty body.
func TestBehavioralDetector_HeaderOnlyResponseNotDoubleWritten(t *testing.T) {
	s := newBehaviorTestServer(t)
	prewarmActor(t, s, dblWriteScannerIP)

	headerOnly := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no body
	})

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(headerOnly).ServeHTTP(rec, scannerRequest("/wp-login.php"))

	if got := rec.Body.String(); got != "" {
		t.Errorf("header-only response had a body appended: %q", got)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("got status %d, want 404", rec.Code)
	}
}

// TestBehavioralDetector_AlertBelowBlockThreshold covers integration case (b) and
// the false branch of the `alert.Score >= BlockScoreThreshold` comparison: an
// alert fires, but scores under the block threshold. Nothing may be written and
// nothing may be counted as blocked.
//
// detectErrorRate scores 40 + rate*100, so a 0.4 error rate (which is exactly the
// ErrorRateThreshold, so an alert IS produced) scores 80 -- under the 95 used here.
func TestBehavioralDetector_AlertBelowBlockThreshold(t *testing.T) {
	s := newBehaviorTestServer(t)
	s.cfg.BehavioralDetect.BlockScoreThreshold = 95
	prewarmActor(t, s, dblWriteScannerIP)

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	// Build a window of 2 errors + 2 successes, then measure the 5th request.
	for i := 0; i < 2; i++ {
		s.behavioralDetectorMiddleware(notFoundHandler()).
			ServeHTTP(httptest.NewRecorder(), scannerRequest("/seed-err"))
	}
	for i := 0; i < 2; i++ {
		s.behavioralDetectorMiddleware(okHandler).
			ServeHTTP(httptest.NewRecorder(), scannerRequest("/seed-ok"))
	}

	before := atomic.LoadInt64(&s.stats.BlockedRequests)

	rec := httptest.NewRecorder()
	// 5th request: total=5, errors=2 -> rate 0.4 -> alert at score 80 (< 95).
	s.behavioralDetectorMiddleware(okHandler).ServeHTTP(rec, scannerRequest("/seed-ok"))

	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("sub-threshold alert must not alter the body: got %q", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}
	if after := atomic.LoadInt64(&s.stats.BlockedRequests); after != before {
		t.Errorf("sub-threshold alert incremented BlockedRequests: %d -> %d", before, after)
	}
}

// TestBehavioralDetector_NilActorTrackerStillBlocks covers the false branch of the
// `s.actorTracker != nil` guard: the block path must not panic and must still
// suppress the second body when no actor tracker is configured.
func TestBehavioralDetector_NilActorTrackerStillBlocks(t *testing.T) {
	s := newBehaviorTestServer(t)
	// Detach only the Server's reference; the tracker created in the helper is
	// still stopped by that helper's t.Cleanup (Tracker.Stop is not idempotent).
	s.actorTracker = nil

	rec := httptest.NewRecorder()
	s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest("/wp-login.php"))

	if got := rec.Body.String(); got != notFoundBody {
		t.Errorf("body corrupted with nil actorTracker: got %q, want %q", got, notFoundBody)
	}
	if got := atomic.LoadInt64(&s.stats.BlockedRequests); got != 1 {
		t.Errorf("stats.BlockedRequests = %d, want 1", got)
	}
}

// BenchmarkResponseWriterWrite measures the wrapper write path directly -- this is
// where the fix adds work (a single bool store per Write/WriteHeader).
func BenchmarkResponseWriterWrite(b *testing.B) {
	payload := []byte(`{"ok":true}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw := &responseWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(payload)
	}
}

// BenchmarkBehavioralDetectorMiddleware_Passthrough measures the true hot path:
// every request that does NOT trip the block threshold.
func BenchmarkBehavioralDetectorMiddleware_Passthrough(b *testing.B) {
	detector := behavior.NewDetector(behavior.DetectorConfig{
		Enabled:             true,
		ErrorRateThreshold:  0.4,
		BlockScoreThreshold: 85,
		CleanupInterval:     time.Hour,
	})
	tracker := actor.NewTracker(1000, 1, time.Hour)
	defer tracker.Stop()

	s := &Server{
		log: logger.New("test"),
		cfg: &config.Config{BehavioralDetect: config.BehavioralDetectorConfig{
			Enabled:             true,
			ErrorRateThreshold:  0.4,
			BlockScoreThreshold: 85,
		}},
		behaviorDetector: detector,
		actorTracker:     tracker,
		stats:            &Stats{StartTime: time.Now()},
	}

	h := s.behavioralDetectorMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	req := scannerRequest("/bench")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// TestBehavioralDetector_DisabledPassthrough covers the early-return branches so
// the modified function reaches full branch coverage.
func TestBehavioralDetector_DisabledPassthrough(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Server)
		path string
	}{
		{"nil detector", func(s *Server) { s.behaviorDetector = nil }, "/wp-login.php"},
		{"disabled in config", func(s *Server) { s.cfg.BehavioralDetect.Enabled = false }, "/wp-login.php"},
		{"ecosystem endpoint exempt", func(s *Server) {}, "/api/v1/shield/threats"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newBehaviorTestServer(t)
			tc.mut(s)

			rec := httptest.NewRecorder()
			s.behavioralDetectorMiddleware(notFoundHandler()).ServeHTTP(rec, scannerRequest(tc.path))

			if got := rec.Body.String(); got != notFoundBody {
				t.Errorf("passthrough body altered: got %q, want %q", got, notFoundBody)
			}
			if got := atomic.LoadInt64(&s.stats.BlockedRequests); got != 0 {
				t.Errorf("stats.BlockedRequests = %d, want 0", got)
			}
		})
	}
}
