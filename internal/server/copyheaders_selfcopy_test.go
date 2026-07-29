package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegis/svalinn/internal/config"
	"github.com/aegis/svalinn/internal/egress"
	"github.com/aegis/svalinn/internal/logger"
	"github.com/aegis/svalinn/internal/response"
)

// REQ SVALINN-COPYHEADERS-SELFCOPY-001
//
// Both advancedEgressMiddleware and responseEncryptMiddleware wrap the real
// ResponseWriter in an *egressResponseWriter, which embeds http.ResponseWriter
// directly and never overrides Header(). That means capture.Header() IS
// w.Header() -- the identical map, not a copy. copyHeaders(w.Header(),
// capture.Header()) therefore always copied a header set onto itself, and
// since copyHeaders uses http.Header.Add (append, not overwrite), every header
// value was duplicated on every response that passed through either
// middleware. No mocks: real egress.Engine and real response.Encryptor.

func newAdvancedEgressTestServer(t *testing.T) *Server {
	t.Helper()
	engine := egress.NewEngine(egress.Config{Enabled: true})
	return &Server{
		log:            logger.New("test"),
		cfg:            &config.Config{AdvancedEgress: config.AdvancedEgressConfig{Enabled: true}},
		advancedEgress: engine,
		stats:          &Stats{},
	}
}

func newResponseEncryptTestServer(t *testing.T) *Server {
	t.Helper()
	enc := response.NewEncryptor(response.EncryptConfig{
		Enabled:      true,
		ProtectPaths: []string{"/admin"},
	})
	return &Server{
		log:             logger.New("test"),
		cfg:             &config.Config{ResponseEncrypt: config.ResponseEncryptConfig{Enabled: true}},
		responseEncrypt: enc,
		stats:           &Stats{},
	}
}

func headerValueCounts(h http.Header) map[string]int {
	counts := make(map[string]int, len(h))
	for k, v := range h {
		counts[k] = len(v)
	}
	return counts
}

func TestAdvancedEgressMiddleware_DoesNotDuplicateHeaders(t *testing.T) {
	s := newAdvancedEgressTestServer(t)

	handler := s.advancedEgressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Marker", "one")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	counts := headerValueCounts(rec.Header())
	if n := counts["Content-Type"]; n != 1 {
		t.Errorf("Content-Type has %d values, want 1 (headers duplicated): %v", n, rec.Header()["Content-Type"])
	}
	if n := counts["X-Custom-Marker"]; n != 1 {
		t.Errorf("X-Custom-Marker has %d values, want 1 (headers duplicated): %v", n, rec.Header()["X-Custom-Marker"])
	}
	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("body = %q, want the handler's original body untouched", got)
	}
}

func TestResponseEncryptMiddleware_DoesNotDuplicateHeaders(t *testing.T) {
	s := newResponseEncryptTestServer(t)

	handler := s.responseEncryptMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret dashboard data"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/panel", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	counts := headerValueCounts(rec.Header())
	if n := counts["Content-Type"]; n != 1 {
		t.Errorf("Content-Type has %d values, want 1 (headers duplicated): %v", n, rec.Header()["Content-Type"])
	}
	if n := counts["X-Svalinn-Response-Token"]; n != 1 {
		t.Errorf("X-Svalinn-Response-Token has %d values, want 1 (headers duplicated): %v", n, rec.Header()["X-Svalinn-Response-Token"])
	}
	if rec.Header().Get("X-Svalinn-Response-Token") == "" {
		t.Error("X-Svalinn-Response-Token was not set at all -- test setup problem, not the bug under test")
	}
}
