package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegis/svalinn/internal/config"
	"github.com/aegis/svalinn/internal/logger"
)

// Phase 7 (REQ SVALINN-CLIENTIP-SPOOF-001): getClientIP runs on every request,
// several times per request in the middleware chain, so its cost is on the hot
// path. This benchmark is written to compile against both the pre-fix and
// post-fix implementations so the two can be compared directly.

func benchServer() *Server {
	return &Server{
		log: logger.New("bench"),
		cfg: &config.Config{},
	}
}

func benchRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	return req
}

// BenchmarkGetClientIP_NginxHop is the dominant production shape: one hop
// through the local nginx, both proxy headers present.
func BenchmarkGetClientIP_NginxHop(b *testing.B) {
	s := benchServer()
	req := benchRequest("127.0.0.1:49200", "203.0.113.5", "203.0.113.5")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.getClientIP(req)
	}
}

// BenchmarkGetClientIP_DirectPeer covers a direct (non-proxied) connection,
// which short-circuits before any header parsing.
func BenchmarkGetClientIP_DirectPeer(b *testing.B) {
	s := benchServer()
	req := benchRequest("198.51.100.77:54321", "", "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.getClientIP(req)
	}
}

// BenchmarkGetClientIP_LongChain is the worst case: a long attacker-supplied
// X-Forwarded-For chain that must be split before the appended element is read.
func BenchmarkGetClientIP_LongChain(b *testing.B) {
	s := benchServer()
	req := benchRequest("127.0.0.1:49200",
		"10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 203.0.113.5, 198.51.100.77", "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.getClientIP(req)
	}
}
