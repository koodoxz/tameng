package netutil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Phase 7 (REQ SVALINN-CLIENTIP-SPOOF-002): TrustedClientIP runs on every
// analyzed request in five detection subsystems, so its cost is on the hot path.
// naiveClientIP reproduces the header-read it replaces, so the two can be
// compared directly in the same run.

func naiveClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return strings.Split(r.RemoteAddr, ":")[0]
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

// BenchmarkTrustedClientIP_NginxHop is the dominant production shape: one hop
// through the local nginx, both proxy headers present.
func BenchmarkTrustedClientIP_NginxHop(b *testing.B) {
	req := benchRequest(nginxPeer, victimIP, victimIP)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TrustedClientIP(req)
	}
}

func BenchmarkNaiveClientIP_NginxHop(b *testing.B) {
	req := benchRequest(nginxPeer, victimIP, victimIP)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = naiveClientIP(req)
	}
}

// BenchmarkTrustedClientIP_DirectPeer covers a direct (non-proxied) connection,
// which short-circuits before any header parsing.
func BenchmarkTrustedClientIP_DirectPeer(b *testing.B) {
	req := benchRequest(attackerIP+":54321", "", "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TrustedClientIP(req)
	}
}

func BenchmarkNaiveClientIP_DirectPeer(b *testing.B) {
	req := benchRequest(attackerIP+":54321", "", "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = naiveClientIP(req)
	}
}

// BenchmarkTrustedClientIP_LongChain is the worst case: a long attacker-supplied
// X-Forwarded-For chain that must be split before the appended element is read.
func BenchmarkTrustedClientIP_LongChain(b *testing.B) {
	req := benchRequest(nginxPeer,
		"10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, "+victimIP+", "+attackerIP, "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TrustedClientIP(req)
	}
}

func BenchmarkNaiveClientIP_LongChain(b *testing.B) {
	req := benchRequest(nginxPeer,
		"10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, "+victimIP+", "+attackerIP, "")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = naiveClientIP(req)
	}
}
