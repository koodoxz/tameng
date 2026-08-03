package server

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-EGRESS-GZIP-BYPASS-001
//
// Independent Opus judge review of the egress DLP change found that
// advancedEgressMiddleware scans capture.buffer.String() directly -- but
// httputil.ReverseProxy forwards a client's own Accept-Encoding untouched
// (Go's http.Transport only auto-decompresses when *it* added the gzip
// header, not when the caller did), so a backend serving a gzip-compressed
// response sails through every secretPatterns regex unscanned. Proven by the
// judge with a real ReverseProxy + real backend: identical NIK payload,
// blocked without compression, allowed through with it. This test
// reproduces that exact scenario through the real proxy+middleware chain
// (s.router, not a hand-built handler) so it cannot pass by accident.
func TestAdvancedEgressMiddleware_DetectsPIIInGzipCompressedResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(`{"customer_nik":"3273011507900123"}`))
		_ = gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer backend.Close()

	cfg := backendProxyTestConfig(backend.URL)
	// PIISecretMode: "block" isolates this test's actual claim (gzip-compressed
	// bytes still get scanned) from the separate alert-vs-block mode question
	// (REQ SVALINN-EGRESS-PII-ALERTMODE-001), which has its own dedicated tests.
	cfg.AdvancedEgress = config.AdvancedEgressConfig{Enabled: true, GeofenceMode: "alert", PIISecretMode: "block"}

	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/customer", nil)
	req.Header.Set("Accept-Encoding", "gzip") // the realistic trigger: every browser sends this by default
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: gzip-compressed NIK leak must still be blocked, not silently pass through", rec.Code, http.StatusForbidden)
	}
}

// TestAdvancedEgressMiddleware_GzipResponseBodyReachesClientUnmodifiedWhenAllowed
// proves the fix is scan-only: when a gzip response has no PII, the client
// must still receive the original compressed bytes byte-for-byte (decoding
// only for the DLP scan, not for the actual wire response), otherwise a
// gzip-aware client would fail to decode a "fixed" response.
func TestAdvancedEgressMiddleware_GzipResponseBodyReachesClientUnmodifiedWhenAllowed(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte(`{"status":"ok"}`))
	_ = gz.Close()
	original := append([]byte(nil), compressed.Bytes()...)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(original)
	}))
	defer backend.Close()

	cfg := backendProxyTestConfig(backend.URL)
	cfg.AdvancedEgress = config.AdvancedEgressConfig{Enabled: true, GeofenceMode: "alert"}

	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(rec.Body.Bytes(), original) {
		t.Errorf("response body was modified -- client received %d bytes, want the original %d compressed bytes unchanged", rec.Body.Len(), len(original))
	}
}

// REQ SVALINN-EGRESS-GZIP-BOMB-001
//
// A second independent Opus judge review of the gzip-bypass fix above found
// it introduced a new CRITICAL regression: gunzip's original io.ReadAll(r)
// had no size limit, so a small compressed body decompressing to hundreds of
// MB (a "gzip bomb") turned a request that used to complete in microseconds
// (uncompressed bodies over egressResponseWriter's own 200KB capture cap
// already skip scanning via the passthrough branch) into a multi-second,
// multi-gigabyte decompression on every matching request -- a DoS vector in
// a product whose job is DDoS defense. Measured by that review: 65.8s/4.5GB
// before a bound, ~71ms/14MB after. This proves the bound actually caps
// decompressed output at egressScanLimit rather than exhausting memory/time.
func TestGunzip_CapsDecompressedOutputAtScanLimit(t *testing.T) {
	// Highly compressible: same byte repeated well past egressScanLimit once
	// decompressed, but compresses down to a tiny wire size.
	huge := bytes.Repeat([]byte{'A'}, egressScanLimit*5)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(huge); err != nil {
		t.Fatalf("gzip.Write failed: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip.Close failed: %v", err)
	}

	decoded, err := gunzip(compressed.Bytes())
	if err != nil {
		t.Fatalf("gunzip failed: %v", err)
	}
	if len(decoded) > egressScanLimit {
		t.Errorf("gunzip returned %d bytes, want capped at egressScanLimit (%d) -- decompression bomb protection regressed", len(decoded), egressScanLimit)
	}
}
