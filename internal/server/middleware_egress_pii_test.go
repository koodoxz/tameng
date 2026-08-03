package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/egress"
	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-DLP-ID-PII-001 / SVALINN-EGRESS-GEOFENCE-CLIENTCC-001 /
// SVALINN-EGRESS-SUPPLYCHAIN-REMOVE-001
//
// Phase 5 integration coverage: these drive advancedEgressMiddleware
// end-to-end with the real egress.Engine (same helper as
// copyheaders_selfcopy_test.go, no mocking of the engine itself) to prove the
// wiring, not just the isolated egress-package unit tests. A real
// *geoip.Reader needs a MaxMind .mmdb file this environment does not have
// (not vendored by the oschwald/maxminddb-golang module, and downloading one
// in a test would be an untracked external dependency) -- so the
// geoip-present path is Not Executed here; that path is a single already
// battle-tested line (s.geoip.LookupCode, identical pattern to
// middleware.go's existing request-logging call) and is out of scope to
// re-verify. What IS proven here is the s.geoip == nil path, which is the
// actual state of every Server built via New() in this test package (no
// GeoIP DB present in CI/dev), plus the PII/supply-chain wiring which needs
// no GeoIP at all.

// TestAdvancedEgressMiddleware_BlocksIndonesianPIILeak uses PIISecretMode:
// "block" explicitly (not newAdvancedEgressTestServer's default) --
// REQ SVALINN-EGRESS-PII-ALERTMODE-001 made PII detection alert-only by
// default (see internal/egress/advanced_test.go), so proving the blocking
// path works end-to-end now requires opting into it, same as an operator
// would after observing false-positive rate.
func TestAdvancedEgressMiddleware_BlocksIndonesianPIILeak(t *testing.T) {
	s := &Server{
		log:            logger.New("test"),
		cfg:            &config.Config{AdvancedEgress: config.AdvancedEgressConfig{Enabled: true}},
		advancedEgress: egress.NewEngine(egress.Config{Enabled: true, PIISecretMode: "block"}),
		stats:          &Stats{},
	}

	handler := s.advancedEgressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"customer_nik":"3273011507900123"}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/customer", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (NIK leak in response body must be blocked under PIISecretMode=block)", rec.Code, http.StatusForbidden)
	}
}

// TestAdvancedEgressMiddleware_PIILeakDefaultsToAlertNotBlocking proves the
// default (unset PIISecretMode -> "alert") end-to-end through the real
// middleware: the same NIK leak that the test above blocks under explicit
// "block" mode must NOT block under the shipped default.
func TestAdvancedEgressMiddleware_PIILeakDefaultsToAlertNotBlocking(t *testing.T) {
	s := newAdvancedEgressTestServer(t) // PIISecretMode unset -> defaults to "alert"

	handler := s.advancedEgressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"customer_nik":"3273011507900123"}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/customer", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: PII leak must not block under the default alert mode", rec.Code, http.StatusOK)
	}
}

func TestAdvancedEgressMiddleware_NilGeoIPDoesNotFalsePositiveOrPanic(t *testing.T) {
	s := newAdvancedEgressTestServer(t) // s.geoip is nil, matching this test package's Server construction

	handler := s.advancedEgressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req) // must not panic on nil s.geoip

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: benign response with no GeoIP reader must pass through", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != `{"ok":true}` {
		t.Errorf("body = %q, want the handler's original body untouched", got)
	}
}

func TestAdvancedEgressMiddleware_NeverBlocksOnSupplyChainShapedPath(t *testing.T) {
	s := newAdvancedEgressTestServer(t)

	handler := s.advancedEgressMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("console.log('ok')"))
	}))

	// Shape that used to trip checkSupplyChain: node_modules-like path served
	// from a host absent from TrustedPackageHosts.
	req := httptest.NewRequest(http.MethodGet, "/node_modules/some-package/dist/bundle.js", nil)
	req.Host = "not-a-registry.example"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d: supply-chain-shaped path must no longer block", rec.Code, http.StatusOK)
	}
}
