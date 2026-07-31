package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-PROXY-BACKEND-001
//
// Before this REQ, SVALINN had no reverse-proxy/backend-forwarding capability
// at all: it only ever served its own routes, so a real tenant application
// "behind" SVALINN got 404s on every one of its own routes. These tests prove
// the fix without weakening the product's core promise -- forwarding to a
// tenant's backend must never bypass WAF/DDoS/actor-tracking/etc.

// backendProxyTestConfig extends the package's existing minimalValidTestConfig
// fixture with a real, enabled WAF (matching the deployed default
// block_threshold, REQ SVALINN-PROXY-BACKEND-001's own test needs a live
// detector to prove blocking still happens) and the given backend URL.
func backendProxyTestConfig(backendURL string) *config.Config {
	cfg := minimalValidTestConfig()
	cfg.Server.BackendURL = backendURL
	cfg.WAF = config.WAFConfig{
		Enabled:        true,
		BlockThreshold: 0.8,
		LogThreshold:   0.5,
	}
	return cfg
}

// TestBackendProxy_LegitimateRequestReachesBackend proves the core feature:
// with server.backend_url configured, a benign request to a path SVALINN does
// not itself serve is forwarded to, and answered by, the real backend.
func TestBackendProxy_LegitimateRequestReachesBackend(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusTeapot) // distinctive: only the fake backend would produce this
	}))
	defer backend.Close()

	s, err := New(backendProxyTestConfig(backend.URL), logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/dashboard", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if !backendCalled {
		t.Fatal("legitimate request never reached the backend")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("response code: got %d, want %d (from the fake backend, proving it wasn't intercepted)", rec.Code, http.StatusTeapot)
	}
}

// TestBackendProxy_MaliciousPayloadIsBlockedBeforeReachingBackend is the
// central security property of this REQ: forwarding to a tenant's backend
// must never bypass SVALINN's own detection. A WAF-triggering payload aimed
// at an application path must be blocked by the existing middleware chain and
// must never reach the backend at all.
func TestBackendProxy_MaliciousPayloadIsBlockedBeforeReachingBackend(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s, err := New(backendProxyTestConfig(backend.URL), logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/search", nil)
	// Same SQLi probe this package's own TestSQLiProbeIsActuallyBlocked
	// (clientip_spoof_test.go) already proves the WAF scores as an attack.
	// URL-encoded so a 403 can only come from the WAF: a raw space in
	// RawQuery makes the forwarded request line malformed, which would make
	// the backend's own net/http reject it with 400 before its handler runs
	// -- a false pass that looks identical to a WAF block from this test's
	// point of view (backendCalled stays false either way).
	req.URL.RawQuery = "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if backendCalled {
		t.Fatal("SECURITY: malicious payload reached the backend -- the reverse proxy bypassed the WAF")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("response code: got %d, want 403 (WAF block)", rec.Code)
	}
}

// TestBackendProxy_UnsetBackendURLPreservesExisting404Behavior is the
// backward-compatibility regression guard: with server.backend_url left empty
// (the default, and every config file that predates this REQ), unmatched
// paths must behave exactly as before -- SVALINN's own 404 shield response,
// never a proxy attempt.
func TestBackendProxy_UnsetBackendURLPreservesExisting404Behavior(t *testing.T) {
	cfg := minimalValidTestConfig() // BackendURL left at its zero value: ""
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/unmatched/path", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("response code: got %d, want 404 (unchanged pre-REQ behavior)", rec.Code)
	}
}

// TestNew_RejectsMalformedBackendURL proves startup fails closed on a
// misconfigured server.backend_url rather than silently ignoring it or
// panicking at request time.
func TestNew_RejectsMalformedBackendURL(t *testing.T) {
	cfg := minimalValidTestConfig()
	cfg.Server.BackendURL = "://not-a-valid-url"

	if _, err := New(cfg, logger.New("test")); err == nil {
		t.Fatal("expected New() to fail with a malformed backend_url, got nil error")
	}
}

// TestBackendProxy_EcosystemPathFallthroughNeverReachesBackend is the
// regression guard for a CRITICAL finding from the independent Opus
// verification pass: isEcosystemEndpoint's 4 paths make wafMiddleware,
// rateLimitMiddleware, and the other detector middlewares skip their own
// checks (those paths are meant to be reached only via the dedicated,
// IP-allowlisted dispatch in Server.ServeHTTP). Server.ServeHTTP's own
// ecosystem interception only inspects GET/POST on the HTTP listener and is
// skipped entirely on the HTTPS listener (s.tlsServer.Handler = s.router), so
// a PUT/DELETE/PATCH -- or any method on the HTTPS listener -- to one of
// those 4 paths falls straight through to s.router, hitting handleCatchAll
// with every one of those detectors already exempted. Before the fix,
// handleCatchAll forwarded that request to the tenant backend anyway,
// turning the exemption into an unauthenticated, unrate-limited channel to
// the backend. This test exercises that exact fallthrough (s.router.ServeHTTP
// directly, bypassing Server.ServeHTTP, exactly as the HTTPS listener would)
// and proves the backend is never reached.
func TestBackendProxy_EcosystemPathFallthroughNeverReachesBackend(t *testing.T) {
	backendCalled := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	s, err := New(backendProxyTestConfig(backend.URL), logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/dns-events", nil)
	req.URL.RawQuery = "id=1%27+UNION+SELECT+username%2Cpassword+FROM+users--"
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if backendCalled {
		t.Fatal("SECURITY: ecosystem-endpoint fallthrough reached the backend with WAF/rate-limit exempted")
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("response code: got %d, want 404 (unchanged pre-REQ behavior for this fallthrough)", rec.Code)
	}
}
