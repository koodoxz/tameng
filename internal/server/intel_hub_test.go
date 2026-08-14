package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/koodoxz/tameng/internal/intel"
	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-INTEL-HUB-WIRE-001
//
// intel.Hub (MITRE mapping, IOC blocklist, threat scoring) was fully built
// but had zero callers anywhere in the codebase -- IsBlockedIP/IsBlockedDomain
// were unreachable dead code. This file proves: (1) the middleware actually
// blocks traffic matching a Hub IOC, (2) the new God-Mode endpoints are the
// only way to populate/depopulate that blocklist, and (3) those endpoints
// carry the same auth-regression coverage Task A established for
// /api/v9/block after a stub-fix turned a harmless auth gap into a real
// primitive.

func newIntelHubTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := minimalValidTestConfig()
	cfg.Intel.Enabled = true
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}
	return s
}

// doProtectedRequest hits /metrics -- a public GET route, like /health, but
// (unlike /health) NOT exempt from intelHubMiddleware, so it's the right
// target for tests proving the middleware actually blocks traffic.
func doProtectedRequest(s *Server, remoteAddr, host string) *httptest.ResponseRecorder {
	return doGetRequest(s, "/metrics", remoteAddr, host)
}

func doGetRequest(s *Server, path, remoteAddr, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

// --- Middleware tests ---------------------------------------------------

func TestIntelHubMiddleware_BlocksMatchingIP(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "192.0.2.1:1234", "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /metrics from a blocklisted IP: got %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_BlocksMatchingDomain(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "192.0.2.9:1234", "evil.example.com")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /metrics with a blocklisted Host: got %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_PassesThroughNonMatching(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "198.51.100.1:1234", "clean.example.com")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics from a clean IP/domain: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_NilHubPassesThrough(t *testing.T) {
	cfg := minimalValidTestConfig()
	// Intel.Enabled left false -> s.intelHub is nil.
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	rec := doProtectedRequest(s, "192.0.2.1:1234", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics with intel hub disabled: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_IncrementsStats(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatHigh, Source: "test"})

	blockedBefore := atomic.LoadInt64(&s.stats.BlockedRequests)
	threatsBefore := atomic.LoadInt64(&s.stats.ThreatsDetected)
	doProtectedRequest(s, "192.0.2.1:1234", "")
	blockedAfter := atomic.LoadInt64(&s.stats.BlockedRequests)
	threatsAfter := atomic.LoadInt64(&s.stats.ThreatsDetected)

	if blockedAfter != blockedBefore+1 {
		t.Errorf("BlockedRequests after IOC block: got %d, want %d", blockedAfter, blockedBefore+1)
	}
	if threatsAfter != threatsBefore+1 {
		t.Errorf("ThreatsDetected after IOC block: got %d, want %d", threatsAfter, threatsBefore+1)
	}
}

// TestIntelHubMiddleware_BlockedResponseDoesNotLeakDetail proves the fix for
// the enumeration-oracle finding: an unauthenticated caller must not learn
// ioc_type/threat_level/source from the 403 body -- those now go server-side
// only, matching countermeasuresMiddleware's existing vague-body convention.
func TestIntelHubMiddleware_BlockedResponseDoesNotLeakDetail(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatCritical, Source: "internal-honeypot-alpha"})

	rec := doProtectedRequest(s, "192.0.2.1:1234", "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"internal-honeypot-alpha", "critical", "ioc_type", "threat_level", "source"} {
		if strings.Contains(body, leak) {
			t.Errorf("blocked response body leaks %q: %s", leak, body)
		}
	}
}

// --- Safe-path exemption tests (self-lockout fix) --------------------------

// TestIntelHubMiddleware_HealthExemptEvenWhenCallerIPBlocked proves the fix
// for the Docker HEALTHCHECK self-outage finding: /health must stay
// reachable even from an IOC'd IP (the healthcheck runs from inside the same
// container, i.e. from whatever IP is configured, which could be loopback).
func TestIntelHubMiddleware_HealthExemptEvenWhenCallerIPBlocked(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "127.0.0.1", ThreatLevel: intel.ThreatCritical, Source: "test"})

	rec := doGetRequest(s, "/health", "127.0.0.1:1234", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health from an IOC'd IP: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestIntelHubMiddleware_IntelUnblockExemptEvenWhenCallerIPBlocked proves
// the fix for the self-lockout finding: an operator whose own IP becomes
// IOC'd must still be able to reach /api/v9/intel/unblock (with a valid
// God-Mode key) to undo it -- the IOC gate is skipped for this path, auth
// still applies normally via godModeMiddleware.
func TestIntelHubMiddleware_IntelUnblockExemptEvenWhenCallerIPBlocked(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatCritical, Source: "test"})

	req := httptest.NewRequest(http.MethodPost, "/api/v9/intel/unblock", strings.NewReader(`{"type":"ip","value":"192.0.2.1"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-API-Key", s.cfg.Security.GodModeKey)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("self-unblock from the blocked IP itself: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestIntelHubMiddleware_IntelUnblockStillRequiresAuthWhenCallerIPBlocked
// proves the exemption above only skips the IOC gate, not authentication --
// an unauthenticated caller from an IOC'd IP still gets 401, not a free
// pass into the recovery endpoint.
func TestIntelHubMiddleware_IntelUnblockStillRequiresAuthWhenCallerIPBlocked(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "192.0.2.1", ThreatLevel: intel.ThreatCritical, Source: "test"})

	req := httptest.NewRequest(http.MethodPost, "/api/v9/intel/unblock", strings.NewReader(`{"type":"ip","value":"192.0.2.1"}`))
	req.RemoteAddr = "192.0.2.1:1234"
	// Deliberately no X-API-Key header.
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated self-unblock attempt: got %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}

// --- Normalization tests (bypass fix) ---------------------------------------

func TestIntelHubMiddleware_DomainMatchIsCaseInsensitive(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "192.0.2.9:1234", "EVIL.Example.COM")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Host with different case: got %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_DomainMatchIgnoresPort(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "192.0.2.9:1234", "evil.example.com:10000")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Host with a port suffix: got %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_DomainMatchIgnoresTrailingDot(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doProtectedRequest(s, "192.0.2.9:1234", "evil.example.com.")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("Host with a trailing dot: got %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntelHubMiddleware_IPMatchIsCanonicalized(t *testing.T) {
	s := newIntelHubTestServer(t)
	// Added via the expanded IPv6 form through the real API, exactly how
	// many threat feeds publish -- must still match the compressed form a
	// real peer presents. Uses the handler (not a direct AddIOC call) since
	// normalization lives at the HTTP boundary, not inside Hub itself.
	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"2001:0db8:0000:0000:0000:0000:0000:0001","threat_level":"high","source":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup block failed: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	blocked := doProtectedRequest(s, "[2001:db8::1]:1234", "")

	if blocked.Code != http.StatusForbidden {
		t.Fatalf("compressed-form IPv6 peer against an expanded-form IOC: got %d, want 403 (body: %s)", blocked.Code, blocked.Body.String())
	}
}

// --- Population-path integration test ------------------------------------

// TestIntelHub_BlockViaAPI_ThenMiddlewareBlocksTraffic proves the population
// path and the enforcement path are actually wired together end to end, not
// just independently unit-tested.
func TestIntelHub_BlockViaAPI_ThenMiddlewareBlocksTraffic(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.50","threat_level":"high","source":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	blocked := doProtectedRequest(s, "203.0.113.50:1234", "")
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("GET /metrics after blocking via API: got %d, want 403 (body: %s)", blocked.Code, blocked.Body.String())
	}

	rec = doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":"203.0.113.50"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/unblock: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	allowed := doProtectedRequest(s, "203.0.113.50:1234", "")
	if allowed.Code != http.StatusOK {
		t.Fatalf("GET /metrics after unblocking via API: got %d, want 200 (body: %s)", allowed.Code, allowed.Body.String())
	}
}

// --- handleIntelBlockIOC tests --------------------------------------------

func TestHandleIntelBlockIOC_AddsIP(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.1","threat_level":"critical","source":"test"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.1"); !blocked {
		t.Fatal("handleIntelBlockIOC returned 200 but IP is NOT in the Hub blocklist")
	}
}

func TestHandleIntelBlockIOC_AddsDomain(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"domain","value":"evil.example.com","threat_level":"medium","source":"test"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedDomain("evil.example.com"); !blocked {
		t.Fatal("handleIntelBlockIOC returned 200 but domain is NOT in the Hub blocklist")
	}
}

func TestHandleIntelBlockIOC_AcceptsLowThreatLevel(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.30","threat_level":"low","source":"test"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block with threat_level=low: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	ioc, blocked := s.intelHub.IsBlockedIP("203.0.113.30")
	if !blocked {
		t.Fatal("handleIntelBlockIOC returned 200 but IP is NOT in the Hub blocklist")
	}
	if ioc.ThreatLevel != intel.ThreatLow {
		t.Errorf("threat level = %v, want ThreatLow", ioc.ThreatLevel)
	}
}

func TestHandleIntelBlockIOC_RejectsCIDR(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.0/24","threat_level":"high","source":"test"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with a CIDR range: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.0/24"); blocked {
		t.Fatal("an unroutable CIDR value must not silently succeed and sit unmatchable in the blocklist")
	}
}

func TestHandleIntelBlockIOC_RejectsUnparseableIP(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"not-an-ip","threat_level":"high","source":"test"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with an unparseable IP: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandleIntelBlockIOC_CanonicalizesIP proves the fix for the storage
// bug: a value with surrounding whitespace must be canonicalized before
// storage, not stored verbatim and silently never match anything.
func TestHandleIntelBlockIOC_CanonicalizesIP(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"  203.0.113.40  ","threat_level":"high","source":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.40"); !blocked {
		t.Fatal("value with surrounding whitespace was not canonicalized before storage")
	}
}

// TestHandleIntelBlockIOC_CanonicalizesDomain proves domain values are
// canonicalized on the write side too, so add/remove and the middleware's
// read-side lookup always agree on the same key.
func TestHandleIntelBlockIOC_CanonicalizesDomain(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"domain","value":"EVIL.Example.COM.","threat_level":"high","source":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/block: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	if _, blocked := s.intelHub.IsBlockedDomain("evil.example.com"); !blocked {
		t.Fatal("domain value was not canonicalized (lowercased, trailing dot stripped) before storage")
	}
}

func TestHandleIntelUnblockIOC_RemovesUsingUnnormalizedInput(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"domain","value":"EVIL.Example.COM."}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/unblock with differently-cased/trailing-dot value: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedDomain("evil.example.com"); blocked {
		t.Fatal("domain still blocked after unblock with an unnormalized-but-equivalent value")
	}
}

func TestHandleIntelBlockIOC_InvalidType(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"hash","value":"deadbeef","threat_level":"high","source":"test"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with type=hash: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelBlockIOC_EmptyValue(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"","threat_level":"high","source":"test"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with empty value: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelBlockIOC_InvalidThreatLevel(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.2","threat_level":"apocalyptic","source":"test"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with invalid threat_level: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.2"); blocked {
		t.Fatal("an invalid threat_level must not silently add the IOC anyway")
	}
}

func TestHandleIntelBlockIOC_InvalidJSONReturns400(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/block", `not-json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/block with invalid JSON: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelBlockIOC_ServiceUnavailableWhenDisabled(t *testing.T) {
	cfg := minimalValidTestConfig()
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.3","threat_level":"high","source":"test"}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v9/intel/block with intel hub disabled: got %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelBlockIOC_RejectsUnauthenticatedCaller(t *testing.T) {
	s := newIntelHubTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v9/intel/block", strings.NewReader(`{"type":"ip","value":"203.0.113.4","threat_level":"high","source":"test"}`))
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /api/v9/intel/block: got %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.4"); blocked {
		t.Fatal("unauthenticated request must not be able to add an IOC")
	}
}

// --- handleIntelUnblockIOC tests -------------------------------------------

func TestHandleIntelUnblockIOC_RemovesExisting(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "203.0.113.5", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":"203.0.113.5"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v9/intel/unblock: got %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.5"); blocked {
		t.Fatal("handleIntelUnblockIOC returned 200 but IP is STILL in the Hub blocklist")
	}
}

func TestHandleIntelUnblockIOC_RejectsUnparseableIP(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":"not-an-ip"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/unblock with an unparseable IP: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_NotFoundWhenNoMatch(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":"203.0.113.6"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /api/v9/intel/unblock for a never-added IOC: got %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_InvalidType(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"hash","value":"deadbeef"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/unblock with type=hash: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_EmptyValue(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":""}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/unblock with empty value: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_InvalidJSONReturns400(t *testing.T) {
	s := newIntelHubTestServer(t)

	rec := doGodModePost(s, "/api/v9/intel/unblock", `not-json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v9/intel/unblock with invalid JSON: got %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_ServiceUnavailableWhenDisabled(t *testing.T) {
	cfg := minimalValidTestConfig()
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	rec := doGodModePost(s, "/api/v9/intel/unblock", `{"type":"ip","value":"203.0.113.7"}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST /api/v9/intel/unblock with intel hub disabled: got %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelUnblockIOC_RejectsUnauthenticatedCaller(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "203.0.113.8", ThreatLevel: intel.ThreatHigh, Source: "test"})

	req := httptest.NewRequest(http.MethodPost, "/api/v9/intel/unblock", strings.NewReader(`{"type":"ip","value":"203.0.113.8"}`))
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /api/v9/intel/unblock: got %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, blocked := s.intelHub.IsBlockedIP("203.0.113.8"); !blocked {
		t.Fatal("unauthenticated request must not be able to remove an IOC")
	}
}

// --- handleIntelStats tests -------------------------------------------------

func TestHandleIntelStats_ReturnsStats(t *testing.T) {
	s := newIntelHubTestServer(t)
	s.intelHub.AddIOC(&intel.IOC{Type: "ip", Value: "203.0.113.20", ThreatLevel: intel.ThreatHigh, Source: "test"})

	rec := doGodModePost(s, "/api/v9/intel/block", `{"type":"ip","value":"203.0.113.21","threat_level":"high","source":"test"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup block failed: got %d (body: %s)", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v9/intel/stats", nil)
	req.Header.Set("X-API-Key", s.cfg.Security.GodModeKey)
	statsRec := httptest.NewRecorder()
	s.router.ServeHTTP(statsRec, req)

	if statsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/v9/intel/stats: got %d, want 200 (body: %s)", statsRec.Code, statsRec.Body.String())
	}
	if !strings.Contains(statsRec.Body.String(), `"blocked_ips":2`) {
		t.Errorf("stats response missing blocked_ips=2: %s", statsRec.Body.String())
	}
}

func TestHandleIntelStats_ServiceUnavailableWhenDisabled(t *testing.T) {
	cfg := minimalValidTestConfig()
	s, err := New(cfg, logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v9/intel/stats", nil)
	req.Header.Set("X-API-Key", s.cfg.Security.GodModeKey)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/v9/intel/stats with intel hub disabled: got %d, want 503 (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestHandleIntelStats_RejectsUnauthenticatedCaller(t *testing.T) {
	s := newIntelHubTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v9/intel/stats", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /api/v9/intel/stats: got %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
}
