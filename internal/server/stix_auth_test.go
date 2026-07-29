package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegis/svalinn/internal/config"
	"github.com/aegis/svalinn/internal/logger"
)

// REQ SVALINN-STIX-AUTH-001
//
// handleTaxiiObjects's POST path (ParseBundle -> addIndicatorFromMap) was
// registered directly on s.router with no authentication at all -- any
// unauthenticated internet caller could inject arbitrary STIX indicators
// (attacker-chosen id/pattern/pattern_type/confidence). stixMiddleware then
// runs MatchIndicators against every subsequent request's real content and,
// when cfg.STIX.BlockOnMatch is true, returns a hard 403 -- so an
// unauthenticated caller could plant a pattern that later blocks arbitrary
// OTHER traffic. Not live-armed today only because BlockOnMatch defaults to
// Go's zero value (false) and the production config never sets it, but a
// single config change away from becoming a real unauthenticated
// blocking-DoS primitive. handleSTIXImport (/api/v9/stix/import, the other
// ParseBundle call site) was already correctly behind godModeMiddleware --
// only the /taxii path was open.
//
// Fix: require the same already-fail-closed API key check
// (apiKeyMiddleware, used by every /api/v1/* route) on POST specifically,
// leaving GET (discovery/collections/read) exactly as before -- matching
// this engagement's established precedent of closing the write/injection
// path first (SVALINN-ECO-AUTH-001 did the same for the Heimdall endpoints)
// without expanding scope to the separately-flagged, still-open read
// exposure.

func minimalValidTestConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			MitnickUser:    "user",
			MitnickPass:    "pass",
			GodModeKey:     "validgodkey",
			APIKeys:        []string{"validapikey"},
			RateLimitRPS:   1000,
			RateLimitBurst: 1000,
		},
		STIX: config.STIXConfig{Enabled: true},
	}
}

func newRealTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(minimalValidTestConfig(), logger.New("test"))
	if err != nil {
		t.Fatalf("New() failed with a minimal valid config: %v", err)
	}
	return s
}

// TestTaxiiObjectsPost_RejectsUnauthenticatedCaller proves the vulnerability
// is closed: POST without any API key must never reach ParseBundle.
func TestTaxiiObjectsPost_RejectsUnauthenticatedCaller(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects",
		strings.NewReader(`{"type":"bundle","objects":[]}`))
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated POST /taxii/collections/default/objects: got %d, want 401", rec.Code)
	}
}

// TestTaxiiObjectsPost_RejectsWrongAPIKey proves the check validates the key
// value, not just its presence.
func TestTaxiiObjectsPost_RejectsWrongAPIKey(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects",
		strings.NewReader(`{"type":"bundle","objects":[]}`))
	req.Header.Set("X-API-Key", "wrongkey")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST with wrong API key: got %d, want 401", rec.Code)
	}
}

// TestTaxiiObjectsPost_AcceptsValidAPIKey proves the fix isn't a blanket
// lockout: a real, correctly-authenticated caller must still reach the
// handler and get normal STIX-bundle-processing behavior.
func TestTaxiiObjectsPost_AcceptsValidAPIKey(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects",
		strings.NewReader(`{"type":"bundle","objects":[]}`))
	req.Header.Set("X-API-Key", "validapikey")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("POST with valid API key was rejected: got %d, want a real handler response (not 401)", rec.Code)
	}
}

// TestTaxiiObjectsPost_AcceptsGodModeKey proves the shared apiKeyMiddleware
// convention (God Mode key also satisfies API-key checks) holds here too,
// consistent with every other /api/v1/* endpoint.
func TestTaxiiObjectsPost_AcceptsGodModeKey(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/taxii/collections/default/objects",
		strings.NewReader(`{"type":"bundle","objects":[]}`))
	req.Header.Set("X-API-Key", "validgodkey")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("POST with God Mode key was rejected: got %d, want a real handler response (not 401)", rec.Code)
	}
}

// TestTaxiiObjectsGet_RemainsUnauthenticated is a regression guard: this fix
// must only close the write/injection path. Read access (discovery,
// collections, export) is a separately-flagged, still-open finding --
// accidentally locking down GET here would be an undeclared scope
// expansion, not a fix.
func TestTaxiiObjectsGet_RemainsUnauthenticated(t *testing.T) {
	s := newRealTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/taxii/collections/default/objects", nil)
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /taxii/collections/default/objects: got 401, want no auth requirement (regression)")
	}
}

// TestTaxiiDiscoveryAndCollections_RemainUnauthenticated is the same
// regression guard for the two sibling GET-only /taxii routes, which this
// REQ never touches.
func TestTaxiiDiscoveryAndCollections_RemainUnauthenticated(t *testing.T) {
	s := newRealTestServer(t)

	for _, path := range []string{"/taxii", "/taxii/collections"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, req)

		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("unauthenticated GET %s: got 401, want no auth requirement (regression)", path)
		}
	}
}
