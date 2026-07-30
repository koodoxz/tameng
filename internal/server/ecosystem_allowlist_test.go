package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
	"github.com/gorilla/mux"
)

// Production ecosystem peers (see SVALINN_ECOSYSTEM_INTEGRATION_FIX.md).
const (
	odinHeimdallIP = "203.0.113.20"
	mimirIP        = "203.0.113.10"
)

// ecosystemTestEndpoints are the four AEGIS integration endpoints that are
// dispatched directly from ServeHTTP, bypassing the entire middleware chain.
var ecosystemTestEndpoints = []struct {
	path   string
	method string
}{
	{"/api/v1/shield/threats", http.MethodGet},
	{"/api/v1/heimdall/report", http.MethodPost},
	{"/api/v1/dns-events", http.MethodPost},
	{"/api/v1/dns-blocklist", http.MethodGet},
}

// newEcosystemTestServer builds a Server whose ecosystem handlers are spies, so
// that "the handler was never reached" can be asserted directly. The allowlist
// logic under test is the real one -- only the downstream handler is a stub.
func newEcosystemTestServer(allowedIPs []string) (*Server, map[string]*bool) {
	called := make(map[string]*bool, len(ecosystemTestEndpoints))
	handlers := make(map[string]http.HandlerFunc, len(ecosystemTestEndpoints))

	for _, ep := range ecosystemTestEndpoints {
		flag := false
		called[ep.path] = &flag
		handlers[ep.path] = func(w http.ResponseWriter, r *http.Request) {
			flag = true
			w.WriteHeader(http.StatusOK)
		}
	}

	s := &Server{
		log: logger.New("test"),
		cfg: &config.Config{
			Ecosystem: config.EcosystemConfig{AllowedIPs: allowedIPs},
		},
		ecosystemHandlers: handlers,
	}

	return s, called
}

// TestServeHTTP_EcosystemDeniesCallerWhenAllowlistUnset proves REQ SVALINN-ECO-AUTH-001.
//
// With no ecosystem allowlist configured, every ecosystem endpoint must fail
// closed (403) rather than serve an arbitrary unauthenticated internet caller.
func TestServeHTTP_EcosystemDeniesCallerWhenAllowlistUnset(t *testing.T) {
	for _, ep := range ecosystemTestEndpoints {
		t.Run(ep.path, func(t *testing.T) {
			s, called := newEcosystemTestServer(nil)

			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
			req.RemoteAddr = "198.51.100.7:54321" // external caller, not allowlisted
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("got status %d, want %d", rec.Code, http.StatusForbidden)
			}
			if *called[ep.path] {
				t.Error("ecosystem handler was reached by a non-allowlisted caller")
			}
		})
	}
}

// TestServeHTTP_EcosystemFailsClosedOnEmptyAllowlist covers the explicitly-empty
// (as opposed to nil/unset) allowlist -- it must deny, never allow-all.
func TestServeHTTP_EcosystemFailsClosedOnEmptyAllowlist(t *testing.T) {
	for _, ep := range ecosystemTestEndpoints {
		t.Run(ep.path, func(t *testing.T) {
			s, called := newEcosystemTestServer([]string{})

			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
			req.RemoteAddr = odinHeimdallIP + ":44444"
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("empty allowlist must fail closed: got %d, want 403", rec.Code)
			}
			if *called[ep.path] {
				t.Error("handler reached despite empty allowlist")
			}
		})
	}
}

// TestServeHTTP_EcosystemAllowsAllowlistedIP verifies each of the four endpoints
// is individually reachable by a configured peer (no endpoint is over-blocked).
func TestServeHTTP_EcosystemAllowsAllowlistedIP(t *testing.T) {
	for _, ep := range ecosystemTestEndpoints {
		t.Run(ep.path, func(t *testing.T) {
			s, called := newEcosystemTestServer([]string{odinHeimdallIP, mimirIP})

			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
			req.RemoteAddr = mimirIP + ":33333"
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("allowlisted peer got %d, want 200", rec.Code)
			}
			if !*called[ep.path] {
				t.Error("handler was not reached by an allowlisted peer")
			}
		})
	}
}

// TestServeHTTP_EcosystemProductionNginxPath exercises the real deployment shape:
// nginx on 127.0.0.1 proxying an allowlisted peer, setting X-Real-IP from
// $remote_addr and appending to X-Forwarded-For via $proxy_add_x_forwarded_for.
func TestServeHTTP_EcosystemProductionNginxPath(t *testing.T) {
	s, called := newEcosystemTestServer([]string{odinHeimdallIP})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shield/threats", nil)
	req.RemoteAddr = "127.0.0.1:49300" // nginx
	req.Header.Set("X-Real-IP", odinHeimdallIP)
	req.Header.Set("X-Forwarded-For", odinHeimdallIP)
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("legitimate HEIMDALL sync via nginx got %d, want 200", rec.Code)
	}
	if !*called["/api/v1/shield/threats"] {
		t.Error("handler not reached for legitimate nginx-proxied peer")
	}
}

// TestServeHTTP_EcosystemTrustsXRealIPWithoutXForwardedFor covers an nginx
// deployment that sets only X-Real-IP. The allowlist must honour it rather than
// falling back to the loopback peer address, which would deny a legitimate peer.
func TestServeHTTP_EcosystemTrustsXRealIPWithoutXForwardedFor(t *testing.T) {
	s, called := newEcosystemTestServer([]string{odinHeimdallIP})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/shield/threats", nil)
	req.RemoteAddr = "127.0.0.1:49300" // nginx
	req.Header.Set("X-Real-IP", odinHeimdallIP)
	// deliberately no X-Forwarded-For
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("X-Real-IP-only peer got %d, want 200", rec.Code)
	}
	if !*called["/api/v1/shield/threats"] {
		t.Error("handler not reached for allowlisted X-Real-IP-only peer")
	}
}

// --- Phase 9: header spoofing ---------------------------------------------

// TestServeHTTP_EcosystemRejectsSpoofedHeadersFromDirectPeer proves a remote
// attacker connecting directly (non-loopback TCP peer) cannot forge an
// allowlisted identity via X-Forwarded-For or X-Real-IP.
func TestServeHTTP_EcosystemRejectsSpoofedHeadersFromDirectPeer(t *testing.T) {
	for _, ep := range ecosystemTestEndpoints {
		t.Run(ep.path, func(t *testing.T) {
			s, called := newEcosystemTestServer([]string{odinHeimdallIP, mimirIP})

			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
			req.RemoteAddr = "198.51.100.7:54321" // attacker's real peer address
			req.Header.Set("X-Forwarded-For", odinHeimdallIP)
			req.Header.Set("X-Real-IP", odinHeimdallIP)
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("spoofed headers from direct peer got %d, want 403", rec.Code)
			}
			if *called[ep.path] {
				t.Error("allowlist bypassed via forged proxy headers")
			}
		})
	}
}

// TestServeHTTP_EcosystemRejectsPrependedXFFViaNginx is the important one.
//
// Production nginx uses `X-Forwarded-For $proxy_add_x_forwarded_for`, which
// APPENDS the real peer to any client-supplied value. An attacker sending
// `X-Forwarded-For: <allowlisted>` therefore reaches SVALINN as
// "<allowlisted>, <attacker>". Trusting the first element (as getClientIP does)
// would hand the attacker a full bypass; the gate must not.
func TestServeHTTP_EcosystemRejectsPrependedXFFViaNginx(t *testing.T) {
	attacker := "198.51.100.7"

	tests := []struct {
		name     string
		xff      string
		xRealIP  string
		wantCode int
	}{
		{
			name:     "attacker prepends allowlisted IP, nginx appends real peer",
			xff:      odinHeimdallIP + ", " + attacker,
			xRealIP:  attacker,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "same prepend with no X-Real-IP present",
			xff:      odinHeimdallIP + ", " + attacker,
			wantCode: http.StatusForbidden,
		},
		{
			name:     "attacker prepends a long forged chain",
			xff:      odinHeimdallIP + ", " + mimirIP + ", " + attacker,
			wantCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, called := newEcosystemTestServer([]string{odinHeimdallIP, mimirIP})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/heimdall/report", strings.NewReader("{}"))
			req.RemoteAddr = "127.0.0.1:49300" // nginx is the TCP peer
			req.Header.Set("X-Forwarded-For", tc.xff)
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("got %d, want %d (XFF=%q)", rec.Code, tc.wantCode, tc.xff)
			}
			if *called["/api/v1/heimdall/report"] {
				t.Error("TempBlock-capable handler reached via forged X-Forwarded-For")
			}
		})
	}
}

// --- IP derivation and matching edge cases ---------------------------------

func TestEcosystemIPMatching(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		remoteAddr string
		wantCode   int
	}{
		{
			name:       "RemoteAddr without a port is still matched",
			allowed:    []string{"203.0.113.9"},
			remoteAddr: "203.0.113.9",
			wantCode:   http.StatusOK,
		},
		{
			name:       "unparseable client IP is denied",
			allowed:    []string{"203.0.113.9"},
			remoteAddr: "not-an-ip",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "CIDR entries never match (documented limitation)",
			allowed:    []string{"203.0.113.0/24"},
			remoteAddr: odinHeimdallIP + ":1234",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "malformed allowlist entries are skipped, valid ones still match",
			allowed:    []string{"garbage", "", odinHeimdallIP},
			remoteAddr: odinHeimdallIP + ":1234",
			wantCode:   http.StatusOK,
		},
		{
			name:       "whitespace around allowlist entries is tolerated",
			allowed:    []string{"  " + odinHeimdallIP + "  "},
			remoteAddr: odinHeimdallIP + ":1234",
			wantCode:   http.StatusOK,
		},
		{
			name:       "IPv4-mapped IPv6 peer matches its IPv4 allowlist entry",
			allowed:    []string{"10.0.0.1"},
			remoteAddr: "[::ffff:10.0.0.1]:1234",
			wantCode:   http.StatusOK,
		},
		{
			name:       "IPv6 peer matches an equivalent-but-differently-written entry",
			allowed:    []string{"2001:db8:0:0:0:0:0:1"},
			remoteAddr: "[2001:db8::1]:1234",
			wantCode:   http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newEcosystemTestServer(tc.allowed)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/dns-blocklist", nil)
			req.RemoteAddr = tc.remoteAddr
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Errorf("got %d, want %d", rec.Code, tc.wantCode)
			}
		})
	}
}

// TestEcosystemClientIP_LoopbackPeerWithoutProxyHeaders covers a loopback caller
// that sets neither X-Real-IP nor X-Forwarded-For (e.g. an on-box health probe).
func TestEcosystemClientIP_LoopbackPeerWithoutProxyHeaders(t *testing.T) {
	s, called := newEcosystemTestServer([]string{"127.0.0.1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns-blocklist", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !*called["/api/v1/dns-blocklist"] {
		t.Error("handler not reached for allowlisted loopback caller")
	}
}

// --- Routing behaviour must be unchanged -----------------------------------

// TestServeHTTP_NonEcosystemPathReachesRouter confirms the allowlist gate does
// not affect ordinary routed traffic, which keeps its full middleware chain.
func TestServeHTTP_NonEcosystemPathReachesRouter(t *testing.T) {
	s, _ := newEcosystemTestServer(nil) // deny-all ecosystem allowlist

	routed := false
	s.router = mux.NewRouter()
	s.router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		routed = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "198.51.100.7:54321"
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	if !routed {
		t.Error("non-ecosystem request did not reach the router")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

// TestServeHTTP_EcosystemNonGetPostFallsThroughToRouter documents that methods
// other than GET/POST were, and remain, handed to the router rather than the
// direct ecosystem handler.
func TestServeHTTP_EcosystemNonGetPostFallsThroughToRouter(t *testing.T) {
	s, called := newEcosystemTestServer([]string{odinHeimdallIP})

	s.router = mux.NewRouter() // no matching route -> 404

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/heimdall/report", nil)
	req.RemoteAddr = odinHeimdallIP + ":1234"
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	if *called["/api/v1/heimdall/report"] {
		t.Error("DELETE reached the direct ecosystem handler")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 from router", rec.Code)
	}
}

// TestReferenceConfigPopulatesEcosystemAllowlist guards the YAML wiring
// end to end. Because the gate is fail-closed, a typo in the `allowed_ips` yaml
// tag would not fail loudly -- it would silently yield an empty allowlist and
// take the entire HEIMDALL/MIMIR sync offline.
func TestReferenceConfigPopulatesEcosystemAllowlist(t *testing.T) {
	cfg, err := config.Load("../../configs/svalinn.yaml")
	if err != nil {
		t.Fatalf("failed to load reference config: %v", err)
	}

	if len(cfg.Ecosystem.AllowedIPs) == 0 {
		t.Fatal("ecosystem.allowed_ips parsed as empty -- check the yaml tag")
	}

	s := &Server{log: logger.New("test"), cfg: cfg}

	for _, ip := range []string{odinHeimdallIP, mimirIP} {
		if !s.isEcosystemIPAllowed(ip) {
			t.Errorf("reference config should allow %s, but it did not", ip)
		}
	}
	if s.isEcosystemIPAllowed("198.51.100.7") {
		t.Error("reference config must not allow an unlisted IP")
	}
}

// --- Phase 7: cost of the gate ---------------------------------------------

// BenchmarkEcosystemAllowlistGate measures the per-request overhead the
// allowlist adds to an ecosystem dispatch (IP derivation + allowlist match).
func BenchmarkEcosystemAllowlistGate(b *testing.B) {
	s, _ := newEcosystemTestServer([]string{odinHeimdallIP, mimirIP})

	cases := []struct {
		name       string
		remoteAddr string
		xRealIP    string
	}{
		{"allowed_direct", odinHeimdallIP + ":1234", ""},
		{"allowed_via_nginx", "127.0.0.1:49300", odinHeimdallIP},
		{"denied_direct", "198.51.100.7:54321", ""},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/shield/threats", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.isEcosystemIPAllowed(s.ecosystemClientIP(req)) {
					continue
				}
			}
		})
	}
}

// --- Phase 5: real-path integration ----------------------------------------

// TestServeHTTP_RealEcosystemHandlerIsGated wires the genuine handlers via
// setupEcosystemRoutes (no stubs) and drives ServeHTTP end to end, proving the
// gate protects the real registration path rather than just a test fixture.
func TestServeHTTP_RealEcosystemHandlerIsGated(t *testing.T) {
	newRealServer := func(allowed []string) *Server {
		s := &Server{
			log: logger.New("test"),
			cfg: &config.Config{
				Ecosystem: config.EcosystemConfig{AllowedIPs: allowed},
			},
			ecosystemHandlers: make(map[string]http.HandlerFunc),
		}
		s.setupEcosystemRoutes()
		return s
	}

	t.Run("allowlisted peer reaches the real handler", func(t *testing.T) {
		s := newRealServer([]string{odinHeimdallIP})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/dns-blocklist", nil)
		req.RemoteAddr = odinHeimdallIP + ":1234"
		rec := httptest.NewRecorder()

		s.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", rec.Code)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("real handler did not return JSON: %v", err)
		}
		if body["status"] != "ok" {
			t.Errorf(`got status %v, want "ok"`, body["status"])
		}
	})

	t.Run("non-allowlisted peer gets 403 and no feed data", func(t *testing.T) {
		s := newRealServer([]string{odinHeimdallIP})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/dns-blocklist", nil)
		req.RemoteAddr = "198.51.100.7:54321"
		rec := httptest.NewRecorder()

		s.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "domain_count") {
			t.Error("threat feed data leaked to a non-allowlisted caller")
		}
	})

	t.Run("all four real endpoints are gated", func(t *testing.T) {
		s := newRealServer(nil) // fail-closed

		for _, ep := range ecosystemTestEndpoints {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader("{}"))
			req.RemoteAddr = "198.51.100.7:54321"
			rec := httptest.NewRecorder()

			s.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: got %d, want 403", ep.path, rec.Code)
			}
		}
	})
}
