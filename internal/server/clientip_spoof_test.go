package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegis/svalinn/internal/config"
	"github.com/aegis/svalinn/internal/logger"
	"github.com/aegis/svalinn/internal/waf"
)

// REQ SVALINN-CLIENTIP-SPOOF-001
//
// getClientIP feeds every IP-keyed security decision in the server package:
// rate limiting, actor threat attribution, DDoS escalation, countermeasure and
// WAF-whitelist checks, honeypot triggers and audit logging. Production nginx
// fronts SVALINN with
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//
// which APPENDS the real peer to whatever the client already sent, so the FIRST
// X-Forwarded-For element is fully attacker-controlled. These tests pin the
// invariant that only nginx-supplied values (X-Real-IP, or the LAST
// X-Forwarded-For element) are ever trusted, and only from a loopback peer.

const (
	spoofNginxPeer  = "127.0.0.1:49200" // the local nginx reverse proxy
	spoofAttackerIP = "198.51.100.77"   // the attacker's real address
	spoofVictimIP   = "203.0.113.5"     // a third party the attacker wants to impersonate
)

func newClientIPTestServer() *Server {
	return &Server{
		log: logger.New("test"),
		cfg: &config.Config{},
	}
}

// TestGetClientIP_ResolvesTrustedSource is the core table: every branch of
// getClientIP, stated as "which address may this request legitimately claim".
func TestGetClientIP_ResolvesTrustedSource(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			// THE BUG (REQ SVALINN-CLIENTIP-SPOOF-001): the attacker prepends a
			// victim address; nginx appends the attacker's real peer. Trusting
			// ips[0] hands the attacker the victim's identity.
			name:       "attacker prepends victim IP, nginx appends real peer",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP + ", " + spoofAttackerIP,
			want:       spoofAttackerIP,
		},
		{
			name:       "prepended chain is ignored, X-Real-IP wins",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP + ", " + spoofAttackerIP,
			xRealIP:    spoofAttackerIP,
			want:       spoofAttackerIP,
		},
		{
			name:       "long forged chain still resolves to the appended peer",
			remoteAddr: spoofNginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + spoofVictimIP + ", " + spoofAttackerIP,
			want:       spoofAttackerIP,
		},
		{
			// Legitimate production shape: one hop through nginx.
			name:       "legitimate nginx hop with X-Real-IP and single-element XFF",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP,
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			name:       "nginx sets only X-Real-IP",
			remoteAddr: spoofNginxPeer,
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			name:       "nginx sets only X-Forwarded-For",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			// A direct (non-loopback) connection may never speak for anyone else.
			name:       "direct remote peer cannot forge via XFF",
			remoteAddr: spoofAttackerIP + ":54321",
			xff:        spoofVictimIP,
			want:       spoofAttackerIP,
		},
		{
			name:       "direct remote peer cannot forge via X-Real-IP",
			remoteAddr: spoofAttackerIP + ":54321",
			xRealIP:    spoofVictimIP,
			want:       spoofAttackerIP,
		},
		{
			name:       "direct remote peer cannot forge via both headers",
			remoteAddr: spoofAttackerIP + ":54321",
			xff:        spoofVictimIP + ", " + spoofVictimIP,
			xRealIP:    spoofVictimIP,
			want:       spoofAttackerIP,
		},
		{
			name:       "loopback peer with no proxy headers is itself",
			remoteAddr: spoofNginxPeer,
			want:       "127.0.0.1",
		},
		{
			name:       "IPv6 loopback peer honours proxy headers",
			remoteAddr: "[::1]:49200",
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			name:       "IPv4-mapped loopback peer honours proxy headers",
			remoteAddr: "[::ffff:127.0.0.1]:49200",
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			// Whitespace around nginx-appended elements must not leak into the
			// key used for rate limiting / actor tracking.
			name:       "appended element is trimmed",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP + " ,   " + spoofAttackerIP + "   ",
			want:       spoofAttackerIP,
		},
		{
			// RemoteAddr without a port must still resolve, not collapse to "".
			name:       "RemoteAddr without a port is still usable",
			remoteAddr: "127.0.0.1",
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			name:       "portless non-loopback RemoteAddr cannot forge",
			remoteAddr: spoofAttackerIP,
			xff:        spoofVictimIP,
			want:       spoofAttackerIP,
		},
		{
			// Previously returned the sentinel "HEADER_INJECTION_ATTACK", which
			// is not an address and silently became a shared rate-limit bucket.
			name:       "loopback-only XFF resolves to loopback, not a sentinel",
			remoteAddr: spoofNginxPeer,
			xff:        "127.0.0.1",
			want:       "127.0.0.1",
		},
		{
			name:       "empty XFF header falls through to X-Real-IP",
			remoteAddr: spoofNginxPeer,
			xff:        "",
			xRealIP:    spoofVictimIP,
			want:       spoofVictimIP,
		},
		{
			// An unparseable X-Real-IP must be ignored, not propagated as an
			// identity, so the nginx-appended XFF element still wins.
			name:       "garbage X-Real-IP is ignored in favour of appended XFF",
			remoteAddr: spoofNginxPeer,
			xff:        spoofVictimIP + ", " + spoofAttackerIP,
			xRealIP:    "not-an-ip",
			want:       spoofAttackerIP,
		},
		{
			name:       "garbage X-Real-IP with no XFF falls back to the peer",
			remoteAddr: spoofNginxPeer,
			xRealIP:    "not-an-ip",
			want:       "127.0.0.1",
		},
		{
			name:       "X-Real-IP is trimmed",
			remoteAddr: spoofNginxPeer,
			xRealIP:    "   " + spoofVictimIP + "   ",
			want:       spoofVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newClientIPTestServer()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			if got := s.getClientIP(req); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetClientIP_NeverReturnsUnparseableIdentity guards the downstream
// contract: the result is used as a GeoIP argument, an actor-tracker key and a
// rate-limit bucket, so it must always be a real address.
func TestGetClientIP_NeverReturnsUnparseableIdentity(t *testing.T) {
	hostile := []struct {
		name    string
		xff     string
		xRealIP string
	}{
		{"loopback injected into XFF", "127.0.0.1", ""},
		{"loopback injected with no other header", "::1", ""},
		{"empty elements", " , , ", ""},
		{"garbage XFF", "not-an-ip", ""},
	}

	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			s := newClientIPTestServer()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = spoofNginxPeer
			if h.xff != "" {
				req.Header.Set("X-Forwarded-For", h.xff)
			}
			if h.xRealIP != "" {
				req.Header.Set("X-Real-IP", h.xRealIP)
			}

			got := s.getClientIP(req)
			if net.ParseIP(got) == nil {
				t.Errorf("getClientIP() = %q, which is not a parseable IP", got)
			}
		})
	}
}

// TestGetClientIP_MatchesEcosystemClientIP proves the two resolvers cannot
// drift apart: a divergence would mean the ecosystem allowlist and the WAF
// disagree about who the caller is.
func TestGetClientIP_MatchesEcosystemClientIP(t *testing.T) {
	cases := []struct {
		remoteAddr string
		xff        string
		xRealIP    string
	}{
		{spoofNginxPeer, spoofVictimIP + ", " + spoofAttackerIP, ""},
		{spoofNginxPeer, spoofVictimIP + ", " + spoofAttackerIP, spoofAttackerIP},
		{spoofNginxPeer, "", spoofVictimIP},
		{spoofNginxPeer, spoofVictimIP, ""},
		{spoofNginxPeer, "", ""},
		{spoofAttackerIP + ":54321", spoofVictimIP, spoofVictimIP},
		{"127.0.0.1", spoofVictimIP, ""},
	}

	for _, c := range cases {
		s := newClientIPTestServer()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remoteAddr
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.xRealIP != "" {
			req.Header.Set("X-Real-IP", c.xRealIP)
		}

		general := s.getClientIP(req)
		ecosystem := s.ecosystemClientIP(req)
		if general != ecosystem {
			t.Errorf("resolvers disagree for %+v: getClientIP=%q ecosystemClientIP=%q",
				c, general, ecosystem)
		}
	}
}

// newWAFTestServer builds a Server with the real signature engine so the
// whitelist decision under test is exercised on the real request path.
func newWAFTestServer(t *testing.T, whitelistedIPs []string) *Server {
	t.Helper()

	engine, err := waf.NewEngine("", 1.0, 0.5)
	if err != nil {
		t.Fatalf("waf.NewEngine: %v", err)
	}

	return &Server{
		log:   logger.New("test"),
		waf:   engine,
		stats: &Stats{},
		cfg: &config.Config{
			WAF: config.WAFConfig{
				Enabled:        true,
				BlockThreshold: 1.0,
				LogThreshold:   0.5,
				WhitelistedIPs: whitelistedIPs,
			},
		},
	}
}

// sqliProbe is a request the WAF must score as an attack. RawQuery is set
// verbatim (not percent-encoded) because Engine.Scan matches signatures against
// the raw query string.
func sqliProbe() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.URL.RawQuery = "id=1' UNION SELECT username,password FROM users--"
	return req
}

// TestSQLiProbeIsActuallyBlocked is an anti-theatre guard: the whitelist tests
// above only mean something if this payload is genuinely blocked when the
// caller is not whitelisted at all.
func TestSQLiProbeIsActuallyBlocked(t *testing.T) {
	s := newWAFTestServer(t, nil)

	reached := false
	handler := s.wafMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := sqliProbe()
	req.RemoteAddr = spoofAttackerIP + ":54321"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if reached || rec.Code != http.StatusForbidden {
		t.Fatalf("probe not blocked (reached=%v status=%d); the whitelist tests would be vacuous",
			reached, rec.Code)
	}
}

// TestWAFMiddleware_SpoofedXFFCannotBorrowWhitelistedIP is the Phase 5
// integration proof: no mocked business logic, the real wafMiddleware and the
// real signature engine. An attacker prepending a whitelisted address must not
// inherit that address's WAF exemption.
func TestWAFMiddleware_SpoofedXFFCannotBorrowWhitelistedIP(t *testing.T) {
	s := newWAFTestServer(t, []string{spoofVictimIP})

	reached := false
	handler := s.wafMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := sqliProbe()
	req.RemoteAddr = spoofNginxPeer                                       // via nginx
	req.Header.Set("X-Forwarded-For", spoofVictimIP+", "+spoofAttackerIP) // forged prefix
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("attack passed the WAF: spoofed X-Forwarded-For borrowed a whitelisted IP")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestWAFMiddleware_LegitimateWhitelistedIPStillExempt is the behaviour-
// preservation guard for the same change: a genuinely whitelisted operator IP,
// arriving the way nginx actually delivers it, must keep its exemption.
func TestWAFMiddleware_LegitimateWhitelistedIPStillExempt(t *testing.T) {
	s := newWAFTestServer(t, []string{spoofVictimIP})

	reached := false
	handler := s.wafMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := sqliProbe()
	req.RemoteAddr = spoofNginxPeer
	req.Header.Set("X-Real-IP", spoofVictimIP)
	req.Header.Set("X-Forwarded-For", spoofVictimIP)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !reached {
		t.Errorf("legitimate whitelisted IP lost its WAF exemption (status %d)", rec.Code)
	}
}

// TestWAFMiddleware_AttackerCannotBeWhitelistedFromDirectPeer covers the
// non-proxied path: a direct connection forging both headers stays unexempt.
func TestWAFMiddleware_AttackerCannotBeWhitelistedFromDirectPeer(t *testing.T) {
	s := newWAFTestServer(t, []string{spoofVictimIP})

	reached := false
	handler := s.wafMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := sqliProbe()
	req.RemoteAddr = spoofAttackerIP + ":54321"
	req.Header.Set("X-Real-IP", spoofVictimIP)
	req.Header.Set("X-Forwarded-For", spoofVictimIP)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if reached {
		t.Error("attack passed the WAF: direct peer forged a whitelisted identity")
	}
}
