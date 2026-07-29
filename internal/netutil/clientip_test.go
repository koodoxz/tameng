package netutil

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// TrustedClientIP is the single shared resolver for client identity used by the
// fingerprint, behavior, session, preattack and ml detection subsystems. Each of
// those packages previously reinvented a naive resolver that trusted the FIRST
// X-Forwarded-For element (or, worse, the entire raw header).
//
// Production nginx fronts SVALINN with
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//	proxy_set_header X-Real-IP       $remote_addr;
//
// $proxy_add_x_forwarded_for APPENDS the real peer to whatever the client
// already sent, so the FIRST element is fully attacker-controlled. X-Real-IP is
// written from nginx's own $remote_addr and is overwritten every hop, so a
// client cannot forge it. These tests pin the invariant that only nginx-supplied
// values (X-Real-IP, or the LAST X-Forwarded-For element) are ever trusted, and
// only when the direct TCP peer is loopback.
//
// This table is the ported counterpart of internal/server/clientip_spoof_test.go
// (REQ SVALINN-CLIENTIP-SPOOF-001), whose logic this package shares.

const (
	nginxPeer  = "127.0.0.1:49200" // the local nginx reverse proxy
	attackerIP = "198.51.100.77"   // the attacker's real address
	victimIP   = "203.0.113.5"     // a third party the attacker wants to impersonate
)

func newRequest(remoteAddr, xff, xRealIP string) *http.Request {
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

// TestTrustedClientIP_ResolvesTrustedSource is the core table: every branch of
// TrustedClientIP, stated as "which address may this request legitimately claim".
func TestTrustedClientIP_ResolvesTrustedSource(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			// THE BUG (REQ SVALINN-CLIENTIP-SPOOF-002): the attacker prepends a
			// victim address; nginx appends the attacker's real peer. Trusting
			// element [0] hands the attacker the victim's identity.
			name:       "attacker prepends victim IP, nginx appends real peer",
			remoteAddr: nginxPeer,
			xff:        victimIP + ", " + attackerIP,
			want:       attackerIP,
		},
		{
			name:       "prepended chain is ignored, X-Real-IP wins",
			remoteAddr: nginxPeer,
			xff:        victimIP + ", " + attackerIP,
			xRealIP:    attackerIP,
			want:       attackerIP,
		},
		{
			name:       "long forged chain still resolves to the appended peer",
			remoteAddr: nginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + victimIP + ", " + attackerIP,
			want:       attackerIP,
		},
		{
			// Precedence is part of the contract, not an accident: X-Real-IP is
			// rewritten by nginx on every hop, so it outranks the XFF chain when
			// the two disagree.
			name:       "X-Real-IP outranks the appended XFF element",
			remoteAddr: nginxPeer,
			xff:        victimIP + ", " + attackerIP,
			xRealIP:    "192.0.2.10",
			want:       "192.0.2.10",
		},
		{
			// Legitimate production shape: one hop through nginx.
			name:       "legitimate nginx hop with X-Real-IP and single-element XFF",
			remoteAddr: nginxPeer,
			xff:        victimIP,
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			name:       "nginx sets only X-Real-IP",
			remoteAddr: nginxPeer,
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			name:       "nginx sets only X-Forwarded-For",
			remoteAddr: nginxPeer,
			xff:        victimIP,
			want:       victimIP,
		},
		{
			// A direct (non-loopback) connection may never speak for anyone else.
			name:       "direct remote peer cannot forge via XFF",
			remoteAddr: attackerIP + ":54321",
			xff:        victimIP,
			want:       attackerIP,
		},
		{
			name:       "direct remote peer cannot forge via X-Real-IP",
			remoteAddr: attackerIP + ":54321",
			xRealIP:    victimIP,
			want:       attackerIP,
		},
		{
			name:       "direct remote peer cannot forge via both headers",
			remoteAddr: attackerIP + ":54321",
			xff:        victimIP + ", " + victimIP,
			xRealIP:    victimIP,
			want:       attackerIP,
		},
		{
			name:       "loopback peer with no proxy headers is itself",
			remoteAddr: nginxPeer,
			want:       "127.0.0.1",
		},
		{
			name:       "IPv6 loopback peer honours proxy headers",
			remoteAddr: "[::1]:49200",
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			name:       "IPv4-mapped loopback peer honours proxy headers",
			remoteAddr: "[::ffff:127.0.0.1]:49200",
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			name:       "IPv6 non-loopback peer cannot forge",
			remoteAddr: "[2001:db8::1]:54321",
			xff:        victimIP,
			xRealIP:    victimIP,
			want:       "2001:db8::1",
		},
		{
			// Whitespace around nginx-appended elements must not leak into the
			// key used for rate limiting / actor tracking.
			name:       "appended element is trimmed",
			remoteAddr: nginxPeer,
			xff:        victimIP + " ,   " + attackerIP + "   ",
			want:       attackerIP,
		},
		{
			// RemoteAddr without a port must still resolve, not collapse to "".
			name:       "RemoteAddr without a port is still usable",
			remoteAddr: "127.0.0.1",
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			name:       "portless non-loopback RemoteAddr cannot forge",
			remoteAddr: attackerIP,
			xff:        victimIP,
			want:       attackerIP,
		},
		{
			// The naive implementations split RemoteAddr on ":" and took [0],
			// which mangles bare IPv6 peers. SplitHostPort failure must fall back
			// to the whole value, unmangled.
			name:       "portless IPv6 RemoteAddr is not mangled",
			remoteAddr: "2001:db8::1",
			xff:        victimIP,
			want:       "2001:db8::1",
		},
		{
			// An unparseable peer is not loopback, so it can never be overridden
			// by headers. It is returned verbatim rather than silently replaced.
			name:       "unparseable RemoteAddr cannot be overridden by headers",
			remoteAddr: "not-an-address",
			xff:        victimIP,
			xRealIP:    victimIP,
			want:       "not-an-address",
		},
		{
			name:       "loopback-only XFF resolves to loopback, not a sentinel",
			remoteAddr: nginxPeer,
			xff:        "127.0.0.1",
			want:       "127.0.0.1",
		},
		{
			name:       "empty XFF header falls through to X-Real-IP",
			remoteAddr: nginxPeer,
			xff:        "",
			xRealIP:    victimIP,
			want:       victimIP,
		},
		{
			// An unparseable X-Real-IP must be ignored, not propagated as an
			// identity, so the nginx-appended XFF element still wins.
			name:       "garbage X-Real-IP is ignored in favour of appended XFF",
			remoteAddr: nginxPeer,
			xff:        victimIP + ", " + attackerIP,
			xRealIP:    "not-an-ip",
			want:       attackerIP,
		},
		{
			name:       "garbage X-Real-IP with no XFF falls back to the peer",
			remoteAddr: nginxPeer,
			xRealIP:    "not-an-ip",
			want:       "127.0.0.1",
		},
		{
			// Both headers unusable: the peer is the only trustworthy answer.
			name:       "garbage in both headers falls back to the peer",
			remoteAddr: nginxPeer,
			xff:        "still-not-an-ip",
			xRealIP:    "not-an-ip",
			want:       "127.0.0.1",
		},
		{
			name:       "trailing empty XFF element falls back to the peer",
			remoteAddr: nginxPeer,
			xff:        victimIP + ", ",
			want:       "127.0.0.1",
		},
		{
			name:       "X-Real-IP is trimmed",
			remoteAddr: nginxPeer,
			xRealIP:    "   " + victimIP + "   ",
			want:       victimIP,
		},
		{
			// 127.0.0.0/8 is loopback in its entirety, not just 127.0.0.1.
			name:       "non-canonical loopback peer is still trusted",
			remoteAddr: "127.0.0.53:49200",
			xRealIP:    victimIP,
			want:       victimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequest(tt.remoteAddr, tt.xff, tt.xRealIP)

			if got := TrustedClientIP(req); got != tt.want {
				t.Errorf("TrustedClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTrustedClientIP_NeverReturnsUnparseableIdentity guards the downstream
// contract: the result is used as a GeoIP argument, an actor-tracker key and a
// rate-limit bucket, so whenever the peer itself is a real address the result
// must be a real address too.
func TestTrustedClientIP_NeverReturnsUnparseableIdentity(t *testing.T) {
	hostile := []struct {
		name    string
		xff     string
		xRealIP string
	}{
		{"loopback injected into XFF", "127.0.0.1", ""},
		{"IPv6 loopback injected into XFF", "::1", ""},
		{"empty elements", " , , ", ""},
		{"garbage XFF", "not-an-ip", ""},
		{"garbage XFF and garbage X-Real-IP", "not-an-ip", "also-not-an-ip"},
		{"header injection sentinel attempt", "HEADER_INJECTION_ATTACK", ""},
		{"CRLF smuggling attempt", "203.0.113.5\r\nX-Evil: 1", ""},
		{"CIDR range instead of an address", "203.0.113.0/24", ""},
		{"port appended to XFF element", "203.0.113.5:1234", ""},
		{"absurdly long chain", "1.1.1.1," + "2.2.2.2," + "3.3.3.3," + "bogus", ""},
	}

	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			req := newRequest(nginxPeer, h.xff, h.xRealIP)

			got := TrustedClientIP(req)
			if net.ParseIP(got) == nil {
				t.Errorf("TrustedClientIP() = %q, which is not a parseable IP", got)
			}
		})
	}
}

// TestTrustedClientIP_HeadersNeverEscalateFromRemotePeer is the security
// invariant in its most reduced form: for ANY combination of proxy headers, a
// non-loopback peer always resolves to its own address. If this ever fails,
// every IP-keyed decision in five detection subsystems is forgeable.
func TestTrustedClientIP_HeadersNeverEscalateFromRemotePeer(t *testing.T) {
	xffValues := []string{
		"",
		victimIP,
		victimIP + ", " + attackerIP,
		"127.0.0.1",
		"::1",
		" , , ",
		"not-an-ip",
	}
	xriValues := []string{"", victimIP, "127.0.0.1", "::1", "not-an-ip"}

	for _, xff := range xffValues {
		for _, xri := range xriValues {
			req := newRequest(attackerIP+":54321", xff, xri)

			if got := TrustedClientIP(req); got != attackerIP {
				t.Errorf("TrustedClientIP() = %q with XFF=%q X-Real-IP=%q, want %q",
					got, xff, xri, attackerIP)
			}
		}
	}
}

// TestTrustedClientIP_MultipleXFFHeaderLines documents the repeated-header
// case explicitly, because it is the one shape where the resolver's answer is
// NOT the last address on the wire.
//
// net/http's Header.Get returns only the FIRST header line (Header.Values
// returns all of them; verified: Get -> "203.0.113.5", Values -> ["203.0.113.5"
// "198.51.100.77"]). So with two X-Forwarded-For lines the resolver reads line
// one and ignores the rest.
//
// This is not exploitable and is deliberately left as-is:
//
//   - Only a LOOPBACK peer ever reaches this code path at all. A remote attacker
//     is judged on its peer address no matter how many headers it sends -- pinned
//     by the non-loopback assertion below.
//   - The only loopback peer in production is nginx, and proxy_set_header
//     REPLACES the client's X-Forwarded-For lines with a single line whose last
//     element is $remote_addr. The Go server therefore never sees two lines.
//   - internal/server's already-deployed trustedClientIP behaves identically
//     (REQ SVALINN-CLIENTIP-SPOOF-001). Switching this port to Header.Values
//     would make the shared helper disagree with the server resolver, which is
//     precisely the drift REQ SVALINN-CLIENTIP-SPOOF-002 exists to remove.
//     Hardening both to Header.Values is recorded as a follow-up, not done here.
func TestTrustedClientIP_MultipleXFFHeaderLines(t *testing.T) {
	// From a loopback peer: Header.Get semantics decide, first line wins.
	viaNginx := httptest.NewRequest(http.MethodGet, "/", nil)
	viaNginx.RemoteAddr = nginxPeer
	viaNginx.Header.Add("X-Forwarded-For", victimIP)
	viaNginx.Header.Add("X-Forwarded-For", attackerIP)

	if got := TrustedClientIP(viaNginx); got != victimIP {
		t.Errorf("TrustedClientIP() = %q, want %q (Header.Get reads the first line)",
			got, victimIP)
	}

	// The security-relevant half: a remote peer gains nothing from splitting the
	// header across lines. This is the assertion that actually has to hold.
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = attackerIP + ":54321"
	direct.Header.Add("X-Forwarded-For", victimIP)
	direct.Header.Add("X-Forwarded-For", victimIP)

	if got := TrustedClientIP(direct); got != attackerIP {
		t.Errorf("TrustedClientIP() = %q, want %q: repeated header lines must not "+
			"let a remote peer forge an identity", got, attackerIP)
	}
}

// TestTrustedClientIP_IsPure asserts the resolver has no side effects on the
// request: it is called several times per request across five subsystems, so it
// must never mutate shared state.
func TestTrustedClientIP_IsPure(t *testing.T) {
	req := newRequest(nginxPeer, victimIP+", "+attackerIP, "")

	first := TrustedClientIP(req)
	second := TrustedClientIP(req)

	if first != second {
		t.Errorf("TrustedClientIP() is not idempotent: %q then %q", first, second)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != victimIP+", "+attackerIP {
		t.Errorf("TrustedClientIP() mutated the X-Forwarded-For header: %q", got)
	}
	if req.RemoteAddr != nginxPeer {
		t.Errorf("TrustedClientIP() mutated RemoteAddr: %q", req.RemoteAddr)
	}
}

// TestTrustedClientIP_ConcurrentUse is the Phase 8 guard: the resolver is called
// from many goroutines (one per in-flight request) across five subsystems.
func TestTrustedClientIP_ConcurrentUse(t *testing.T) {
	const goroutines = 64

	done := make(chan string, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			req := newRequest(nginxPeer, victimIP+", "+attackerIP, "")
			done <- TrustedClientIP(req)
		}()
	}

	for i := 0; i < goroutines; i++ {
		if got := <-done; got != attackerIP {
			t.Errorf("TrustedClientIP() = %q under concurrency, want %q", got, attackerIP)
		}
	}
}
