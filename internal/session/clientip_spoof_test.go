package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// Guard.getClientIP supplies SessionInfo.IP and the per-request IP-change
// comparison in CheckSession. It used to return the ENTIRE raw X-Forwarded-For
// header, so behind the production nginx (which APPENDS the real peer) an
// attacker could both bind a session to a victim's address and forge or mask
// "ip_change" hijack signals at will.

const (
	sesNginxPeer  = "127.0.0.1:49200"
	sesAttackerIP = "198.51.100.77"
	sesVictimIP   = "203.0.113.5"
)

func sesGuard() *Guard {
	return NewGuard(Config{Enabled: true})
}

func sesRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", "probe/1.0")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	return req
}

func TestGuardGetClientIP_RejectsSpoofedHeaders(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			name:       "attacker prepends victim IP via nginx",
			remoteAddr: sesNginxPeer,
			xff:        sesVictimIP + ", " + sesAttackerIP,
			want:       sesAttackerIP,
		},
		{
			name:       "multi-element chain is not returned verbatim",
			remoteAddr: sesNginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + sesAttackerIP,
			want:       sesAttackerIP,
		},
		{
			name:       "direct peer cannot forge via XFF",
			remoteAddr: sesAttackerIP + ":54321",
			xff:        sesVictimIP,
			want:       sesAttackerIP,
		},
		{
			name:       "direct peer cannot forge via X-Real-IP",
			remoteAddr: sesAttackerIP + ":54321",
			xRealIP:    sesVictimIP,
			want:       sesAttackerIP,
		},
		{
			// REGRESSION GUARD: legitimate nginx shape resolves as before.
			name:       "legitimate nginx hop is unchanged",
			remoteAddr: sesNginxPeer,
			xff:        sesVictimIP,
			xRealIP:    sesVictimIP,
			want:       sesVictimIP,
		},
		{
			name:       "legitimate nginx hop with only X-Real-IP is unchanged",
			remoteAddr: sesNginxPeer,
			xRealIP:    sesVictimIP,
			want:       sesVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := sesGuard()
			if got := g.getClientIP(sesRequest(tt.remoteAddr, tt.xff, tt.xRealIP)); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckSession_SpoofedXFFCannotBindSessionToVictim is the Phase 5
// integration proof: the real Guard, the real CheckSession path, no mocks.
func TestCheckSession_SpoofedXFFCannotBindSessionToVictim(t *testing.T) {
	g := sesGuard()

	g.CheckSession(sesRequest(sesNginxPeer, sesVictimIP+", "+sesAttackerIP, ""), "sess-1", "user-1")

	val, ok := g.sessions.Load("sess-1")
	if !ok {
		t.Fatal("CheckSession did not create a session")
	}
	if got := val.(*SessionInfo).IP; got != sesAttackerIP {
		t.Errorf("session bound to %q, want the real peer %q", got, sesAttackerIP)
	}
}

// TestCheckSession_LegitimateHopStillBindsVictimIP is the behaviour-preservation
// half: a genuine client behind nginx keeps its own address on the session.
func TestCheckSession_LegitimateHopStillBindsVictimIP(t *testing.T) {
	g := sesGuard()

	g.CheckSession(sesRequest(sesNginxPeer, sesVictimIP, sesVictimIP), "sess-2", "user-2")

	val, ok := g.sessions.Load("sess-2")
	if !ok {
		t.Fatal("CheckSession did not create a session")
	}
	if got := val.(*SessionInfo).IP; got != sesVictimIP {
		t.Errorf("legitimate session bound to %q, want %q", got, sesVictimIP)
	}
}

// TestCheckSession_RotatedXFFCannotForgeIPChange proves the hijack-signal
// forgery path is closed: one real peer rotating a forged header must not be
// able to manufacture "ip_change" violations on a session.
func TestCheckSession_RotatedXFFCannotForgeIPChange(t *testing.T) {
	g := sesGuard()

	g.CheckSession(sesRequest(sesAttackerIP+":54321", "1.1.1.1", "1.1.1.1"), "sess-3", "user-3")
	result := g.CheckSession(sesRequest(sesAttackerIP+":54321", "2.2.2.2", "2.2.2.2"), "sess-3", "user-3")

	for _, v := range result.Violations {
		if v == "ip_change" {
			t.Error("a forged X-Forwarded-For manufactured an ip_change violation from a single real peer")
		}
	}
}

// TestCheckSession_RealIPChangeStillDetected is the anti-theatre guard for the
// test above: genuine peer movement must still raise ip_change, otherwise the
// assertion above would be vacuous.
func TestCheckSession_RealIPChangeStillDetected(t *testing.T) {
	g := sesGuard()

	g.CheckSession(sesRequest(sesAttackerIP+":54321", "", ""), "sess-4", "user-4")
	result := g.CheckSession(sesRequest(sesVictimIP+":54321", "", ""), "sess-4", "user-4")

	found := false
	for _, v := range result.Violations {
		if v == "ip_change" {
			found = true
		}
	}
	if !found {
		t.Error("a genuine peer change no longer raises ip_change")
	}
}
