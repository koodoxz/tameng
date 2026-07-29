package fingerprint

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// getClientIP keys the per-fingerprint IP history (Fingerprint.IPs), which is
// what GetFingerprintsByIP and the downstream threat attribution read. It used
// to trust the FIRST X-Forwarded-For element, which production nginx makes
// attacker-controlled because it APPENDS the real peer:
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//
// These tests pin both halves of the fix: forged values are rejected, and the
// legitimate nginx-shaped request still resolves to exactly the same address it
// resolved to before the change (regression guard).

const (
	fpNginxPeer  = "127.0.0.1:49200"
	fpAttackerIP = "198.51.100.77"
	fpVictimIP   = "203.0.113.5"
)

func fpRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", "probe/1.0")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	return req
}

func TestGetClientIP_RejectsSpoofedHeaders(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{
			name:       "attacker prepends victim IP via nginx",
			remoteAddr: fpNginxPeer,
			xff:        fpVictimIP + ", " + fpAttackerIP,
			want:       fpAttackerIP,
		},
		{
			name:       "direct peer cannot forge via XFF",
			remoteAddr: fpAttackerIP + ":54321",
			xff:        fpVictimIP,
			want:       fpAttackerIP,
		},
		{
			name:       "direct peer cannot forge via X-Real-IP",
			remoteAddr: fpAttackerIP + ":54321",
			xRealIP:    fpVictimIP,
			want:       fpAttackerIP,
		},
		{
			// REGRESSION GUARD: the legitimate production shape must resolve to
			// the same address as before the change.
			name:       "legitimate nginx hop is unchanged",
			remoteAddr: fpNginxPeer,
			xff:        fpVictimIP,
			xRealIP:    fpVictimIP,
			want:       fpVictimIP,
		},
		{
			name:       "legitimate nginx hop with only X-Real-IP is unchanged",
			remoteAddr: fpNginxPeer,
			xRealIP:    fpVictimIP,
			want:       fpVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getClientIP(fpRequest(tt.remoteAddr, tt.xff, tt.xRealIP)); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGenerateHTTPFingerprint_SpoofedXFFCannotAttributeToVictim is the Phase 5
// integration proof: the real Engine, the real fingerprint path, no mocks. A
// forged X-Forwarded-For must not file the attacker's fingerprint under the
// victim's address.
func TestGenerateHTTPFingerprint_SpoofedXFFCannotAttributeToVictim(t *testing.T) {
	e := NewEngine()

	req := fpRequest(fpNginxPeer, fpVictimIP+", "+fpAttackerIP, "")
	e.GenerateHTTPFingerprint(req)

	if got := e.GetFingerprintsByIP(fpVictimIP); len(got) != 0 {
		t.Errorf("victim %s was attributed %d fingerprint(s) from a forged header",
			fpVictimIP, len(got))
	}
	if got := e.GetFingerprintsByIP(fpAttackerIP); len(got) != 1 {
		t.Errorf("attacker %s was attributed %d fingerprint(s), want 1",
			fpAttackerIP, len(got))
	}
}

// TestGenerateHTTPFingerprint_LegitimateHopStillAttributed is the behaviour-
// preservation half: a genuine client behind nginx keeps its attribution.
func TestGenerateHTTPFingerprint_LegitimateHopStillAttributed(t *testing.T) {
	e := NewEngine()

	req := fpRequest(fpNginxPeer, fpVictimIP, fpVictimIP)
	e.GenerateHTTPFingerprint(req)

	if got := e.GetFingerprintsByIP(fpVictimIP); len(got) != 1 {
		t.Errorf("legitimate client %s was attributed %d fingerprint(s), want 1",
			fpVictimIP, len(got))
	}
}

// TestGenerateHTTPFingerprint_RotatedXFFCannotSplitAttribution proves the
// evasion path is closed: rotating a forged header from one real peer must not
// scatter that peer's fingerprint history across many identities.
func TestGenerateHTTPFingerprint_RotatedXFFCannotSplitAttribution(t *testing.T) {
	e := NewEngine()

	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		req := fpRequest(fpAttackerIP+":54321", forged, forged)
		e.GenerateHTTPFingerprint(req)

		if got := e.GetFingerprintsByIP(forged); len(got) != 0 {
			t.Errorf("forged identity %s accumulated %d fingerprint(s)", forged, len(got))
		}
	}

	if got := e.GetFingerprintsByIP(fpAttackerIP); len(got) != 1 {
		t.Errorf("attacker %s was attributed %d fingerprint(s), want 1",
			fpAttackerIP, len(got))
	}
}
