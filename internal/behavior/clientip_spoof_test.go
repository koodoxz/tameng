package behavior

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// getClientIP (analytics.go) keys the per-IP behavioural profiles read by
// Detector.AnalyzeRequest, credential-stuffing detection, API-enumeration
// detection and scraping detection. It used to return the ENTIRE raw
// X-Forwarded-For header -- not even split on "," -- so an attacker behind the
// production nginx (which APPENDS the real peer) both stole a victim's identity
// and could rotate the header to scatter their own profile across unlimited
// buckets, defeating every threshold-based detector in this package.

const (
	behNginxPeer  = "127.0.0.1:49200"
	behAttackerIP = "198.51.100.77"
	behVictimIP   = "203.0.113.5"
)

func behRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = remoteAddr
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
			remoteAddr: behNginxPeer,
			xff:        behVictimIP + ", " + behAttackerIP,
			want:       behAttackerIP,
		},
		{
			// The old body returned the whole header verbatim, so a multi-element
			// chain became a single nonsensical "IP" used as a map key.
			name:       "multi-element chain is not returned verbatim",
			remoteAddr: behNginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + behAttackerIP,
			want:       behAttackerIP,
		},
		{
			name:       "direct peer cannot forge via XFF",
			remoteAddr: behAttackerIP + ":54321",
			xff:        behVictimIP,
			want:       behAttackerIP,
		},
		{
			name:       "direct peer cannot forge via X-Real-IP",
			remoteAddr: behAttackerIP + ":54321",
			xRealIP:    behVictimIP,
			want:       behAttackerIP,
		},
		{
			// REGRESSION GUARD: legitimate nginx shape resolves as before.
			name:       "legitimate nginx hop is unchanged",
			remoteAddr: behNginxPeer,
			xff:        behVictimIP,
			xRealIP:    behVictimIP,
			want:       behVictimIP,
		},
		{
			name:       "legitimate nginx hop with only X-Real-IP is unchanged",
			remoteAddr: behNginxPeer,
			xRealIP:    behVictimIP,
			want:       behVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getClientIP(behRequest(tt.remoteAddr, tt.xff, tt.xRealIP)); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAnalyzeRequest_SpoofedXFFCannotAttributeToVictim is the Phase 5
// integration proof: the real Detector, the real AnalyzeRequest path, no mocks.
func TestAnalyzeRequest_SpoofedXFFCannotAttributeToVictim(t *testing.T) {
	d := NewDetector(DetectorConfig{Enabled: true})

	d.AnalyzeRequest(behRequest(behNginxPeer, behVictimIP+", "+behAttackerIP, ""), 401, 128, "sess-1")

	if _, ok := d.profiles.Load(behVictimIP); ok {
		t.Errorf("a behavioural profile was created for victim %s from a forged header", behVictimIP)
	}
	if _, ok := d.profiles.Load(behAttackerIP); !ok {
		t.Errorf("no behavioural profile was created for the real peer %s", behAttackerIP)
	}
}

// TestAnalyzeRequest_LegitimateHopStillProfiled is the behaviour-preservation
// half: a genuine client behind nginx is still profiled under its own address.
func TestAnalyzeRequest_LegitimateHopStillProfiled(t *testing.T) {
	d := NewDetector(DetectorConfig{Enabled: true})

	d.AnalyzeRequest(behRequest(behNginxPeer, behVictimIP, behVictimIP), 200, 512, "sess-2")

	if _, ok := d.profiles.Load(behVictimIP); !ok {
		t.Errorf("legitimate client %s lost its behavioural profile", behVictimIP)
	}
}

// TestAnalyzeRequest_RotatedXFFCannotSplitProfile proves the detector-evasion
// path is closed: one real peer rotating a forged header must accumulate into
// ONE profile, so credential-stuffing and enumeration thresholds still trip.
func TestAnalyzeRequest_RotatedXFFCannotSplitProfile(t *testing.T) {
	d := NewDetector(DetectorConfig{Enabled: true})

	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		d.AnalyzeRequest(behRequest(behAttackerIP+":54321", forged, forged), 401, 128, "sess-3")
	}

	tracked := 0
	d.profiles.Range(func(_, _ interface{}) bool {
		tracked++
		return true
	})

	if tracked != 1 {
		t.Errorf("rotating a forged X-Forwarded-For produced %d profiles, want 1", tracked)
	}
	if _, ok := d.profiles.Load(behAttackerIP); !ok {
		t.Errorf("the single profile is not keyed by the real peer %s", behAttackerIP)
	}
}
