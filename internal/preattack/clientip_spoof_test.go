package preattack

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// getClientIP keys Detector.scanPatterns, which drives recon, path-enumeration
// and port-scan detection. It used to trust the FIRST X-Forwarded-For element,
// which production nginx makes attacker-controlled because it APPENDS the real
// peer. A scanner could therefore rotate the header and never accumulate enough
// requests in any single bucket to trip ReconThreshold.

const (
	paNginxPeer  = "127.0.0.1:49200"
	paAttackerIP = "198.51.100.77"
	paVictimIP   = "203.0.113.5"
)

func paRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin.php", nil)
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
			remoteAddr: paNginxPeer,
			xff:        paVictimIP + ", " + paAttackerIP,
			want:       paAttackerIP,
		},
		{
			name:       "long forged chain resolves to the appended peer",
			remoteAddr: paNginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + paVictimIP + ", " + paAttackerIP,
			want:       paAttackerIP,
		},
		{
			name:       "direct peer cannot forge via XFF",
			remoteAddr: paAttackerIP + ":54321",
			xff:        paVictimIP,
			want:       paAttackerIP,
		},
		{
			name:       "direct peer cannot forge via X-Real-IP",
			remoteAddr: paAttackerIP + ":54321",
			xRealIP:    paVictimIP,
			want:       paAttackerIP,
		},
		{
			// REGRESSION GUARD: legitimate nginx shape resolves as before.
			name:       "legitimate nginx hop is unchanged",
			remoteAddr: paNginxPeer,
			xff:        paVictimIP,
			xRealIP:    paVictimIP,
			want:       paVictimIP,
		},
		{
			name:       "legitimate nginx hop with only X-Real-IP is unchanged",
			remoteAddr: paNginxPeer,
			xRealIP:    paVictimIP,
			want:       paVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getClientIP(paRequest(tt.remoteAddr, tt.xff, tt.xRealIP)); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAnalyze_SpoofedXFFCannotAttributeToVictim is the Phase 5 integration
// proof: the real Detector, the real Analyze path, no mocks.
func TestAnalyze_SpoofedXFFCannotAttributeToVictim(t *testing.T) {
	d := NewDetector(Config{Enabled: true})

	d.Analyze(paRequest(paNginxPeer, paVictimIP+", "+paAttackerIP, ""))

	if _, ok := d.scanPatterns.Load(paVictimIP); ok {
		t.Errorf("scan activity was attributed to victim %s from a forged header", paVictimIP)
	}
	if _, ok := d.scanPatterns.Load(paAttackerIP); !ok {
		t.Errorf("scan activity was not attributed to the real peer %s", paAttackerIP)
	}
}

// TestAnalyze_LegitimateHopStillTracked is the behaviour-preservation half.
func TestAnalyze_LegitimateHopStillTracked(t *testing.T) {
	d := NewDetector(Config{Enabled: true})

	d.Analyze(paRequest(paNginxPeer, paVictimIP, paVictimIP))

	if _, ok := d.scanPatterns.Load(paVictimIP); !ok {
		t.Errorf("legitimate client %s is no longer tracked", paVictimIP)
	}
}

// TestAnalyze_RotatedXFFCannotSplitScanPattern proves the scanner-evasion path
// is closed: rotating a forged header from one real peer must accumulate into a
// single scan pattern so the recon thresholds still trip.
func TestAnalyze_RotatedXFFCannotSplitScanPattern(t *testing.T) {
	d := NewDetector(Config{Enabled: true})

	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		d.Analyze(paRequest(paAttackerIP+":54321", forged, forged))
	}

	stats := d.GetStats()
	if got := stats["tracked_ips"]; got != 1 {
		t.Errorf("rotating a forged X-Forwarded-For produced tracked_ips=%v, want 1", got)
	}
	if _, ok := d.scanPatterns.Load(paAttackerIP); !ok {
		t.Errorf("the single scan pattern is not keyed by the real peer %s", paAttackerIP)
	}
}
