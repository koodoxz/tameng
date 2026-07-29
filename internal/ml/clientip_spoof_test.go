package ml

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ SVALINN-CLIENTIP-SPOOF-002
//
// getClientIP keys the anomaly detector's per-IP baselines, path-transition
// chains and request-time series. It used to return the ENTIRE raw
// X-Forwarded-For header (its own comment already flagged this as debt), so
// behind the production nginx -- which APPENDS the real peer -- an attacker
// could rotate the header and keep every z-score, IQR and speed baseline
// permanently empty, which is a silent fail-open of the ML detection layer.

const (
	mlNginxPeer  = "127.0.0.1:49200"
	mlAttackerIP = "198.51.100.77"
	mlVictimIP   = "203.0.113.5"
)

func mlRequest(remoteAddr, xff, xRealIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xRealIP != "" {
		req.Header.Set("X-Real-IP", xRealIP)
	}
	return req
}

func mlMetrics() RequestMetrics {
	return RequestMetrics{
		PathLength:   14,
		QueryLength:  0,
		HeaderCount:  3,
		SpecialChars: 2,
		Entropy:      3.5,
	}
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
			remoteAddr: mlNginxPeer,
			xff:        mlVictimIP + ", " + mlAttackerIP,
			want:       mlAttackerIP,
		},
		{
			name:       "multi-element chain is not returned verbatim",
			remoteAddr: mlNginxPeer,
			xff:        "10.0.0.1, 172.16.0.9, " + mlAttackerIP,
			want:       mlAttackerIP,
		},
		{
			name:       "direct peer cannot forge via XFF",
			remoteAddr: mlAttackerIP + ":54321",
			xff:        mlVictimIP,
			want:       mlAttackerIP,
		},
		{
			name:       "direct peer cannot forge via X-Real-IP",
			remoteAddr: mlAttackerIP + ":54321",
			xRealIP:    mlVictimIP,
			want:       mlAttackerIP,
		},
		{
			// REGRESSION GUARD: legitimate nginx shape resolves as before.
			name:       "legitimate nginx hop is unchanged",
			remoteAddr: mlNginxPeer,
			xff:        mlVictimIP,
			xRealIP:    mlVictimIP,
			want:       mlVictimIP,
		},
		{
			name:       "legitimate nginx hop with only X-Real-IP is unchanged",
			remoteAddr: mlNginxPeer,
			xRealIP:    mlVictimIP,
			want:       mlVictimIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getClientIP(mlRequest(tt.remoteAddr, tt.xff, tt.xRealIP)); got != tt.want {
				t.Errorf("getClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAnalyzeRequest_SpoofedXFFCannotAttributeToVictim is the Phase 5
// integration proof: the real AnomalyDetector, the real AnalyzeRequest path.
func TestAnalyzeRequest_SpoofedXFFCannotAttributeToVictim(t *testing.T) {
	a := NewAnomalyDetector()

	a.AnalyzeRequest(mlRequest(mlNginxPeer, mlVictimIP+", "+mlAttackerIP, ""), mlMetrics())

	if _, ok := a.baselines.Load(mlVictimIP); ok {
		t.Errorf("a baseline was created for victim %s from a forged header", mlVictimIP)
	}
	if _, ok := a.baselines.Load(mlAttackerIP); !ok {
		t.Errorf("no baseline was created for the real peer %s", mlAttackerIP)
	}
}

// TestAnalyzeRequest_LegitimateHopStillBaselined is the behaviour-preservation
// half: a genuine client behind nginx still accumulates its own baseline.
func TestAnalyzeRequest_LegitimateHopStillBaselined(t *testing.T) {
	a := NewAnomalyDetector()

	a.AnalyzeRequest(mlRequest(mlNginxPeer, mlVictimIP, mlVictimIP), mlMetrics())

	if _, ok := a.baselines.Load(mlVictimIP); !ok {
		t.Errorf("legitimate client %s lost its ML baseline", mlVictimIP)
	}
}

// TestAnalyzeRequest_RotatedXFFCannotSplitBaseline proves the ML-evasion path
// is closed: one real peer rotating a forged header must accumulate into ONE
// baseline, so z-score / IQR / speed detection still has data to work with.
func TestAnalyzeRequest_RotatedXFFCannotSplitBaseline(t *testing.T) {
	a := NewAnomalyDetector()

	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		a.AnalyzeRequest(mlRequest(mlAttackerIP+":54321", forged, forged), mlMetrics())
	}

	stats := a.GetStats()
	if got := stats["tracked_ips"]; got != 1 {
		t.Errorf("rotating a forged X-Forwarded-For produced tracked_ips=%v, want 1", got)
	}
	if _, ok := a.baselines.Load(mlAttackerIP); !ok {
		t.Errorf("the single baseline is not keyed by the real peer %s", mlAttackerIP)
	}
}
