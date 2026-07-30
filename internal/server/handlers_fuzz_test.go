package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

// newEcosystemFuzzServer builds the smallest Server that can drive the two
// ecosystem JSON handlers end to end. countermeasures is deliberately nil (the
// handler nil-checks it) so no real blocking happens during fuzzing.
func newEcosystemFuzzServer() *Server {
	return &Server{
		log:           logger.New("fuzz"),
		cfg:           &config.Config{Ecosystem: config.EcosystemConfig{}},
		stats:         &Stats{StartTime: time.Now()},
		heimdallDedup: make(map[string]time.Time),
	}
}

// ecosystemBodySeeds are shared between both handlers: same JSON decoder, same
// "trusted peer sends us a document" threat model.
var ecosystemBodySeeds = [][]byte{
	[]byte(`{}`),
	[]byte(``),
	[]byte(`null`),
	[]byte(`[]`),
	[]byte(`{"ip":"1.2.3.4","threat_type":"port_scan","severity":9,"confidence":0.95}`),
	[]byte(`{"client_ip":"1.2.3.4","domain":"evil.example","type":"dga","score":0.99}`),
	[]byte(`{"severity":99999999999999999999,"confidence":1e400}`),
	[]byte(`{"severity":-2147483648,"confidence":-1.5,"score":-0}`),
	[]byte(`{"confidence":null,"score":null,"severity":null}`),
	[]byte(`{"ip":"\ud800","threat_type":" ","evidence":"\\"}`),
	[]byte(`{"ip":1,"threat_type":true}`),
	[]byte(`{"client_ip":"a","domain":"b"}{"client_ip":"c","domain":"d"}`),
	[]byte(`{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":1}}}}}}}}`),
	[]byte("{\x00\xff}"),
	[]byte(`{"ip":"1.2.3.4","threat_type":"x","detected_at":"not-a-timestamp"}`),
}

// FuzzHandleHeimdallReport fuzzes the HEIMDALL threat-report JSON parser. The
// endpoint is behind an IP allowlist (REQ SVALINN-ECO-AUTH-001) but the decoder
// itself has never been fuzzed; a panic here is reachable by any allowlisted
// peer, including a compromised or buggy one.
func FuzzHandleHeimdallReport(f *testing.F) {
	for _, s := range ecosystemBodySeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		s := newEcosystemFuzzServer()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/heimdall/report", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.20:44444"
		rec := httptest.NewRecorder()

		s.handleHeimdallReport(rec, req)

		if rec.Code < 200 || rec.Code > 599 {
			t.Fatalf("invalid HTTP status %d for body %q", rec.Code, body)
		}
	})
}

// FuzzHandleDNSEvents fuzzes the MIMIR/ODIN DNS threat-event JSON parser.
func FuzzHandleDNSEvents(f *testing.F) {
	for _, s := range ecosystemBodySeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		s := newEcosystemFuzzServer()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/dns-events", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.10:44444"
		req.Header.Set("X-Source", "mimir")
		rec := httptest.NewRecorder()

		s.handleDNSEvents(rec, req)

		if rec.Code < 200 || rec.Code > 599 {
			t.Fatalf("invalid HTTP status %d for body %q", rec.Code, body)
		}
	})
}
