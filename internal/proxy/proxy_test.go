package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koodoxz/tameng/internal/logger"
)

// REQ SVALINN-PROXY-BACKEND-001

func TestNewBackendProxy_RejectsInvalidURL(t *testing.T) {
	if _, err := NewBackendProxy("://bad-url", logger.New("test"), false); err == nil {
		t.Fatal("expected error for a malformed URL, got nil")
	}
}

func TestNewBackendProxy_RejectsMissingScheme(t *testing.T) {
	if _, err := NewBackendProxy("example.com", logger.New("test"), false); err == nil {
		t.Fatal("expected error for a URL missing a scheme, got nil")
	}
}

func TestNewBackendProxy_RejectsUnsupportedScheme(t *testing.T) {
	if _, err := NewBackendProxy("ftp://example.com", logger.New("test"), false); err == nil {
		t.Fatal("expected error for an unsupported scheme, got nil")
	}
}

func TestNewBackendProxy_RejectsMissingHost(t *testing.T) {
	if _, err := NewBackendProxy("http://", logger.New("test"), false); err == nil {
		t.Fatal("expected error for a URL missing a host, got nil")
	}
}

func TestNewBackendProxy_AcceptsValidHTTPURL(t *testing.T) {
	rp, err := NewBackendProxy("http://127.0.0.1:9999", logger.New("test"), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rp == nil {
		t.Fatal("expected a non-nil ReverseProxy")
	}
}

func TestNewBackendProxy_AcceptsValidHTTPSURL(t *testing.T) {
	rp, err := NewBackendProxy("https://backend.internal:8443", logger.New("test"), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rp == nil {
		t.Fatal("expected a non-nil ReverseProxy")
	}
}

// TestBackendProxy_ForwardsRequestAndSetsTrustedHeaders proves the proxy
// actually reaches the backend, preserves the request path, and -- the core
// security property -- presents SVALINN's own trust-resolved caller identity
// to the backend rather than the request's raw, attacker-forgeable
// X-Forwarded-For/X-Real-IP headers.
func TestBackendProxy_ForwardsRequestAndSetsTrustedHeaders(t *testing.T) {
	var gotPath, gotXRealIP, gotXFF, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route?x=1", nil)
	req.RemoteAddr = "203.0.113.7:54321" // non-loopback direct peer: this IS the trusted identity
	// Forged headers an untrusted direct client sent must not reach the backend verbatim.
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	req.Header.Set("X-Real-IP", "8.8.8.8")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("backend response code: got %d, want 200", rec.Code)
	}
	if gotPath != "/app/route" {
		t.Fatalf("path forwarded to backend: got %q, want /app/route", gotPath)
	}
	if gotXRealIP != "203.0.113.7" {
		t.Fatalf("X-Real-IP forwarded to backend: got %q, want the trust-resolved peer 203.0.113.7 (not the forged header)", gotXRealIP)
	}
	if !strings.HasPrefix(gotXFF, "203.0.113.7") {
		t.Fatalf("X-Forwarded-For forwarded to backend: got %q, want it to start with the trust-resolved peer 203.0.113.7 (not the forged 9.9.9.9)", gotXFF)
	}
	if gotProto != "http" {
		t.Fatalf("X-Forwarded-Proto forwarded to backend: got %q, want http", gotProto)
	}
}

// TestBackendProxy_SetsHTTPSForwardedProtoForTLSRequests proves the proto
// SVALINN presents to the backend reflects how the caller actually reached
// SVALINN (TLS terminated at SVALINN's own listener), not a hardcoded value.
func TestBackendProxy_SetsHTTPSForwardedProtoForTLSRequests(t *testing.T) {
	var gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.TLS = &tls.ConnectionState{} // non-nil: this request arrived over TLS

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotProto != "https" {
		t.Fatalf("X-Forwarded-Proto for a TLS request: got %q, want https", gotProto)
	}
}

// TestBackendProxy_StripsOtherSpoofableIdentityAndRoutingHeaders proves that
// beyond overriding X-Real-IP/X-Forwarded-For/X-Forwarded-Proto, the Director
// also strips every other caller-settable identity/routing header rather
// than forwarding it verbatim. Found by the independent Opus verification
// pass for REQ SVALINN-PROXY-BACKEND-001: backends behind a CDN commonly
// trust True-Client-IP/CF-Connecting-IP for identity, and some backend
// stacks honor X-Original-URL/X-Rewrite-URL for internal routing -- passing
// either through would let a direct, untrusted caller spoof identity or the
// effective request path on the backend.
func TestBackendProxy_StripsOtherSpoofableIdentityAndRoutingHeaders(t *testing.T) {
	got := map[string]string{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range spoofableHeaders() {
			got[h] = r.Header.Get(h)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route", nil)
	req.RemoteAddr = "203.0.113.7:54321" // non-loopback: an untrusted direct caller
	for _, h := range spoofableHeaders() {
		req.Header.Set(h, "attacker-controlled-value")
	}

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("backend response code: got %d, want 200", rec.Code)
	}
	for _, h := range spoofableHeaders() {
		if got[h] != "" {
			t.Errorf("header %s reached the backend as %q, want it stripped", h, got[h])
		}
	}
}

// TestBackendProxy_ConnectionHeaderCannotEraseTrustedHeaders is the
// regression guard for a MEDIUM finding from the round-2 independent Opus
// verification pass: httputil.ReverseProxy honors caller-supplied Connection
// tokens to decide which *additional* headers to strip as hop-by-hop, after
// the Director has already run. Without stripping the Connection header
// itself, a caller could send "Connection: X-Real-IP, X-Forwarded-For,
// X-Forwarded-Proto" to erase the exact trusted-identity headers this
// Director sets -- not forgery (the caller can't choose the value), but
// suppression that defeats backend-side IP attribution/rate-limiting and can
// downgrade HTTPS-gated backend logic via a blanked X-Forwarded-Proto.
func TestBackendProxy_ConnectionHeaderCannotEraseTrustedHeaders(t *testing.T) {
	var gotXRealIP, gotXFF, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXRealIP = r.Header.Get("X-Real-IP")
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set("Connection", "X-Real-IP, X-Forwarded-For, X-Forwarded-Proto")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("backend response code: got %d, want 200", rec.Code)
	}
	if gotXRealIP != "203.0.113.7" {
		t.Errorf("X-Real-IP: got %q, want the trusted identity 203.0.113.7 (a Connection-header attack erased it)", gotXRealIP)
	}
	if !strings.HasPrefix(gotXFF, "203.0.113.7") {
		t.Errorf("X-Forwarded-For: got %q, want it to start with 203.0.113.7 (a Connection-header attack erased it)", gotXFF)
	}
	if gotProto != "http" {
		t.Errorf("X-Forwarded-Proto: got %q, want http (a Connection-header attack erased it)", gotProto)
	}
}

// REQ SVALINN-EGRESS-ENCODING-NORMALIZE-001
//
// The egress DLP scanner (advancedEgressMiddleware) can only decode gzip and
// deflate response bodies for scanning. httputil.ReverseProxy's default
// Director forwards a client's own Accept-Encoding untouched, so a backend
// free to answer with br or zstd (any modern browser sends "br, gzip" by
// default) would let every secretPatterns regex silently miss a compressed
// PII/secret leak. When normalizeResponseEncoding is true, the Director
// overrides whatever the client asked for with a fixed "gzip" before
// forwarding to the backend, closing that gap at the source.
func TestNewBackendProxy_NormalizesAcceptEncodingWhenRequested(t *testing.T) {
	var gotAcceptEncoding string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), true)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route", nil)
	req.Header.Set("Accept-Encoding", "br, gzip, deflate, zstd") // realistic modern-browser default

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("backend response code: got %d, want 200", rec.Code)
	}
	if gotAcceptEncoding != "gzip" {
		t.Errorf("Accept-Encoding forwarded to backend: got %q, want %q -- DLP can only decode gzip/deflate, so br/zstd must never reach the backend as an option", gotAcceptEncoding, "gzip")
	}
}

// TestNewBackendProxy_PreservesClientAcceptEncodingWhenNormalizationDisabled
// locks in the opt-out behavior: deployments without the egress DLP feature
// enabled must not pay a compression-ratio cost (gzip is worse than br/zstd)
// for a scanning capability they never turned on.
func TestNewBackendProxy_PreservesClientAcceptEncodingWhenNormalizationDisabled(t *testing.T) {
	var gotAcceptEncoding string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if gotAcceptEncoding != "br, gzip" {
		t.Errorf("Accept-Encoding forwarded to backend: got %q, want the client's original %q unchanged", gotAcceptEncoding, "br, gzip")
	}
}

// TestNewBackendProxy_ClientWithNoAcceptEncodingReceivesUncompressedBody
// proves normalization does not risk sending an undecodable body to a client
// that never declared compression support. Director leaves an absent
// Accept-Encoding absent (does not force "gzip" onto it) specifically so
// Go's http.Transport applies its own standard behavior for a request with
// no Accept-Encoding at all: it adds "Accept-Encoding: gzip" itself and
// transparently decompresses the response before ReverseProxy forwards it,
// stripping Content-Encoding -- so the client, who asked for nothing, gets a
// plain body it can always read, never a compressed one it cannot decode.
func TestNewBackendProxy_ClientWithNoAcceptEncodingReceivesUncompressedBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(`{"status":"ok"}`))
		_ = gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer backend.Close()

	rp, err := NewBackendProxy(backend.URL, logger.New("test"), true)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/app/route", nil) // no Accept-Encoding set

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding reaching a client that declared no compression support: got %q, want absent", enc)
	}
	if rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("client body: got %q, want the plain decompressed JSON", rec.Body.String())
	}
}

// REQ SVALINN-EGRESS-ENCODING-NORMALIZE-001, round 2
//
// An independent Opus-judge review of the first version of this fix found
// that unconditionally forcing "gzip" onto any non-empty Accept-Encoding
// violated RFC 9110 SS12.5.3 for a client that explicitly asked for
// something else (e.g. "identity" or "deflate" alone, or "gzip;q=0"). The
// fix deletes Accept-Encoding instead of forcing gzip when the client's own
// header does not actually permit gzip -- Go's http.Transport then adds its
// own "Accept-Encoding: gzip" and transparently decompresses the response,
// stripping Content-Encoding, before ReverseProxy ever forwards it. So the
// backend legitimately still sees "gzip" on the wire in these cases (that is
// Transport's own standard, safe behavior, proven separately by
// TestNewBackendProxy_ClientWithNoAcceptEncodingReceivesUncompressedBody) --
// what this test proves is the property that actually matters: the CLIENT
// never receives a Content-Encoding it did not agree to, regardless of what
// Transport negotiated with the backend on its behalf.
func TestNewBackendProxy_ClientNeverReceivesAnEncodingItDidNotAccept(t *testing.T) {
	cases := []struct {
		name          string
		clientAccepts string
		gzipForced    bool // true only when the client's header itself permits gzip
	}{
		{name: "identity only", clientAccepts: "identity"},
		{name: "deflate only", clientAccepts: "deflate"},
		{name: "br only", clientAccepts: "br"},
		{name: "gzip explicitly refused", clientAccepts: "gzip;q=0, br"},
		{name: "wildcard refused", clientAccepts: "*;q=0, deflate"},
		// Round 2: an independent Opus-judge review found parseCodingToken's
		// "q=" match was case-sensitive and stopped at the first ';', so
		// both of these were misread as accepting gzip despite explicitly
		// refusing it (RFC 9110 SS12.4.2 weight-parameter names are
		// case-insensitive; a qvalue can be followed by further params).
		{name: "gzip refused, uppercase Q", clientAccepts: "gzip;Q=0, br"},
		{name: "gzip refused, trailing param after qvalue", clientAccepts: "gzip;q=0;foo=bar"},
		{name: "gzip accepted", clientAccepts: "br, gzip, deflate", gzipForced: true},
		{name: "wildcard accepted", clientAccepts: "*", gzipForced: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var buf bytes.Buffer
				gz := gzip.NewWriter(&buf)
				_, _ = gz.Write([]byte(`{"status":"ok"}`))
				_ = gz.Close()
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(buf.Bytes())
			}))
			defer backend.Close()

			rp, err := NewBackendProxy(backend.URL, logger.New("test"), true)
			if err != nil {
				t.Fatalf("NewBackendProxy: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/app/route", nil)
			req.Header.Set("Accept-Encoding", tc.clientAccepts)

			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)

			gotEncoding := rec.Header().Get("Content-Encoding")
			if tc.gzipForced {
				if gotEncoding != "gzip" {
					t.Errorf("client sent %q (accepts gzip): Content-Encoding = %q, want gzip", tc.clientAccepts, gotEncoding)
				}
				return
			}
			if gotEncoding != "" {
				t.Errorf("client sent %q (does not accept gzip): Content-Encoding = %q, want absent -- client received a coding it never agreed to", tc.clientAccepts, gotEncoding)
			}
			if rec.Body.String() != `{"status":"ok"}` {
				t.Errorf("client sent %q: body = %q, want the plain decompressed JSON (Transport should have transparently decoded it)", tc.clientAccepts, rec.Body.String())
			}
		})
	}
}

// unreachableBackendAddr reserves a TCP port, closes it immediately, and
// returns the now-guaranteed-unreachable host:port -- used to exercise the
// proxy's ErrorHandler path deterministically.
func unreachableBackendAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("failed to close reserved listener: %v", err)
	}
	return addr
}

// TestBackendProxy_UnreachableBackendFailsClosedWithoutLeakingDetails proves
// an unreachable backend returns a generic 502 and never leaks the backend's
// address or connection-error internals to the caller (REQ
// SVALINN-PROXY-BACKEND-001 -- forwarding must not become an infrastructure
// disclosure vector, matching the project's existing honeypot-topology
// invariant).
func TestBackendProxy_UnreachableBackendFailsClosedWithoutLeakingDetails(t *testing.T) {
	addr := unreachableBackendAddr(t)

	rp, err := NewBackendProxy("http://"+addr, logger.New("test"), false)
	if err != nil {
		t.Fatalf("NewBackendProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("unreachable backend: got status %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), addr) {
		t.Fatalf("error response body leaked the backend address %q: body=%q", addr, rec.Body.String())
	}
}
