/*
Package proxy implements reverse-proxy forwarding from SVALINN to a protected
backend, so SVALINN can sit directly in a tenant's request path instead of
only serving its own routes (REQ SVALINN-PROXY-BACKEND-001).
*/
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/koodoxz/tameng/internal/logger"
	"github.com/koodoxz/tameng/internal/netutil"
)

// spoofableHeaders lists caller-settable identity/routing/scheme headers,
// beyond X-Real-IP/X-Forwarded-For/X-Forwarded-Proto, that must never reach
// the backend verbatim: backends behind a CDN or load balancer commonly
// trust the identity group (True-Client-IP, CF-Connecting-IP, X-Client-IP,
// X-Cluster-Client-IP, Client-IP, Forwarded) for caller identity;
// IIS/Symfony/Spring-Cloud-Gateway-style stacks honor the routing group
// (X-Original-URL, X-Rewrite-URL, X-Forwarded-Host, X-Forwarded-Port,
// X-Original-Host, X-Forwarded-Prefix, X-Host) for internal routing or
// rewrites; and X-Http-Method-Override/X-Forwarded-Scheme/Front-End-Https
// can flip the effective method or scheme a backend framework acts on.
// Connection is stripped too: httputil.ReverseProxy honors caller-supplied
// Connection tokens to decide which *additional* headers to strip as
// hop-by-hop, so an attacker naming X-Real-IP (etc.) in their own Connection
// header could otherwise erase the trusted values this Director sets below.
// Passing any of these through unfiltered would let a caller spoof identity,
// the effective request path, method, or scheme on the backend after
// SVALINN already made its own trust decisions for the same request.
//
// ponytail: this is a denylist, not an allowlist -- it needs a new entry
// every time a backend framework's own header convention is discovered.
// Ceiling: fine as long as this list keeps getting extended when found; if
// bypasses via new headers keep recurring, invert to allowlisting only
// SVALINN's own X-Real-IP/X-Forwarded-For/X-Forwarded-Proto and stripping
// everything else in the identity/X-Forwarded-*/X-* control namespace.
func spoofableHeaders() []string {
	return []string{
		"True-Client-IP",
		"CF-Connecting-IP",
		"X-Client-IP",
		"X-Cluster-Client-IP",
		"Client-IP",
		"Forwarded",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-Prefix",
		"X-Original-Host",
		"X-Host",
		"X-Http-Method-Override",
		"X-Forwarded-Scheme",
		"Front-End-Https",
		"Connection",
	}
}

// NewBackendProxy builds a reverse proxy to backendURL.
//
// Callers must register the returned proxy as a route on a router whose
// middleware chain (WAF, DDoS, actor-tracking, deception, ...) already wraps
// it -- this constructor does not add any detection of its own, and forwards
// whatever request it is given.
//
// The default Director's caller-identity headers are overridden with
// SVALINN's own trust-resolved client identity (netutil.TrustedClientIP)
// rather than the request's raw, potentially attacker-forged
// X-Forwarded-For/X-Real-IP, so the backend sees the same validated caller
// SVALINN itself already trusted for its own security decisions. See
// spoofableHeaders for the other headers stripped for the same reason.
func NewBackendProxy(backendURL string, log *logger.Logger) (*httputil.ReverseProxy, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server.backend_url %q: %w", backendURL, err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("server.backend_url %q must use the http or https scheme", backendURL)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("server.backend_url %q must include a host", backendURL)
	}

	rp := httputil.NewSingleHostReverseProxy(target)

	baseDirector := rp.Director
	rp.Director = func(req *http.Request) {
		trusted := netutil.TrustedClientIP(req)
		proto := "http"
		if req.TLS != nil {
			proto = "https"
		}

		baseDirector(req)

		for _, h := range spoofableHeaders() {
			req.Header.Del(h)
		}

		req.Header.Set("X-Real-IP", trusted)
		req.Header.Set("X-Forwarded-For", trusted)
		req.Header.Set("X-Forwarded-Proto", proto)
	}

	// Fail closed on a broken backend connection: log server-side via the
	// project's structured logger and return a generic 502, never the raw
	// dial/transport error (which would otherwise leak the backend's
	// host:port to the caller -- the same infrastructure-topology exposure
	// the honeypot subsystem is careful to avoid).
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Backend proxy request failed", "path", r.URL.Path, "error", err.Error())
		w.WriteHeader(http.StatusBadGateway)
	}

	return rp, nil
}
