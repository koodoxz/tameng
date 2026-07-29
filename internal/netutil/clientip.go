// Package netutil holds small, dependency-free network helpers shared by the
// SVALINN detection subsystems.
//
// It imports nothing from this repository (standard library only), so it can sit
// below every internal package without creating an import cycle -- in particular
// below internal/server, which already imports the detection packages that need
// this helper.
package netutil

import (
	"net"
	"net/http"
	"strings"
)

// TrustedClientIP derives the client address that may safely be used as a
// security identity: rate-limit bucket, actor-tracking key, GeoIP argument,
// behavioural/ML baseline key and whitelist comparison.
//
// Production nginx fronts SVALINN with
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//	proxy_set_header X-Real-IP       $remote_addr;
//
// $proxy_add_x_forwarded_for APPENDS the real peer to whatever the client
// already sent. The FIRST X-Forwarded-For element is therefore fully
// attacker-controlled and must never be trusted (REQ SVALINN-CLIENTIP-SPOOF-002).
// X-Real-IP is set from nginx's own $remote_addr and is overwritten on every
// hop, so the client cannot forge it; the LAST X-Forwarded-For element carries
// that same nginx-appended value and is used as a fallback.
//
// Headers are only consulted when the direct TCP peer is loopback (i.e. the
// local nginx); a direct remote connection is judged on its real peer address
// alone. A header value that is not a parseable IP is ignored rather than
// propagated, so the result is always a usable address for the lookups, map keys
// and rate-limit buckets downstream.
//
// This is the shared port of the resolver proven in internal/server
// (REQ SVALINN-CLIENTIP-SPOOF-001); the trust logic is identical.
func TrustedClientIP(r *http.Request) string {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Only a loopback peer (the local nginx reverse proxy) may speak for another IP.
	if !isLoopbackIP(remoteIP) {
		return remoteIP
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(xri) != nil {
		return xri
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
			return last
		}
	}

	return remoteIP
}

// isLoopbackIP reports whether ip is a loopback address (127.0.0.0/8, ::1, or
// the IPv4-mapped form of either).
func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}
