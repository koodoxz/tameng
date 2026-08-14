/*
Package server - Threat Intel Hub (intel.Hub) request-path wiring.

REQ SVALINN-INTEL-HUB-WIRE-001: intel.Hub's IOC blocklist (IsBlockedIP,
IsBlockedDomain) was fully built but had zero callers anywhere -- this file
wires it into the middleware chain and adds a God-Mode population API.

The blocklist is in-memory only (Hub has no persistence layer) -- unlike
countermeasures.blockedIPs (see SVALINN-COUNTERMEASURES-RESTART-PERSIST-001),
every IOC is lost on restart. This is currently accepted as-is: it doubles as
the only recovery path if an operator's own IP ever gets IOC'd (see the
intelHubSafePath* exemptions below for the other half of that recovery path).
*/
package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/koodoxz/tameng/internal/intel"
)

// intelHubSafePath and intelHubSafePathPrefix are exempt from IOC blocking.
// Without this, an operator whose own IP becomes IOC'd (deliberately or by
// mistake) has no way back in -- godModeMiddleware auth on
// /api/v9/intel/unblock still applies, this only skips the earlier IOC gate
// so a valid key can still reach it. /health is exempt because the Docker
// HEALTHCHECK (wget --spider http://localhost:10000/health, see Dockerfile)
// running from inside the same container would otherwise trip on an IOC'd
// loopback/hostname entry and cascade into a restart loop.
const (
	intelHubSafePath       = "/health"
	intelHubSafePathPrefix = "/api/v9/intel/"
)

// normalizeIP parses and canonicalizes an IP address so equivalent textual
// forms (IPv4-mapped IPv6, expanded vs. compressed IPv6) compare equal on
// both the write side (AddIOC/RemoveIOC) and the read side (the middleware's
// lookup) -- mirrors the same net.ParseIP-based convention already used by
// isEcosystemIPAllowed. Rejects CIDR ranges and unparseable input; this Hub
// only ever matches single addresses.
func normalizeIP(value string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

// normalizeDomain canonicalizes a Host header or operator-supplied domain so
// case, port, and trailing-dot differences can't bypass the blocklist.
func normalizeDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

// intelHubMiddleware blocks requests whose client IP or Host header matches
// an indicator of compromise in the threat-intel Hub.
func (s *Server) intelHubMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.intelHub == nil {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Path == intelHubSafePath || strings.HasPrefix(r.URL.Path, intelHubSafePathPrefix) {
			next.ServeHTTP(w, r)
			return
		}

		if ip, ok := normalizeIP(s.getClientIP(r)); ok {
			if ioc, blocked := s.intelHub.IsBlockedIP(ip); blocked {
				s.blockOnIOC(w, r, ioc)
				return
			}
		}

		if ioc, blocked := s.intelHub.IsBlockedDomain(normalizeDomain(r.Host)); blocked {
			s.blockOnIOC(w, r, ioc)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// blockOnIOC responds with a deliberately vague body -- matching
// countermeasuresMiddleware's convention -- so an unauthenticated caller
// can't enumerate blocklist contents (ioc_type/threat_level/source) by
// probing IPs or Host headers. Detail goes server-side only.
func (s *Server) blockOnIOC(w http.ResponseWriter, r *http.Request, ioc *intel.IOC) {
	atomic.AddInt64(&s.stats.ThreatsDetected, 1)
	atomic.AddInt64(&s.stats.BlockedRequests, 1)
	s.log.Warn("Request blocked by threat intel IOC",
		"ioc_type", ioc.Type,
		"threat_level", ioc.ThreatLevel.String(),
		"source", ioc.Source,
		"client_ip", s.getClientIP(r),
		"path", r.URL.Path,
	)
	s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
		"status":  "blocked",
		"message": "Your access has been temporarily restricted",
	})
}

// parseThreatLevel validates and converts a caller-supplied threat level
// string. Unlike ThreatLevel.String()'s permissive default-to-"unknown"
// behavior (used for display), this is a trust-boundary parse: an
// unrecognized value must be rejected, not silently coerced.
func parseThreatLevel(s string) (intel.ThreatLevel, bool) {
	switch strings.ToLower(s) {
	case "low":
		return intel.ThreatLow, true
	case "medium":
		return intel.ThreatMedium, true
	case "high":
		return intel.ThreatHigh, true
	case "critical":
		return intel.ThreatCritical, true
	default:
		return intel.ThreatUnknown, false
	}
}

// normalizeIOCValue canonicalizes a caller-supplied IOC value according to
// its type, returning ok=false if an "ip" value doesn't parse (CIDR ranges
// included -- this Hub has no range-matching support, so storing one would
// silently never match anything).
func normalizeIOCValue(iocType, value string) (string, bool) {
	if iocType == "ip" {
		return normalizeIP(value)
	}
	return normalizeDomain(value), true
}

// handleIntelBlockIOC adds an indicator of compromise to the threat-intel Hub.
func (s *Server) handleIntelBlockIOC(w http.ResponseWriter, r *http.Request) {
	if s.intelHub == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status": "error",
			"error":  "Threat intel hub not enabled",
		})
		return
	}

	var req struct {
		Type        string   `json:"type"`
		Value       string   `json:"value"`
		ThreatLevel string   `json:"threat_level"`
		Source      string   `json:"source"`
		Tags        []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body",
		})
		return
	}

	if req.Type != "ip" && req.Type != "domain" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  `type must be "ip" or "domain"`,
		})
		return
	}

	if req.Value == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "value required",
		})
		return
	}

	value, ok := normalizeIOCValue(req.Type, req.Value)
	if !ok {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "value is not a valid IP address (CIDR ranges are not supported)",
		})
		return
	}

	level, ok := parseThreatLevel(req.ThreatLevel)
	if !ok {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "threat_level must be one of: low, medium, high, critical",
		})
		return
	}

	now := time.Now()
	s.intelHub.AddIOC(&intel.IOC{
		Type:        req.Type,
		Value:       value,
		ThreatLevel: level,
		Source:      req.Source,
		FirstSeen:   now,
		LastSeen:    now,
		Tags:        req.Tags,
	})

	s.log.Info("IOC added via God Mode",
		"ioc_type", req.Type,
		"ioc_value", value,
		"threat_level", level.String(),
		"by", s.getClientIP(r),
	)

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("%s %s added to threat intel blocklist", req.Type, value),
	})
}

// handleIntelUnblockIOC removes an indicator of compromise from the
// threat-intel Hub.
func (s *Server) handleIntelUnblockIOC(w http.ResponseWriter, r *http.Request) {
	if s.intelHub == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status": "error",
			"error":  "Threat intel hub not enabled",
		})
		return
	}

	var req struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body",
		})
		return
	}

	if req.Type != "ip" && req.Type != "domain" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  `type must be "ip" or "domain"`,
		})
		return
	}

	if req.Value == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "value required",
		})
		return
	}

	value, ok := normalizeIOCValue(req.Type, req.Value)
	if !ok {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "value is not a valid IP address (CIDR ranges are not supported)",
		})
		return
	}

	if ok := s.intelHub.RemoveIOC(req.Type, value); !ok {
		s.jsonResponse(w, http.StatusNotFound, map[string]interface{}{
			"status": "error",
			"error":  "No matching IOC found",
		})
		return
	}

	s.log.Info("IOC removed via God Mode",
		"ioc_type", req.Type,
		"ioc_value", value,
		"by", s.getClientIP(r),
	)

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("%s %s removed from threat intel blocklist", req.Type, value),
	})
}

// handleIntelStats returns threat-intel Hub statistics.
func (s *Server) handleIntelStats(w http.ResponseWriter, r *http.Request) {
	if s.intelHub == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status": "error",
			"error":  "Threat intel hub not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.intelHub.GetIOCStats(),
	})
}
