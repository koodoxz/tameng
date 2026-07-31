/*
Package server - Middleware implementations
*/
package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
	"github.com/koodoxz/tameng/internal/ddos"
	"github.com/koodoxz/tameng/internal/detect"
	"github.com/koodoxz/tameng/internal/egress"
	"github.com/koodoxz/tameng/internal/fingerprint"
	"github.com/koodoxz/tameng/internal/orchestrator"
	"github.com/koodoxz/tameng/internal/waf"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Context keys
type contextKey string

const (
	requestIDKey   contextKey = "requestID"
	startTimeKey   contextKey = "startTime"
	clientIPKey    contextKey = "clientIP"
	fingerprintKey contextKey = "fingerprint"
	signatureKey   contextKey = "payloadSignature"
	logContextKey  contextKey = "logContext"
)

type requestLogContext struct {
	Fingerprint      string
	PayloadSignature map[string]string
	ReserseProfileID string
	WAFSignatures    []string
	WAFReason        string
	WAFSeverity      string
}

func getLogContext(r *http.Request) *requestLogContext {
	if ctxVal := r.Context().Value(logContextKey); ctxVal != nil {
		if logCtx, ok := ctxVal.(*requestLogContext); ok {
			return logCtx
		}
	}
	return nil
}

// Rate limiter storage
var (
	limiters     = make(map[string]*rate.Limiter)
	limiterMutex sync.Mutex
)

// ecosystemBypassMiddleware is the FIRST middleware that completely bypasses ALL other middleware for ecosystem endpoints
// This prevents any middleware from consuming/corrupting the request body for HEIMDALL/MIMIR agents
func (s *Server) ecosystemBypassMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isEcosystemEndpoint(r.URL.Path) {
			// Call the handler directly, bypassing ALL remaining middleware
			next.ServeHTTP(w, r)
			return
		}
		// Not an ecosystem endpoint, continue with middleware chain
		next.ServeHTTP(w, r)
	})
}

// isEcosystemEndpoint checks if path is an ecosystem integration endpoint that should bypass security middleware
func isEcosystemEndpoint(path string) bool {
	// Ecosystem endpoints used by HEIMDALL, MIMIR, and other AEGIS services
	ecosystemPaths := []string{
		"/api/v1/shield/threats",
		"/api/v1/heimdall/report",
		"/api/v1/dns-events",
		"/api/v1/dns-blocklist",
	}
	for _, ep := range ecosystemPaths {
		if path == ep {
			return true
		}
	}
	return false
}

// recoveryMiddleware catches panics and returns 500
func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				s.log.Error("Panic recovered",
					"error", err,
					"stack", string(debug.Stack()),
					"path", r.URL.Path,
				)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) businessLogicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.businessLogic == nil || !s.cfg.BusinessLogic.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		sessionID := r.Header.Get("X-Session-Id")
		result := s.businessLogic.Track(sessionID, r, 0)
		if result != nil && result.Detected {
			atomic.AddInt64(&s.stats.ThreatsDetected, 1)
			if s.cfg.BusinessLogic.Mode == "block" {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":   "blocked",
					"reason":   "business_logic_abuse",
					"severity": result.Severity,
					"reasons":  result.Reasons,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// maxScannedBodyBytes is the size ceiling already forced on every request by
// payloadSignatureMiddleware (PayloadSignature.Enabled is unconditionally
// true, config.go:580-581), so this has always been the real, effective
// upper bound for any request body that must survive JSON decoding
// downstream. REQ SVALINN-BODYSIZE-EARLYGATE-001.
//
// Reduced from 1024*50 to 1024*8 under REQ SVALINN-BODYCAP-REDUCE-001: the
// six body-scanning detector middlewares plus the WAF signature engine cost
// ~110ms/KiB linearly (RATATOSKR round 5, 2026-07-28), and the AC-prefilter
// mitigation (SVALINN-WAFSCAN-ACPREFILTER-001) is fully defeated by an
// adaptive attacker who knows about it -- so the cap itself is the only
// thing bounding worst-case per-request cost. Real production traffic
// showed zero genuine external TAXII/body-heavy requests in a 24h window
// (2026-07-29), so this reduction has no observed functional cost today.
// ponytail: ceiling is 8KiB; if a real external STIX/TAXII integration
// needs bigger bundles, raise this against real traffic data, not a guess.
const maxScannedBodyBytes = 1024 * 8

// bodySizeLimitMiddleware rejects oversized request bodies before any of the
// six body-scanning detector middlewares that follow it in the chain
// (semantic/malware/exploitation/evasion/networkAttack/adAttack) or
// payloadSignatureMiddleware/stixMiddleware/wafMiddleware run. Enforced via
// http.MaxBytesReader so it holds regardless of whether Content-Length is
// present, absent, or lying (chunked transfer encoding).
func (s *Server) bodySizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}

		limited := http.MaxBytesReader(w, r.Body, maxScannedBodyBytes)
		bodyBytes, err := io.ReadAll(limited)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if !errors.As(err, &tooLarge) {
				s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
					"error":   "INVALID_REQUEST_BODY",
					"message": "Failed to read request body",
				})
				return
			}
			s.jsonResponse(w, http.StatusRequestEntityTooLarge, map[string]interface{}{
				"error":     "PAYLOAD_TOO_LARGE",
				"message":   "Request body exceeds the maximum allowed size",
				"max_bytes": maxScannedBodyBytes,
			})
			return
		}
		limited.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		next.ServeHTTP(w, r)
	})
}

func (s *Server) semanticPayloadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.semanticAnalyzer == nil || !s.cfg.SemanticPayload.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			result := s.semanticAnalyzer.Analyze(payload)
			if result == nil || !result.Detected {
				continue
			}
			if result.Score >= s.cfg.SemanticPayload.AlertThreshold {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
			}
			if result.Score >= s.cfg.SemanticPayload.BlockThreshold {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":     "blocked",
					"reason":     "semantic_payload",
					"categories": result.Categories,
					"score":      result.Score,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) protocolGuardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.protocolGuard == nil || !s.cfg.ProtocolGuard.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		violations := s.protocolGuard.CheckRequest(r)
		if len(violations) > 0 && s.cfg.ProtocolGuard.BlockOnViolation {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
				"status":     "blocked",
				"reason":     "protocol_violation",
				"violations": violations,
			})
			return
		}

		if strings.Contains(r.URL.Path, "graphql") {
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024*50))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			query := string(bodyBytes)
			if query != "" {
				violations = append(violations, s.protocolGuard.CheckGraphQL(query)...)
			}
			if len(violations) > 0 && s.cfg.ProtocolGuard.BlockOnViolation {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
					"status":     "blocked",
					"reason":     "graphql_violation",
					"violations": violations,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) responseEncryptMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.responseEncrypt == nil || !s.cfg.ResponseEncrypt.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if !s.responseEncrypt.ShouldProtect(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		capture := newEgressResponseWriter(w, 1024*200)
		next.ServeHTTP(capture, r)
		if capture.passthrough {
			return
		}

		token := s.responseEncrypt.Token()
		body := s.responseEncrypt.Obfuscate(capture.Header().Get("Content-Type"), capture.buffer.Bytes(), token)
		// capture.Header() IS w.Header() -- egressResponseWriter embeds w
		// directly and never overrides Header(), so this Set already lands on
		// the real response; no copy back to w is needed or correct
		// (REQ SVALINN-COPYHEADERS-SELFCOPY-001).
		capture.Header().Set("X-Svalinn-Response-Token", token)
		if capture.status != 0 {
			w.WriteHeader(capture.status)
		}
		_, _ = w.Write(body)
	})
}

func (s *Server) proofOfWorkMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.powEngine == nil || !s.cfg.ProofOfWork.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if !pathMatches(r.URL.Path, s.cfg.ProofOfWork.ProtectedPaths) {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get(s.cfg.ProofOfWork.HeaderToken)
		nonce := r.Header.Get(s.cfg.ProofOfWork.HeaderNonce)
		if token != "" && nonce != "" && s.powEngine.Validate(token, nonce) {
			next.ServeHTTP(w, r)
			return
		}

		token, prefix := s.powEngine.Challenge()
		w.Header().Set(s.cfg.ProofOfWork.HeaderToken, token)
		w.Header().Set("X-Svalinn-PoW-Prefix", prefix)
		w.Header().Set("X-Svalinn-PoW-Difficulty", strconv.Itoa(s.cfg.ProofOfWork.Difficulty))
		s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
			"status":     "challenge",
			"token":      token,
			"prefix":     prefix,
			"difficulty": s.cfg.ProofOfWork.Difficulty,
			"message":    "Proof-of-work required",
		})
	})
}

func (s *Server) malwareBehaviorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.malwareBehavior == nil || !s.cfg.MalwareBehavior.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			result := s.malwareBehavior.Analyze(payload)
			if result == nil || !result.Detected {
				continue
			}
			if result.Confidence >= s.cfg.MalwareBehavior.AlertThreshold {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
				if s.actorTracker != nil {
					s.actorTracker.AddThreat(s.getClientIP(r), "malware_behavior", result.Confidence)
				}
			}
			if result.Confidence >= s.cfg.MalwareBehavior.BlockThreshold || result.Severity == "critical" || result.Severity == "high" {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":     "blocked",
					"reason":     "malware_behavior",
					"family":     result.Family,
					"severity":   result.Severity,
					"confidence": result.Confidence,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) payloadSignatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.payloadGenerator == nil || !s.cfg.PayloadSignature.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		body := ""
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024*50))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			body = strings.TrimSpace(string(bodyBytes))
		}

		if body != "" {
			signatures := s.payloadGenerator.GenerateFromPayload("DynamicPayload", body)
			if logCtx := getLogContext(r); logCtx != nil {
				payloadSig := map[string]string{}
				if signatures.YARA != "" {
					payloadSig["yara"] = signatures.YARA
				}
				if signatures.Sigma != "" {
					payloadSig["sigma"] = signatures.Sigma
				}
				if signatures.Snort != "" {
					payloadSig["snort"] = signatures.Snort
				}
				if len(payloadSig) > 0 {
					logCtx.PayloadSignature = payloadSig
				}
			}
			ctx := context.WithValue(r.Context(), signatureKey, signatures)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) stixMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.stixEngine == nil || !s.cfg.STIX.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		content := strings.Join(payloads, " ")
		matches := s.stixEngine.MatchIndicators(content, s.cfg.STIX.ConfidenceThreshold)
		if len(matches) > 0 {
			atomic.AddInt64(&s.stats.ThreatsDetected, 1)
			if s.cfg.STIX.BlockOnMatch {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":  "blocked",
					"reason":  "stix_indicator",
					"matches": matches,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) advancedEgressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.advancedEgress == nil || !s.cfg.AdvancedEgress.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		capture := newEgressResponseWriter(w, 1024*200)
		next.ServeHTTP(capture, r)

		if capture.passthrough {
			return
		}

		req := egress.Request{
			Hostname: r.Host,
			Path:     r.URL.Path,
			Method:   r.Method,
			IP:       s.getClientIP(r),
			UserID:   r.Header.Get("X-User-Id"),
			Body:     capture.buffer.String(),
			BodySize: capture.buffer.Len(),
		}
		analysis := s.advancedEgress.Analyze(req)
		if !analysis.Allowed {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
				"status":  "blocked",
				"reason":  "advanced_egress",
				"score":   analysis.Score,
				"threats": analysis.Threats,
			})
			return
		}

		// capture.Header() IS w.Header() -- egressResponseWriter embeds w
		// directly and never overrides Header(), so headers the downstream
		// handler set are already on the real response; copying them back
		// onto themselves only duplicated every value (REQ
		// SVALINN-COPYHEADERS-SELFCOPY-001).
		if capture.status != 0 {
			w.WriteHeader(capture.status)
		}
		_, _ = w.Write(capture.buffer.Bytes())
	})
}

func (s *Server) behavioralDetectorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.behaviorDetector == nil || !s.cfg.BehavioralDetect.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints from behavioral detection
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		sessionID := r.Header.Get("X-Session-Id")
		alert := s.behaviorDetector.AnalyzeRequest(r, wrapped.status, wrapped.bytes, sessionID)
		if alert == nil {
			return
		}

		if alert.Score >= s.cfg.BehavioralDetect.BlockScoreThreshold {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			if s.actorTracker != nil {
				s.actorTracker.AddThreat(s.getClientIP(r), "behavioral_detector", alert.Score)
			}
			// REQ SVALINN-BEHAVIOR-DBLWRITE-001: the alert is only evaluated after
			// next.ServeHTTP has run, so the downstream chain has usually already
			// committed a response. Writing the block body onto an already-committed
			// response appends a second top-level JSON document (malformed for strict
			// parsers) and leaks the detector's internal scoring state -- alert ID,
			// exact score and raw window counters -- to an unauthenticated caller,
			// handing them a threshold-evasion oracle. The bookkeeping above stays
			// valid either way; only the HTTP write is suppressed.
			//
			// Overriding an already-sent status is deliberately NOT attempted here:
			// Go honours only the first WriteHeader, and changing that is a larger
			// behaviour change requiring its own REQ.
			if wrapped.wroteHeader {
				return
			}
			s.jsonResponse(wrapped, http.StatusTooManyRequests, map[string]interface{}{
				"status": "blocked",
				"reason": "behavioral_detector",
				"alert":  alert,
			})
			return
		}
	})
}

func (s *Server) exploitationDetectorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.exploitationDetector == nil || !s.cfg.Exploitation.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			result := s.exploitationDetector.Analyze(payload)
			if result == nil || !result.Detected {
				continue
			}
			if result.Confidence >= s.cfg.Exploitation.AlertThreshold {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
				if s.actorTracker != nil {
					s.actorTracker.AddThreat(s.getClientIP(r), "exploitation", result.Confidence)
				}
			}
			if result.Confidence >= s.cfg.Exploitation.BlockThreshold {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":     "blocked",
					"reason":     "exploitation_detector",
					"types":      result.Types,
					"confidence": result.Confidence,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) evasionDetectorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.evasionDetector == nil || !s.cfg.Evasion.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			result := s.evasionDetector.Analyze(payload)
			if result == nil || !result.Detected {
				continue
			}
			if result.Confidence >= s.cfg.Evasion.AlertThreshold {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
				if s.actorTracker != nil {
					s.actorTracker.AddThreat(s.getClientIP(r), "evasion", result.Confidence)
				}
			}
			if result.Confidence >= s.cfg.Evasion.BlockThreshold {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":     "blocked",
					"reason":     "evasion_detector",
					"techniques": result.Techniques,
					"confidence": result.Confidence,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) networkAttackDetectorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.networkAttackDetector == nil || !s.cfg.NetworkAttack.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		clientID := s.getClientIP(r)
		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			state := s.networkAttackDetector.TrackConnection(clientID, payload)
			if state == nil || state.Anomalies == 0 {
				continue
			}
			if float64(state.Anomalies) >= s.cfg.NetworkAttack.AlertThreshold/10 {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
				if s.actorTracker != nil {
					s.actorTracker.AddThreat(clientID, "network_attack", float64(state.Anomalies)*10)
				}
			}
			if float64(state.Anomalies) >= s.cfg.NetworkAttack.BlockThreshold/10 {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":    "blocked",
					"reason":    "network_attack_detector",
					"attacks":   uniqueStrings(state.Attacks),
					"anomalies": state.Anomalies,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) adAttackDetectorMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.adAttackDetector == nil || !s.cfg.ADAttack.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		payloads := collectDetectionSources(r)
		for _, payload := range payloads {
			result := s.adAttackDetector.Analyze(payload)
			if result == nil || !result.Detected {
				continue
			}
			if result.Confidence >= s.cfg.ADAttack.AlertThreshold {
				atomic.AddInt64(&s.stats.ThreatsDetected, 1)
				if s.actorTracker != nil {
					s.actorTracker.AddThreat(s.getClientIP(r), "ad_attack", result.Confidence)
				}
			}
			if result.Confidence >= s.cfg.ADAttack.BlockThreshold || result.Severity == "critical" || result.Severity == "high" {
				atomic.AddInt64(&s.stats.BlockedRequests, 1)
				s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
					"status":     "blocked",
					"reason":     "ad_attack_detector",
					"severity":   result.Severity,
					"attacks":    result.Attacks,
					"confidence": result.Confidence,
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func collectDetectionSources(r *http.Request) []string {
	sources := []string{}
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024*100))
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if len(bodyBytes) > 0 {
			sources = append(sources, string(bodyBytes))
		}
	}

	sources = append(sources, r.URL.Path)
	if r.URL.RawQuery != "" {
		sources = append(sources, r.URL.RawQuery)
	}
	if len(r.Header) > 0 {
		sources = append(sources, headersToString(r.Header))
	}

	return sources
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(values))
	for _, val := range values {
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		unique = append(unique, val)
	}
	return unique
}

func headersToString(headers http.Header) string {
	var builder strings.Builder
	for key, values := range headers {
		builder.WriteString(key)
		builder.WriteString(":")
		for i, value := range values {
			if i > 0 {
				builder.WriteString(",")
			}
			builder.WriteString(value)
		}
		builder.WriteString(";")
	}
	return builder.String()
}

func (s *Server) behavioralBaselineMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.behaviorAnalytics == nil || !s.cfg.Behavioral.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		userID := r.Header.Get("X-User-Id")
		if userID == "" {
			userID = s.getClientIP(r)
		}

		deviceHash, _ := r.Context().Value(fingerprintKey).(string)
		if deviceHash == "" {
			deviceHash = r.UserAgent()
		}

		result := s.behaviorAnalytics.AnalyzeUser(r, userID, deviceHash)
		if result != nil && result.IsAnomaly && result.DeviationScore >= s.cfg.Behavioral.BlockThreshold {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			if s.actorTracker != nil {
				s.actorTracker.AddThreat(userID, "behavioral_anomaly", result.DeviationScore)
			}
			s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"status":  "blocked",
				"reason":  "behavioral_baseline",
				"score":   result.DeviationScore,
				"signals": result.Violations,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) preAttackMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.preAttackDetector == nil {
			next.ServeHTTP(w, r)
			return
		}

		result := s.preAttackDetector.Analyze(r)
		if result != nil && result.RecommendedAction == "BLOCK" {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			if s.actorTracker != nil {
				s.actorTracker.AddThreat(s.getClientIP(r), "preattack", result.Score)
			}
			s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"status":  "blocked",
				"reason":  "pre_attack_detection",
				"score":   result.Score,
				"signals": result.Indicators,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func detectEventType(res *waf.ScanResult) string {
	if res == nil || len(res.Matches) == 0 || res.Matches[0].Signature == nil {
		return "unknown"
	}

	category := res.Matches[0].Signature.Category
	switch category {
	case "scanner", "api_abuse":
		return "scanner"
	case "sqli":
		return "sqli"
	case "xss":
		return "xss"
	case "rce":
		return "rce"
	case "c2":
		return "c2_beacon"
	case "path_traversal":
		return "path_traversal"
	default:
		return category
	}
}

func (s *Server) activeDefenseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.ActiveDefense.Enabled || s.activeDefense == nil {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := s.getClientIP(r)
		result := s.activeDefense.Orchestrate(r, clientIP)
		if result == nil {
			next.ServeHTTP(w, r)
			return
		}

		switch result.Action {
		case string(orchestrator.Block), string(orchestrator.Blackhole), string(orchestrator.Isolate):
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
				"error":  "ACCESS_DENIED",
				"reason": result.Reason,
			})
			return
		case string(orchestrator.Tarpit):
			if result.Delay > 0 {
				time.Sleep(result.Delay)
			}
		case string(orchestrator.Challenge):
			atomic.AddInt64(&s.stats.ChallengesSent, 1)
			s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"error": "Challenge Required",
				"code":  "ACTIVE_DEFENSE_CHALLENGE",
				"token": result.ChallengeToken,
			})
			return
		case string(orchestrator.Honeypot):
			if result.RedirectPath != "" {
				r.URL.Path = result.RedirectPath
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) countermeasuresMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Countermeasures.Enabled || s.countermeasures == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)
		if block, ok := s.countermeasures.IsBlocked(ip); ok {
			s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
				"error":       "ACCESS_DENIED",
				"message":     "Your access has been temporarily restricted",
				"retry_after": int(time.Until(block.Until).Seconds()),
			})
			return
		}

		multiplier := s.countermeasures.ThrottleMultiplier(ip)
		if multiplier > 1 {
			delay := time.Duration((multiplier-1)*1000) * time.Millisecond
			time.Sleep(delay)
		}

		if s.countermeasures.IsIsolated(ip) {
			s.log.Info("Countermeasures isolation", "ip", ip, "path", r.URL.Path)
		}

		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware adds a unique request ID
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		ctx = context.WithValue(ctx, startTimeKey, time.Now())
		ctx = context.WithValue(ctx, clientIPKey, s.getClientIP(r))

		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggingMiddleware logs all requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, status: 200}

		logCtx := &requestLogContext{}
		r = r.WithContext(context.WithValue(r.Context(), logContextKey, logCtx))

		next.ServeHTTP(wrapped, r)

		// Get timing
		startTime, _ := r.Context().Value(startTimeKey).(time.Time)
		duration := time.Since(startTime)

		// Get client IP
		clientIP, _ := r.Context().Value(clientIPKey).(string)

		// Get GeoIP country code
		countryCode := ""
		if s.geoip != nil {
			countryCode = s.geoip.LookupCode(clientIP)
		}

		// Log request with GeoIP
		s.log.Request(r.Method, r.URL.Path, wrapped.status, duration,
			"ip", clientIP,
			"geo", countryCode,
			"user_agent", r.UserAgent(),
			"bytes", wrapped.bytes,
			"fingerprint", logCtx.Fingerprint,
			"payload_signature", logCtx.PayloadSignature,
			"reserse_profile", logCtx.ReserseProfileID,
			"waf_signatures", logCtx.WAFSignatures,
			"waf_reason", logCtx.WAFReason,
			"waf_severity", logCtx.WAFSeverity,
		)

		// Update stats
		atomic.AddInt64(&s.stats.TotalRequests, 1)
	})
}

// securityHeadersMiddleware adds security headers
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Allow inline scripts/styles for Observatory dashboard + Chart.js CDN
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("Server", "SVALINN")

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements per-IP rate limiting
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt ecosystem endpoints from rate limiting
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := s.getClientIP(r)

		// Get or create limiter for this IP
		limiter := s.getLimiter(clientIP)

		if !limiter.Allow() {
			s.log.Warn("Rate limit exceeded", "ip", clientIP)
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getLimiter returns a rate limiter for the given IP
func (s *Server) getLimiter(ip string) *rate.Limiter {
	limiterMutex.Lock()
	defer limiterMutex.Unlock()

	if limiter, exists := limiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(
		rate.Limit(s.cfg.Security.RateLimitRPS),
		s.cfg.Security.RateLimitBurst,
	)
	limiters[ip] = limiter
	return limiter
}

// godModeMiddleware checks for God Mode API key
func (s *Server) godModeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey != s.cfg.Security.GodModeKey {
			s.log.Warn("Unauthorized God Mode access attempt",
				"ip", s.getClientIP(r),
				"path", r.URL.Path,
			)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// apiKeyMiddleware checks for valid API key on protected endpoints
func (s *Server) apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		// Check if API key is valid
		validKey := false
		for _, key := range s.cfg.Security.APIKeys {
			if apiKey == key {
				validKey = true
				break
			}
		}

		// Also allow God Mode key
		if apiKey == s.cfg.Security.GodModeKey {
			validKey = true
		}

		if !validKey {
			s.log.Warn("Unauthorized API access attempt",
				"ip", s.getClientIP(r),
				"path", r.URL.Path,
			)
			s.jsonResponse(w, http.StatusUnauthorized, map[string]interface{}{
				"status": "error",
				"error":  "Unauthorized - Valid API key required",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// reserseAuthMiddleware implements Basic Auth for Reserse endpoints
func (s *Server) reserseAuthMiddleware(next http.Handler) http.Handler {
	expectedUser := s.cfg.Security.ReserseUser
	expectedPass := s.cfg.Security.ResersePass

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Reserse Zone"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Parse Basic Auth
		const prefix = "Basic "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		userMatch := len(credentials) == 2 && subtle.ConstantTimeCompare([]byte(credentials[0]), []byte(expectedUser)) == 1
		passMatch := len(credentials) == 2 && subtle.ConstantTimeCompare([]byte(credentials[1]), []byte(expectedPass)) == 1
		if !userMatch || !passMatch {
			s.log.Warn("Failed Reserse auth", "ip", s.getClientIP(r))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
//
// wroteHeader records whether the response has already been committed to the
// client. It cannot be inferred from status: callers construct this wrapper with
// status pre-seeded to 200, so a zero-value check would always report "committed".
// Middlewares that inspect the response AFTER next.ServeHTTP must consult
// wroteHeader before attempting to write a replacement response
// (REQ SVALINN-BEHAVIOR-DBLWRITE-001).
type responseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.wroteHeader = true
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// net/http implicitly sends a 200 header on the first Write, so any Write
	// commits the response just as surely as an explicit WriteHeader does.
	rw.wroteHeader = true
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += n
	return n, err
}

type egressResponseWriter struct {
	http.ResponseWriter
	status      int
	buffer      *bytes.Buffer
	limit       int
	passthrough bool
}

func newEgressResponseWriter(w http.ResponseWriter, limit int) *egressResponseWriter {
	return &egressResponseWriter{
		ResponseWriter: w,
		buffer:         &bytes.Buffer{},
		limit:          limit,
	}
}

func (erw *egressResponseWriter) WriteHeader(code int) {
	erw.status = code
	if erw.passthrough {
		erw.ResponseWriter.WriteHeader(code)
	}
}

func (erw *egressResponseWriter) Write(b []byte) (int, error) {
	if erw.passthrough {
		return erw.ResponseWriter.Write(b)
	}
	if erw.buffer.Len()+len(b) > erw.limit {
		erw.passthrough = true
		if erw.status != 0 {
			erw.ResponseWriter.WriteHeader(erw.status)
		}
		if erw.buffer.Len() > 0 {
			_, _ = erw.ResponseWriter.Write(erw.buffer.Bytes())
			erw.buffer.Reset()
		}
		return erw.ResponseWriter.Write(b)
	}
	return erw.buffer.Write(b)
}

func pathMatches(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if strings.HasPrefix(path, pattern) {
			return true
		}
	}
	return false
}

func (s *Server) fingerprintMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.fingerprinter == nil {
			next.ServeHTTP(w, r)
			return
		}

		fp := s.fingerprinter.GenerateHTTPFingerprint(r)
		if logCtx := getLogContext(r); logCtx != nil {
			logCtx.Fingerprint = fp.Hash
		}
		ctx := context.WithValue(r.Context(), fingerprintKey, fp.Hash)
		w.Header().Set("X-Fingerprint", fp.Hash)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) actorTrackingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Actor.Enabled || s.actorTracker == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)

		// Enforce existing block first
		if blocked, reason := s.actorTracker.IsBlocked(ip); blocked {
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
				"status": "blocked",
				"reason": reason,
			})
			return
		}

		actorObj := s.actorTracker.Track(ip)
		if actorObj != nil {
			actorObj.RecordUserAgent(r.UserAgent())
			actorObj.RecordPath(r.URL.Path)
			if s.cfg.Countermeasures.Enabled && s.countermeasures != nil && s.cfg.ActiveDefense.AutoEscalate {
				s.countermeasures.AutoRespond(ip, actorObj)
			}
		}

		if s.reserseTracker != nil && s.cfg.Actor.ReserseEnabled {
			fpHash, _ := r.Context().Value(fingerprintKey).(string)

			// Build enriched event description with User-Agent
			description := r.Method + " " + r.URL.Path
			if ua := r.UserAgent(); ua != "" {
				description += " | User-Agent: " + ua
			}

			// Detect header injection patterns
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				if strings.Contains(xff, "127.0.0.1") || strings.Contains(xff, "localhost") {
					description += " | X-Forwarded-For: " + xff + " (header injection)"
				}
			}

			event := actor.TimelineEvent{
				Timestamp:   time.Now(),
				EventType:   "http_request",
				Description: description,
				IP:          ip,
				Path:        r.URL.Path,
				Score:       0,
			}

			if profile := s.reserseTracker.Track(ip, fpHash, event); profile != nil {
				if logCtx := getLogContext(r); logCtx != nil {
					logCtx.ReserseProfileID = profile.ID
				}

				// Track post-block persistence
				if profile.BlocksTriggered > 0 {
					postBlockCount := s.reserseTracker.RecordPostBlockRequest(ip)
					if postBlockCount > 50 {
						s.log.Warn("POST-BLOCK PERSISTENCE DETECTED",
							"ip", ip,
							"path", r.URL.Path,
							"post_block_requests", postBlockCount,
							"profile_id", profile.ID)
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) wafMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.WAF.Enabled || s.waf == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt ecosystem endpoints
		if isEcosystemEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)

		for _, wip := range s.cfg.WAF.WhitelistedIPs {
			if ip == wip {
				next.ServeHTTP(w, r)
				return
			}
		}
		for _, wp := range s.cfg.WAF.WhitelistedPaths {
			if r.URL.Path == wp {
				next.ServeHTTP(w, r)
				return
			}
		}

		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 1024*100))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		if s.mlWAF != nil && s.cfg.MLEnhancedWAF.Enabled {
			mlResult := s.mlWAF.AnalyzeRequest(r, 0, len(bodyBytes), 0, nil)
			if mlResult != nil {
				if mlResult.Score >= s.cfg.MLEnhancedWAF.AlertThreshold {
					atomic.AddInt64(&s.stats.ThreatsDetected, 1)
					if s.log != nil {
						s.log.MLScoreHigh(ip, mlResult.MLScore, mlResult.Score)
					}
				}
				if mlResult.Blocked {
					atomic.AddInt64(&s.stats.BlockedRequests, 1)
					if s.actorTracker != nil {
						s.actorTracker.Block(ip, "ml_waf", 10*time.Minute)
					}
					s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
						"status":   "blocked",
						"reason":   "ml_waf",
						"severity": mlResult.Severity,
						"score":    mlResult.Score,
						"details":  mlResult.Reasons,
					})
					return
				}
			}
		}

		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		res := s.waf.Scan(r.URL.Path, r.URL.RawQuery, string(bodyBytes), headers, r.UserAgent())
		if res == nil || len(res.Matches) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		if logCtx := getLogContext(r); logCtx != nil {
			matched := make([]string, 0, len(res.Matches))
			for _, m := range res.Matches {
				if m.Signature != nil && m.Signature.ID != "" {
					matched = append(matched, m.Signature.ID)
				}
			}
			if len(matched) > 0 {
				logCtx.WAFSignatures = matched
			}
			logCtx.WAFReason = res.Reason
			logCtx.WAFSeverity = res.Severity
		}

		atomic.AddInt64(&s.stats.ThreatsDetected, 1)
		if s.actorTracker != nil {
			s.actorTracker.AddThreat(ip, res.Severity, res.Score)
		}
		if s.attackAnalyzer != nil {
			eventType := detectEventType(res)
			event := detect.AttackEvent{
				Timestamp: time.Now(),
				Type:      eventType,
				Path:      r.URL.Path,
				Payload:   string(bodyBytes),
				Signature: res.Reason,
				Score:     res.Score,
			}
			s.attackAnalyzer.ProcessEvent(ip, event)
		}

		// Gray zone logging for uncertain events
		if s.grayZone != nil && res.Score >= s.cfg.WAF.LogThreshold && res.Score < s.cfg.WAF.BlockThreshold {
			matched := make([]string, 0, len(res.Matches))
			for _, m := range res.Matches {
				if m.Signature != nil {
					matched = append(matched, m.Signature.ID)
				}
			}
			cc := ""
			if s.geoip != nil {
				cc = s.geoip.LookupCode(ip)
			}
			s.grayZone.Add(actor.GrayZoneEntry{
				IP:        ip,
				Method:    r.Method,
				Path:      r.URL.Path,
				Headers:   headers,
				Body:      string(bodyBytes),
				Score:     res.Score,
				Reason:    res.Reason,
				Matched:   matched,
				UserAgent: r.UserAgent(),
				Country:   cc,
			})
		}

		if !res.Blocked {
			next.ServeHTTP(w, r)
			return
		}

		atomic.AddInt64(&s.stats.BlockedRequests, 1)
		if s.actorTracker != nil {
			s.actorTracker.Block(ip, "waf:"+res.Reason, 10*time.Minute)
		}

		s.jsonResponse(w, http.StatusForbidden, map[string]interface{}{
			"status":   "blocked",
			"reason":   res.Reason,
			"severity": res.Severity,
			"score":    res.Score,
		})
	})
}

func (s *Server) ddosMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.DDoS.Enabled || s.ddosEngine == nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := s.getClientIP(r)

		phase, _ := s.ddosEngine.Check(ip)
		switch phase {
		case ddos.PhaseNormal:
			next.ServeHTTP(w, r)
			return
		case ddos.PhaseThrottle:
			time.Sleep(50 * time.Millisecond)
			next.ServeHTTP(w, r)
			return
		case ddos.PhaseChallenge:
			atomic.AddInt64(&s.stats.ChallengesSent, 1)
			ch := fingerprint.GenerateChallenge(4)
			w.Header().Set("X-Svalinn-PoW-Prefix", ch.Prefix)
			w.Header().Set("X-Svalinn-PoW-Difficulty", "4")
			s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"status":     "challenge",
				"challenge":  ch.Prefix,
				"difficulty": ch.Difficulty,
				"message":    "Proof-of-work required",
			})
			return
		case ddos.PhaseBlock:
			atomic.AddInt64(&s.stats.BlockedRequests, 1)
			if s.actorTracker != nil {
				s.actorTracker.Block(ip, "ddos", s.cfg.DDoS.BlockDuration)
			}
			s.jsonResponse(w, http.StatusTooManyRequests, map[string]interface{}{
				"status":  "blocked",
				"message": "DDoS protection active",
			})
			return
		default:
			next.ServeHTTP(w, r)
			return
		}
	})
}
