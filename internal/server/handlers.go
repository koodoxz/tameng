/*
Package server - HTTP Handlers
*/
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

// calculateDerivedScore computes a risk score from legacy actor data indicators
// Used when the stored riskScore is too low but other indicators suggest malicious behavior
func calculateDerivedScore(actor map[string]interface{}) float64 {
	score := 0.0

	// 1. Status-based scoring (20 points max)
	if status, ok := actor["status"].(string); ok {
		switch status {
		case "BLOCKED":
			score += 20
		case "HOSTILE":
			score += 15
		case "SUSPICIOUS":
			score += 10
		case "RECON":
			score += 5
		}
	}

	// 2. Honeypot triggered (25 points)
	if honeypot, ok := actor["honeypotTriggered"].(bool); ok && honeypot {
		score += 25
	}

	// 3. Behavioral indicators (30 points max)
	if behavior, ok := actor["behavior"].(map[string]interface{}); ok {
		if totalActions, ok := behavior["totalActions"].(float64); ok {
			// High action count is suspicious
			if totalActions > 100 {
				score += 10
			}
			if totalActions > 500 {
				score += 10
			}
			if totalActions > 1000 {
				score += 10
			}
		}
	}

	// 4. Fingerprint diversity (10 points max)
	if fingerprint, ok := actor["fingerprint"].(map[string]interface{}); ok {
		if userAgents, ok := fingerprint["userAgents"].([]interface{}); ok {
			// Multiple user agents = evasion
			if len(userAgents) > 2 {
				score += 5
			}
			if len(userAgents) > 5 {
				score += 5
			}
		}
	}

	// 5. Persistence score (15 points max)
	if persistence, ok := actor["persistenceScore"].(float64); ok {
		score += persistence * 0.15
	}

	// 6. Aggressiveness index (15 points max)
	if aggro, ok := actor["aggressivenessIndex"].(float64); ok {
		score += aggro * 0.15
	}

	return score
}

// handleMalwareBehaviorStats returns malware behavior analyzer stats
func (s *Server) handleMalwareBehaviorStats(w http.ResponseWriter, r *http.Request) {
	if s.malwareBehavior == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Malware behavior analyzer not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.malwareBehavior.Stats(),
	})
}

// handlePayloadSignatureStats returns payload signature generator stats
func (s *Server) handlePayloadSignatureStats(w http.ResponseWriter, r *http.Request) {
	if s.payloadGenerator == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Payload signature generator not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.payloadGenerator.Stats(),
	})
}

// handlePayloadSignatureGenerate generates signatures for provided payload
func (s *Server) handlePayloadSignatureGenerate(w http.ResponseWriter, r *http.Request) {
	if s.payloadGenerator == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Payload signature generator not enabled",
		})
		return
	}

	var payload struct {
		Name    string `json:"name"`
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid JSON payload",
		})
		return
	}
	if payload.Payload == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Payload is required",
		})
		return
	}
	if payload.Name == "" {
		payload.Name = "DynamicPayload"
	}

	signatures := s.payloadGenerator.GenerateFromPayload(payload.Name, payload.Payload)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"signatures": signatures,
	})
}

// handleBusinessLogicStats returns business logic abuse stats
func (s *Server) handleBusinessLogicStats(w http.ResponseWriter, r *http.Request) {
	if s.businessLogic == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Business logic abuse detector not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.businessLogic.Stats(),
	})
}

// handleSemanticPayloadStats returns semantic payload analyzer stats
func (s *Server) handleSemanticPayloadStats(w http.ResponseWriter, r *http.Request) {
	if s.semanticAnalyzer == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Semantic payload analyzer not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.semanticAnalyzer.Stats(),
	})
}

// handleProtocolGuardStats returns protocol guard stats
func (s *Server) handleProtocolGuardStats(w http.ResponseWriter, r *http.Request) {
	if s.protocolGuard == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Protocol guard not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.protocolGuard.Stats(),
	})
}

// handleResponseEncryptStats returns response encryption stats
func (s *Server) handleResponseEncryptStats(w http.ResponseWriter, r *http.Request) {
	if s.responseEncrypt == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Response encryption not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.responseEncrypt.Stats(),
	})
}

// handleProofOfWorkStats returns proof-of-work stats
func (s *Server) handleProofOfWorkStats(w http.ResponseWriter, r *http.Request) {
	if s.powEngine == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Proof-of-work engine not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.powEngine.Stats(),
	})
}

// handleAdvancedEgressStats returns advanced egress stats
func (s *Server) handleAdvancedEgressStats(w http.ResponseWriter, r *http.Request) {
	if s.advancedEgress == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Advanced egress engine not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.advancedEgress.Stats(),
	})
}

// handleAdvancedEgressAlerts returns recent advanced egress alerts
func (s *Server) handleAdvancedEgressAlerts(w http.ResponseWriter, r *http.Request) {
	if s.advancedEgress == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Advanced egress engine not enabled",
		})
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		fmt.Sscanf(raw, "%d", &limit)
	}
	alerts := s.advancedEgress.Alerts(limit)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(alerts),
		"alerts":  alerts,
	})
}

// handleSTIXStats returns STIX engine stats
func (s *Server) handleSTIXStats(w http.ResponseWriter, r *http.Request) {
	if s.stixEngine == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "STIX engine not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.stixEngine.Stats(),
	})
}

// handleSTIXExport exports a STIX bundle
func (s *Server) handleSTIXExport(w http.ResponseWriter, r *http.Request) {
	if s.stixEngine == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "STIX engine not enabled",
		})
		return
	}

	limit := 1000
	if raw := r.URL.Query().Get("limit"); raw != "" {
		fmt.Sscanf(raw, "%d", &limit)
	}

	bundle := s.stixEngine.ExportBundle(limit)
	if bundle == nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "Failed to export STIX bundle",
		})
		return
	}

	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	s.jsonResponse(w, http.StatusOK, bundle)
}

// handleSTIXImport imports a STIX bundle
func (s *Server) handleSTIXImport(w http.ResponseWriter, r *http.Request) {
	if s.stixEngine == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "STIX engine not enabled",
		})
		return
	}

	var payload interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid STIX bundle",
		})
		return
	}

	bundle := s.stixEngine.ParseBundle(payload)
	if bundle == nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Failed to parse STIX bundle",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"bundle":  bundle,
	})
}

// handleTaxiiDiscovery returns TAXII discovery document
func (s *Server) handleTaxiiDiscovery(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"title":       "SVALINN Threat Intel Hub",
		"description": "STIX/TAXII Threat Intelligence Sharing",
		"contact":     "support@example.com",
		"default":     "/taxii/collections/default",
		"api_roots":   []string{"/taxii"},
	})
}

// handleTaxiiCollections returns TAXII collections
func (s *Server) handleTaxiiCollections(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"collections": []map[string]interface{}{
			{
				"id":          "default",
				"title":       "Default Collection",
				"description": "Main indicator collection",
				"can_read":    true,
				"can_write":   true,
				"media_types": []string{"application/stix+json;version=2.1"},
			},
		},
	})
}

// handleTaxiiObjects handles TAXII object collection
func (s *Server) handleTaxiiObjects(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit := 100
		if raw := r.URL.Query().Get("limit"); raw != "" {
			fmt.Sscanf(raw, "%d", &limit)
		}
		if s.stixEngine == nil {
			s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": "STIX engine not enabled",
			})
			return
		}
		bundle := s.stixEngine.ExportBundle(limit)
		if bundle == nil {
			s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
				"error": "Failed to export STIX bundle",
			})
			return
		}
		w.Header().Set("Content-Type", "application/stix+json;version=2.1")
		s.jsonResponse(w, http.StatusOK, bundle)
		return
	}

	if r.Method == http.MethodPost {
		if s.stixEngine == nil {
			s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": "STIX engine not enabled",
			})
			return
		}
		var payload interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error": "Invalid STIX bundle",
			})
			return
		}
		bundle := s.stixEngine.ParseBundle(payload)
		if bundle == nil {
			s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
				"error": "Failed to parse STIX bundle",
			})
			return
		}
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status": "success",
		})
		return
	}

	s.jsonResponse(w, http.StatusMethodNotAllowed, map[string]interface{}{
		"error": "Method not allowed",
	})
}

// handleCountermeasuresStats returns countermeasure statistics
func (s *Server) handleCountermeasuresStats(w http.ResponseWriter, r *http.Request) {
	if s.countermeasures == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Countermeasures not enabled",
		})
		return
	}

	stats := s.countermeasures.Stats()
	actions := s.countermeasures.RecentActions(20)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"stats":   stats,
			"actions": actions,
		},
	})
}

// handleCountermeasuresBlock blocks an IP via countermeasures
func (s *Server) handleCountermeasuresBlock(w http.ResponseWriter, r *http.Request) {
	if s.countermeasures == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Countermeasures not enabled",
		})
		return
	}

	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "IP required",
		})
		return
	}

	result := s.countermeasures.TempBlock(req.IP, req.Reason)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

// handleCountermeasuresUnblock reverses a temporary block
func (s *Server) handleCountermeasuresUnblock(w http.ResponseWriter, r *http.Request) {
	if s.countermeasures == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Countermeasures not enabled",
		})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "IP required",
		})
		return
	}

	if ok := s.countermeasures.ReverseLastBlock(req.IP); !ok {
		s.jsonResponse(w, http.StatusNotFound, map[string]interface{}{
			"error": "No active block found for IP",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Block reversed",
	})
}

// handleCountermeasuresAutoRespond triggers auto-respond logic
func (s *Server) handleCountermeasuresAutoRespond(w http.ResponseWriter, r *http.Request) {
	if s.countermeasures == nil || s.actorTracker == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Countermeasures not available",
		})
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "IP required",
		})
		return
	}

	actorObj := s.actorTracker.Get(req.IP)
	if actorObj == nil {
		s.jsonResponse(w, http.StatusNotFound, map[string]interface{}{
			"error": "Actor not found",
		})
		return
	}

	actions := s.countermeasures.AutoRespond(req.IP, actorObj)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"actions": actions,
	})
}

// handleActiveDefenseStatus returns orchestrator stats
func (s *Server) handleActiveDefenseStatus(w http.ResponseWriter, r *http.Request) {
	if s.activeDefense == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Active defense not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"module":    "ActiveDefenseOrchestrator",
		"version":   "37.0",
		"stats":     s.activeDefense.GetStats(),
		"killChain": s.activeDefense.KillChainStats(),
	})
}

// handleActiveDefenseActors returns active actors and JA3 clusters
func (s *Server) handleActiveDefenseActors(w http.ResponseWriter, r *http.Request) {
	if s.activeDefense == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Active defense not enabled",
		})
		return
	}

	clusters := s.activeDefense.GetJA3Clusters()
	if len(clusters) > 20 {
		clusters = clusters[:20]
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"actors":      s.activeDefense.GetActiveActors(),
		"ja3Clusters": clusters,
	})
}

// handleKillChainTimeline returns kill chain timeline for an IP
func (s *Server) handleKillChainTimeline(w http.ResponseWriter, r *http.Request) {
	if s.activeDefense == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Active defense not enabled",
		})
		return
	}

	vars := mux.Vars(r)
	ip := vars["ip"]
	if ip == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "IP required",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"ip":       ip,
		"timeline": s.activeDefense.GetKillChainTimeline(ip),
	})
}

// handleJA3Clusters returns JA3 clusters
func (s *Server) handleJA3Clusters(w http.ResponseWriter, r *http.Request) {
	if s.activeDefense == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Active defense not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"clusters": s.activeDefense.GetJA3Clusters(),
	})
}

// handleStatus returns unified status for v9 dashboard
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "9.0",
		"modules":   map[string]interface{}{},
	}

	modules := status["modules"].(map[string]interface{})
	if s.behaviorAnalytics != nil {
		modules["behavioralBaseline"] = s.behaviorAnalytics.GetStats()
	}
	if s.mlWAF != nil {
		modules["mlWAF"] = s.mlWAF.Stats()
	}
	if s.malwareBehavior != nil {
		modules["malwareBehavior"] = s.malwareBehavior.Stats()
	}
	if s.payloadGenerator != nil {
		modules["payloadSignature"] = s.payloadGenerator.Stats()
	}
	if s.advancedEgress != nil {
		modules["advancedEgress"] = s.advancedEgress.Stats()
	}
	if s.stixEngine != nil {
		modules["stixIntel"] = s.stixEngine.Stats()
	}
	if s.businessLogic != nil {
		modules["businessLogicAbuse"] = s.businessLogic.Stats()
	}
	if s.semanticAnalyzer != nil {
		modules["semanticPayload"] = s.semanticAnalyzer.Stats()
	}
	if s.protocolGuard != nil {
		modules["protocolGuard"] = s.protocolGuard.Stats()
	}
	if s.responseEncrypt != nil {
		modules["responseEncrypt"] = s.responseEncrypt.Stats()
	}
	if s.powEngine != nil {
		modules["proofOfWork"] = s.powEngine.Stats()
	}
	if s.exploitationDetector != nil {
		modules["exploitationDetector"] = s.exploitationDetector.GetStats()
	}
	if s.evasionDetector != nil {
		modules["evasionDetector"] = s.evasionDetector.GetStats()
	}
	if s.networkAttackDetector != nil {
		modules["networkAttackDetector"] = s.networkAttackDetector.GetStats()
	}
	if s.adAttackDetector != nil {
		modules["adAttackDetector"] = s.adAttackDetector.GetStats()
	}
	if s.attackAnalyzer != nil {
		modules["attackChain"] = map[string]interface{}{
			"stats":         s.attackAnalyzer.Stats(),
			"active_chains": s.attackAnalyzer.GetActiveChains(),
		}
	}
	if s.forecastEngine != nil {
		forecasts, err := s.forecastEngine.LoadForecasts()
		if err == nil {
			modules["attackForecast"] = map[string]interface{}{
				"count": len(forecasts),
			}
		} else {
			modules["attackForecast"] = map[string]interface{}{
				"error": err.Error(),
			}
		}
	}
	if s.activeDefense != nil {
		modules["activeDefense"] = s.activeDefense.GetStats()
	}
	if s.countermeasures != nil {
		modules["countermeasures"] = s.countermeasures.Stats()
	}

	s.jsonResponse(w, http.StatusOK, status)
}

// handleBehavioralBaselineStats returns behavioral baseline stats
func (s *Server) handleBehavioralBaselineStats(w http.ResponseWriter, r *http.Request) {
	if s.behaviorAnalytics == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Behavioral baseline not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    s.behaviorAnalytics.GetStats(),
	})
}

// handleAttackChainStats returns attack chain analyzer stats
func (s *Server) handleAttackChainStats(w http.ResponseWriter, r *http.Request) {
	if s.attackAnalyzer == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Attack chain analyzer not enabled",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"stats":         s.attackAnalyzer.Stats(),
			"active_chains": s.attackAnalyzer.GetActiveChains(),
		},
	})
}

// handleAttackForecast returns forecast summary
func (s *Server) handleAttackForecast(w http.ResponseWriter, r *http.Request) {
	if s.forecastEngine == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Attack forecast not enabled",
		})
		return
	}

	forecasts, err := s.forecastEngine.LoadForecasts()
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"count":     len(forecasts),
		"forecasts": forecasts,
	})
}

// handleTriangulate validates intelligence through triangulation
func (s *Server) handleTriangulate(w http.ResponseWriter, r *http.Request) {
	if s.triangulation == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Triangulation engine not enabled",
		})
		return
	}

	var item map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "Invalid JSON payload",
		})
		return
	}

	result := s.triangulation.Triangulate(item)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    result,
	})
}

// JSON response helper
func (s *Server) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"version": "1.0.0",
		"uptime":  time.Since(s.stats.StartTime).String(),
	})
}

// handleMetrics returns Prometheus-compatible metrics
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.statsLock.RLock()
	defer s.statsLock.RUnlock()

	metrics := `# HELP svalinn_requests_total Total HTTP requests
# TYPE svalinn_requests_total counter
svalinn_requests_total %d

# HELP svalinn_blocked_requests_total Blocked requests
# TYPE svalinn_blocked_requests_total counter
svalinn_blocked_requests_total %d

# HELP svalinn_threats_detected_total Threats detected
# TYPE svalinn_threats_detected_total counter
svalinn_threats_detected_total %d

# HELP svalinn_active_actors Current active actors
# TYPE svalinn_active_actors gauge
svalinn_active_actors %d

# HELP svalinn_uptime_seconds Server uptime
# TYPE svalinn_uptime_seconds gauge
svalinn_uptime_seconds %.2f
`
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(metrics,
		atomic.LoadInt64(&s.stats.TotalRequests),
		atomic.LoadInt64(&s.stats.BlockedRequests),
		atomic.LoadInt64(&s.stats.ThreatsDetected),
		atomic.LoadInt64(&s.stats.ActiveActors),
		time.Since(s.stats.StartTime).Seconds(),
	)))
}

// handleSecurityTxt returns RFC 9116 security.txt
func (s *Server) handleSecurityTxt(w http.ResponseWriter, r *http.Request) {
	securityTxt := `# ᛊᚹᚨᛚᛁᚾᚾ Security Policy

Contact: support@example.com
Expires: 2026-12-31T23:59:59.000Z
Preferred-Languages: en, id
Canonical: https://shield.example.com/.well-known/security.txt
Policy: https://shield.example.com/security-policy

# Vulnerability Disclosure Program

We appreciate security researchers who help us keep SVALINN safe.

## Scope
- shield.example.com (Main WAF)
- intel.example.com (Threat Intelligence - Coming Soon)
- audit.example.com (WAF Audit - Coming Soon)

## Out of Scope
- Social engineering attacks
- DoS/DDoS attacks
- Physical attacks

## Rewards
We offer recognition and potential bounties for valid reports.
Contact us at support@example.com

## Response Times
- Initial Response: 24 hours
- Triage: 72 hours
- Resolution: Varies by severity

# ᛊᚹᚨᛚᛁᚾᚾ - The Shield That Remembers
# Heimdall sees all. The Bifrost records forever.
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(securityTxt))
}

// handleSecurityPolicy returns the security policy markdown
func (s *Server) handleSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	policy := `# ᛊᚹᚨᛛᛁᚾᚾ Vulnerability Disclosure Policy

---

## Disclosure Channel

For identified security vulnerabilities, contact:

**Email:** support@example.com

Include:
- Vulnerability description
- Reproduction steps
- Impact assessment
- Contact information

---

## Scope

### Authorized Testing
- shield.example.com
- API endpoints explicitly documented

### Excluded
- Physical security
- Social engineering
- Denial of service
- Third-party services

---

## Legal Boundaries

Research conducted according to this policy is considered:
- Authorized under applicable laws
- Exempt from DMCA restrictions

We do not pursue legal action against researchers who:
- Follow responsible disclosure
- Avoid data access/modification
- Provide reasonable remediation time

---

## Interaction Notice

All traffic to SVALINN infrastructure is monitored.

Automated scanning, enumeration, or interaction with non-public interfaces may be logged, analyzed, and used for defensive research purposes.

---

## Response

| Phase          | Timeline          |
|----------------|-------------------|
| Acknowledgment | Within 24 hours   |
| Triage         | Within 72 hours   |
| Status Update  | Every 7 days      |
| Resolution     | Varies by severity|

---

## Recognition

Valid reports may receive:
- Public acknowledgment
- Discretionary compensation

---

## Contact

📧 support@example.com

---

*ᛊᚹᚨᛛᛁᚾᚾ*
`
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(policy))
}

// handleStats returns detailed server statistics
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.statsLock.RLock()
	defer s.statsLock.RUnlock()

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"stats": map[string]interface{}{
			"start_time":       s.stats.StartTime,
			"uptime":           time.Since(s.stats.StartTime).String(),
			"total_requests":   atomic.LoadInt64(&s.stats.TotalRequests),
			"blocked_requests": atomic.LoadInt64(&s.stats.BlockedRequests),
			"challenges_sent":  atomic.LoadInt64(&s.stats.ChallengesSent),
			"threats_detected": atomic.LoadInt64(&s.stats.ThreatsDetected),
			"active_actors":    atomic.LoadInt64(&s.stats.ActiveActors),
		},
	})
}

// handleThreats returns recent threats
func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement threat listing from database
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"threats": []interface{}{},
		"message": "Threat listing not yet implemented",
	})
}

// handleActors returns active actors
func (s *Server) handleActors(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement actor listing
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"actors": []interface{}{},
		"count":  atomic.LoadInt64(&s.stats.ActiveActors),
	})
}

// handleConfig returns non-sensitive config info
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"config": map[string]interface{}{
			"waf_enabled":   s.cfg.WAF.Enabled,
			"ddos_enabled":  s.cfg.DDoS.Enabled,
			"actor_enabled": s.cfg.Actor.Enabled,
			"intel_enabled": s.cfg.Intel.Enabled,
			"ml_enabled":    s.cfg.ML.Enabled,
		},
	})
}

// handleReload reloads configuration (God Mode only)
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement hot reload
	s.log.Info("Configuration reload requested", "ip", s.getClientIP(r))
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Configuration reload not yet implemented",
	})
}

// handleBlockIP blocks an IP (God Mode only)
func (s *Server) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP       string `json:"ip"`
		Duration string `json:"duration"`
		Reason   string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body",
		})
		return
	}

	s.log.Info("IP blocked via God Mode",
		"blocked_ip", req.IP,
		"duration", req.Duration,
		"reason", req.Reason,
		"by", s.getClientIP(r),
	)

	// TODO: Implement actual blocking
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("IP %s blocked for %s", req.IP, req.Duration),
	})
}

// handleUnblockIP unblocks an IP (God Mode only)
func (s *Server) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body",
		})
		return
	}

	s.log.Info("IP unblocked via God Mode",
		"unblocked_ip", req.IP,
		"by", s.getClientIP(r),
	)

	// TODO: Implement actual unblocking
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("IP %s unblocked", req.IP),
	})
}

// handleReserseActors returns detailed actor information
func (s *Server) handleReserseActors(w http.ResponseWriter, r *http.Request) {
	if s.reserseTracker == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Reserse tracker not available",
		})
		return
	}

	profiles := s.reserseTracker.GetAllProfiles()
	highThreatOnly := r.URL.Query().Get("high_threat") == "true"

	if highThreatOnly {
		profiles = s.reserseTracker.GetHighThreatProfiles()
	}

	// Convert to JSON-safe format
	response := map[string]interface{}{
		"total":    len(profiles),
		"profiles": make([]map[string]interface{}, 0, len(profiles)),
		"stats":    s.reserseTracker.Stats(),
	}

	for _, profile := range profiles {
		profileData := map[string]interface{}{
			"id":              profile.ID,
			"ips":             profile.IPs,
			"fingerprints":    profile.Fingerprints,
			"user_agents":     profile.UserAgents,
			"session_count":   profile.SessionCount,
			"ttp_profile":     profile.TTPProfile,
			"threat_level":    profile.ThreatLevel,
			"attribution":     profile.Attribution,
			"first_seen":      profile.FirstSeen,
			"last_seen":       profile.LastSeen,
			"timeline_events": len(profile.Timeline),
		}

		response["profiles"] = append(response["profiles"].([]map[string]interface{}), profileData)
	}

	s.jsonResponse(w, http.StatusOK, response)
}

// handleReserseTimeline returns timeline events for a Reserse profile by ID.
func (s *Server) handleReserseTimeline(w http.ResponseWriter, r *http.Request) {
	if s.reserseTracker == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Reserse tracker not available",
		})
		return
	}

	profileID := mux.Vars(r)["id"]
	if profileID == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "missing profile id",
		})
		return
	}

	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		var parsed int
		if _, err := fmt.Sscanf(q, "%d", &parsed); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	profile := s.reserseTracker.GetProfile(profileID)
	if profile == nil {
		s.jsonResponse(w, http.StatusNotFound, map[string]interface{}{
			"error": "profile not found",
		})
		return
	}

	timeline := s.reserseTracker.GetProfileTimeline(profileID, limit)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"profile":     profileID,
		"ip":          profile.IPs,
		"events":      timeline,
		"count":       len(timeline),
		"limit":       limit,
		"threatLevel": profile.ThreatLevel,
	})
}

// handleReserseTimelineByIP returns timeline events for a Reserse profile by IP.
func (s *Server) handleReserseTimelineByIP(w http.ResponseWriter, r *http.Request) {
	if s.reserseTracker == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Reserse tracker not available",
		})
		return
	}

	ip := mux.Vars(r)["ip"]
	if ip == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"error": "missing ip",
		})
		return
	}

	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		var parsed int
		if _, err := fmt.Sscanf(q, "%d", &parsed); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	profile := s.reserseTracker.GetProfileByIP(ip)
	if profile == nil {
		s.jsonResponse(w, http.StatusNotFound, map[string]interface{}{
			"error": "profile not found",
		})
		return
	}

	timeline := s.reserseTracker.GetProfileTimeline(profile.ID, limit)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"profile":     profile.ID,
		"ip":          ip,
		"events":      timeline,
		"count":       len(timeline),
		"limit":       limit,
		"threatLevel": profile.ThreatLevel,
	})
}

// handleReserseGraph returns actor relationship graph
func (s *Server) handleReserseGraph(w http.ResponseWriter, r *http.Request) {
	if s.reserseTracker == nil {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "Reserse tracker not available",
		})
		return
	}

	profiles := s.reserseTracker.GetAllProfiles()
	maxNodes := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		var parsed int
		if _, err := fmt.Sscanf(q, "%d", &parsed); err == nil && parsed > 0 {
			maxNodes = parsed
		}
	}
	if len(profiles) > maxNodes {
		profiles = profiles[:maxNodes]
	}

	nodes := make([]map[string]interface{}, 0, len(profiles))
	edges := make([]map[string]interface{}, 0)

	seen := make(map[string]struct{})
	for _, p := range profiles {
		seen[p.ID] = struct{}{}
		nodes = append(nodes, map[string]interface{}{
			"id":           p.ID,
			"threat_level": p.ThreatLevel,
			"ip_count":     len(p.IPs),
			"fp_count":     len(p.Fingerprints),
			"ttp_count":    len(p.TTPProfile),
			"events":       len(p.Timeline),
			"first_seen":   p.FirstSeen,
			"last_seen":    p.LastSeen,
		})
	}

	// Build correlation edges among included nodes
	added := make(map[string]struct{})
	for _, p := range profiles {
		related := s.reserseTracker.Correlate(p)
		for _, other := range related {
			if other == nil {
				continue
			}
			if _, ok := seen[other.ID]; !ok {
				continue
			}
			key := p.ID + "->" + other.ID
			if _, ok := added[key]; ok {
				continue
			}
			added[key] = struct{}{}
			edges = append(edges, map[string]interface{}{
				"source":     p.ID,
				"target":     other.ID,
				"type":       "correlation",
				"confidence": "high",
			})
		}
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"nodes":    nodes,
		"edges":    edges,
		"total":    len(nodes),
		"edge_cnt": len(edges),
	})
}

// handleObservatoryHTML serves the Observatory HTML page
func (s *Server) handleObservatoryHTML(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SVALINN Observatory - Threat Intelligence Dashboard</title>
    <style>
        :root { --bg: #0a0a0f; --card: #12121a; --accent: #00ff88; --warn: #ff4444; --text: #e0e0e0; --purple: #9b59b6; --blue: #3498db; --orange: #e67e22; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
        .header { text-align: center; margin-bottom: 1.5rem; padding: 1rem; background: linear-gradient(135deg, rgba(0,255,136,0.1), rgba(155,89,182,0.1)); border-radius: 12px; }
        .header h1 { font-size: 2rem; color: var(--accent); text-shadow: 0 0 20px rgba(0,255,136,0.3); }
        .header .rune { font-size: 1.3rem; color: #666; letter-spacing: 0.5rem; }
        .header .subtitle { color: #666; font-size: 0.9rem; margin-top: 0.5rem; }
        .stats { display: grid; grid-template-columns: repeat(6, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; }
        @media (max-width: 900px) { .stats { grid-template-columns: repeat(3, 1fr); } }
        .stat { background: var(--card); border-radius: 10px; padding: 1rem; text-align: center; border: 1px solid #222; transition: transform 0.2s; }
        .stat:hover { transform: translateY(-2px); border-color: var(--accent); }
        .stat .value { font-size: 1.5rem; font-weight: bold; color: var(--accent); }
        .stat.warn .value { color: var(--warn); }
        .stat.purple .value { color: var(--purple); }
        .stat .label { color: #666; font-size: 0.75rem; margin-top: 0.25rem; text-transform: uppercase; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
        .section { background: var(--card); border-radius: 10px; padding: 1rem; border: 1px solid #222; }
        .section h2 { color: var(--accent); margin-bottom: 0.75rem; font-size: 1rem; display: flex; align-items: center; gap: 0.5rem; }
        .section h2 .badge { background: var(--accent); color: #000; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.7rem; }
        .event { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px; margin-bottom: 0.4rem; font-size: 0.85rem; border-left: 3px solid var(--warn); }
        .event.blocked { border-left-color: var(--warn); }
        .event.challenge { border-left-color: var(--orange); }
        .event.honeypot { border-left-color: var(--purple); }
        .event .ip { color: var(--warn); font-family: monospace; font-size: 0.8rem; }
        .event .path { color: #888; font-size: 0.75rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .event .time { color: #555; font-size: 0.7rem; }
        .event .ml { background: var(--purple); color: #fff; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.7rem; }
        .forecast { padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px; margin-bottom: 0.4rem; }
        .forecast .type { color: var(--accent); font-weight: bold; font-size: 0.85rem; }
        .forecast .prediction { color: #888; font-size: 0.75rem; }
        .forecast .bar { height: 4px; background: #333; border-radius: 2px; margin-top: 0.3rem; overflow: hidden; }
        .forecast .bar-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--purple)); border-radius: 2px; }
        .actor { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px; margin-bottom: 0.4rem; }
        .actor .codename { color: var(--warn); font-weight: bold; font-size: 0.9rem; }
        .actor .meta { color: #666; font-size: 0.75rem; }
        .actor .score { background: var(--warn); color: #000; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }
        .footer { text-align: center; color: #333; font-size: 0.75rem; padding: 1rem; }
        .live { display: inline-block; width: 8px; height: 8px; background: var(--accent); border-radius: 50%; animation: pulse 1.5s infinite; margin-right: 0.5rem; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .scroll { max-height: 300px; overflow-y: auto; }
        .scroll::-webkit-scrollbar { width: 4px; }
        .scroll::-webkit-scrollbar-track { background: #111; }
        .scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 2px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="rune">ᛊ ᚹ ᚨ ᛚ ᛁ ᚾ ᚾ</div>
            <h1>SVALINN Observatory</h1>
            <div class="subtitle"><span class="live"></span>Threat Intelligence Dashboard - Real-time Attack Monitoring</div>
        </div>
        <div class="stats">
            <div class="stat warn"><div class="value" id="grayzone">-</div><div class="label">Gray Zone</div></div>
            <div class="stat"><div class="value" id="blocked">-</div><div class="label">Blocked</div></div>
            <div class="stat purple"><div class="value" id="actors">-</div><div class="label">Actors</div></div>
            <div class="stat"><div class="value" id="forecasts">-</div><div class="label">Forecasts</div></div>
            <div class="stat"><div class="value" id="rules">-</div><div class="label">WAF Rules</div></div>
            <div class="stat"><div class="value" id="uptime">-</div><div class="label">Uptime</div></div>
        </div>
        <div class="grid">
            <div class="section">
                <h2>⚡ Gray Zone Events <span class="badge" id="gzCount">0</span></h2>
                <div id="grayEvents" class="scroll">Loading...</div>
            </div>
            <div class="section">
                <h2>📊 ML Threat Forecasts</h2>
                <div id="forecastList" class="scroll">Loading...</div>
            </div>
        </div>
        <div class="grid">
            <div class="section">
                <h2>🎯 Tracked Actors <span class="badge" id="actorCount">0</span></h2>
                <div id="actorList" class="scroll">Loading...</div>
            </div>
            <div class="section">
                <h2>🛡️ Evolved WAF Rules</h2>
                <div id="rulesList" class="scroll">Loading...</div>
        </div>
        <!-- Charts Section -->
        <div class="grid">
            <div class="section">
                <h2>📈 Threat Trends (by Day)</h2>
                <canvas id="trendChart" height="150"></canvas>
            </div>
            <div class="section">
                <h2>🎯 Threat Level Distribution</h2>
                <canvas id="levelChart" height="150"></canvas>
            </div>
        </div>
        <!-- Actor Network Graph -->
        <div class="section">
            <h2>🕸️ Actor Network Graph <span class="badge" id="nodeCount">0</span></h2>
            <div id="networkGraph" style="height:400px;background:#0a0a0f;border-radius:8px;position:relative;overflow:hidden"></div>
        </div>
        <!-- Live Feed -->
        <div class="section">
            <h2><span class="live"></span> Live Attack Feed</h2>
            <div id="liveFeed" class="scroll" style="max-height:150px;font-family:monospace;font-size:0.75rem"></div>
        </div>
        <!-- Export Section -->
        <div class="section" style="text-align:center">
            <h2>📥 Export Data</h2>
            <button onclick="exportCSV()" style="background:var(--accent);color:#000;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;margin:0.25rem">Download CSV</button>
            <button onclick="exportJSON()" style="background:var(--purple);color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;margin:0.25rem">Download JSON</button>
            <button onclick="exportSTIX()" style="background:var(--blue);color:#fff;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer;margin:0.25rem">Export STIX</button>
        </div>
        <div class="footer">SVALINN-GO v1.0 | Shield of Asgard | Updated: <span id="updated">-</span></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
    <script>
        const API_KEY = new URLSearchParams(window.location.search).get('key') || '';
        const headers = API_KEY ? {'X-API-Key': API_KEY} : {};
        let trendChart, levelChart;
        
        async function fetchData(url) {
            try {
                const res = await fetch(url, {headers});
                if (!res.ok) return null;
                return await res.json();
            } catch(e) { return null; }
        }
        
        function formatTime(ts) {
            if (!ts) return '-';
            const d = new Date(ts);
            return d.toLocaleTimeString();
        }
        
        function exportCSV() {
            window.location.href = '/api/v9/export/csv' + (API_KEY ? '?api_key=' + API_KEY : '');
        }
        function exportJSON() {
            window.location.href = '/api/v9/export/json' + (API_KEY ? '?api_key=' + API_KEY : '');
        }
        
        async function initCharts() {
            const trends = await fetchData('/api/v9/trends');
            if (!trends) return;
            
            // Trend Line Chart
            const days = Object.keys(trends.byDay || {}).sort();
            const counts = days.map(d => trends.byDay[d]);
            const ctx1 = document.getElementById('trendChart').getContext('2d');
            trendChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: days.map(d => d.substring(5)),
                    datasets: [{
                        label: 'Threats',
                        data: counts,
                        borderColor: '#00ff88',
                        backgroundColor: 'rgba(0,255,136,0.1)',
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { color: '#222' }, ticks: { color: '#666' } },
                        y: { grid: { color: '#222' }, ticks: { color: '#666' } }
                    }
                }
            });
            
            // Threat Level Doughnut
            const levels = Object.keys(trends.byThreatLevel || {});
            const levelCounts = levels.map(l => trends.byThreatLevel[l]);
            const colors = { HIGH: '#ff4444', MEDIUM: '#e67e22', LOW: '#3498db', CRITICAL: '#9b59b6' };
            const ctx2 = document.getElementById('levelChart').getContext('2d');
            levelChart = new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: levels,
                    datasets: [{
                        data: levelCounts,
                        backgroundColor: levels.map(l => colors[l] || '#666')
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: 'right', labels: { color: '#e0e0e0' } } }
                }
            });
        }
        
        async function refresh() {
            const obs = await fetchData('/api/v9/observatory');
            if (obs) {
                document.getElementById('blocked').textContent = obs.stats?.totalBlocked || 0;
                document.getElementById('uptime').textContent = (obs.stats?.uptimeHours || 0).toFixed(1) + 'h';
            }
            
            const gz = await fetchData('/api/v9/grayzone');
            if (gz) {
                document.getElementById('grayzone').textContent = gz.total || 0;
                document.getElementById('gzCount').textContent = gz.showing || 0;
                const events = (gz.events || []).slice(-15).reverse();
                document.getElementById('grayEvents').innerHTML = events.length ? 
                    events.map(e => {
                        const cls = e.honeypotTriggered ? 'honeypot' : (e.blocked ? 'blocked' : 'challenge');
                        return '<div class="event ' + cls + '">' +
                            '<div><span class="ip">' + (e.ip || '-') + '</span> <span class="path">' + (e.path || '/') + '</span></div>' +
                            '<div><span class="ml">ML:' + (e.mlScore || 0) + '</span> <span class="time">' + formatTime(e.timestamp) + '</span></div>' +
                        '</div>';
                    }).join('') : '<div style="color:#666;text-align:center;padding:1rem">No events</div>';
            }
            
            const fc = await fetchData('/api/v9/forecasts');
            if (fc) {
                document.getElementById('forecasts').textContent = fc.total || 0;
                const types = Object.keys(fc.byType || {});
                document.getElementById('forecastList').innerHTML = types.length ?
                    types.map(t => {
                        const items = fc.byType[t] || [];
                        const latest = items[items.length - 1] || {};
                        const val = (latest.yhat || 0).toFixed(1);
                        const pct = Math.min(100, val * 5);
                        return '<div class="forecast">' +
                            '<div class="type">' + t + '</div>' +
                            '<div class="prediction">Predicted: ' + val + ' (±' + ((latest.yhat_upper - latest.yhat_lower) / 2 || 0).toFixed(1) + ')</div>' +
                            '<div class="bar"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
                        '</div>';
                    }).join('') : '<div style="color:#666;text-align:center;padding:1rem">No forecasts</div>';
            }
            
            const actors = await fetchData('/api/v9/attackers');
            if (actors && actors.memory?.actors) {
                const actorList = Object.values(actors.memory.actors);
                document.getElementById('actors').textContent = actorList.length;
                document.getElementById('actorCount').textContent = actorList.length;
                const sorted = actorList.sort((a,b) => (b.riskScore || 0) - (a.riskScore || 0)).slice(0, 10);
                document.getElementById('actorList').innerHTML = sorted.length ?
                    sorted.map(a => '<div class="actor">' +
                        '<div><span class="codename">' + (a.id || '-').substring(0,15) + '</span><div class="meta">' + (a.status || 'UNKNOWN') + ' | Actions: ' + (a.behavior?.totalActions || 0) + '</div></div>' +
                        '<span class="score">' + (a.riskScore || 0) + '</span>' +
                    '</div>').join('') : '<div style="color:#666;text-align:center;padding:1rem">No actors tracked</div>';
            }
            
            const rules = await fetchData('/api/v9/evolved-rules');
            if (rules) {
                document.getElementById('rules').textContent = rules.ruleCount || 0;
                document.getElementById('rulesList').innerHTML = (rules.rules || []).length ?
                    rules.rules.map(r => '<div class="event">' +
                        '<div><strong>' + (r.name || r.rule_id) + '</strong><div class="path">' + (r.pattern || '-') + '</div></div>' +
                        '<span class="ml">' + (r.action || 'BLOCK') + '</span>' +
                    '</div>').join('') : '<div style="color:#666;text-align:center;padding:1rem">No rules</div>';
            }
            
            document.getElementById('updated').textContent = new Date().toLocaleTimeString();
        }
        
        function exportSTIX() {
            fetchData('/api/v9/grayzone').then(gz => {
                if (!gz) return alert('No data');
                const bundle = {
                    type: 'bundle',
                    id: 'bundle--' + crypto.randomUUID(),
                    objects: (gz.events || []).slice(0, 100).map(e => ({
                        type: 'indicator',
                        spec_version: '2.1',
                        id: 'indicator--' + crypto.randomUUID(),
                        created: e.timestamp,
                        modified: e.timestamp,
                        name: 'Malicious IP: ' + e.ip,
                        pattern: "[ipv4-addr:value = '" + e.ip + "']",
                        pattern_type: 'stix',
                        valid_from: e.timestamp,
                        labels: ['malicious-activity'],
                        confidence: Math.min(100, (e.mlScore || 50)),
                        external_references: [{source_name: 'SVALINN', description: e.reason || 'threat'}]
                    }))
                };
                const blob = new Blob([JSON.stringify(bundle, null, 2)], {type: 'application/json'});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'svalinn_stix_' + new Date().toISOString().split('T')[0] + '.json';
                a.click();
            });
        }
        
        async function initNetworkGraph() {
            const actors = await fetchData('/api/v9/attackers');
            if (!actors?.memory?.actors) return;
            
            const actorList = Object.values(actors.memory.actors);
            document.getElementById('nodeCount').textContent = actorList.length;
            
            const container = document.getElementById('networkGraph');
            const width = container.clientWidth;
            const height = 400;
            
            // Build nodes and links
            const nodes = actorList.slice(0, 30).map((a, i) => ({
                id: a.id || 'actor-' + i,
                risk: a.riskScore || 0,
                actions: a.behavior?.totalActions || 0
            }));
            
            // Create links between actors with similar behavior
            const links = [];
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    if (Math.abs(nodes[i].risk - nodes[j].risk) < 20) {
                        links.push({source: nodes[i].id, target: nodes[j].id});
                    }
                }
            }
            
            const svg = d3.select('#networkGraph').append('svg')
                .attr('width', width).attr('height', height);
            
            const simulation = d3.forceSimulation(nodes)
                .force('link', d3.forceLink(links).id(d => d.id).distance(80))
                .force('charge', d3.forceManyBody().strength(-200))
                .force('center', d3.forceCenter(width/2, height/2));
            
            const link = svg.append('g').selectAll('line').data(links).join('line')
                .attr('stroke', '#333').attr('stroke-opacity', 0.6);
            
            const node = svg.append('g').selectAll('circle').data(nodes).join('circle')
                .attr('r', d => 5 + Math.min(15, d.risk / 10))
                .attr('fill', d => d.risk > 70 ? '#ff4444' : d.risk > 40 ? '#e67e22' : '#3498db')
                .call(d3.drag().on('start', dragstarted).on('drag', dragged).on('end', dragended));
            
            node.append('title').text(d => d.id + ' (Risk: ' + d.risk + ')');
            
            simulation.on('tick', () => {
                link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
                node.attr('cx', d => d.x).attr('cy', d => d.y);
            });
            
            function dragstarted(e) { if (!e.active) simulation.alphaTarget(0.3).restart(); e.subject.fx = e.subject.x; e.subject.fy = e.subject.y; }
            function dragged(e) { e.subject.fx = e.x; e.subject.fy = e.y; }
            function dragended(e) { if (!e.active) simulation.alphaTarget(0); e.subject.fx = null; e.subject.fy = null; }
        }
        
        function updateLiveFeed(events) {
            const feed = document.getElementById('liveFeed');
            const recent = (events || []).slice(-5).reverse();
            feed.innerHTML = recent.map(e => 
                '<div style="color:' + (e.blocked ? '#ff4444' : '#e67e22') + ';padding:2px 0">' +
                '[' + formatTime(e.timestamp) + '] ' + (e.ip || '-') + ' → ' + (e.path || '/').substring(0,40) +
                ' <span style="color:#00ff88">ML:' + (e.mlScore || 0) + '</span></div>'
            ).join('');
        }
        
        initCharts();
        initNetworkGraph();
        refresh();
        setInterval(refresh, 5000);
        setInterval(async () => {
            const gz = await fetchData('/api/v9/grayzone');
            if (gz) updateLiveFeed(gz.events);
        }, 3000);
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// handleObservatoryAPI returns Observatory data as JSON
func (s *Server) handleObservatoryAPI(w http.ResponseWriter, r *http.Request) {
	s.statsLock.RLock()
	defer s.statsLock.RUnlock()

	data := map[string]interface{}{
		"stats": map[string]interface{}{
			"totalThreatsToday": atomic.LoadInt64(&s.stats.ThreatsDetected),
			"totalBlocked":      atomic.LoadInt64(&s.stats.BlockedRequests),
			"totalChallenged":   atomic.LoadInt64(&s.stats.ChallengesSent),
			"activeActors":      atomic.LoadInt64(&s.stats.ActiveActors),
			"avgThreatScore":    0.0,
			"uptimeHours":       time.Since(s.stats.StartTime).Hours(),
		},
		"highlights":   []interface{}{},
		"recentEvents": []interface{}{},
		"lastUpdated":  time.Now().Format(time.RFC3339),
		"version":      "SVALINN-GO v1.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=5")
	s.jsonResponse(w, http.StatusOK, data)
}

// handleNotFound logs and handles 404s with SVALINN rune response
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIP(r)

	// Log potential scanning attempt
	s.log.Warn("Path not found (potential scan)",
		"ip", clientIP,
		"path", r.URL.Path,
		"method", r.Method,
		"user_agent", r.UserAgent(),
	)

	// Return SVALINN shield response with Norse runes
	response := NewShieldResponse("Not Found", true)
	w.Header().Set("X-Svalinn-Shield", "active")
	w.Header().Set("Server", "Rune")
	s.jsonResponse(w, http.StatusNotFound, response)
}

// handleGrayZone returns gray zone events
func (s *Server) handleGrayZone(w http.ResponseWriter, r *http.Request) {
	// Read gray-zone.json from data directory
	dataFile := "/root/data/gray-zone.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to load gray zone data",
		})
		return
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(data, &events); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse gray zone data",
		})
		return
	}

	// Return last 100 events
	start := 0
	if len(events) > 100 {
		start = len(events) - 100
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"total":       len(events),
		"showing":     len(events) - start,
		"events":      events[start:],
		"lastUpdated": time.Now().Format(time.RFC3339),
	})
}

// handleForecasts returns ML threat forecasts
func (s *Server) handleForecasts(w http.ResponseWriter, r *http.Request) {
	dataFile := "/root/data/forecasts/all_forecasts.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to load forecast data",
		})
		return
	}

	var forecasts []map[string]interface{}
	if err := json.Unmarshal(data, &forecasts); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse forecast data",
		})
		return
	}

	// Group by threat type
	byType := make(map[string][]map[string]interface{})
	for _, f := range forecasts {
		threatType, _ := f["threat_type"].(string)
		byType[threatType] = append(byType[threatType], f)
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"total":       len(forecasts),
		"threatTypes": len(byType),
		"forecasts":   forecasts,
		"byType":      byType,
		"source":      "Prophet ML Engine",
		"lastUpdated": time.Now().Format(time.RFC3339),
	})
}

// handleAttackerMemory returns tracked attackers
func (s *Server) handleAttackerMemory(w http.ResponseWriter, r *http.Request) {
	dataFile := "/root/data/attacker-memory.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to load attacker memory",
		})
		return
	}

	var memory map[string]interface{}
	if err := json.Unmarshal(data, &memory); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse attacker memory",
		})
		return
	}

	// Count actors
	actors, _ := memory["actors"].(map[string]interface{})

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"actorCount":  len(actors),
		"memory":      memory,
		"lastUpdated": time.Now().Format(time.RFC3339),
	})
}

// handleEvolvedRules returns custom WAF rules
func (s *Server) handleEvolvedRules(w http.ResponseWriter, r *http.Request) {
	dataFile := "/root/data/evolved-rules.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to load evolved rules",
		})
		return
	}

	var rules []map[string]interface{}
	if err := json.Unmarshal(data, &rules); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse evolved rules",
		})
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"ruleCount":   len(rules),
		"rules":       rules,
		"lastUpdated": time.Now().Format(time.RFC3339),
	})
}

// handleReloadRules hot-reloads evolved rules from file into WAF engine
func (s *Server) handleReloadRules(w http.ResponseWriter, r *http.Request) {
	evolvedRulesPath := "/root/data/evolved-rules.json"

	count, err := s.waf.LoadEvolvedRules(evolvedRulesPath)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to reload rules: " + err.Error(),
		})
		return
	}

	s.log.Info("Reloaded evolved rules", "count", count)
	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     "Rules reloaded successfully",
		"rulesLoaded": count,
		"timestamp":   time.Now().Format(time.RFC3339),
	})
}

// handleExportCSV exports gray zone events as CSV
func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	dataFile := "/root/data/gray-zone.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		http.Error(w, "Failed to load data", http.StatusInternalServerError)
		return
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(data, &events); err != nil {
		http.Error(w, "Failed to parse data", http.StatusInternalServerError)
		return
	}

	// Build CSV
	var csv strings.Builder
	csv.WriteString("timestamp,ip,method,path,mlScore,threatLevel,blocked,reason\n")
	for _, e := range events {
		ts, _ := e["timestamp"].(string)
		ip, _ := e["ip"].(string)
		method, _ := e["method"].(string)
		path, _ := e["path"].(string)
		mlScore, _ := e["mlScore"].(float64)
		threatLevel, _ := e["threatLevel"].(string)
		blocked, _ := e["blocked"].(bool)
		reason, _ := e["reason"].(string)

		// Escape fields with quotes
		path = strings.ReplaceAll(path, "\"", "\"\"")
		reason = strings.ReplaceAll(reason, "\"", "\"\"")

		csv.WriteString(fmt.Sprintf("%s,%s,%s,\"%s\",%.0f,%s,%t,\"%s\"\n",
			ts, ip, method, path, mlScore, threatLevel, blocked, reason))
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=svalinn_grayzone_"+time.Now().Format("20060102")+".csv")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(csv.String()))
}

// handleExportJSON exports all data as JSON
func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	export := make(map[string]interface{})

	// Gray Zone
	if data, err := os.ReadFile("/root/data/gray-zone.json"); err == nil {
		var gz []map[string]interface{}
		json.Unmarshal(data, &gz)
		export["grayZone"] = map[string]interface{}{"count": len(gz), "events": gz}
	}

	// Attackers
	if data, err := os.ReadFile("/root/data/attacker-memory.json"); err == nil {
		var mem map[string]interface{}
		json.Unmarshal(data, &mem)
		export["attackers"] = mem
	}

	// Forecasts
	if data, err := os.ReadFile("/root/data/forecasts/all_forecasts.json"); err == nil {
		var fc []map[string]interface{}
		json.Unmarshal(data, &fc)
		export["forecasts"] = map[string]interface{}{"count": len(fc), "predictions": fc}
	}

	// Rules
	if data, err := os.ReadFile("/root/data/evolved-rules.json"); err == nil {
		var rules []map[string]interface{}
		json.Unmarshal(data, &rules)
		export["evolvedRules"] = map[string]interface{}{"count": len(rules), "rules": rules}
	}

	export["exportedAt"] = time.Now().Format(time.RFC3339)
	export["version"] = "SVALINN-GO v1.0"

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=svalinn_export_"+time.Now().Format("20060102")+".json")
	json.NewEncoder(w).Encode(export)
}

// handleThreatTrends returns aggregated threat data for charting
func (s *Server) handleThreatTrends(w http.ResponseWriter, r *http.Request) {
	dataFile := "/root/data/gray-zone.json"
	data, err := os.ReadFile(dataFile)
	if err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "No data available",
		})
		return
	}

	var events []map[string]interface{}
	if err := json.Unmarshal(data, &events); err != nil {
		s.jsonResponse(w, http.StatusInternalServerError, map[string]interface{}{
			"status": "error",
			"error":  "Failed to parse data",
		})
		return
	}

	// Aggregate by day
	byDay := make(map[string]int)
	byLevel := make(map[string]int)
	byCategory := make(map[string]int)

	for _, e := range events {
		if ts, ok := e["timestamp"].(string); ok && len(ts) >= 10 {
			day := ts[:10]
			byDay[day]++
		}
		if level, ok := e["threatLevel"].(string); ok {
			byLevel[level]++
		}
		if cat, ok := e["category"].(string); ok {
			byCategory[cat]++
		}
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"totalEvents":   len(events),
		"byDay":         byDay,
		"byThreatLevel": byLevel,
		"byCategory":    byCategory,
		"lastUpdated":   time.Now().Format(time.RFC3339),
	})
}

// =============================================================================
// ECOSYSTEM INTEGRATION HANDLERS (MIMIR, HEIMDALL, HERMOD)
// =============================================================================

// DNSEvent represents a threat event from MIMIR or other ecosystem components
type DNSEvent struct {
	Type      string  `json:"type"` // dga, beacon, tunnel, suspicious
	ClientIP  string  `json:"client_ip"`
	Domain    string  `json:"domain"`
	Score     float64 `json:"score"`
	Reason    string  `json:"reason"`
	ActorID   string  `json:"actor_id,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
	Source    string  `json:"source,omitempty"` // mimir, heimdall, hermod
}

// handleDNSEvents receives threat events from ecosystem components (MIMIR, HEIMDALL, etc.)
func (s *Server) handleDNSEvents(w http.ResponseWriter, r *http.Request) {
	var event DNSEvent

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate required fields
	if event.ClientIP == "" || event.Domain == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "client_ip and domain are required",
		})
		return
	}

	// Set defaults
	if event.Source == "" {
		event.Source = r.Header.Get("X-Source")
		if event.Source == "" {
			event.Source = "unknown"
		}
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().Format(time.RFC3339)
	}

	// Log the event
	s.log.Info("DNS threat event received",
		"type", event.Type,
		"client_ip", event.ClientIP,
		"domain", event.Domain,
		"score", event.Score,
		"reason", event.Reason,
		"source", event.Source,
	)

	// Increment threat counter
	atomic.AddInt64(&s.stats.ThreatsDetected, 1)

	// High-score events could trigger auto-blocking
	if event.Score >= 0.8 {
		s.log.Warn("High-risk DNS threat detected",
			"client_ip", event.ClientIP,
			"domain", event.Domain,
			"score", event.Score,
			"source", event.Source,
		)
		// TODO: Auto-block high-risk IPs via WAF
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"message":   "Event received",
		"event_id":  fmt.Sprintf("dns-%d", time.Now().UnixNano()),
		"processed": true,
	})
}

// handleDNSBlocklist returns blocked IPs and domains for ecosystem sync
func (s *Server) handleDNSBlocklist(w http.ResponseWriter, r *http.Request) {
	// Read attacker memory for blocked IPs
	var blockedIPs []map[string]interface{}
	var blockedDomains []map[string]interface{}

	dataFile := "/root/data/attacker-memory.json"
	if data, err := os.ReadFile(dataFile); err == nil {
		var memory map[string]interface{}
		if err := json.Unmarshal(data, &memory); err == nil {
			if actors, ok := memory["actors"].(map[string]interface{}); ok {
				for id, actorData := range actors {
					actor, ok := actorData.(map[string]interface{})
					if !ok {
						continue
					}
					// Include actors with high risk scores
					riskScore, _ := actor["riskScore"].(float64)
					if riskScore >= 70 {
						blockedIPs = append(blockedIPs, map[string]interface{}{
							"value":      id,
							"reason":     fmt.Sprintf("High risk score: %.0f", riskScore),
							"source":     "svalinn",
							"added_at":   actor["firstSeen"],
							"expires_at": actor["lastSeen"], // Will need proper expiry logic
						})
					}
				}
			}
		}
	}

	// Read gray zone for recently blocked domains
	gzFile := "/root/data/gray-zone.json"
	if data, err := os.ReadFile(gzFile); err == nil {
		var events []map[string]interface{}
		if err := json.Unmarshal(data, &events); err == nil {
			domainSet := make(map[string]bool)
			for _, e := range events {
				blocked, _ := e["blocked"].(bool)
				if blocked {
					if host, ok := e["host"].(string); ok && host != "" && !domainSet[host] {
						domainSet[host] = true
						blockedDomains = append(blockedDomains, map[string]interface{}{
							"value":    host,
							"reason":   e["reason"],
							"source":   "svalinn",
							"added_at": e["timestamp"],
						})
					}
				}
			}
		}
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":       "ok",
		"ips":          blockedIPs,
		"domains":      blockedDomains,
		"ip_count":     len(blockedIPs),
		"domain_count": len(blockedDomains),
		"lastUpdated":  time.Now().Format(time.RFC3339),
	})
}

// handleShieldThreats returns threat intelligence feed for tenant shielding
// This is the core of "Intelligence-as-a-Service" - tenants pull this to update their ipset/blocklists
func (s *Server) handleShieldThreats(w http.ResponseWriter, r *http.Request) {
	// Query parameters
	threatType := r.URL.Query().Get("type")    // Optional: filter by type (ddos, bot, scanner)
	minScore := r.URL.Query().Get("min_score") // Optional: minimum threat score (default 50)
	tenantID := r.URL.Query().Get("tenant_id") // Optional: for future multi-tenant tracking

	// Default minimum score - balanced threshold for precision
	minScoreFloat := 50.0
	if minScore != "" {
		fmt.Sscanf(minScore, "%f", &minScoreFloat)
	}

	// Collect high-confidence threat IPs
	var threatIPs []map[string]interface{}
	var threatFingerprints []string

	// Read from attacker memory (high-risk actors)
	amFile := "/root/data/attacker-memory.json"
	if data, err := os.ReadFile(amFile); err == nil {
		var memory map[string]interface{}
		if err := json.Unmarshal(data, &memory); err == nil {
			if actors, ok := memory["actors"].(map[string]interface{}); ok {
				for ip, actorData := range actors {
					actor, ok := actorData.(map[string]interface{})
					if !ok {
						continue
					}

					// Get legacy riskScore or calculate from indicators
					riskScore, _ := actor["riskScore"].(float64)

					// If riskScore is low, calculate from other indicators
					if riskScore < minScoreFloat {
						riskScore = calculateDerivedScore(actor)
					}

					if riskScore < minScoreFloat {
						continue
					}

					// Filter by type if specified
					actorType, _ := actor["type"].(string)
					if threatType != "" && actorType != threatType {
						continue
					}

					threatIPs = append(threatIPs, map[string]interface{}{
						"ip":         ip,
						"score":      riskScore,
						"type":       actorType,
						"ttps":       actor["techniques"],
						"first_seen": actor["firstSeen"],
						"last_seen":  actor["lastSeen"],
						"tenant":     tenantID,
					})

					// Collect fingerprints if available
					if fps, ok := actor["fingerprints"].([]interface{}); ok {
						for _, fp := range fps {
							if fpStr, ok := fp.(string); ok {
								threatFingerprints = append(threatFingerprints, fpStr)
							}
						}
					}
				}
			}
		}
	}

	// Read from gray zone for recently blocked
	gzFile := "/root/data/gray-zone.json"
	if data, err := os.ReadFile(gzFile); err == nil {
		var events []map[string]interface{}
		if err := json.Unmarshal(data, &events); err == nil {
			seenIPs := make(map[string]bool)
			for _, e := range events {
				blocked, _ := e["blocked"].(bool)
				if !blocked {
					continue
				}

				ip, _ := e["ip"].(string)
				if ip == "" || seenIPs[ip] {
					continue
				}
				seenIPs[ip] = true

				score, _ := e["riskScore"].(float64)
				if score < minScoreFloat {
					continue
				}

				threatIPs = append(threatIPs, map[string]interface{}{
					"ip":         ip,
					"score":      score,
					"type":       "grayzone",
					"reason":     e["reason"],
					"first_seen": e["timestamp"],
					"last_seen":  e["timestamp"],
				})
			}
		}
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":       "ok",
		"version":      "1.0.0",
		"ips":          threatIPs,
		"ip_count":     len(threatIPs),
		"fingerprints": threatFingerprints,
		"fp_count":     len(threatFingerprints),
		"generated_at": time.Now().Format(time.RFC3339),
		"ttl_seconds":  600, // Recommended refresh interval
	})
}

// HeimdallReport represents a threat report from HEIMDALL L3/L4 firewall
type HeimdallReport struct {
	NodeID     string  `json:"node_id"`
	IP         string  `json:"ip"`
	ThreatType string  `json:"threat_type"` // port_scan, syn_flood, blocked, brute_force
	Severity   int     `json:"severity"`    // 1-10
	Confidence float64 `json:"confidence"`  // 0.0-1.0
	DetectedAt string  `json:"detected_at"`
	Evidence   string  `json:"evidence"`
}

// handleHeimdallReport receives threat reports from HEIMDALL L3/L4 firewall nodes
// This allows HEIMDALL to contribute its detections back to the SVALINN intelligence hub
func (s *Server) handleHeimdallReport(w http.ResponseWriter, r *http.Request) {
	var report HeimdallReport

	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "Invalid request body: " + err.Error(),
		})
		return
	}

	// Validate required fields
	if report.IP == "" || report.ThreatType == "" {
		s.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"status": "error",
			"error":  "ip and threat_type are required",
		})
		return
	}

	// Set defaults
	if report.NodeID == "" {
		report.NodeID = "unknown"
	}
	if report.DetectedAt == "" {
		report.DetectedAt = time.Now().Format(time.RFC3339)
	}
	if report.Severity == 0 {
		report.Severity = 5 // Default medium severity
	}
	if report.Confidence == 0 {
		report.Confidence = 0.8 // Default high confidence
	}

	// Dedup: skip if same IP+threat_type reported within 5 minutes
	dedupKey := report.IP + ":" + report.ThreatType
	s.heimdallDedupLock.RLock()
	lastSeen, isDuplicate := s.heimdallDedup[dedupKey]
	s.heimdallDedupLock.RUnlock()

	if isDuplicate && time.Since(lastSeen) < 5*time.Minute {
		// Already processed recently - just ack without full processing
		s.log.Debug("HEIMDALL report deduplicated",
			"ip", report.IP,
			"threat_type", report.ThreatType,
			"last_seen_ago", time.Since(lastSeen).String(),
		)
		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":       "ok",
			"message":      "Duplicate report deduplicated",
			"ip":           report.IP,
			"deduplicated": true,
		})
		return
	}

	// Update dedup cache
	s.heimdallDedupLock.Lock()
	s.heimdallDedup[dedupKey] = time.Now()
	// Cleanup old entries (keep cache small)
	for k, t := range s.heimdallDedup {
		if time.Since(t) > 10*time.Minute {
			delete(s.heimdallDedup, k)
		}
	}
	s.heimdallDedupLock.Unlock()

	// Log the event
	s.log.Warn("HEIMDALL threat report received",
		"node_id", report.NodeID,
		"ip", report.IP,
		"threat_type", report.ThreatType,
		"severity", report.Severity,
		"confidence", report.Confidence,
		"evidence", report.Evidence,
	)

	// Increment threat counter
	atomic.AddInt64(&s.stats.ThreatsDetected, 1)

	// Calculate risk score from HEIMDALL data
	riskScore := float64(report.Severity) * 10 * report.Confidence

	// Actually block high-severity threats via countermeasures
	if report.Severity >= 7 && report.Confidence >= 0.7 && s.countermeasures != nil {
		reason := fmt.Sprintf("HEIMDALL %s (severity=%d, confidence=%.1f, evidence=%s)",
			report.ThreatType, report.Severity, report.Confidence, report.Evidence)
		entry := s.countermeasures.TempBlock(report.IP, reason)
		s.log.Warn("HEIMDALL threat auto-blocked via countermeasures",
			"ip", report.IP,
			"threat_type", report.ThreatType,
			"block_level", entry.Level,
			"block_until", entry.Until.Format(time.RFC3339),
		)
	}

	// Update attacker-memory.json with new threat
	dataFile := "/root/data/attacker-memory.json"
	memory := make(map[string]interface{})
	actors := make(map[string]interface{})

	// Read existing data
	if data, err := os.ReadFile(dataFile); err == nil {
		json.Unmarshal(data, &memory)
		if existing, ok := memory["actors"].(map[string]interface{}); ok {
			actors = existing
		}
	}

	// Update or create actor entry
	actor, exists := actors[report.IP].(map[string]interface{})
	if !exists {
		actor = map[string]interface{}{
			"id":        report.IP,
			"firstSeen": report.DetectedAt,
			"lastSeen":  report.DetectedAt,
			"status":    "HOSTILE",
			"riskScore": riskScore,
			"source":    "heimdall",
			"behavior": map[string]interface{}{
				"totalActions":  1,
				"actionsByType": map[string]interface{}{report.ThreatType: 1},
			},
			"timeline": []interface{}{},
		}
	} else {
		// Update existing actor
		actor["lastSeen"] = report.DetectedAt
		if existingScore, ok := actor["riskScore"].(float64); ok {
			if riskScore > existingScore {
				actor["riskScore"] = riskScore
			}
		}
		// Increment action count
		if behavior, ok := actor["behavior"].(map[string]interface{}); ok {
			if total, ok := behavior["totalActions"].(float64); ok {
				behavior["totalActions"] = total + 1
			}
			if byType, ok := behavior["actionsByType"].(map[string]interface{}); ok {
				if count, ok := byType[report.ThreatType].(float64); ok {
					byType[report.ThreatType] = count + 1
				} else {
					byType[report.ThreatType] = 1.0
				}
			}
		}
		// Escalate status if high severity
		if report.Severity >= 7 {
			actor["status"] = "BLOCKED"
		}
	}

	// Add timeline entry
	timelineEntry := map[string]interface{}{
		"timestamp": report.DetectedAt,
		"action":    strings.ToUpper(report.ThreatType),
		"details": map[string]interface{}{
			"source":     "heimdall",
			"node_id":    report.NodeID,
			"evidence":   report.Evidence,
			"severity":   report.Severity,
			"confidence": report.Confidence,
		},
		"severity": "HIGH",
	}
	if timeline, ok := actor["timeline"].([]interface{}); ok {
		// Keep last 50 entries
		if len(timeline) >= 50 {
			timeline = timeline[len(timeline)-49:]
		}
		actor["timeline"] = append(timeline, timelineEntry)
	} else {
		actor["timeline"] = []interface{}{timelineEntry}
	}

	// Save updated actor
	actors[report.IP] = actor
	memory["actors"] = actors
	memory["lastUpdated"] = time.Now().Format(time.RFC3339)

	// Write back to file
	if data, err := json.MarshalIndent(memory, "", "  "); err == nil {
		os.WriteFile(dataFile, data, 0644)
	}

	s.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"message":    "Threat report received",
		"report_id":  fmt.Sprintf("hdl-%d", time.Now().UnixNano()),
		"ip":         report.IP,
		"risk_score": riskScore,
		"processed":  true,
	})
}
