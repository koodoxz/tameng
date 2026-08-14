/*
Package server implements the SVALINN HTTP/HTTPS server.
*/
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/actor"
	"github.com/koodoxz/tameng/internal/behavior"
	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/countermeasures"
	"github.com/koodoxz/tameng/internal/ddos"
	"github.com/koodoxz/tameng/internal/deception"
	"github.com/koodoxz/tameng/internal/detect"
	"github.com/koodoxz/tameng/internal/egress"
	"github.com/koodoxz/tameng/internal/fingerprint"
	"github.com/koodoxz/tameng/internal/geoip"
	"github.com/koodoxz/tameng/internal/heuristics"
	"github.com/koodoxz/tameng/internal/honeypot"
	"github.com/koodoxz/tameng/internal/intel"
	"github.com/koodoxz/tameng/internal/logger"
	"github.com/koodoxz/tameng/internal/logic"
	"github.com/koodoxz/tameng/internal/malware"
	"github.com/koodoxz/tameng/internal/ml"
	"github.com/koodoxz/tameng/internal/orchestrator"
	"github.com/koodoxz/tameng/internal/payload"
	"github.com/koodoxz/tameng/internal/preattack"
	"github.com/koodoxz/tameng/internal/protocol"
	"github.com/koodoxz/tameng/internal/proxy"
	"github.com/koodoxz/tameng/internal/response"
	"github.com/koodoxz/tameng/internal/security"
	"github.com/koodoxz/tameng/internal/semantic"
	"github.com/koodoxz/tameng/internal/session"
	"github.com/koodoxz/tameng/internal/waf"
	"github.com/gorilla/mux"
)

// Server is the main SVALINN server
type Server struct {
	cfg               *config.Config
	log               *logger.Logger
	router            *mux.Router
	httpServer        *http.Server
	ecosystemHandlers map[string]http.HandlerFunc // Direct handlers for ecosystem endpoints
	tlsServer         *http.Server

	// backendProxy forwards requests SVALINN does not itself serve to the
	// tenant's protected backend (REQ SVALINN-PROXY-BACKEND-001). Nil when
	// server.backend_url is unset -- the catch-all route then falls back to
	// handleNotFound, matching pre-REQ behavior exactly.
	backendProxy *httputil.ReverseProxy

	// WAF Engine
	waf   *waf.Engine
	mlWAF *waf.MLEnhancedEngine

	// GeoIP Reader
	geoip *geoip.Reader

	// ML Engine
	mlEngine *ml.Engine

	// Advanced Security Components
	deceptionLadder  *deception.Ladder
	honeypotEngine   *honeypot.Engine
	heuristicsEngine *heuristics.Engine

	// v9.0 NEW COMPONENTS
	fingerprinter         *fingerprint.Engine
	anomalyDetector       *ml.AnomalyDetector
	sessionGuard          *session.Guard
	behaviorAnalytics     *behavior.Analytics
	behaviorDetector      *behavior.Detector
	exploitationDetector  *detect.ExploitationDetector
	evasionDetector       *detect.EvasionDetector
	networkAttackDetector *detect.NetworkAttackDetector
	adAttackDetector      *detect.ADAttackDetector
	malwareBehavior       *malware.BehaviorAnalyzer
	payloadGenerator      *payload.Generator
	advancedEgress        *egress.Engine
	stixEngine            *intel.STIXEngine
	intelHub              *intel.Hub
	businessLogic         *logic.AbuseDetector
	semanticAnalyzer      *semantic.Analyzer
	protocolGuard         *protocol.Guard
	responseEncrypt       *response.Encryptor
	powEngine             *security.PoWEngine
	preAttackDetector     *preattack.Detector
	attackAnalyzer        *detect.Analyzer
	forecastEngine        *ml.ProphetForecaster
	triangulation         *ml.TriangulationEngine
	reserseTracker        *actor.ReserseTracker
	actorTracker          *actor.Tracker
	ddosEngine            *ddos.Engine
	grayZone              *actor.GrayZone
	activeDefense         *orchestrator.Orchestrator
	countermeasures       *countermeasures.Countermeasures

	// HEIMDALL report dedup cache: key="ip:threat_type" -> last report time
	heimdallDedup     map[string]time.Time
	heimdallDedupLock sync.RWMutex

	// Stats
	stats     *Stats
	statsLock sync.RWMutex

	// Shutdown
	shutdown chan struct{}
}

// Stats holds server statistics
type Stats struct {
	StartTime       time.Time
	TotalRequests   int64
	BlockedRequests int64
	ChallengesSent  int64
	ThreatsDetected int64
	ActiveActors    int64
}

// New creates a new SVALINN server
func New(cfg *config.Config, log *logger.Logger) (*Server, error) {
	if cfg.Security.ReserseUser == "" || cfg.Security.ResersePass == "" {
		return nil, fmt.Errorf("security.reserse_user and security.reserse_pass must be set (empty credentials would allow unauthenticated access to the Reserse zone)")
	}
	if cfg.Security.GodModeKey == "" {
		return nil, fmt.Errorf("security.god_mode_key must be set (an empty value would allow unauthenticated God Mode access)")
	}
	for _, key := range cfg.Security.APIKeys {
		if key == "" {
			return nil, fmt.Errorf("security.api_keys must not contain empty values (an empty entry would allow unauthenticated access to API-key-protected endpoints)")
		}
	}

	// REQ SVALINN-PROXY-BACKEND-001: fail closed on a malformed backend_url at
	// startup rather than silently disabling forwarding or panicking on the
	// first proxied request.
	var backendProxy *httputil.ReverseProxy
	if cfg.Server.BackendURL != "" {
		bp, err := proxy.NewBackendProxy(cfg.Server.BackendURL, log.WithModule("proxy"), cfg.AdvancedEgress.Enabled)
		if err != nil {
			return nil, fmt.Errorf("failed to configure backend proxy: %w", err)
		}
		backendProxy = bp
	}

	// Initialize WAF engine with default signatures
	wafEngine, err := waf.NewEngine("", cfg.WAF.BlockThreshold, cfg.WAF.LogThreshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF engine: %w", err)
	}

	// Load evolved rules from file
	evolvedRulesPath := "data/evolved-rules.json"
	if count, err := wafEngine.LoadEvolvedRules(evolvedRulesPath); err == nil {
		log.Info("Loaded evolved rules", "count", count, "path", evolvedRulesPath)
	} else {
		log.Warn("Could not load evolved rules", "error", err.Error())
	}

	// Initialize GeoIP reader
	var geoipReader *geoip.Reader
	geoipPath := "data/geoip/GeoLite2-Country.mmdb"
	if reader, err := geoip.New(geoipPath); err == nil {
		geoipReader = reader
		log.Info("Loaded GeoIP database", "path", geoipPath)
	} else {
		log.Warn("Could not load GeoIP database", "error", err.Error())
	}

	// Initialize ML Engine
	mlEngine := ml.NewEngine("scripts", "data", true)

	// Initialize Advanced Security Components
	deceptionLadder := deception.NewLadder()
	honeypotEngine := honeypot.NewEngine()
	heuristicsEngine := heuristics.NewEngine()

	// Initialize v9.0+ Components
	fingerprinter := fingerprint.NewEngine()
	anomalyDetector := mlEngine.AnomalyDetector
	sessionGuard := session.NewGuard(session.Config{})
	behaviorAnalytics := behavior.NewAnalytics(behavior.Config{
		Enabled:               cfg.Behavioral.Enabled,
		DeviationThreshold:    cfg.Behavioral.DeviationThreshold,
		MinSamplesForBaseline: cfg.Behavioral.MinSamplesForBaseline,
	})
	behaviorDetector := behavior.NewDetector(behavior.DetectorConfig{
		Enabled:                     cfg.BehavioralDetect.Enabled,
		CleanupInterval:             cfg.BehavioralDetect.CleanupInterval,
		CredentialStuffingThreshold: cfg.BehavioralDetect.CredentialStuffingThreshold,
		APIEnumerationThreshold:     cfg.BehavioralDetect.APIEnumerationThreshold,
		ScrapingThreshold:           cfg.BehavioralDetect.ScrapingThreshold,
		ErrorRateThreshold:          cfg.BehavioralDetect.ErrorRateThreshold,
		AlertScoreThreshold:         cfg.BehavioralDetect.AlertScoreThreshold,
		BlockScoreThreshold:         cfg.BehavioralDetect.BlockScoreThreshold,
		SuspiciousSessionThreshold:  cfg.BehavioralDetect.SuspiciousSessionThreshold,
		TemporalAnomalyThreshold:    cfg.BehavioralDetect.TemporalAnomalyThreshold,
		MaxTrackedEvents:            cfg.BehavioralDetect.MaxTrackedEvents,
		SessionWindow:               cfg.BehavioralDetect.SessionWindow,
		ShortWindow:                 cfg.BehavioralDetect.ShortWindow,
		MediumWindow:                cfg.BehavioralDetect.MediumWindow,
		LongWindow:                  cfg.BehavioralDetect.LongWindow,
	})
	malwareBehavior := malware.NewBehaviorAnalyzer(malware.BehaviorConfig{
		Enabled:          cfg.MalwareBehavior.Enabled,
		ScoringThreshold: cfg.MalwareBehavior.ScoringThreshold,
		AlertThreshold:   cfg.MalwareBehavior.AlertThreshold,
		BlockThreshold:   cfg.MalwareBehavior.BlockThreshold,
	})
	payloadGenerator := payload.NewGenerator(payload.SignatureConfig{
		Enabled:      cfg.PayloadSignature.Enabled,
		YARAEnabled:  cfg.PayloadSignature.YARAEnabled,
		SigmaEnabled: cfg.PayloadSignature.SigmaEnabled,
		SnortEnabled: cfg.PayloadSignature.SnortEnabled,
	})
	advancedEgress := egress.NewEngine(egress.Config{
		Enabled:                 cfg.AdvancedEgress.Enabled,
		BlockedCountries:        cfg.AdvancedEgress.BlockedCountries,
		AllowedCountries:        cfg.AdvancedEgress.AllowedCountries,
		GeofenceMode:            cfg.AdvancedEgress.GeofenceMode,
		VelocityWindow:          cfg.AdvancedEgress.VelocityWindow,
		MaxBytesPerWindow:       cfg.AdvancedEgress.MaxBytesPerWindow,
		MaxRequestsPerWindow:    cfg.AdvancedEgress.MaxRequestsPerWindow,
		VelocitySpikeMultiplier: cfg.AdvancedEgress.VelocitySpikeMultiplier,
		TrustedPackageHosts:     cfg.AdvancedEgress.TrustedPackageHosts,
		MaxEncodedPayloadSize:   cfg.AdvancedEgress.MaxEncodedPayloadSize,
		EntropyThreshold:        cfg.AdvancedEgress.EntropyThreshold,
		PIISecretMode:           cfg.AdvancedEgress.PIISecretMode,
		GenericSecretMode:       cfg.AdvancedEgress.GenericSecretMode,
	})
	stixEngine := intel.NewSTIXEngine(intel.STIXConfig{
		Enabled:             cfg.STIX.Enabled,
		DefaultTLP:          cfg.STIX.DefaultTLP,
		IOCTTL:              cfg.STIX.IOCTTL,
		MaxIndicators:       cfg.STIX.MaxIndicators,
		ConfidenceThreshold: cfg.STIX.ConfidenceThreshold,
		BlockOnMatch:        cfg.STIX.BlockOnMatch,
	})
	businessLogic := logic.NewAbuseDetector(logic.AbuseConfig{
		Enabled:          cfg.BusinessLogic.Enabled,
		Mode:             cfg.BusinessLogic.Mode,
		FlowWindow:       cfg.BusinessLogic.FlowWindow,
		MaxActions:       cfg.BusinessLogic.MaxActions,
		MaxSensitiveHits: cfg.BusinessLogic.MaxSensitiveHits,
		SensitivePaths:   cfg.BusinessLogic.SensitivePaths,
		CleanupInterval:  cfg.BusinessLogic.CleanupInterval,
	})
	semanticAnalyzer := semantic.NewAnalyzer(semantic.AnalyzerConfig{
		Enabled:        cfg.SemanticPayload.Enabled,
		AlertThreshold: cfg.SemanticPayload.AlertThreshold,
		BlockThreshold: cfg.SemanticPayload.BlockThreshold,
	})
	protocolGuard := protocol.NewGuard(&protocol.Config{
		MaxGraphQLDepth:      cfg.ProtocolGuard.MaxGraphQLDepth,
		MaxGraphQLComplexity: cfg.ProtocolGuard.MaxGraphQLComplexity,
		WSRateLimit:          cfg.ProtocolGuard.WSRateLimit,
	})
	responseEncrypt := response.NewEncryptor(response.EncryptConfig{
		Enabled:      cfg.ResponseEncrypt.Enabled,
		ProtectPaths: cfg.ResponseEncrypt.ProtectPaths,
		ExcludePaths: cfg.ResponseEncrypt.ExcludePaths,
		TokenTTL:     cfg.ResponseEncrypt.TokenTTL,
		EncryptHTML:  cfg.ResponseEncrypt.EncryptHTML,
		EncryptJS:    cfg.ResponseEncrypt.EncryptJS,
	})
	powEngine := security.NewPoWEngine(security.PoWConfig{
		Enabled:    cfg.ProofOfWork.Enabled,
		Difficulty: cfg.ProofOfWork.Difficulty,
		TokenTTL:   cfg.ProofOfWork.TokenTTL,
	})
	exploitationDetector := detect.NewExploitationDetector(detect.ExploitationConfig{
		Enabled:             cfg.Exploitation.Enabled,
		HeapSprayThreshold:  cfg.Exploitation.HeapSprayThreshold,
		ROPChainThreshold:   cfg.Exploitation.ROPChainThreshold,
		ShellcodeThreshold:  cfg.Exploitation.ShellcodeThreshold,
		InjectionThreshold:  cfg.Exploitation.InjectionThreshold,
		EscalationThreshold: cfg.Exploitation.EscalationThreshold,
		AlertThreshold:      cfg.Exploitation.AlertThreshold,
		BlockThreshold:      cfg.Exploitation.BlockThreshold,
	})
	evasionDetector := detect.NewEvasionDetector(detect.EvasionConfig{
		Enabled:            cfg.Evasion.Enabled,
		AmsiThreshold:      cfg.Evasion.AmsiThreshold,
		EtwThreshold:       cfg.Evasion.EtwThreshold,
		UnhookingThreshold: cfg.Evasion.UnhookingThreshold,
		SandboxThreshold:   cfg.Evasion.SandboxThreshold,
		SyscallThreshold:   cfg.Evasion.SyscallThreshold,
		ModuleThreshold:    cfg.Evasion.ModuleThreshold,
		TimestampThreshold: cfg.Evasion.TimestampThreshold,
		AlertThreshold:     cfg.Evasion.AlertThreshold,
		BlockThreshold:     cfg.Evasion.BlockThreshold,
	})
	networkAttackDetector := detect.NewNetworkAttackDetector(detect.NetworkAttackConfig{
		Enabled:             cfg.NetworkAttack.Enabled,
		ARPThreshold:        cfg.NetworkAttack.ARPThreshold,
		DNSThreshold:        cfg.NetworkAttack.DNSThreshold,
		SMBThreshold:        cfg.NetworkAttack.SMBThreshold,
		KerberoastThreshold: cfg.NetworkAttack.KerberoastThreshold,
		PoisoningThreshold:  cfg.NetworkAttack.PoisoningThreshold,
		PTXThreshold:        cfg.NetworkAttack.PTXThreshold,
		AlertThreshold:      cfg.NetworkAttack.AlertThreshold,
		BlockThreshold:      cfg.NetworkAttack.BlockThreshold,
		ConnectionTTL:       cfg.NetworkAttack.ConnectionTTL,
	})
	adAttackDetector := detect.NewADAttackDetector(detect.ADAttackConfig{
		Enabled:             cfg.ADAttack.Enabled,
		DCSyncThreshold:     cfg.ADAttack.DCSyncThreshold,
		GoldenThreshold:     cfg.ADAttack.GoldenThreshold,
		SilverThreshold:     cfg.ADAttack.SilverThreshold,
		SkeletonThreshold:   cfg.ADAttack.SkeletonThreshold,
		AdminSDThreshold:    cfg.ADAttack.AdminSDThreshold,
		GPOThreshold:        cfg.ADAttack.GPOThreshold,
		BloodhoundThreshold: cfg.ADAttack.BloodhoundThreshold,
		LDAPThreshold:       cfg.ADAttack.LDAPThreshold,
		AlertThreshold:      cfg.ADAttack.AlertThreshold,
		BlockThreshold:      cfg.ADAttack.BlockThreshold,
	})
	mlWAFEngine, err := waf.NewMLEnhancedEngine(waf.MLEnhancedConfig{
		Enabled:        cfg.MLEnhancedWAF.Enabled,
		ModelPath:      cfg.MLEnhancedWAF.ModelPath,
		AlertThreshold: cfg.MLEnhancedWAF.AlertThreshold,
		BlockThreshold: cfg.MLEnhancedWAF.BlockThreshold,
		MLWeight:       cfg.MLEnhancedWAF.MLWeight,
		AnomalyWeight:  cfg.MLEnhancedWAF.AnomalyWeight,
	}, anomalyDetector, log.WithModule("ml_waf"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ML-enhanced WAF: %w", err)
	}
	preAttackDetector := preattack.NewDetector(preattack.Config{Enabled: true})

	var attackAnalyzer *detect.Analyzer
	if cfg.AttackChain.Enabled {
		attackAnalyzer = detect.NewAnalyzer(&detect.Config{
			ChainTimeout:    cfg.AttackChain.ChainTimeout,
			AlertThreshold:  cfg.AttackChain.AlertThreshold,
			BeaconThreshold: cfg.AttackChain.BeaconThreshold,
		})
	}

	var forecastEngine *ml.ProphetForecaster
	if cfg.AttackForecast.Enabled {
		forecastEngine = ml.NewProphetForecaster("/usr/bin/python3", "data")
		forecastEngine.SetScriptsDir("scripts")
	}

	var triangulationEngine *ml.TriangulationEngine
	if cfg.Triangulation.Enabled {
		triangulationEngine = ml.NewTriangulationEngine(ml.TriangulationConfig{})
	}

	// Initialize Reserse Tracker for cross-IP actor correlation
	reserseTracker := actor.NewReserseTracker(0.7) // 70% similarity threshold
	log.Info("Reserse tracker initialized", "correlation_threshold", 0.7)
	if count, err := reserseTracker.ImportLegacyActorMemory("data/attacker-memory.json"); err != nil {
		log.Warn("Failed to import legacy attacker memory", "error", err)
	} else if count > 0 {
		log.Info("Imported legacy attacker memory into Reserse", "profiles", count)
	}

	var actorTracker *actor.Tracker
	if cfg.Actor.Enabled {
		actorTracker = actor.NewTracker(cfg.Actor.MaxActors, cfg.Actor.PromotionThreshold, cfg.Actor.EvictionInterval)
	}

	var ddosEngine *ddos.Engine
	if cfg.DDoS.Enabled {
		ddosCfg := &ddos.Config{
			EWMAWindow:         cfg.DDoS.EWMAWindow,
			ChallengeThreshold: cfg.DDoS.ThresholdRPS,
			ThrottleThreshold:  cfg.DDoS.ThresholdRPS * 1.25,
			BlockThreshold:     cfg.DDoS.ThresholdRPS * 1.5,
			ChallengeDuration:  cfg.DDoS.ChallengeDuration,
			ThrottleDuration:   cfg.DDoS.ChallengeDuration,
			BlockDuration:      cfg.DDoS.BlockDuration,
			Phase3Enabled:      cfg.DDoS.Phase3Enabled,
			ChallengeEnabled:   cfg.DDoS.ChallengeEnabled,
			ThrottleEnabled:    cfg.DDoS.ThrottleEnabled,
			BlockEnabled:       cfg.DDoS.BlockEnabled,
		}
		ddosEngine = ddos.NewEngine(ddosCfg)
	}

	var grayZone *actor.GrayZone
	if cfg.Actor.Enabled {
		grayZone = actor.NewGrayZone(cfg.Actor.GrayZoneSize, "data/gray-zone.json")
	}

	var activeDefense *orchestrator.Orchestrator
	if cfg.ActiveDefense.Enabled {
		activeDefense = orchestrator.NewOrchestrator(reserseTracker, fingerprinter, orchestrator.Config{
			Enabled:       cfg.ActiveDefense.Enabled,
			AutoEscalate:  cfg.ActiveDefense.AutoEscalate,
			TarpitDelay:   cfg.ActiveDefense.TarpitDelay,
			HoneypotPath:  cfg.ActiveDefense.HoneypotPath,
			BlockDuration: cfg.ActiveDefense.BlockDuration,
		})
	}

	var intelHub *intel.Hub
	if cfg.Intel.Enabled {
		intelHub = intel.NewHub(&intel.Config{
			Enabled:      cfg.Intel.Enabled,
			MITREEnabled: cfg.Intel.MITREEnabled,
			STIXEnabled:  cfg.Intel.STIXEnabled,
			FeedsEnabled: cfg.Intel.FeedsEnabled,
			SyncInterval: cfg.Intel.SyncInterval,
		})
	}

	var countermeasuresEngine *countermeasures.Countermeasures
	if cfg.Countermeasures.Enabled {
		countermeasuresEngine = countermeasures.New(cfg.Countermeasures.ActionLogPath)
		// REQ SVALINN-COUNTERMEASURES-LOG-DURABILITY-001: a corrupted
		// action log degrades to "no restored block state" rather than
		// failing startup (matching the GeoIP/evolved-rules "warn but
		// continue" convention above) -- but it must not go unnoticed,
		// since it means every block active before the crash/restart is
		// gone.
		if err := countermeasuresEngine.LoadError(); err != nil {
			log.Warn("Could not fully load countermeasures action log -- active blocks from before this restart may be lost", "error", err.Error())
		}
	}

	s := &Server{
		cfg:                   cfg,
		log:                   log.WithModule("Server"),
		router:                mux.NewRouter(),
		stats:                 &Stats{StartTime: time.Now()},
		shutdown:              make(chan struct{}),
		ecosystemHandlers:     make(map[string]http.HandlerFunc),
		backendProxy:          backendProxy,
		waf:                   wafEngine,
		mlWAF:                 mlWAFEngine,
		geoip:                 geoipReader,
		mlEngine:              mlEngine,
		deceptionLadder:       deceptionLadder,
		honeypotEngine:        honeypotEngine,
		heuristicsEngine:      heuristicsEngine,
		fingerprinter:         fingerprinter,
		anomalyDetector:       anomalyDetector,
		sessionGuard:          sessionGuard,
		behaviorAnalytics:     behaviorAnalytics,
		behaviorDetector:      behaviorDetector,
		exploitationDetector:  exploitationDetector,
		evasionDetector:       evasionDetector,
		networkAttackDetector: networkAttackDetector,
		adAttackDetector:      adAttackDetector,
		malwareBehavior:       malwareBehavior,
		payloadGenerator:      payloadGenerator,
		advancedEgress:        advancedEgress,
		stixEngine:            stixEngine,
		businessLogic:         businessLogic,
		semanticAnalyzer:      semanticAnalyzer,
		protocolGuard:         protocolGuard,
		responseEncrypt:       responseEncrypt,
		powEngine:             powEngine,
		preAttackDetector:     preAttackDetector,
		attackAnalyzer:        attackAnalyzer,
		forecastEngine:        forecastEngine,
		triangulation:         triangulationEngine,
		reserseTracker:        reserseTracker,
		actorTracker:          actorTracker,
		ddosEngine:            ddosEngine,
		grayZone:              grayZone,
		activeDefense:         activeDefense,
		countermeasures:       countermeasuresEngine,
		intelHub:              intelHub,
		heimdallDedup:         make(map[string]time.Time),
	}

	if s.countermeasures != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.countermeasures.Cleanup()
				case <-s.shutdown:
					return
				}
			}
		}()
	}

	if s.networkAttackDetector != nil {
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.networkAttackDetector.Cleanup()
				case <-s.shutdown:
					return
				}
			}
		}()
	}

	if s.grayZone != nil {
		go grayZoneAutoSave(s.grayZone, 30*time.Second, s.shutdown, s.log)
	}

	// Setup ecosystem handlers FIRST (bypass middleware completely)
	s.setupEcosystemRoutes()

	// Setup middleware chain
	s.setupMiddleware()

	// Setup routes
	s.setupRoutes()

	log.Info("ML Engine initialized", "anomaly", mlEngine != nil && mlEngine.AnomalyDetector != nil, "prophet", mlEngine != nil && mlEngine.Prophet != nil)
	log.Info("Advanced features active", "deception", true, "honeypots", len(honeypot.DefaultTraps), "heuristics", true)

	return s, nil
}

// ServeHTTP implements http.Handler and intercepts ecosystem endpoints BEFORE middleware
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is an ecosystem endpoint - handle directly, bypass ALL middleware
	if handler, ok := s.ecosystemHandlers[r.URL.Path]; ok {
		if r.Method == http.MethodGet || r.Method == http.MethodPost {
			// These endpoints bypass the entire middleware and auth chain, so the
			// source-IP allowlist is their only access control (REQ SVALINN-ECO-AUTH-001).
			clientIP := s.ecosystemClientIP(r)
			if !s.isEcosystemIPAllowed(clientIP) {
				s.log.Warn("Ecosystem endpoint denied: source IP not in allowlist",
					"path", r.URL.Path,
					"method", r.Method,
					"client_ip", clientIP,
					"remote_addr", r.RemoteAddr,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			// Log ecosystem bypass for debugging
			s.log.Debug("Ecosystem endpoint bypass",
				"path", r.URL.Path,
				"method", r.Method,
				"remote_addr", r.RemoteAddr,
			)
			// Serve directly without any middleware
			handler(w, r)
			return
		}
	}
	// Not an ecosystem endpoint, pass to router with full middleware chain
	s.router.ServeHTTP(w, r)
}

// trustedClientIP resolves the address a request may legitimately be attributed
// to. It is the single source of truth for caller identity: every IP-keyed
// security decision in this package (rate limiting, actor threat attribution,
// DDoS escalation, countermeasure and WAF-whitelist checks, honeypot triggers
// and audit logging) as well as the ecosystem allowlist derive from it.
//
// Production nginx fronts SVALINN with
//
//	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//
// which APPENDS the real peer to whatever the client already sent. The FIRST
// X-Forwarded-For element is therefore fully attacker-controlled and must never
// be trusted (REQ SVALINN-CLIENTIP-SPOOF-001). X-Real-IP is set from nginx's own
// $remote_addr and is overwritten on every hop, so the client cannot forge it;
// the LAST X-Forwarded-For element carries that same nginx-appended value and is
// used as a fallback.
//
// Headers are only consulted when the direct TCP peer is loopback (i.e. the
// local nginx); a direct remote connection is judged on its real peer address
// alone. A header value that is not a parseable IP is ignored rather than
// propagated, so the result is always a usable address for the GeoIP lookups,
// map keys and rate-limit buckets downstream.
func trustedClientIP(r *http.Request) string {
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

// ecosystemClientIP derives the caller IP used for the ecosystem allowlist
// check (REQ SVALINN-ECO-AUTH-001). It is kept as a distinct entry point so the
// ecosystem gate -- whose source-IP allowlist is its only access control, since
// it bypasses the entire middleware chain -- can be tightened independently of
// general traffic attribution if that is ever needed.
func (s *Server) ecosystemClientIP(r *http.Request) string {
	return trustedClientIP(r)
}

// isLoopbackIP reports whether ip is a loopback address (127.0.0.0/8, ::1, or
// the IPv4-mapped form of either).
func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// isEcosystemIPAllowed reports whether ip appears in ecosystem.allowed_ips.
//
// Fail-closed: an empty or unset allowlist denies every caller, as does an
// unparseable client IP. Comparison is done on parsed addresses so that
// equivalent textual forms (e.g. "::ffff:10.0.0.1" and "10.0.0.1") match.
// Entries that are not valid IP literals -- including CIDR ranges -- never match.
func (s *Server) isEcosystemIPAllowed(ip string) bool {
	candidate := net.ParseIP(ip)
	if candidate == nil {
		return false
	}

	for _, allowed := range s.cfg.Ecosystem.AllowedIPs {
		if a := net.ParseIP(strings.TrimSpace(allowed)); a != nil && a.Equal(candidate) {
			return true
		}
	}

	return false
}

// setupMiddleware configures the middleware chain
func (s *Server) setupMiddleware() {
	// Recovery middleware (catch panics)
	s.router.Use(s.recoveryMiddleware)

	// Request ID middleware
	s.router.Use(s.requestIDMiddleware)

	// Logging middleware
	s.router.Use(s.loggingMiddleware)

	// Security headers middleware
	s.router.Use(s.securityHeadersMiddleware)

	// Rate limiting middleware
	s.router.Use(s.rateLimitMiddleware)

	// Threat intel Hub middleware (IOC blocklist) -- placed here, not
	// alongside countermeasuresMiddleware further down, because this is a
	// single O(1) map lookup whose verdict depends on nothing any other
	// middleware produces; a confirmed-bad IP/domain shouldn't pay for the
	// ~10 analyzer passes and countermeasures throttle sleep below before
	// being rejected. REQ SVALINN-INTEL-HUB-WIRE-001 review finding.
	s.router.Use(s.intelHubMiddleware)

	// Honeypot middleware
	s.router.Use(s.honeypotMiddleware())

	// Fingerprinting middleware
	s.router.Use(s.fingerprintMiddleware)

	// Behavioral baseline middleware
	s.router.Use(s.behavioralBaselineMiddleware)

	// Behavioral detector middleware
	s.router.Use(s.behavioralDetectorMiddleware)

	// Business logic abuse middleware
	s.router.Use(s.businessLogicMiddleware)

	// Body size limit middleware -- must run before every body-scanning
	// detector below (semantic/malware/exploitation/evasion/
	// networkAttack/adAttack/payloadSignature/stix/waf), so an oversized
	// body is rejected before any of them pay the cost of scanning it.
	// REQ SVALINN-BODYSIZE-EARLYGATE-001.
	s.router.Use(s.bodySizeLimitMiddleware)

	// Semantic payload analyzer middleware
	s.router.Use(s.semanticPayloadMiddleware)

	// Malware behavior analyzer middleware
	s.router.Use(s.malwareBehaviorMiddleware)

	// Exploitation detector middleware
	s.router.Use(s.exploitationDetectorMiddleware)

	// Evasion detector middleware
	s.router.Use(s.evasionDetectorMiddleware)

	// Network attack detector middleware
	s.router.Use(s.networkAttackDetectorMiddleware)

	// AD attack detector middleware
	s.router.Use(s.adAttackDetectorMiddleware)

	// Protocol guard middleware
	s.router.Use(s.protocolGuardMiddleware)

	// Payload signature generator middleware
	s.router.Use(s.payloadSignatureMiddleware)

	// STIX/TAXII indicator matching middleware
	s.router.Use(s.stixMiddleware)

	// Response encryption middleware
	s.router.Use(s.responseEncryptMiddleware)

	// Pre-attack detection middleware
	s.router.Use(s.preAttackMiddleware)

	// Active defense middleware
	s.router.Use(s.activeDefenseMiddleware)

	// Countermeasures middleware
	s.router.Use(s.countermeasuresMiddleware)

	// Actor tracking middleware
	s.router.Use(s.actorTrackingMiddleware)

	// WAF middleware
	s.router.Use(s.wafMiddleware)

	// DDoS middleware
	s.router.Use(s.ddosMiddleware)

	// Proof-of-work middleware
	s.router.Use(s.proofOfWorkMiddleware)

	// Advanced egress middleware
	s.router.Use(s.advancedEgressMiddleware)
}

// setupEcosystemRoutes registers ecosystem integration endpoints that bypass ALL middleware
// These endpoints are used by HEIMDALL, MIMIR, and other AEGIS services
// They bypass all security middleware to prevent interference with legitimate agent traffic
func (s *Server) setupEcosystemRoutes() {
	// Populate direct handlers map for ServeHTTP interception (bypasses middleware)
	s.ecosystemHandlers["/api/v1/shield/threats"] = s.handleShieldThreats
	s.ecosystemHandlers["/api/v1/heimdall/report"] = s.handleHeimdallReport
	s.ecosystemHandlers["/api/v1/dns-events"] = s.handleDNSEvents
	s.ecosystemHandlers["/api/v1/dns-blocklist"] = s.handleDNSBlocklist

	s.log.Info("Ecosystem endpoints registered (middleware bypass)", "count", len(s.ecosystemHandlers))
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Health & Metrics
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/metrics", s.handleMetrics).Methods("GET")

	// .well-known endpoints (public)
	s.router.HandleFunc("/.well-known/security.txt", s.handleSecurityTxt).Methods("GET")
	s.router.HandleFunc("/security.txt", s.handleSecurityTxt).Methods("GET")
	s.router.HandleFunc("/security-policy", s.handleSecurityPolicy).Methods("GET")
	s.router.HandleFunc("/security-policy.md", s.handleSecurityPolicy).Methods("GET")

	// Observatory (Hall of Fame) - Public dashboard
	s.router.HandleFunc("/observatory", s.handleObservatoryHTML).Methods("GET")
	s.router.HandleFunc("/api/v9/observatory", s.handleObservatoryAPI).Methods("GET")

	// Setup honeypot trap routes (BEFORE API routes to catch attackers early)
	s.setupHoneypotRoutes()

	// TAXII endpoints (public reads; write requires an API key -- REQ
	// SVALINN-STIX-AUTH-001. Unauthenticated POST let anyone inject
	// arbitrary STIX indicators, which stixMiddleware later matches against
	// every other request's real content and, when STIX.BlockOnMatch is
	// configured on, uses to block them -- an unauthenticated
	// blocking-DoS/false-positive-injection primitive. Read access (GET) is
	// unchanged and is a separately-tracked, still-open finding, not part
	// of this REQ's scope.)
	s.router.HandleFunc("/taxii", s.handleTaxiiDiscovery).Methods("GET")
	s.router.HandleFunc("/taxii/collections", s.handleTaxiiCollections).Methods("GET")
	s.router.HandleFunc("/taxii/collections/default/objects", s.handleTaxiiObjects).Methods("GET")
	s.router.Handle("/taxii/collections/default/objects", s.apiKeyMiddleware(http.HandlerFunc(s.handleTaxiiObjects))).Methods("POST")

	// API v1 (Protected with API Key)
	// Note: Ecosystem endpoints (/api/v1/shield/threats, /heimdall/report, etc) are registered in setupEcosystemRoutes()
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.apiKeyMiddleware)
	api.HandleFunc("/stats", s.handleStats).Methods("GET")
	api.HandleFunc("/threats", s.handleThreats).Methods("GET")
	api.HandleFunc("/actors", s.handleActors).Methods("GET")
	api.HandleFunc("/config", s.handleConfig).Methods("GET")

	// Protected API v9 (God Mode)
	v9 := s.router.PathPrefix("/api/v9").Subrouter()
	v9.Use(s.godModeMiddleware)
	v9.HandleFunc("/status", s.handleStatus).Methods("GET")
	v9.HandleFunc("/reload", s.handleReload).Methods("POST")
	v9.HandleFunc("/block", s.handleBlockIP).Methods("POST")
	v9.HandleFunc("/unblock", s.handleUnblockIP).Methods("POST")
	v9.HandleFunc("/grayzone", s.handleGrayZone).Methods("GET")
	v9.HandleFunc("/forecasts", s.handleForecasts).Methods("GET")
	v9.HandleFunc("/attackers", s.handleAttackerMemory).Methods("GET")
	v9.HandleFunc("/evolved-rules", s.handleEvolvedRules).Methods("GET")
	v9.HandleFunc("/rules/reload", s.handleReloadRules).Methods("POST")
	v9.HandleFunc("/export/csv", s.handleExportCSV).Methods("GET")
	v9.HandleFunc("/export/json", s.handleExportJSON).Methods("GET")
	v9.HandleFunc("/trends", s.handleThreatTrends).Methods("GET")

	// Phase 3 detection endpoints
	v9.HandleFunc("/behavioral-baseline/stats", s.handleBehavioralBaselineStats).Methods("GET")
	v9.HandleFunc("/attack-chain/stats", s.handleAttackChainStats).Methods("GET")
	v9.HandleFunc("/attack-forecast", s.handleAttackForecast).Methods("GET")
	v9.HandleFunc("/triangulate", s.handleTriangulate).Methods("POST")
	v9.HandleFunc("/malware-behavior/stats", s.handleMalwareBehaviorStats).Methods("GET")
	v9.HandleFunc("/payload-signature/stats", s.handlePayloadSignatureStats).Methods("GET")
	v9.HandleFunc("/payload-signature/generate", s.handlePayloadSignatureGenerate).Methods("POST")
	v9.HandleFunc("/advanced-egress/stats", s.handleAdvancedEgressStats).Methods("GET")
	v9.HandleFunc("/advanced-egress/alerts", s.handleAdvancedEgressAlerts).Methods("GET")
	v9.HandleFunc("/stix/stats", s.handleSTIXStats).Methods("GET")
	v9.HandleFunc("/stix/export", s.handleSTIXExport).Methods("GET")
	v9.HandleFunc("/stix/import", s.handleSTIXImport).Methods("POST")
	v9.HandleFunc("/intel/stats", s.handleIntelStats).Methods("GET")
	v9.HandleFunc("/intel/block", s.handleIntelBlockIOC).Methods("POST")
	v9.HandleFunc("/intel/unblock", s.handleIntelUnblockIOC).Methods("POST")
	v9.HandleFunc("/business-logic/stats", s.handleBusinessLogicStats).Methods("GET")
	v9.HandleFunc("/semantic-payload/stats", s.handleSemanticPayloadStats).Methods("GET")
	v9.HandleFunc("/protocol-guard/stats", s.handleProtocolGuardStats).Methods("GET")
	v9.HandleFunc("/response-encrypt/stats", s.handleResponseEncryptStats).Methods("GET")
	v9.HandleFunc("/proof-of-work/stats", s.handleProofOfWorkStats).Methods("GET")

	// Countermeasures endpoints
	v9.HandleFunc("/countermeasures", s.handleCountermeasuresStats).Methods("GET")
	v9.HandleFunc("/countermeasures/block", s.handleCountermeasuresBlock).Methods("POST")
	v9.HandleFunc("/countermeasures/unblock", s.handleCountermeasuresUnblock).Methods("POST")
	v9.HandleFunc("/countermeasures/auto-respond", s.handleCountermeasuresAutoRespond).Methods("POST")

	// Active Defense endpoints
	v9.HandleFunc("/active-defense/status", s.handleActiveDefenseStatus).Methods("GET")
	v9.HandleFunc("/active-defense/actors", s.handleActiveDefenseActors).Methods("GET")
	v9.HandleFunc("/kill-chain/{ip}/timeline", s.handleKillChainTimeline).Methods("GET")
	v9.HandleFunc("/ja3/clusters", s.handleJA3Clusters).Methods("GET")

	// Reserse endpoints (Basic Auth)
	reserse := s.router.PathPrefix("/reserse").Subrouter()
	reserse.Use(s.reserseAuthMiddleware)
	reserse.HandleFunc("/actors", s.handleReserseActors).Methods("GET")
	reserse.HandleFunc("/actors/{id}/timeline", s.handleReserseTimeline).Methods("GET")
	reserse.HandleFunc("/actors/by-ip/{ip}/timeline", s.handleReserseTimelineByIP).Methods("GET")
	reserse.HandleFunc("/graph", s.handleReserseGraph).Methods("GET")

	// HONEYPOT TRAPS - Juicy endpoints for attackers
	// Any access = logged + fake response with taunt
	s.router.PathPrefix("/admin").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "admin")
	})
	s.router.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "env")
	})
	s.router.PathPrefix("/.git").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "git")
	})
	s.router.PathPrefix("/backup").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "backup")
	})
	s.router.HandleFunc("/wp-admin", func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "admin")
	})
	s.router.HandleFunc("/phpmyadmin", func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "database")
	})
	s.router.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "api")
	})
	s.router.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
		s.handleHoneypot(w, r, "api")
	})

	// Catch-all: forwards to the backend proxy when server.backend_url is
	// configured (REQ SVALINN-PROXY-BACKEND-001), otherwise unchanged
	// pre-REQ behavior (log unknown paths, 404 shield response).
	s.router.PathPrefix("/").HandlerFunc(s.handleCatchAll)
}

// Start starts the HTTP and HTTPS servers
func (s *Server) Start() error {
	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		s.httpServer = &http.Server{
			Addr:         s.cfg.Server.HTTPAddr,
			Handler:      s, // Use Server.ServeHTTP for ecosystem bypass
			ReadTimeout:  s.cfg.Server.ReadTimeout,
			WriteTimeout: s.cfg.Server.WriteTimeout,
			IdleTimeout:  s.cfg.Server.IdleTimeout,
		}
		s.log.Info("HTTP server starting", "addr", s.cfg.Server.HTTPAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if TLS configured
	if s.cfg.Server.TLSCert != "" && s.cfg.Server.TLSKey != "" {
		go func() {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
			}

			s.tlsServer = &http.Server{
				Addr:         s.cfg.Server.HTTPSAddr,
				Handler:      s.router,
				TLSConfig:    tlsConfig,
				ReadTimeout:  s.cfg.Server.ReadTimeout,
				WriteTimeout: s.cfg.Server.WriteTimeout,
				IdleTimeout:  s.cfg.Server.IdleTimeout,
			}
			s.log.Info("HTTPS server starting", "addr", s.cfg.Server.HTTPSAddr)
			if err := s.tlsServer.ListenAndServeTLS(s.cfg.Server.TLSCert, s.cfg.Server.TLSKey); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Wait for shutdown or error
	select {
	case err := <-errChan:
		return err
	case <-s.shutdown:
		return nil
	}
}

// grayZoneAutoSave persists gz to disk on each tick until stop is closed.
func grayZoneAutoSave(gz *actor.GrayZone, interval time.Duration, stop <-chan struct{}, log *logger.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := gz.SaveToFile(); err != nil {
				log.Error("Failed to persist gray zone", "error", err)
			}
		case <-stop:
			return
		}
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.shutdown)

	if s.grayZone != nil {
		if err := s.grayZone.SaveToFile(); err != nil {
			s.log.Error("Failed to persist gray zone on shutdown", "error", err)
		}
	}

	var err error
	if s.httpServer != nil {
		if e := s.httpServer.Shutdown(ctx); e != nil {
			err = e
		}
	}
	if s.tlsServer != nil {
		if e := s.tlsServer.Shutdown(ctx); e != nil {
			err = e
		}
	}
	return err
}

// getClientIP extracts the real client IP from request.
//
// REQ SVALINN-CLIENTIP-SPOOF-001: this previously trusted the FIRST
// X-Forwarded-For element, which nginx's $proxy_add_x_forwarded_for lets a
// remote attacker control outright -- letting them evade their own rate limits
// and blocks, or frame a third-party IP into being blocked. Resolution is now
// delegated to trustedClientIP, which only honours nginx-supplied values.
func (s *Server) getClientIP(r *http.Request) string {
	return trustedClientIP(r)
}
