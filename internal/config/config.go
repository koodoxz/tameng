/*
Package config handles SVALINN configuration loading and management.
*/
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the complete SVALINN configuration
type Config struct {
	Server           ServerConfig             `yaml:"server"`
	Security         SecurityConfig           `yaml:"security"`
	WAF              WAFConfig                `yaml:"waf"`
	MLEnhancedWAF    MLEnhancedWAFConfig      `yaml:"ml_waf"`
	DDoS             DDoSConfig               `yaml:"ddos"`
	Actor            ActorConfig              `yaml:"actor"`
	Intel            IntelConfig              `yaml:"intel"`
	ML               MLConfig                 `yaml:"ml"`
	ActiveDefense    ActiveDefenseConfig      `yaml:"active_defense"`
	Countermeasures  CountermeasuresConfig    `yaml:"countermeasures"`
	Behavioral       BehavioralConfig         `yaml:"behavioral_baseline"`
	BehavioralDetect BehavioralDetectorConfig `yaml:"behavioral_detector"`
	MalwareBehavior  MalwareBehaviorConfig    `yaml:"malware_behavior"`
	PayloadSignature PayloadSignatureConfig   `yaml:"payload_signature"`
	AdvancedEgress   AdvancedEgressConfig     `yaml:"advanced_egress"`
	STIX             STIXConfig               `yaml:"stix_intel"`
	BusinessLogic    BusinessLogicConfig      `yaml:"business_logic_abuse"`
	SemanticPayload  SemanticPayloadConfig    `yaml:"semantic_payload"`
	ResponseEncrypt  ResponseEncryptConfig    `yaml:"response_encrypt"`
	ProofOfWork      ProofOfWorkConfig        `yaml:"proof_of_work"`
	ProtocolGuard    ProtocolGuardConfig      `yaml:"protocol_guard"`
	Exploitation     ExploitationConfig       `yaml:"exploitation_detector"`
	Evasion          EvasionConfig            `yaml:"evasion_detector"`
	NetworkAttack    NetworkAttackConfig      `yaml:"network_attack_detector"`
	ADAttack         ADAttackConfig           `yaml:"ad_attack_detector"`
	AttackForecast   AttackForecastConfig     `yaml:"attack_forecast"`
	AttackChain      AttackChainConfig        `yaml:"attack_chain"`
	Triangulation    TriangulationConfig      `yaml:"triangulation"`
	Database         DatabaseConfig           `yaml:"database"`
	Logging          LoggingConfig            `yaml:"logging"`
	Ecosystem        EcosystemConfig          `yaml:"ecosystem"`
	Observatory      ObservatoryConfig        `yaml:"observatory"`
}

// ServerConfig holds HTTP server settings
type ServerConfig struct {
	HTTPAddr     string        `yaml:"http_addr"`
	HTTPSAddr    string        `yaml:"https_addr"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	GodModeKey     string   `yaml:"god_mode_key"`
	APIKeys        []string `yaml:"api_keys"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	RateLimitRPS   float64  `yaml:"rate_limit_rps"`
	RateLimitBurst int      `yaml:"rate_limit_burst"`
	ReserseUser    string   `yaml:"reserse_user"`
	ResersePass    string   `yaml:"reserse_pass"`
}

// WAFConfig holds Web Application Firewall settings
type WAFConfig struct {
	Enabled          bool     `yaml:"enabled"`
	SignaturesPath   string   `yaml:"signatures_path"`
	BlockThreshold   float64  `yaml:"block_threshold"`
	LogThreshold     float64  `yaml:"log_threshold"`
	WhitelistedPaths []string `yaml:"whitelisted_paths"`
	WhitelistedIPs   []string `yaml:"whitelisted_ips"`
}

// MLEnhancedWAFConfig holds ML-enhanced WAF settings
type MLEnhancedWAFConfig struct {
	Enabled        bool    `yaml:"enabled"`
	ModelPath      string  `yaml:"model_path"`
	AlertThreshold float64 `yaml:"alert_threshold"`
	BlockThreshold float64 `yaml:"block_threshold"`
	MLWeight       float64 `yaml:"ml_weight"`
	AnomalyWeight  float64 `yaml:"anomaly_weight"`
}

// DDoSConfig holds DDoS protection settings
type DDoSConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Phase3Enabled     bool          `yaml:"phase3_enabled"`
	ChallengeEnabled  bool          `yaml:"challenge_enabled"`
	ThrottleEnabled   bool          `yaml:"throttle_enabled"`
	BlockEnabled      bool          `yaml:"block_enabled"`
	EWMAWindow        time.Duration `yaml:"ewma_window"`
	ThresholdRPS      float64       `yaml:"threshold_rps"`
	BurstThreshold    int           `yaml:"burst_threshold"`
	BlockDuration     time.Duration `yaml:"block_duration"`
	ChallengeDuration time.Duration `yaml:"challenge_duration"`
}

// ActorConfig holds actor tracking settings
type ActorConfig struct {
	Enabled            bool          `yaml:"enabled"`
	MaxActors          int           `yaml:"max_actors"`
	EvictionInterval   time.Duration `yaml:"eviction_interval"`
	ReserseEnabled     bool          `yaml:"reserse_enabled"`
	GrayZoneSize       int           `yaml:"gray_zone_size"`
	PromotionThreshold int           `yaml:"promotion_threshold"`
}

// IntelConfig holds threat intelligence settings
type IntelConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MITREEnabled bool          `yaml:"mitre_enabled"`
	STIXEnabled  bool          `yaml:"stix_enabled"`
	FeedsEnabled bool          `yaml:"feeds_enabled"`
	SyncInterval time.Duration `yaml:"sync_interval"`
}

// MLConfig holds machine learning settings
type MLConfig struct {
	Enabled         bool          `yaml:"enabled"`
	EngineURL       string        `yaml:"engine_url"`
	Timeout         time.Duration `yaml:"timeout"`
	FallbackToRules bool          `yaml:"fallback_to_rules"`
}

// ActiveDefenseConfig holds active defense orchestrator settings
type ActiveDefenseConfig struct {
	Enabled       bool          `yaml:"enabled"`
	AutoEscalate  bool          `yaml:"auto_escalate"`
	TarpitDelay   time.Duration `yaml:"tarpit_delay"`
	HoneypotPath  string        `yaml:"honeypot_path"`
	BlockDuration time.Duration `yaml:"block_duration"`
}

// CountermeasuresConfig holds micro-countermeasure settings
type CountermeasuresConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ActionLogPath string `yaml:"action_log_path"`
}

// BehavioralConfig holds behavioral baseline settings
type BehavioralConfig struct {
	Enabled               bool    `yaml:"enabled"`
	DeviationThreshold    float64 `yaml:"deviation_threshold"`
	MinSamplesForBaseline int     `yaml:"min_samples_for_baseline"`
	BlockThreshold        float64 `yaml:"block_threshold"`
}

// BehavioralDetectorConfig holds behavioral detector settings
type BehavioralDetectorConfig struct {
	Enabled                     bool          `yaml:"enabled"`
	CleanupInterval             time.Duration `yaml:"cleanup_interval"`
	CredentialStuffingThreshold int           `yaml:"credential_stuffing_threshold"`
	APIEnumerationThreshold     int           `yaml:"api_enumeration_threshold"`
	ScrapingThreshold           int           `yaml:"scraping_threshold"`
	ErrorRateThreshold          float64       `yaml:"error_rate_threshold"`
	AlertScoreThreshold         float64       `yaml:"alert_score_threshold"`
	BlockScoreThreshold         float64       `yaml:"block_score_threshold"`
	SuspiciousSessionThreshold  int           `yaml:"suspicious_session_threshold"`
	TemporalAnomalyThreshold    int           `yaml:"temporal_anomaly_threshold"`
	MaxTrackedEvents            int           `yaml:"max_tracked_events"`
	SessionWindow               time.Duration `yaml:"session_window"`
	ShortWindow                 time.Duration `yaml:"short_window"`
	MediumWindow                time.Duration `yaml:"medium_window"`
	LongWindow                  time.Duration `yaml:"long_window"`
}

// MalwareBehaviorConfig holds malware behavior analyzer settings
type MalwareBehaviorConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ScoringThreshold float64 `yaml:"scoring_threshold"`
	AlertThreshold   float64 `yaml:"alert_threshold"`
	BlockThreshold   float64 `yaml:"block_threshold"`
}

// PayloadSignatureConfig holds payload signature generator settings
type PayloadSignatureConfig struct {
	Enabled      bool `yaml:"enabled"`
	YARAEnabled  bool `yaml:"yara_enabled"`
	SigmaEnabled bool `yaml:"sigma_enabled"`
	SnortEnabled bool `yaml:"snort_enabled"`
}

// AdvancedEgressConfig holds advanced egress settings
type AdvancedEgressConfig struct {
	Enabled                 bool          `yaml:"enabled"`
	BlockedCountries        []string      `yaml:"blocked_countries"`
	AllowedCountries        []string      `yaml:"allowed_countries"`
	GeofenceMode            string        `yaml:"geofence_mode"`
	VelocityWindow          time.Duration `yaml:"velocity_window"`
	MaxBytesPerWindow       int           `yaml:"max_bytes_per_window"`
	MaxRequestsPerWindow    int           `yaml:"max_requests_per_window"`
	VelocitySpikeMultiplier float64       `yaml:"velocity_spike_multiplier"`
	TrustedPackageHosts     []string      `yaml:"trusted_package_hosts"`
	MaxEncodedPayloadSize   int           `yaml:"max_encoded_payload_size"`
	EntropyThreshold        float64       `yaml:"entropy_threshold"`
}

// STIXConfig holds STIX/TAXII engine settings
type STIXConfig struct {
	Enabled             bool          `yaml:"enabled"`
	DefaultTLP          string        `yaml:"default_tlp"`
	IOCTTL              time.Duration `yaml:"ioc_ttl"`
	MaxIndicators       int           `yaml:"max_indicators"`
	ConfidenceThreshold float64       `yaml:"confidence_threshold"`
	BlockOnMatch        bool          `yaml:"block_on_match"`
}

// BusinessLogicConfig holds business logic abuse settings
type BusinessLogicConfig struct {
	Enabled          bool          `yaml:"enabled"`
	Mode             string        `yaml:"mode"`
	FlowWindow       time.Duration `yaml:"flow_window"`
	MaxActions       int           `yaml:"max_actions"`
	MaxSensitiveHits int           `yaml:"max_sensitive_hits"`
	SensitivePaths   []string      `yaml:"sensitive_paths"`
	CleanupInterval  time.Duration `yaml:"cleanup_interval"`
}

// SemanticPayloadConfig holds semantic payload analyzer settings
type SemanticPayloadConfig struct {
	Enabled        bool    `yaml:"enabled"`
	AlertThreshold float64 `yaml:"alert_threshold"`
	BlockThreshold float64 `yaml:"block_threshold"`
}

// ResponseEncryptConfig holds response encryption settings
type ResponseEncryptConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ProtectPaths []string      `yaml:"protect_paths"`
	ExcludePaths []string      `yaml:"exclude_paths"`
	TokenTTL     time.Duration `yaml:"token_ttl"`
	EncryptHTML  bool          `yaml:"encrypt_html"`
	EncryptJS    bool          `yaml:"encrypt_js"`
}

// ProofOfWorkConfig holds PoW settings
type ProofOfWorkConfig struct {
	Enabled        bool          `yaml:"enabled"`
	Difficulty     int           `yaml:"difficulty"`
	TokenTTL       time.Duration `yaml:"token_ttl"`
	ProtectedPaths []string      `yaml:"protected_paths"`
	HeaderToken    string        `yaml:"header_token"`
	HeaderNonce    string        `yaml:"header_nonce"`
}

// ProtocolGuardConfig holds protocol guard settings
type ProtocolGuardConfig struct {
	Enabled              bool `yaml:"enabled"`
	MaxGraphQLDepth      int  `yaml:"max_graphql_depth"`
	MaxGraphQLComplexity int  `yaml:"max_graphql_complexity"`
	WSRateLimit          int  `yaml:"ws_rate_limit"`
	BlockOnViolation     bool `yaml:"block_on_violation"`
}

// ExploitationConfig holds exploitation detector settings
type ExploitationConfig struct {
	Enabled             bool    `yaml:"enabled"`
	HeapSprayThreshold  int     `yaml:"heap_spray_threshold"`
	ROPChainThreshold   int     `yaml:"rop_chain_threshold"`
	ShellcodeThreshold  int     `yaml:"shellcode_threshold"`
	InjectionThreshold  int     `yaml:"injection_threshold"`
	EscalationThreshold int     `yaml:"escalation_threshold"`
	AlertThreshold      float64 `yaml:"alert_threshold"`
	BlockThreshold      float64 `yaml:"block_threshold"`
}

// EvasionConfig holds evasion detector settings
type EvasionConfig struct {
	Enabled            bool    `yaml:"enabled"`
	AmsiThreshold      int     `yaml:"amsi_threshold"`
	EtwThreshold       int     `yaml:"etw_threshold"`
	UnhookingThreshold int     `yaml:"unhooking_threshold"`
	SandboxThreshold   int     `yaml:"sandbox_threshold"`
	SyscallThreshold   int     `yaml:"syscall_threshold"`
	ModuleThreshold    int     `yaml:"module_threshold"`
	TimestampThreshold int     `yaml:"timestamp_threshold"`
	AlertThreshold     float64 `yaml:"alert_threshold"`
	BlockThreshold     float64 `yaml:"block_threshold"`
}

// NetworkAttackConfig holds network attack detector settings
type NetworkAttackConfig struct {
	Enabled             bool          `yaml:"enabled"`
	ARPThreshold        int           `yaml:"arp_threshold"`
	DNSThreshold        int           `yaml:"dns_threshold"`
	SMBThreshold        int           `yaml:"smb_threshold"`
	KerberoastThreshold int           `yaml:"kerberoast_threshold"`
	PoisoningThreshold  int           `yaml:"poisoning_threshold"`
	PTXThreshold        int           `yaml:"ptx_threshold"`
	AlertThreshold      float64       `yaml:"alert_threshold"`
	BlockThreshold      float64       `yaml:"block_threshold"`
	ConnectionTTL       time.Duration `yaml:"connection_ttl"`
}

// ADAttackConfig holds AD attack detector settings
type ADAttackConfig struct {
	Enabled             bool    `yaml:"enabled"`
	DCSyncThreshold     int     `yaml:"dcsync_threshold"`
	GoldenThreshold     int     `yaml:"golden_threshold"`
	SilverThreshold     int     `yaml:"silver_threshold"`
	SkeletonThreshold   int     `yaml:"skeleton_threshold"`
	AdminSDThreshold    int     `yaml:"adminsd_threshold"`
	GPOThreshold        int     `yaml:"gpo_threshold"`
	BloodhoundThreshold int     `yaml:"bloodhound_threshold"`
	LDAPThreshold       int     `yaml:"ldap_threshold"`
	AlertThreshold      float64 `yaml:"alert_threshold"`
	BlockThreshold      float64 `yaml:"block_threshold"`
}

// AttackForecastConfig holds attack forecast settings
type AttackForecastConfig struct {
	Enabled          bool    `yaml:"enabled"`
	ForecastHorizon  int     `yaml:"forecast_horizon"`
	TrendThreshold   float64 `yaml:"trend_threshold"`
	SpikeThreshold   float64 `yaml:"spike_threshold"`
	QuietThreshold   float64 `yaml:"quiet_threshold"`
	ConfidenceLevel  float64 `yaml:"confidence_level"`
	MaxHistorySize   int     `yaml:"max_history_size"`
	CleanupIntervalM int     `yaml:"cleanup_interval_minutes"`
}

// AttackChainConfig holds attack chain analyzer settings
type AttackChainConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ChainTimeout    time.Duration `yaml:"chain_timeout"`
	AlertThreshold  float64       `yaml:"alert_threshold"`
	BeaconThreshold float64       `yaml:"beacon_threshold"`
}

// TriangulationConfig holds triangulation engine settings
type TriangulationConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DatabaseConfig holds database settings
type DatabaseConfig struct {
	Type     string `yaml:"type"`
	Path     string `yaml:"path"`
	InMemory bool   `yaml:"in_memory"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	OutputPath string `yaml:"output_path"`
}

// EcosystemConfig holds AEGIS ecosystem settings
type EcosystemConfig struct {
	Enabled     bool   `yaml:"enabled"`
	ODINURL     string `yaml:"odin_url"`
	ODINAPIKey  string `yaml:"odin_api_key"`
	MIMIRIP     string `yaml:"mimir_ip"`
	SyncWorkers int    `yaml:"sync_workers"`

	// AllowedIPs is the source-IP allowlist for the four ecosystem endpoints
	// (/api/v1/shield/threats, /heimdall/report, /dns-events, /dns-blocklist).
	// Those endpoints bypass the entire middleware and auth chain, so this list
	// is the only access control protecting them.
	//
	// Entries must be exact IP addresses; CIDR ranges are NOT supported and
	// will never match. An empty or unset list denies every request
	// (fail-closed) -- it must be populated before deployment or ecosystem
	// sync from HEIMDALL/MIMIR will break.
	AllowedIPs []string `yaml:"allowed_ips"`
}

// ObservatoryConfig holds Observatory (Hall of Fame) settings
type ObservatoryConfig struct {
	Enabled   bool          `yaml:"enabled"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	TopActors int           `yaml:"top_actors"`
}

// Load reads and parses the configuration file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	data = []byte(os.ExpandEnv(string(data)))

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	setDefaults(cfg)

	return cfg, nil
}

// setDefaults applies default values to unset config fields
func setDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.HTTPAddr == "" {
		cfg.Server.HTTPAddr = ":80"
	}
	if cfg.Server.HTTPSAddr == "" {
		cfg.Server.HTTPSAddr = ":443"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 120 * time.Second
	}

	// Security defaults
	if cfg.Security.RateLimitRPS == 0 {
		cfg.Security.RateLimitRPS = 100
	}
	if cfg.Security.RateLimitBurst == 0 {
		cfg.Security.RateLimitBurst = 200
	}

	// WAF defaults
	if cfg.WAF.SignaturesPath == "" {
		cfg.WAF.SignaturesPath = "data/signatures.json"
	}
	if cfg.WAF.BlockThreshold == 0 {
		cfg.WAF.BlockThreshold = 0.8
	}
	if cfg.WAF.LogThreshold == 0 {
		cfg.WAF.LogThreshold = 0.5
	}

	// ML-enhanced WAF defaults
	if !cfg.MLEnhancedWAF.Enabled {
		cfg.MLEnhancedWAF.Enabled = true
	}
	if cfg.MLEnhancedWAF.ModelPath == "" {
		cfg.MLEnhancedWAF.ModelPath = "/root/data/models/threat_scorer.txt"
	}
	if cfg.MLEnhancedWAF.AlertThreshold == 0 {
		cfg.MLEnhancedWAF.AlertThreshold = 70
	}
	if cfg.MLEnhancedWAF.BlockThreshold == 0 {
		cfg.MLEnhancedWAF.BlockThreshold = 85
	}
	if cfg.MLEnhancedWAF.MLWeight == 0 {
		cfg.MLEnhancedWAF.MLWeight = 0.7
	}
	if cfg.MLEnhancedWAF.AnomalyWeight == 0 {
		cfg.MLEnhancedWAF.AnomalyWeight = 0.3
	}

	// DDoS defaults
	if cfg.DDoS.EWMAWindow == 0 {
		cfg.DDoS.EWMAWindow = 10 * time.Second
	}
	if cfg.DDoS.ThresholdRPS == 0 {
		cfg.DDoS.ThresholdRPS = 1000
	}
	if cfg.DDoS.BlockDuration == 0 {
		cfg.DDoS.BlockDuration = 5 * time.Minute
	}
	if cfg.DDoS.ChallengeDuration == 0 {
		cfg.DDoS.ChallengeDuration = 1 * time.Minute
	}

	// Actor defaults
	if cfg.Actor.MaxActors == 0 {
		cfg.Actor.MaxActors = 100000
	}
	if cfg.Actor.EvictionInterval == 0 {
		cfg.Actor.EvictionInterval = 1 * time.Minute
	}
	if cfg.Actor.GrayZoneSize == 0 {
		cfg.Actor.GrayZoneSize = 10000
	}
	if cfg.Actor.PromotionThreshold == 0 {
		cfg.Actor.PromotionThreshold = 5
	}

	// Intel defaults
	if cfg.Intel.SyncInterval == 0 {
		cfg.Intel.SyncInterval = 1 * time.Hour
	}

	// ML defaults
	if cfg.ML.EngineURL == "" {
		cfg.ML.EngineURL = "http://localhost:8000"
	}
	if cfg.ML.Timeout == 0 {
		cfg.ML.Timeout = 5 * time.Second
	}

	// Behavioral baseline defaults
	if !cfg.Behavioral.Enabled {
		cfg.Behavioral.Enabled = true
	}
	if cfg.Behavioral.DeviationThreshold == 0 {
		cfg.Behavioral.DeviationThreshold = 0.7
	}
	if cfg.Behavioral.MinSamplesForBaseline == 0 {
		cfg.Behavioral.MinSamplesForBaseline = 50
	}
	if cfg.Behavioral.BlockThreshold == 0 {
		cfg.Behavioral.BlockThreshold = 0.9
	}

	// Behavioral detector defaults
	if !cfg.BehavioralDetect.Enabled {
		cfg.BehavioralDetect.Enabled = true
	}
	if cfg.BehavioralDetect.CleanupInterval == 0 {
		cfg.BehavioralDetect.CleanupInterval = 5 * time.Minute
	}
	if cfg.BehavioralDetect.CredentialStuffingThreshold == 0 {
		cfg.BehavioralDetect.CredentialStuffingThreshold = 20
	}
	if cfg.BehavioralDetect.APIEnumerationThreshold == 0 {
		cfg.BehavioralDetect.APIEnumerationThreshold = 40
	}
	if cfg.BehavioralDetect.ScrapingThreshold == 0 {
		cfg.BehavioralDetect.ScrapingThreshold = 120
	}
	if cfg.BehavioralDetect.ErrorRateThreshold == 0 {
		cfg.BehavioralDetect.ErrorRateThreshold = 0.4
	}
	if cfg.BehavioralDetect.AlertScoreThreshold == 0 {
		cfg.BehavioralDetect.AlertScoreThreshold = 60
	}
	if cfg.BehavioralDetect.BlockScoreThreshold == 0 {
		cfg.BehavioralDetect.BlockScoreThreshold = 85
	}
	if cfg.BehavioralDetect.SuspiciousSessionThreshold == 0 {
		cfg.BehavioralDetect.SuspiciousSessionThreshold = 5
	}
	if cfg.BehavioralDetect.TemporalAnomalyThreshold == 0 {
		cfg.BehavioralDetect.TemporalAnomalyThreshold = 20
	}
	if cfg.BehavioralDetect.MaxTrackedEvents == 0 {
		cfg.BehavioralDetect.MaxTrackedEvents = 500
	}
	if cfg.BehavioralDetect.SessionWindow == 0 {
		cfg.BehavioralDetect.SessionWindow = 10 * time.Minute
	}
	if cfg.BehavioralDetect.ShortWindow == 0 {
		cfg.BehavioralDetect.ShortWindow = 1 * time.Minute
	}
	if cfg.BehavioralDetect.MediumWindow == 0 {
		cfg.BehavioralDetect.MediumWindow = 5 * time.Minute
	}
	if cfg.BehavioralDetect.LongWindow == 0 {
		cfg.BehavioralDetect.LongWindow = 1 * time.Hour
	}

	// Malware behavior analyzer defaults
	if !cfg.MalwareBehavior.Enabled {
		cfg.MalwareBehavior.Enabled = true
	}
	if cfg.MalwareBehavior.ScoringThreshold == 0 {
		cfg.MalwareBehavior.ScoringThreshold = 50
	}
	if cfg.MalwareBehavior.AlertThreshold == 0 {
		cfg.MalwareBehavior.AlertThreshold = 50
	}
	if cfg.MalwareBehavior.BlockThreshold == 0 {
		cfg.MalwareBehavior.BlockThreshold = 85
	}

	// Payload signature generator defaults
	if !cfg.PayloadSignature.Enabled {
		cfg.PayloadSignature.Enabled = true
	}
	if !cfg.PayloadSignature.YARAEnabled {
		cfg.PayloadSignature.YARAEnabled = true
	}
	if !cfg.PayloadSignature.SigmaEnabled {
		cfg.PayloadSignature.SigmaEnabled = true
	}
	if !cfg.PayloadSignature.SnortEnabled {
		cfg.PayloadSignature.SnortEnabled = true
	}

	// Advanced egress defaults
	if !cfg.AdvancedEgress.Enabled {
		cfg.AdvancedEgress.Enabled = true
	}
	if cfg.AdvancedEgress.GeofenceMode == "" {
		cfg.AdvancedEgress.GeofenceMode = "alert"
	}
	if cfg.AdvancedEgress.VelocityWindow == 0 {
		cfg.AdvancedEgress.VelocityWindow = 1 * time.Minute
	}
	if cfg.AdvancedEgress.MaxBytesPerWindow == 0 {
		cfg.AdvancedEgress.MaxBytesPerWindow = 10 * 1024 * 1024
	}
	if cfg.AdvancedEgress.MaxRequestsPerWindow == 0 {
		cfg.AdvancedEgress.MaxRequestsPerWindow = 100
	}
	if cfg.AdvancedEgress.VelocitySpikeMultiplier == 0 {
		cfg.AdvancedEgress.VelocitySpikeMultiplier = 5
	}
	if cfg.AdvancedEgress.MaxEncodedPayloadSize == 0 {
		cfg.AdvancedEgress.MaxEncodedPayloadSize = 10000
	}
	if cfg.AdvancedEgress.EntropyThreshold == 0 {
		cfg.AdvancedEgress.EntropyThreshold = 4.5
	}
	if len(cfg.AdvancedEgress.BlockedCountries) == 0 {
		cfg.AdvancedEgress.BlockedCountries = []string{"RU", "CN", "KP", "IR", "BY", "SY"}
	}

	// STIX defaults
	if !cfg.STIX.Enabled {
		cfg.STIX.Enabled = true
	}
	if cfg.STIX.DefaultTLP == "" {
		cfg.STIX.DefaultTLP = "AMBER"
	}
	if cfg.STIX.IOCTTL == 0 {
		cfg.STIX.IOCTTL = 24 * time.Hour
	}
	if cfg.STIX.MaxIndicators == 0 {
		cfg.STIX.MaxIndicators = 10000
	}
	if cfg.STIX.ConfidenceThreshold == 0 {
		cfg.STIX.ConfidenceThreshold = 50
	}

	// Business logic abuse defaults
	if !cfg.BusinessLogic.Enabled {
		cfg.BusinessLogic.Enabled = true
	}
	if cfg.BusinessLogic.Mode == "" {
		cfg.BusinessLogic.Mode = "detect"
	}
	if cfg.BusinessLogic.FlowWindow == 0 {
		cfg.BusinessLogic.FlowWindow = 5 * time.Minute
	}
	if cfg.BusinessLogic.MaxActions == 0 {
		cfg.BusinessLogic.MaxActions = 120
	}
	if cfg.BusinessLogic.MaxSensitiveHits == 0 {
		cfg.BusinessLogic.MaxSensitiveHits = 15
	}
	if cfg.BusinessLogic.CleanupInterval == 0 {
		cfg.BusinessLogic.CleanupInterval = 2 * time.Minute
	}
	if len(cfg.BusinessLogic.SensitivePaths) == 0 {
		cfg.BusinessLogic.SensitivePaths = []string{"/admin", "/billing", "/checkout", "/password", "/token", "/api/v9"}
	}

	// Semantic payload defaults
	if !cfg.SemanticPayload.Enabled {
		cfg.SemanticPayload.Enabled = true
	}
	if cfg.SemanticPayload.AlertThreshold == 0 {
		cfg.SemanticPayload.AlertThreshold = 60
	}
	if cfg.SemanticPayload.BlockThreshold == 0 {
		cfg.SemanticPayload.BlockThreshold = 85
	}

	// Response encrypt defaults
	if !cfg.ResponseEncrypt.Enabled {
		cfg.ResponseEncrypt.Enabled = false
	}
	if cfg.ResponseEncrypt.TokenTTL == 0 {
		cfg.ResponseEncrypt.TokenTTL = 5 * time.Minute
	}
	if len(cfg.ResponseEncrypt.ProtectPaths) == 0 {
		cfg.ResponseEncrypt.ProtectPaths = []string{"/admin", "/dashboard", "/api/v9"}
	}
	if len(cfg.ResponseEncrypt.ExcludePaths) == 0 {
		cfg.ResponseEncrypt.ExcludePaths = []string{"/health", "/metrics"}
	}
	if !cfg.ResponseEncrypt.EncryptHTML {
		cfg.ResponseEncrypt.EncryptHTML = true
	}
	if !cfg.ResponseEncrypt.EncryptJS {
		cfg.ResponseEncrypt.EncryptJS = true
	}

	// Proof-of-work defaults
	if !cfg.ProofOfWork.Enabled {
		cfg.ProofOfWork.Enabled = false
	}
	if cfg.ProofOfWork.Difficulty == 0 {
		cfg.ProofOfWork.Difficulty = 4
	}
	if cfg.ProofOfWork.TokenTTL == 0 {
		cfg.ProofOfWork.TokenTTL = 2 * time.Minute
	}
	if len(cfg.ProofOfWork.ProtectedPaths) == 0 {
		cfg.ProofOfWork.ProtectedPaths = []string{"/api/v9"}
	}
	if cfg.ProofOfWork.HeaderToken == "" {
		cfg.ProofOfWork.HeaderToken = "X-Svalinn-PoW-Token"
	}
	if cfg.ProofOfWork.HeaderNonce == "" {
		cfg.ProofOfWork.HeaderNonce = "X-Svalinn-PoW-Nonce"
	}

	// Protocol guard defaults
	if !cfg.ProtocolGuard.Enabled {
		cfg.ProtocolGuard.Enabled = true
	}
	if cfg.ProtocolGuard.MaxGraphQLDepth == 0 {
		cfg.ProtocolGuard.MaxGraphQLDepth = 10
	}
	if cfg.ProtocolGuard.MaxGraphQLComplexity == 0 {
		cfg.ProtocolGuard.MaxGraphQLComplexity = 1000
	}
	if cfg.ProtocolGuard.WSRateLimit == 0 {
		cfg.ProtocolGuard.WSRateLimit = 100
	}

	// Exploitation detector defaults
	if !cfg.Exploitation.Enabled {
		cfg.Exploitation.Enabled = true
	}
	if cfg.Exploitation.HeapSprayThreshold == 0 {
		cfg.Exploitation.HeapSprayThreshold = 50
	}
	if cfg.Exploitation.ROPChainThreshold == 0 {
		cfg.Exploitation.ROPChainThreshold = 30
	}
	if cfg.Exploitation.ShellcodeThreshold == 0 {
		cfg.Exploitation.ShellcodeThreshold = 70
	}
	if cfg.Exploitation.InjectionThreshold == 0 {
		cfg.Exploitation.InjectionThreshold = 80
	}
	if cfg.Exploitation.EscalationThreshold == 0 {
		cfg.Exploitation.EscalationThreshold = 60
	}
	if cfg.Exploitation.AlertThreshold == 0 {
		cfg.Exploitation.AlertThreshold = 70
	}
	if cfg.Exploitation.BlockThreshold == 0 {
		cfg.Exploitation.BlockThreshold = 85
	}

	// Evasion detector defaults
	if !cfg.Evasion.Enabled {
		cfg.Evasion.Enabled = true
	}
	if cfg.Evasion.AmsiThreshold == 0 {
		cfg.Evasion.AmsiThreshold = 35
	}
	if cfg.Evasion.EtwThreshold == 0 {
		cfg.Evasion.EtwThreshold = 30
	}
	if cfg.Evasion.UnhookingThreshold == 0 {
		cfg.Evasion.UnhookingThreshold = 40
	}
	if cfg.Evasion.SandboxThreshold == 0 {
		cfg.Evasion.SandboxThreshold = 25
	}
	if cfg.Evasion.SyscallThreshold == 0 {
		cfg.Evasion.SyscallThreshold = 45
	}
	if cfg.Evasion.ModuleThreshold == 0 {
		cfg.Evasion.ModuleThreshold = 35
	}
	if cfg.Evasion.TimestampThreshold == 0 {
		cfg.Evasion.TimestampThreshold = 30
	}
	if cfg.Evasion.AlertThreshold == 0 {
		cfg.Evasion.AlertThreshold = 70
	}
	if cfg.Evasion.BlockThreshold == 0 {
		cfg.Evasion.BlockThreshold = 75
	}

	// Network attack detector defaults
	if !cfg.NetworkAttack.Enabled {
		cfg.NetworkAttack.Enabled = true
	}
	if cfg.NetworkAttack.ARPThreshold == 0 {
		cfg.NetworkAttack.ARPThreshold = 25
	}
	if cfg.NetworkAttack.DNSThreshold == 0 {
		cfg.NetworkAttack.DNSThreshold = 30
	}
	if cfg.NetworkAttack.SMBThreshold == 0 {
		cfg.NetworkAttack.SMBThreshold = 35
	}
	if cfg.NetworkAttack.KerberoastThreshold == 0 {
		cfg.NetworkAttack.KerberoastThreshold = 40
	}
	if cfg.NetworkAttack.PoisoningThreshold == 0 {
		cfg.NetworkAttack.PoisoningThreshold = 30
	}
	if cfg.NetworkAttack.PTXThreshold == 0 {
		cfg.NetworkAttack.PTXThreshold = 45
	}
	if cfg.NetworkAttack.AlertThreshold == 0 {
		cfg.NetworkAttack.AlertThreshold = 70
	}
	if cfg.NetworkAttack.BlockThreshold == 0 {
		cfg.NetworkAttack.BlockThreshold = 85
	}
	if cfg.NetworkAttack.ConnectionTTL == 0 {
		cfg.NetworkAttack.ConnectionTTL = 10 * time.Minute
	}

	// AD attack detector defaults
	if !cfg.ADAttack.Enabled {
		cfg.ADAttack.Enabled = true
	}
	if cfg.ADAttack.DCSyncThreshold == 0 {
		cfg.ADAttack.DCSyncThreshold = 50
	}
	if cfg.ADAttack.GoldenThreshold == 0 {
		cfg.ADAttack.GoldenThreshold = 50
	}
	if cfg.ADAttack.SilverThreshold == 0 {
		cfg.ADAttack.SilverThreshold = 45
	}
	if cfg.ADAttack.SkeletonThreshold == 0 {
		cfg.ADAttack.SkeletonThreshold = 40
	}
	if cfg.ADAttack.AdminSDThreshold == 0 {
		cfg.ADAttack.AdminSDThreshold = 40
	}
	if cfg.ADAttack.GPOThreshold == 0 {
		cfg.ADAttack.GPOThreshold = 35
	}
	if cfg.ADAttack.BloodhoundThreshold == 0 {
		cfg.ADAttack.BloodhoundThreshold = 30
	}
	if cfg.ADAttack.LDAPThreshold == 0 {
		cfg.ADAttack.LDAPThreshold = 25
	}
	if cfg.ADAttack.AlertThreshold == 0 {
		cfg.ADAttack.AlertThreshold = 70
	}
	if cfg.ADAttack.BlockThreshold == 0 {
		cfg.ADAttack.BlockThreshold = 85
	}

	// Attack forecast defaults
	if !cfg.AttackForecast.Enabled {
		cfg.AttackForecast.Enabled = true
	}
	if cfg.AttackForecast.ForecastHorizon == 0 {
		cfg.AttackForecast.ForecastHorizon = 24
	}
	if cfg.AttackForecast.TrendThreshold == 0 {
		cfg.AttackForecast.TrendThreshold = 0.15
	}
	if cfg.AttackForecast.SpikeThreshold == 0 {
		cfg.AttackForecast.SpikeThreshold = 2.0
	}
	if cfg.AttackForecast.QuietThreshold == 0 {
		cfg.AttackForecast.QuietThreshold = 0.3
	}
	if cfg.AttackForecast.ConfidenceLevel == 0 {
		cfg.AttackForecast.ConfidenceLevel = 0.95
	}
	if cfg.AttackForecast.MaxHistorySize == 0 {
		cfg.AttackForecast.MaxHistorySize = 100000
	}
	if cfg.AttackForecast.CleanupIntervalM == 0 {
		cfg.AttackForecast.CleanupIntervalM = 60
	}

	// Attack chain defaults
	if !cfg.AttackChain.Enabled {
		cfg.AttackChain.Enabled = true
	}
	if cfg.AttackChain.ChainTimeout == 0 {
		cfg.AttackChain.ChainTimeout = 1 * time.Hour
	}
	if cfg.AttackChain.AlertThreshold == 0 {
		cfg.AttackChain.AlertThreshold = 0.7
	}
	if cfg.AttackChain.BeaconThreshold == 0 {
		cfg.AttackChain.BeaconThreshold = 0.8
	}

	// Triangulation defaults
	if !cfg.Triangulation.Enabled {
		cfg.Triangulation.Enabled = true
	}

	// Active defense defaults
	if cfg.ActiveDefense.TarpitDelay == 0 {
		cfg.ActiveDefense.TarpitDelay = 2 * time.Second
	}
	if cfg.ActiveDefense.HoneypotPath == "" {
		cfg.ActiveDefense.HoneypotPath = "/observatory"
	}
	if cfg.ActiveDefense.BlockDuration == 0 {
		cfg.ActiveDefense.BlockDuration = 1 * time.Hour
	}

	// Countermeasures defaults
	if cfg.Countermeasures.ActionLogPath == "" {
		cfg.Countermeasures.ActionLogPath = "/root/data/defense-actions.json"
	}

	// Database defaults
	if cfg.Database.Type == "" {
		cfg.Database.Type = "sqlite"
	}
	if cfg.Database.Path == "" {
		cfg.Database.Path = "data/svalinn.db"
	}

	// Logging defaults
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
}
