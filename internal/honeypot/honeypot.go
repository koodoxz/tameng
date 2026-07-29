/*
Package honeypot implements honeypots and honeytokens

Trap endpoints that detect and record attacker behavior
*/
package honeypot

import (
	"strings"
	"sync"
	"time"
)

// Trap represents a honeypot trap
type Trap struct {
	Path        string
	Type        string // file, admin, api, config
	Description string
	Severity    string // low, medium, high, critical
}

// Engine manages honeypots
type Engine struct {
	traps       map[string]*Trap
	prefixTraps []*PrefixTrap             // prefix-based traps
	triggers    map[string][]TriggerEvent // IP -> events
	mu          sync.RWMutex
}

// PrefixTrap matches paths by prefix (for scanner variants)
type PrefixTrap struct {
	Prefix string
	Trap   *Trap
}

// TriggerEvent represents a trap trigger
type TriggerEvent struct {
	IP        string
	Path      string
	Timestamp time.Time
	UserAgent string
	Method    string
}

// DefaultTraps are common honeypot endpoints
var DefaultTraps = []*Trap{
	// Environment files (CRITICAL)
	{Path: "/.env", Type: "file", Description: "Environment variables", Severity: "critical"},
	{Path: "/.env.local", Type: "file", Description: "Local env file", Severity: "critical"},
	{Path: "/.env.production", Type: "file", Description: "Production env", Severity: "critical"},
	{Path: "/config.json", Type: "config", Description: "Config file", Severity: "high"},
	{Path: "/config.php", Type: "config", Description: "PHP config", Severity: "high"},

	// Git/Source control (HIGH)
	{Path: "/.git/config", Type: "file", Description: "Git config", Severity: "high"},
	{Path: "/.git/HEAD", Type: "file", Description: "Git HEAD", Severity: "high"},
	{Path: "/.gitignore", Type: "file", Description: "Git ignore", Severity: "medium"},
	{Path: "/.svn", Type: "file", Description: "SVN directory", Severity: "high"},

	// Admin panels (HIGH)
	{Path: "/admin", Type: "admin", Description: "Admin panel", Severity: "high"},
	{Path: "/administrator", Type: "admin", Description: "Administrator", Severity: "high"},
	{Path: "/wp-admin", Type: "admin", Description: "WordPress admin", Severity: "high"},
	{Path: "/phpmyadmin", Type: "admin", Description: "phpMyAdmin", Severity: "critical"},
	{Path: "/pma", Type: "admin", Description: "phpMyAdmin short", Severity: "critical"},
	{Path: "/cpanel", Type: "admin", Description: "cPanel", Severity: "high"},
	{Path: "/webadmin", Type: "admin", Description: "Web admin", Severity: "high"},

	// Database (CRITICAL)
	{Path: "/backup.sql", Type: "file", Description: "SQL backup", Severity: "critical"},
	{Path: "/database.sql", Type: "file", Description: "Database file", Severity: "critical"},
	{Path: "/dump.sql", Type: "file", Description: "SQL dump", Severity: "critical"},
	{Path: "/db_backup.tar.gz", Type: "file", Description: "DB backup archive", Severity: "critical"},

	// Backup files (HIGH)
	{Path: "/backup.zip", Type: "file", Description: "Backup archive", Severity: "high"},
	{Path: "/backup.tar.gz", Type: "file", Description: "Backup tarball", Severity: "high"},
	{Path: "/www.zip", Type: "file", Description: "WWW backup", Severity: "high"},
	{Path: "/site-backup.zip", Type: "file", Description: "Site backup", Severity: "high"},

	// API/Internal (MEDIUM)
	{Path: "/api/internal", Type: "api", Description: "Internal API", Severity: "high"},
	{Path: "/api/admin", Type: "api", Description: "Admin API", Severity: "high"},
	{Path: "/api/debug", Type: "api", Description: "Debug API", Severity: "medium"},
	{Path: "/internal", Type: "api", Description: "Internal endpoint", Severity: "medium"},

	// Scanner bait — observed from libredtail-http botnet (CRITICAL)
	{Path: "/observatory", Type: "scanner_bait", Description: "Mozilla Observatory probe", Severity: "high"},
	{Path: "/hello.world", Type: "scanner_bait", Description: "Hello world probe", Severity: "medium"},

	// === LeakIX-observed paths (commercial vuln scanner, Feb 2026) ===

	// Swagger/OpenAPI documentation (HIGH — reveals API surface)
	{Path: "/swagger.json", Type: "api_docs", Description: "Swagger JSON spec", Severity: "high"},
	{Path: "/swagger-ui.html", Type: "api_docs", Description: "Swagger UI", Severity: "high"},
	{Path: "/swagger/index.html", Type: "api_docs", Description: "Swagger index", Severity: "high"},
	{Path: "/swagger/swagger-ui.html", Type: "api_docs", Description: "Swagger UI nested", Severity: "high"},
	{Path: "/swagger/v1/swagger.json", Type: "api_docs", Description: "Swagger v1 spec", Severity: "high"},
	{Path: "/v2/api-docs", Type: "api_docs", Description: "Swagger v2 docs", Severity: "high"},
	{Path: "/v3/api-docs", Type: "api_docs", Description: "OpenAPI v3 docs", Severity: "high"},
	{Path: "/api-docs/swagger.json", Type: "api_docs", Description: "API docs swagger", Severity: "high"},
	{Path: "/api/swagger.json", Type: "api_docs", Description: "API swagger spec", Severity: "high"},
	{Path: "/webjars/swagger-ui/index.html", Type: "api_docs", Description: "Swagger webjars", Severity: "high"},

	// GraphQL endpoints (HIGH — query introspection)
	{Path: "/graphql", Type: "graphql", Description: "GraphQL endpoint", Severity: "high"},
	{Path: "/api/graphql", Type: "graphql", Description: "API GraphQL", Severity: "high"},
	{Path: "/api/gql", Type: "graphql", Description: "API GQL shorthand", Severity: "high"},
	{Path: "/graphql/api", Type: "graphql", Description: "GraphQL API", Severity: "high"},

	// Framework debug/actuator (CRITICAL — info disclosure)
	{Path: "/actuator/env", Type: "framework_debug", Description: "Spring Boot actuator env", Severity: "critical"},
	{Path: "/telescope/requests", Type: "framework_debug", Description: "Laravel Telescope", Severity: "critical"},
	{Path: "/debug/default/view", Type: "framework_debug", Description: "Yii debug view", Severity: "critical"},
	{Path: "/info.php", Type: "framework_debug", Description: "PHP info", Severity: "high"},
	{Path: "/@vite/env", Type: "framework_debug", Description: "Vite env leak", Severity: "medium"},

	// Server status/info (MEDIUM)
	{Path: "/server-status", Type: "server_info", Description: "Apache server-status", Severity: "medium"},
	{Path: "/server", Type: "server_info", Description: "Server info", Severity: "medium"},
	{Path: "/version", Type: "server_info", Description: "Version info", Severity: "medium"},

	// IDE/Dev file leaks (HIGH)
	{Path: "/.vscode/sftp.json", Type: "ide_leak", Description: "VSCode SFTP credentials", Severity: "critical"},
	{Path: "/.DS_Store", Type: "ide_leak", Description: "macOS directory listing", Severity: "medium"},

	// Docker Registry (CRITICAL)
	{Path: "/v2/_catalog", Type: "docker", Description: "Docker Registry catalog", Severity: "critical"},

	// Enterprise app probes (HIGH)
	{Path: "/login.action", Type: "enterprise_probe", Description: "Struts login action", Severity: "high"},

	// Setup wizards (HIGH — observed from 152.77.98.132)
	{Path: "/setup/", Type: "setup_wizard", Description: "Setup wizard", Severity: "high"},
	{Path: "/_internal/api/setup.php", Type: "setup_wizard", Description: "Internal setup API", Severity: "critical"},
	{Path: "/api/user/", Type: "api", Description: "User API enumeration", Severity: "high"},

	// === Wave 3: Real-world scanner intel (185.177.72.60 FR, Feb 12 2026) ===

	// Docker/Infrastructure config leaks (CRITICAL)
	{Path: "/docker-compose.yml", Type: "docker_config", Description: "Docker Compose leak", Severity: "critical"},
	{Path: "/docker-compose.yaml", Type: "docker_config", Description: "Docker Compose YAML leak", Severity: "critical"},
	{Path: "/docker/.env", Type: "docker_config", Description: "Docker env file", Severity: "critical"},

	// Credential files (CRITICAL)
	{Path: "/credentials.json", Type: "credential_leak", Description: "GCP/Firebase credentials", Severity: "critical"},
	{Path: "/api/v1/namespaces/default/secrets", Type: "k8s_secrets", Description: "Kubernetes secrets API", Severity: "critical"},
	{Path: "/api/keys", Type: "credential_leak", Description: "API keys endpoint", Severity: "critical"},
	{Path: "/api/config", Type: "credential_leak", Description: "API config endpoint", Severity: "high"},

	// Payment/Stripe config (CRITICAL — attackers love payment data)
	{Path: "/stripe/.env", Type: "payment_config", Description: "Stripe env leak", Severity: "critical"},
	{Path: "/payment/.env", Type: "payment_config", Description: "Payment env leak", Severity: "critical"},
	{Path: "/api/payment/config", Type: "payment_config", Description: "Payment API config", Severity: "critical"},
	{Path: "/api/stripe", Type: "payment_config", Description: "Stripe API endpoint", Severity: "critical"},

	// WordPress config variants (HIGH — 5+ variants observed)
	{Path: "/wp-config.php~", Type: "wordpress_config", Description: "WP config backup (tilde)", Severity: "critical"},
	{Path: "/wp-config.php.bak", Type: "wordpress_config", Description: "WP config backup", Severity: "critical"},
	{Path: "/wp-config.php.old", Type: "wordpress_config", Description: "WP config old", Severity: "critical"},
	{Path: "/wp-config.php.save", Type: "wordpress_config", Description: "WP config save", Severity: "critical"},
	{Path: "/wp-config.php.txt", Type: "wordpress_config", Description: "WP config txt", Severity: "critical"},

	// Laravel internals (CRITICAL)
	{Path: "/_ignition/health-check", Type: "laravel_internal", Description: "Laravel Ignition health", Severity: "critical"},
	{Path: "/horizon/api/stats", Type: "laravel_internal", Description: "Laravel Horizon stats", Severity: "critical"},

	// CVE baseline probe (HIGH — scanner fingerprinting technique)
	{Path: "/__cve_probe_cve_test_404", Type: "cve_probe", Description: "CVE scanner baseline probe", Severity: "high"},

	// Additional env variants observed in scan
	{Path: "/.env.vite", Type: "file", Description: "Vite env file", Severity: "high"},
	{Path: "/.env.staging", Type: "file", Description: "Staging env", Severity: "critical"},
	{Path: "/.env.save", Type: "file", Description: "Saved env file", Severity: "critical"},
	{Path: "/.env.old", Type: "file", Description: "Old env file", Severity: "critical"},
	{Path: "/.env.example", Type: "file", Description: "Example env", Severity: "medium"},
	{Path: "/.env.dev", Type: "file", Description: "Dev env file", Severity: "high"},
	{Path: "/.env.bak", Type: "file", Description: "Backup env file", Severity: "critical"},
	{Path: "/.env.backup", Type: "file", Description: "Backup env file", Severity: "critical"},
	{Path: "/app/.env", Type: "file", Description: "App env file", Severity: "critical"},
	{Path: "/api/.env", Type: "file", Description: "API env file", Severity: "critical"},
	{Path: "/backend/.env", Type: "file", Description: "Backend env file", Severity: "critical"},
	{Path: "/core/.env", Type: "file", Description: "Core env file", Severity: "critical"},
	{Path: "/admin/.env", Type: "file", Description: "Admin env file", Severity: "critical"},
	{Path: "/laravel/.env", Type: "file", Description: "Laravel env file", Severity: "critical"},
	{Path: "/assets/.env", Type: "file", Description: "Assets env file", Severity: "high"},
	{Path: "/env", Type: "file", Description: "Env endpoint", Severity: "high"},
	{Path: "/env.json", Type: "file", Description: "Env JSON", Severity: "high"},
	{Path: "/env.js", Type: "file", Description: "Env JS file", Severity: "high"},
	{Path: "/__env.js", Type: "file", Description: "Internal env JS", Severity: "high"},
	{Path: "/config.env", Type: "file", Description: "Config env file", Severity: "high"},

	// Webpack/Vite dev server probes
	{Path: "/webpack-dev-server", Type: "framework_debug", Description: "Webpack dev server", Severity: "high"},
	{Path: "/__debug__/", Type: "framework_debug", Description: "Debug panel", Severity: "critical"},
	{Path: "/@vite/client", Type: "framework_debug", Description: "Vite client", Severity: "medium"},
	{Path: "/.vite/manifest.json", Type: "framework_debug", Description: "Vite manifest", Severity: "medium"},

	// Symfony profiler
	{Path: "/_profiler", Type: "framework_debug", Description: "Symfony profiler", Severity: "critical"},
	{Path: "/_profiler/latest", Type: "framework_debug", Description: "Symfony profiler latest", Severity: "critical"},
	{Path: "/_profiler/open", Type: "framework_debug", Description: "Symfony profiler open", Severity: "critical"},
	{Path: "/_wdt", Type: "framework_debug", Description: "Symfony web debug toolbar", Severity: "high"},
	{Path: "/app_dev.php", Type: "framework_debug", Description: "Symfony dev front controller", Severity: "critical"},
	{Path: "/app_dev.php/_profiler", Type: "framework_debug", Description: "Symfony dev profiler", Severity: "critical"},
}

// DefaultPrefixTraps catch scanner path variants via prefix matching
var DefaultPrefixTraps = []*PrefixTrap{
	// PHPUnit RCE scanner — libredtail-http botnet uses 20+ path variants
	{Prefix: "/vendor/phpunit", Trap: &Trap{Path: "/vendor/phpunit/*", Type: "phpunit_rce", Description: "PHPUnit eval-stdin.php RCE probe", Severity: "critical"}},
	{Prefix: "/phpunit", Trap: &Trap{Path: "/phpunit/*", Type: "phpunit_rce", Description: "PHPUnit RCE probe", Severity: "critical"}},
	{Prefix: "/lib/phpunit", Trap: &Trap{Path: "/lib/phpunit/*", Type: "phpunit_rce", Description: "PHPUnit lib RCE probe", Severity: "critical"}},

	// Exchange OWA/ECP — LeakIX probes for Exchange vulns (ProxyShell/ProxyLogon)
	{Prefix: "/ecp/", Trap: &Trap{Path: "/ecp/*", Type: "exchange_probe", Description: "Exchange ECP probe", Severity: "critical"}},
	{Prefix: "/owa/", Trap: &Trap{Path: "/owa/*", Type: "exchange_probe", Description: "Exchange OWA probe", Severity: "critical"}},

	// Jira/Confluence — LeakIX probes for Atlassian vulns
	{Prefix: "/s/", Trap: &Trap{Path: "/s/*", Type: "jira_probe", Description: "Jira/Confluence static resource probe", Severity: "high"}},

	// Spring Boot actuator variants
	{Prefix: "/actuator", Trap: &Trap{Path: "/actuator/*", Type: "framework_debug", Description: "Spring Boot actuator", Severity: "critical"}},
}

// NewEngine creates a new honeypot engine
func NewEngine() *Engine {
	e := &Engine{
		traps:    make(map[string]*Trap),
		triggers: make(map[string][]TriggerEvent),
	}

	// Load default traps
	for _, trap := range DefaultTraps {
		e.traps[trap.Path] = trap
	}

	// Load prefix traps
	e.prefixTraps = append(e.prefixTraps, DefaultPrefixTraps...)

	return e
}

// IsTrap checks if a path is a honeypot (exact or prefix match)
func (e *Engine) IsTrap(path string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if _, exists := e.traps[path]; exists {
		return true
	}
	// Check prefix traps
	for _, pt := range e.prefixTraps {
		if strings.HasPrefix(path, pt.Prefix) {
			return true
		}
	}
	return false
}

// GetTrap returns trap information for a path (exact or prefix match)
func (e *Engine) GetTrap(path string) *Trap {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if trap, exists := e.traps[path]; exists {
		return trap
	}
	// Check prefix traps
	for _, pt := range e.prefixTraps {
		if strings.HasPrefix(path, pt.Prefix) {
			return pt.Trap
		}
	}
	return nil
}

// RecordTrigger records a trap trigger event
func (e *Engine) RecordTrigger(ip, path, ua, method string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	event := TriggerEvent{
		IP:        ip,
		Path:      path,
		Timestamp: time.Now(),
		UserAgent: ua,
		Method:    method,
	}

	e.triggers[ip] = append(e.triggers[ip], event)

	// Keep only last 100 triggers per IP
	if len(e.triggers[ip]) > 100 {
		e.triggers[ip] = e.triggers[ip][len(e.triggers[ip])-100:]
	}
}

// GetTriggers returns all triggers for an IP
func (e *Engine) GetTriggers(ip string) []TriggerEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.triggers[ip]
}

// GetTriggerCount returns number of triggers for an IP
func (e *Engine) GetTriggerCount(ip string) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return len(e.triggers[ip])
}

// GetStats returns honeypot statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	totalTriggers := 0
	for _, events := range e.triggers {
		totalTriggers += len(events)
	}

	severityCounts := make(map[string]int)
	for _, trap := range e.traps {
		severityCounts[trap.Severity]++
	}

	return map[string]interface{}{
		"total_traps":     len(e.traps),
		"trapped_ips":     len(e.triggers),
		"total_triggers":  totalTriggers,
		"severity_counts": severityCounts,
	}
}
