/*
Package deception implements deception and honeypot features for SVALINN.

Migrated from:
- deception-intel.js
- deception-ladder.js
- hidden-canaries.js
- honeypot-network.js
- sandbox-deception.js
*/
package deception

import (
	"math/rand"
	"sync"
	"time"
)

// TrapType represents the type of deception trap
type TrapType string

const (
	TrapCanary    TrapType = "canary"    // Hidden tokens/endpoints
	TrapHoneypot  TrapType = "honeypot"  // Fake services
	TrapTarpit    TrapType = "tarpit"    // Slow responses
	TrapLabyrinth TrapType = "labyrinth" // Endless redirects
	TrapFake      TrapType = "fake"      // Fake data
)

// Trap represents a deception trap
type Trap struct {
	ID          string
	Type        TrapType
	Path        string
	Description string
	Enabled     bool
	Triggers    int64
	LastTrigger time.Time
	CreatedAt   time.Time
}

// TriggerEvent represents a trap trigger event
type TriggerEvent struct {
	TrapID    string
	TrapType  TrapType
	IP        string
	UserAgent string
	Path      string
	Timestamp time.Time
	Headers   map[string]string
}

// Engine is the deception engine
type Engine struct {
	traps       map[string]*Trap
	canaryPaths map[string]bool

	// Event callback
	onTrigger func(*TriggerEvent)

	// Stats
	totalTriggers   int64
	uniqueAttackers int64
	attackerIPs     sync.Map

	lock sync.RWMutex
}

// Config holds deception engine configuration
type Config struct {
	Enabled       bool
	CanaryPaths   []string
	HoneypotPaths []string
	TarpitDelay   time.Duration
}

// NewEngine creates a new deception engine
func NewEngine(cfg *Config) *Engine {
	e := &Engine{
		traps:       make(map[string]*Trap),
		canaryPaths: make(map[string]bool),
	}

	// Load default traps
	e.loadDefaultTraps()

	// Add custom canary paths
	for _, path := range cfg.CanaryPaths {
		e.AddCanary(path)
	}

	return e
}

// loadDefaultTraps loads built-in deception traps
func (e *Engine) loadDefaultTraps() {
	defaults := []*Trap{
		// Canary tokens (hidden paths that shouldn't be accessed)
		{ID: "canary-admin", Type: TrapCanary, Path: "/secret-admin-panel", Description: "Hidden admin panel"},
		{ID: "canary-backup", Type: TrapCanary, Path: "/backup.zip", Description: "Fake backup file"},
		{ID: "canary-config", Type: TrapCanary, Path: "/config.old", Description: "Fake old config"},
		{ID: "canary-git", Type: TrapCanary, Path: "/.git/config", Description: "Git config exposure"},
		{ID: "canary-env", Type: TrapCanary, Path: "/.env.bak", Description: "Env backup file"},
		{ID: "canary-debug", Type: TrapCanary, Path: "/debug.php", Description: "Debug endpoint"},
		{ID: "canary-test", Type: TrapCanary, Path: "/test.php", Description: "Test endpoint"},

		// Honeypot endpoints (fake login pages, etc.)
		{ID: "honeypot-wp", Type: TrapHoneypot, Path: "/wp-login.php", Description: "Fake WordPress login"},
		{ID: "honeypot-phpmyadmin", Type: TrapHoneypot, Path: "/phpmyadmin", Description: "Fake phpMyAdmin"},
		{ID: "honeypot-manager", Type: TrapHoneypot, Path: "/manager/html", Description: "Fake Tomcat manager"},
		{ID: "honeypot-solr", Type: TrapHoneypot, Path: "/solr/admin", Description: "Fake Solr admin"},

		// Tarpit endpoints (slow down attackers)
		{ID: "tarpit-robots", Type: TrapTarpit, Path: "/robots.txt.bak", Description: "Tarpit for scanners"},
		{ID: "tarpit-sitemap", Type: TrapTarpit, Path: "/sitemap.xml.old", Description: "Tarpit for crawlers"},
	}

	for _, trap := range defaults {
		trap.Enabled = true
		trap.CreatedAt = time.Now()
		e.traps[trap.ID] = trap
		e.canaryPaths[trap.Path] = true
	}
}

// Check checks if a path triggers a trap
func (e *Engine) Check(path string, ip string, userAgent string, headers map[string]string) (*Trap, bool) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	// Check exact matches
	if e.canaryPaths[path] {
		for _, trap := range e.traps {
			if trap.Path == path && trap.Enabled {
				return trap, true
			}
		}
	}

	// Check pattern matches (simplified)
	suspiciousPaths := []string{
		"/.git", "/.svn", "/.env", "/.htaccess", "/.htpasswd",
		"/wp-admin", "/wp-content", "/wp-includes",
		"/phpmyadmin", "/pma", "/mysql", "/adminer",
		"/shell", "/cmd", "/exec", "/system",
		"/backup", "/dump", "/export",
	}

	for _, sus := range suspiciousPaths {
		if containsPath(path, sus) {
			// Create dynamic trap for this path
			return &Trap{
				ID:      "dynamic-" + path,
				Type:    TrapCanary,
				Path:    path,
				Enabled: true,
			}, true
		}
	}

	return nil, false
}

// Trigger records a trap trigger
func (e *Engine) Trigger(trap *Trap, ip string, userAgent string, headers map[string]string) {
	e.lock.Lock()
	defer e.lock.Unlock()

	trap.Triggers++
	trap.LastTrigger = time.Now()
	e.totalTriggers++

	// Track unique attackers
	if _, seen := e.attackerIPs.Load(ip); !seen {
		e.attackerIPs.Store(ip, true)
		e.uniqueAttackers++
	}

	// Fire callback
	if e.onTrigger != nil {
		e.onTrigger(&TriggerEvent{
			TrapID:    trap.ID,
			TrapType:  trap.Type,
			IP:        ip,
			UserAgent: userAgent,
			Path:      trap.Path,
			Timestamp: time.Now(),
			Headers:   headers,
		})
	}
}

// OnTrigger sets the trigger callback
func (e *Engine) OnTrigger(fn func(*TriggerEvent)) {
	e.onTrigger = fn
}

// AddCanary adds a new canary path
func (e *Engine) AddCanary(path string) {
	e.lock.Lock()
	defer e.lock.Unlock()

	id := "custom-" + path
	e.traps[id] = &Trap{
		ID:        id,
		Type:      TrapCanary,
		Path:      path,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	e.canaryPaths[path] = true
}

// GetTrap returns a trap by ID
func (e *Engine) GetTrap(id string) *Trap {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.traps[id]
}

// GetAllTraps returns all traps
func (e *Engine) GetAllTraps() []*Trap {
	e.lock.RLock()
	defer e.lock.RUnlock()

	var result []*Trap
	for _, trap := range e.traps {
		result = append(result, trap)
	}
	return result
}

// GetTriggeredTraps returns traps that have been triggered
func (e *Engine) GetTriggeredTraps() []*Trap {
	e.lock.RLock()
	defer e.lock.RUnlock()

	var result []*Trap
	for _, trap := range e.traps {
		if trap.Triggers > 0 {
			result = append(result, trap)
		}
	}
	return result
}

// GenerateTarpit generates a slow response (tarpit)
func (e *Engine) GenerateTarpit() string {
	// Generate random fake content slowly
	delay := time.Duration(rand.Intn(5)+1) * time.Second
	time.Sleep(delay)

	fake := `<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<h1>Please wait...</h1>
<script>setTimeout(function(){location.reload();}, 5000);</script>
</body>
</html>`

	return fake
}

// GenerateLabyrinth generates an endless redirect maze
func (e *Engine) GenerateLabyrinth() string {
	pages := []string{
		"/admin/login", "/user/dashboard", "/api/v1/auth",
		"/system/config", "/settings/security", "/data/export",
	}

	next := pages[rand.Intn(len(pages))]
	return next + "?token=" + randString(32)
}

// Stats returns engine statistics
func (e *Engine) Stats() map[string]interface{} {
	e.lock.RLock()
	defer e.lock.RUnlock()

	return map[string]interface{}{
		"total_traps":      len(e.traps),
		"total_triggers":   e.totalTriggers,
		"unique_attackers": e.uniqueAttackers,
	}
}

// Helpers
func containsPath(path, substr string) bool {
	return len(path) >= len(substr) && (path == substr ||
		(len(path) > len(substr) && path[:len(substr)] == substr))
}

func randString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
