/*
Package server - Honeypot Handler Integration

Connects honeypot engine with taunt system
*/
package server

import (
	"net/http"
)

// honeypotMiddleware checks if path is a honeypot trap
func (s *Server) honeypotMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a honeypot trap
			if s.honeypotEngine != nil && s.honeypotEngine.IsTrap(r.URL.Path) {
				trap := s.honeypotEngine.GetTrap(r.URL.Path)
				clientIP := s.getClientIP(r)

				// Record the trigger
				s.honeypotEngine.RecordTrigger(
					clientIP,
					r.URL.Path,
					r.UserAgent(),
					r.Method,
				)

				// Record block in Mitnick tracker
				if s.mitnickTracker != nil {
					s.mitnickTracker.RecordBlock(clientIP)

					// Check for persistent attacker escalation
					if shouldEscalate, duration, reason := s.mitnickTracker.ShouldEscalateBlock(clientIP); shouldEscalate {
						s.log.Error("PERSISTENT ATTACKER ESCALATED",
							"ip", clientIP,
							"path", r.URL.Path,
							"block_duration", duration,
							"reason", reason)
						if s.countermeasures != nil {
							entry := s.countermeasures.TempBlock(clientIP, "Honeypot escalation: "+reason)
							s.log.Warn("Honeypot auto-blocked via countermeasures",
								"ip", clientIP,
								"path", r.URL.Path,
								"block_level", entry.Level,
								"block_until", entry.Until)
						}
					}
				}

				// Escalate deception ladder
				if s.deceptionLadder != nil {
					s.deceptionLadder.Escalate(clientIP, "honeypot_triggered")
				}

				// Serve honeypot response with taunts
				s.handleHoneypot(w, r, trap.Type)
				return
			}

			// Not a trap, continue
			next.ServeHTTP(w, r)
		})
	}
}

// honeypotHandler serves specific honeypot endpoints
func (s *Server) honeypotHandler(w http.ResponseWriter, r *http.Request) {
	// Determine trap type from path
	trapType := "file"
	path := r.URL.Path

	// Use honeypot engine trap type if available
	if s.honeypotEngine != nil {
		if trap := s.honeypotEngine.GetTrap(path); trap != nil {
			trapType = trap.Type
		}
	}
	if trapType == "file" {
		// Fallback for paths not in engine — map to specific response types
		switch {
		case path == "/.env" || path == "/.env.local" || path == "/.env.production" ||
			path == "/.env.vite" || path == "/.env.staging" || path == "/.env.save" ||
			path == "/.env.old" || path == "/.env.example" || path == "/.env.dev" ||
			path == "/.env.bak" || path == "/.env.backup" ||
			path == "/app/.env" || path == "/api/.env" || path == "/backend/.env" ||
			path == "/core/.env" || path == "/admin/.env" || path == "/laravel/.env" ||
			path == "/assets/.env" || path == "/env" || path == "/env.json" ||
			path == "/env.js" || path == "/__env.js" || path == "/config.env":
			trapType = "env"
		case path == "/.git/config" || path == "/.git/HEAD":
			trapType = "git"
		case path == "/admin" || path == "/administrator" || path == "/wp-admin" || path == "/phpmyadmin":
			trapType = "admin"
		case path == "/backup.sql" || path == "/database.sql" || path == "/dump.sql":
			trapType = "database"
		case path == "/backup.zip" || path == "/backup.tar.gz":
			trapType = "backup"
		case path == "/api/internal" || path == "/api/admin":
			trapType = "api"
		}
	}

	clientIP := s.getClientIP(r)

	// Record trigger
	if s.honeypotEngine != nil {
		s.honeypotEngine.RecordTrigger(
			clientIP,
			r.URL.Path,
			r.UserAgent(),
			r.Method,
		)
	}

	// Record block in Mitnick tracker
	if s.mitnickTracker != nil {
		s.mitnickTracker.RecordBlock(clientIP)

		if shouldEscalate, duration, reason := s.mitnickTracker.ShouldEscalateBlock(clientIP); shouldEscalate {
			s.log.Error("PERSISTENT ATTACKER ESCALATED",
				"ip", clientIP,
				"path", r.URL.Path,
				"block_duration", duration,
				"reason", reason)
			if s.countermeasures != nil {
				entry := s.countermeasures.TempBlock(clientIP, "Honeypot escalation: "+reason)
				s.log.Warn("Honeypot auto-blocked via countermeasures",
					"ip", clientIP,
					"path", r.URL.Path,
					"block_level", entry.Level,
					"block_until", entry.Until)
			}
		}
	}

	// Escalate deception
	if s.deceptionLadder != nil {
		s.deceptionLadder.Escalate(clientIP, "honeypot_triggered")
	}

	// Serve taunt response
	s.handleHoneypot(w, r, trapType)
}

// setupHoneypotRoutes registers all honeypot endpoints
func (s *Server) setupHoneypotRoutes() {
	if s.honeypotEngine == nil {
		return
	}

	// Register each honeypot trap
	s.router.HandleFunc("/.env", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/.env.local", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.production", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.git/config", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.git/HEAD", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.gitignore", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/admin", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/admin/login", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/administrator", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/wp-admin", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/phpmyadmin", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/pma", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/cpanel", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/backup.sql", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/database.sql", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/dump.sql", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/backup.zip", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/backup.tar.gz", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/internal", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/api/admin", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/api/debug", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/config.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/config.php", s.honeypotHandler).Methods("GET")

	// Scanner bait routes (libredtail-http botnet patterns)
	s.router.HandleFunc("/observatory", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/hello.world", s.honeypotHandler).Methods("GET", "POST")

	// === LeakIX-observed paths (commercial vuln scanner, Feb 2026) ===

	// Swagger/OpenAPI documentation
	s.router.HandleFunc("/swagger.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/swagger-ui.html", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/swagger/index.html", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/swagger/swagger-ui.html", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/swagger/v1/swagger.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/v2/api-docs", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/v3/api-docs", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api-docs/swagger.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/swagger.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/webjars/swagger-ui/index.html", s.honeypotHandler).Methods("GET")

	// GraphQL endpoints
	s.router.HandleFunc("/graphql", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/api/graphql", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/api/gql", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/graphql/api", s.honeypotHandler).Methods("GET", "POST")

	// Framework debug/actuator
	s.router.HandleFunc("/actuator/env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/telescope/requests", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/debug/default/view", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/info.php", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/@vite/env", s.honeypotHandler).Methods("GET")

	// Server status/info
	s.router.HandleFunc("/server-status", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/server", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/version", s.honeypotHandler).Methods("GET")

	// IDE/Dev file leaks
	s.router.HandleFunc("/.vscode/sftp.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.DS_Store", s.honeypotHandler).Methods("GET")

	// Docker Registry
	s.router.HandleFunc("/v2/_catalog", s.honeypotHandler).Methods("GET")

	// Enterprise app probes
	s.router.HandleFunc("/login.action", s.honeypotHandler).Methods("GET", "POST")

	// Setup wizards (observed from 152.77.98.132)
	s.router.HandleFunc("/setup/", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/_internal/api/setup.php", s.honeypotHandler).Methods("GET", "POST")
	s.router.HandleFunc("/api/user/", s.honeypotHandler).Methods("GET")

	// === Wave 3: Real-world scanner intel (185.177.72.60 FR, Feb 12 2026) ===

	// Docker/Infrastructure config
	s.router.HandleFunc("/docker-compose.yml", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/docker-compose.yaml", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/docker/.env", s.honeypotHandler).Methods("GET")

	// Credential files
	s.router.HandleFunc("/credentials.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/v1/namespaces/default/secrets", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/keys", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/config", s.honeypotHandler).Methods("GET")

	// Payment/Stripe config
	s.router.HandleFunc("/stripe/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/payment/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/payment/config", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/stripe", s.honeypotHandler).Methods("GET")

	// WordPress config variants
	s.router.HandleFunc("/wp-config.php~", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/wp-config.php.bak", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/wp-config.php.old", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/wp-config.php.save", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/wp-config.php.txt", s.honeypotHandler).Methods("GET")

	// Laravel internals
	s.router.HandleFunc("/_ignition/health-check", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/horizon/api/stats", s.honeypotHandler).Methods("GET")

	// CVE baseline probe
	s.router.HandleFunc("/__cve_probe_cve_test_404", s.honeypotHandler).Methods("GET")

	// Additional env variants
	s.router.HandleFunc("/.env.vite", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.staging", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.save", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.old", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.example", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.dev", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.bak", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.env.backup", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/app/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/api/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/backend/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/core/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/admin/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/laravel/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/assets/.env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/env", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/env.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/env.js", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/__env.js", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/config.env", s.honeypotHandler).Methods("GET")

	// Webpack/Vite/Symfony debug
	s.router.HandleFunc("/webpack-dev-server", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/__debug__/", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/@vite/client", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/.vite/manifest.json", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/_profiler", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/_profiler/latest", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/_profiler/open", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/_wdt", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/app_dev.php", s.honeypotHandler).Methods("GET")
	s.router.HandleFunc("/app_dev.php/_profiler", s.honeypotHandler).Methods("GET")

	// Prefix-matched paths (phpunit, exchange, jira, actuator) handled by honeypotMiddleware

	stats := s.honeypotEngine.GetStats()
	s.log.Info("Honeypot routes active", "traps", stats["total_traps"], "prefix_traps", 7)
}
