/*
Package hardening implements security hardening for SVALINN.

Migrated from:
- security-hardening.js
- production-hardening.js
- memory-protection.js
- memory-safeguard.js
*/
package hardening

import (
	"net/http"
	"runtime"
	"sync"
	"time"
)

// SecurityHeaders contains recommended security headers
var SecurityHeaders = map[string]string{
	"X-Content-Type-Options":            "nosniff",
	"X-Frame-Options":                   "DENY",
	"X-XSS-Protection":                  "1; mode=block",
	"Referrer-Policy":                   "strict-origin-when-cross-origin",
	"Content-Security-Policy":           "default-src 'self'",
	"Permissions-Policy":                "geolocation=(), microphone=(), camera=()",
	"Cache-Control":                     "no-store, no-cache, must-revalidate",
	"Pragma":                            "no-cache",
	"X-Permitted-Cross-Domain-Policies": "none",
}

// Hardener applies security hardening measures
type Hardener struct {
	// Memory limits
	maxGoroutines int
	maxHeapMB     int

	// Connection limits
	maxConnections int
	maxBodySize    int64

	// Rate limits
	globalRateLimit float64

	// Stats
	memoryAlerts    int64
	goroutineAlerts int64

	// Monitoring
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// Config holds hardening configuration
type Config struct {
	MaxGoroutines   int
	MaxHeapMB       int
	MaxConnections  int
	MaxBodySize     int64
	GlobalRateLimit float64
}

// New creates a new hardener
func New(cfg *Config) *Hardener {
	if cfg.MaxGoroutines == 0 {
		cfg.MaxGoroutines = 10000
	}
	if cfg.MaxHeapMB == 0 {
		cfg.MaxHeapMB = 1024 // 1GB
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 10000
	}
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 10 * 1024 * 1024 // 10MB
	}

	h := &Hardener{
		maxGoroutines:   cfg.MaxGoroutines,
		maxHeapMB:       cfg.MaxHeapMB,
		maxConnections:  cfg.MaxConnections,
		maxBodySize:     cfg.MaxBodySize,
		globalRateLimit: cfg.GlobalRateLimit,
		shutdown:        make(chan struct{}),
	}

	// Start monitoring
	h.wg.Add(1)
	go h.monitor()

	return h
}

// monitor monitors system resources
func (h *Hardener) monitor() {
	defer h.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.checkResources()
		case <-h.shutdown:
			return
		}
	}
}

// checkResources checks and enforces resource limits
func (h *Hardener) checkResources() {
	// Check goroutine count
	numGoroutines := runtime.NumGoroutine()
	if numGoroutines > h.maxGoroutines {
		h.goroutineAlerts++
		// Force GC to help cleanup
		runtime.GC()
	}

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	heapMB := memStats.Alloc / 1024 / 1024
	if int(heapMB) > h.maxHeapMB {
		h.memoryAlerts++
		// Force GC
		runtime.GC()
	}
}

// ApplyHeaders applies security headers to a response
func (h *Hardener) ApplyHeaders(w http.ResponseWriter) {
	for header, value := range SecurityHeaders {
		w.Header().Set(header, value)
	}
	w.Header().Set("Server", "SVALINN")
}

// Middleware returns a hardening middleware
func (h *Hardener) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Apply security headers
			h.ApplyHeaders(w)

			// Limit body size
			r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)

			// Check resource limits
			if runtime.NumGoroutine() > h.maxGoroutines {
				http.Error(w, "Service Overloaded", http.StatusServiceUnavailable)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// MemoryStats returns current memory statistics
func (h *Hardener) MemoryStats() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"alloc_mb":         memStats.Alloc / 1024 / 1024,
		"total_alloc_mb":   memStats.TotalAlloc / 1024 / 1024,
		"sys_mb":           memStats.Sys / 1024 / 1024,
		"num_gc":           memStats.NumGC,
		"goroutines":       runtime.NumGoroutine(),
		"memory_alerts":    h.memoryAlerts,
		"goroutine_alerts": h.goroutineAlerts,
	}
}

// ForceGC forces garbage collection
func (h *Hardener) ForceGC() {
	runtime.GC()
}

// Stop stops the hardener
func (h *Hardener) Stop() {
	close(h.shutdown)
	h.wg.Wait()
}

// SanitizeInput sanitizes user input
func SanitizeInput(input string) string {
	// Remove null bytes
	result := ""
	for _, r := range input {
		if r != 0 {
			result += string(r)
		}
	}
	return result
}

// ValidatePathDepth checks for excessive path depth
func ValidatePathDepth(path string, maxDepth int) bool {
	depth := 0
	for _, c := range path {
		if c == '/' {
			depth++
		}
	}
	return depth <= maxDepth
}
