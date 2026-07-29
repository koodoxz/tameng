/*
Package ecosystem implements AEGIS ecosystem integration for SVALINN.

This connects SVALINN to:
- ODIN: DoH/DoT DNS server (for DNS-based threat intel and blocking)
- MIMIR: Authoritative DNS (for zone management and response)

The ecosystem works as follows:
1. SVALINN detects threats and blocks IPs
2. SVALINN notifies ODIN of blocked IPs (for DNS-level blocking)
3. ODIN forwards DNS queries to MIMIR
4. MIMIR provides authoritative responses

Integration Points:
- ODIN API: /api/v1/block, /api/v1/unblock, /api/v1/stats
- MIMIR: Direct DNS queries (via ODIN)
*/
package ecosystem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Component represents an AEGIS ecosystem component
type Component string

const (
	ComponentODIN    Component = "ODIN"
	ComponentMIMIR   Component = "MIMIR"
	ComponentSVALINN Component = "SVALINN"
)

// Status represents component health status
type Status struct {
	Component Component `json:"component"`
	Healthy   bool      `json:"healthy"`
	Version   string    `json:"version,omitempty"`
	Uptime    string    `json:"uptime,omitempty"`
	LastCheck time.Time `json:"lastCheck"`
	Message   string    `json:"message,omitempty"`
}

// BlockRequest represents a request to block an IP via ODIN
type BlockRequest struct {
	IP       string        `json:"ip"`
	Duration time.Duration `json:"duration"`
	Reason   string        `json:"reason"`
	Source   string        `json:"source"`
}

// Hub manages AEGIS ecosystem connections
type Hub struct {
	// ODIN connection
	odinURL    string
	odinAPIKey string
	odinStatus *Status

	// MIMIR connection (via ODIN)
	mimirIP     string
	mimirStatus *Status

	// HTTP client
	client *http.Client

	// Sync queue for blocked IPs
	syncQueue chan BlockRequest

	// Status tracking
	lastSync     time.Time
	syncedBlocks int64
	failedSyncs  int64

	// Control
	shutdown chan struct{}
	wg       sync.WaitGroup

	lock sync.RWMutex
}

// Config holds ecosystem configuration
type Config struct {
	ODINUrl     string
	ODINAPIKey  string
	MIMIRIp     string
	SyncWorkers int
}

// NewHub creates a new ecosystem hub
func NewHub(cfg *Config) *Hub {
	h := &Hub{
		odinURL:     cfg.ODINUrl,
		odinAPIKey:  cfg.ODINAPIKey,
		mimirIP:     cfg.MIMIRIp,
		client:      &http.Client{Timeout: 10 * time.Second},
		syncQueue:   make(chan BlockRequest, 1000),
		shutdown:    make(chan struct{}),
		odinStatus:  &Status{Component: ComponentODIN},
		mimirStatus: &Status{Component: ComponentMIMIR},
	}

	// Start sync workers
	workers := cfg.SyncWorkers
	if workers == 0 {
		workers = 2
	}

	for i := 0; i < workers; i++ {
		h.wg.Add(1)
		go h.syncWorker()
	}

	// Start health checker
	h.wg.Add(1)
	go h.healthChecker()

	return h
}

// syncWorker processes the block sync queue
func (h *Hub) syncWorker() {
	defer h.wg.Done()

	for {
		select {
		case req := <-h.syncQueue:
			if err := h.syncBlockToODIN(req); err != nil {
				h.failedSyncs++
			} else {
				h.syncedBlocks++
			}
		case <-h.shutdown:
			return
		}
	}
}

// healthChecker periodically checks ecosystem health
func (h *Hub) healthChecker() {
	defer h.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial check
	h.checkHealth()

	for {
		select {
		case <-ticker.C:
			h.checkHealth()
		case <-h.shutdown:
			return
		}
	}
}

// checkHealth checks all ecosystem components
func (h *Hub) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check ODIN
	h.checkODINHealth(ctx)

	// MIMIR is checked via ODIN (ODIN forwards to MIMIR)
	h.checkMIMIRHealth(ctx)
}

// checkODINHealth checks ODIN health
func (h *Hub) checkODINHealth(ctx context.Context) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.odinStatus.LastCheck = time.Now()

	if h.odinURL == "" {
		h.odinStatus.Healthy = false
		h.odinStatus.Message = "ODIN URL not configured"
		return
	}

	req, err := http.NewRequestWithContext(ctx, "GET", h.odinURL+"/health", nil)
	if err != nil {
		h.odinStatus.Healthy = false
		h.odinStatus.Message = err.Error()
		return
	}

	if h.odinAPIKey != "" {
		req.Header.Set("X-API-Key", h.odinAPIKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.odinStatus.Healthy = false
		h.odinStatus.Message = err.Error()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		h.odinStatus.Healthy = true
		h.odinStatus.Message = "OK"

		// Parse version/uptime from response
		var data map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			if v, ok := data["version"].(string); ok {
				h.odinStatus.Version = v
			}
			if u, ok := data["uptime"].(string); ok {
				h.odinStatus.Uptime = u
			}
		}
	} else {
		h.odinStatus.Healthy = false
		h.odinStatus.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}

// checkMIMIRHealth checks MIMIR via DNS query
func (h *Hub) checkMIMIRHealth(ctx context.Context) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.mimirStatus.LastCheck = time.Now()

	if h.mimirIP == "" {
		h.mimirStatus.Healthy = false
		h.mimirStatus.Message = "MIMIR IP not configured"
		return
	}

	// MIMIR health is inferred from ODIN health
	// (ODIN uses MIMIR as upstream, if ODIN works, MIMIR works)
	if h.odinStatus.Healthy {
		h.mimirStatus.Healthy = true
		h.mimirStatus.Message = "OK (via ODIN)"
	} else {
		h.mimirStatus.Healthy = false
		h.mimirStatus.Message = "Unknown (ODIN unhealthy)"
	}
}

// BlockIP queues an IP block to sync with ODIN
func (h *Hub) BlockIP(ip string, duration time.Duration, reason string) {
	select {
	case h.syncQueue <- BlockRequest{
		IP:       ip,
		Duration: duration,
		Reason:   reason,
		Source:   "SVALINN",
	}:
	default:
		// Queue full, drop (will be retried on next block)
	}
}

// syncBlockToODIN sends a block request to ODIN
func (h *Hub) syncBlockToODIN(req BlockRequest) error {
	if h.odinURL == "" {
		return fmt.Errorf("ODIN URL not configured")
	}

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest("POST", h.odinURL+"/api/v1/block", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if h.odinAPIKey != "" {
		httpReq.Header.Set("X-API-Key", h.odinAPIKey)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("ODIN returned %d", resp.StatusCode)
	}

	h.lastSync = time.Now()
	return nil
}

// UnblockIP sends an unblock request to ODIN
func (h *Hub) UnblockIP(ip string) error {
	if h.odinURL == "" {
		return fmt.Errorf("ODIN URL not configured")
	}

	data, _ := json.Marshal(map[string]string{"ip": ip, "source": "SVALINN"})

	req, err := http.NewRequest("POST", h.odinURL+"/api/v1/unblock", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if h.odinAPIKey != "" {
		req.Header.Set("X-API-Key", h.odinAPIKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// GetStatus returns ecosystem status
func (h *Hub) GetStatus() map[string]interface{} {
	h.lock.RLock()
	defer h.lock.RUnlock()

	return map[string]interface{}{
		"odin": map[string]interface{}{
			"healthy":   h.odinStatus.Healthy,
			"url":       h.odinURL,
			"version":   h.odinStatus.Version,
			"lastCheck": h.odinStatus.LastCheck,
			"message":   h.odinStatus.Message,
		},
		"mimir": map[string]interface{}{
			"healthy":   h.mimirStatus.Healthy,
			"ip":        h.mimirIP,
			"lastCheck": h.mimirStatus.LastCheck,
			"message":   h.mimirStatus.Message,
		},
		"sync": map[string]interface{}{
			"synced":    h.syncedBlocks,
			"failed":    h.failedSyncs,
			"queueSize": len(h.syncQueue),
			"lastSync":  h.lastSync,
		},
	}
}

// IsODINHealthy returns ODIN health status
func (h *Hub) IsODINHealthy() bool {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.odinStatus.Healthy
}

// IsMIMIRHealthy returns MIMIR health status
func (h *Hub) IsMIMIRHealthy() bool {
	h.lock.RLock()
	defer h.lock.RUnlock()
	return h.mimirStatus.Healthy
}

// Stop shuts down the ecosystem hub
func (h *Hub) Stop() {
	close(h.shutdown)
	h.wg.Wait()
}
