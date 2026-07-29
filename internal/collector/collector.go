/*
Package collector implements threat intelligence collectors for SVALINN.

Migrated from:
- collectors/cve-feed.js
- collectors/osint-collector.js
- collectors/threat-actors.js
- collectors/geopolitical-feed.js
*/
package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// CollectorType represents the type of collector
type CollectorType string

const (
	CollectorCVE          CollectorType = "cve"
	CollectorOSINT        CollectorType = "osint"
	CollectorThreatActor  CollectorType = "threat_actor"
	CollectorGeopolitical CollectorType = "geopolitical"
)

// Collector is the interface for all collectors
type Collector interface {
	Name() string
	Type() CollectorType
	Collect(ctx context.Context) ([]Item, error)
	Enabled() bool
	SetEnabled(enabled bool)
}

// Item represents a collected intelligence item
type Item struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Severity    string                 `json:"severity,omitempty"`
	CVSSScore   float64                `json:"cvss_score,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	IOCs        []string               `json:"iocs,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
}

// Manager manages multiple collectors
type Manager struct {
	collectors []Collector
	items      sync.Map // map[string]*Item
	schedule   *time.Ticker

	// Stats
	totalCollected int64
	lastRun        time.Time

	shutdown chan struct{}
	wg       sync.WaitGroup
}

// NewManager creates a new collector manager
func NewManager(interval time.Duration) *Manager {
	return &Manager{
		collectors: make([]Collector, 0),
		schedule:   time.NewTicker(interval),
		shutdown:   make(chan struct{}),
	}
}

// Register registers a collector
func (m *Manager) Register(c Collector) {
	m.collectors = append(m.collectors, c)
}

// Start starts the collector scheduler
func (m *Manager) Start() {
	m.wg.Add(1)
	go m.run()
}

// run is the collector loop
func (m *Manager) run() {
	defer m.wg.Done()

	// Run immediately on start
	m.collectAll()

	for {
		select {
		case <-m.schedule.C:
			m.collectAll()
		case <-m.shutdown:
			return
		}
	}
}

// collectAll runs all collectors
func (m *Manager) collectAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	m.lastRun = time.Now()

	for _, c := range m.collectors {
		if !c.Enabled() {
			continue
		}

		items, err := c.Collect(ctx)
		if err != nil {
			continue
		}

		for _, item := range items {
			m.items.Store(item.ID, &item)
			m.totalCollected++
		}
	}
}

// GetItems returns all collected items
func (m *Manager) GetItems() []Item {
	var result []Item

	m.items.Range(func(_, value interface{}) bool {
		item := value.(*Item)
		result = append(result, *item)
		return true
	})

	return result
}

// Stop stops the collector manager
func (m *Manager) Stop() {
	m.schedule.Stop()
	close(m.shutdown)
	m.wg.Wait()
}

// Stats returns manager statistics
func (m *Manager) Stats() map[string]interface{} {
	return map[string]interface{}{
		"collectors":      len(m.collectors),
		"total_collected": m.totalCollected,
		"last_run":        m.lastRun,
	}
}

// CVECollector collects CVE data from NVD
type CVECollector struct {
	client  *http.Client
	enabled bool
}

func NewCVECollector() *CVECollector {
	return &CVECollector{
		client:  &http.Client{Timeout: 30 * time.Second},
		enabled: true,
	}
}

func (c *CVECollector) Name() string            { return "NVD CVE Feed" }
func (c *CVECollector) Type() CollectorType     { return CollectorCVE }
func (c *CVECollector) Enabled() bool           { return c.enabled }
func (c *CVECollector) SetEnabled(enabled bool) { c.enabled = enabled }

func (c *CVECollector) Collect(ctx context.Context) ([]Item, error) {
	// NVD API 2.0
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					DescriptionData []struct {
						Value string `json:"value"`
					} `json:"descriptions"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var items []Item
	for _, vuln := range result.Vulnerabilities {
		description := ""
		if len(vuln.CVE.Description.DescriptionData) > 0 {
			description = vuln.CVE.Description.DescriptionData[0].Value
		}

		cvss := 0.0
		if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
			cvss = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		}

		severity := "low"
		if cvss >= 9.0 {
			severity = "critical"
		} else if cvss >= 7.0 {
			severity = "high"
		} else if cvss >= 4.0 {
			severity = "medium"
		}

		items = append(items, Item{
			ID:          vuln.CVE.ID,
			Type:        "cve",
			Title:       vuln.CVE.ID,
			Description: description,
			Source:      "NVD",
			Timestamp:   time.Now(),
			Severity:    severity,
			CVSSScore:   cvss,
		})
	}

	return items, nil
}

// ThreatActorCollector collects threat actor information
type ThreatActorCollector struct {
	enabled bool
}

func NewThreatActorCollector() *ThreatActorCollector {
	return &ThreatActorCollector{enabled: true}
}

func (c *ThreatActorCollector) Name() string            { return "Threat Actors" }
func (c *ThreatActorCollector) Type() CollectorType     { return CollectorThreatActor }
func (c *ThreatActorCollector) Enabled() bool           { return c.enabled }
func (c *ThreatActorCollector) SetEnabled(enabled bool) { c.enabled = enabled }

func (c *ThreatActorCollector) Collect(ctx context.Context) ([]Item, error) {
	// Built-in threat actors relevant to SEA region
	actors := []Item{
		{ID: "APT41", Type: "threat_actor", Title: "APT41 (Double Dragon)", Source: "Internal", Severity: "critical", Tags: []string{"China", "espionage", "finance"}},
		{ID: "Lazarus", Type: "threat_actor", Title: "Lazarus Group", Source: "Internal", Severity: "critical", Tags: []string{"DPRK", "finance", "cryptocurrency"}},
		{ID: "Ocean Buffalo", Type: "threat_actor", Title: "Ocean Buffalo (APT32)", Source: "Internal", Severity: "high", Tags: []string{"Vietnam", "SEA", "espionage"}},
		{ID: "Mustang Panda", Type: "threat_actor", Title: "Mustang Panda", Source: "Internal", Severity: "high", Tags: []string{"China", "SEA", "government"}},
	}

	for i := range actors {
		actors[i].Timestamp = time.Now()
	}

	return actors, nil
}
