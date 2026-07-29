/*
Package siem implements SIEM integration for SVALINN.

Migrated from:
- siem-integration.js
*/
package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// EventType represents the type of security event
type EventType string

const (
	EventThreat    EventType = "threat"
	EventBlock     EventType = "block"
	EventChallenge EventType = "challenge"
	EventAnomaly   EventType = "anomaly"
	EventAuth      EventType = "auth"
	EventAudit     EventType = "audit"
)

// Severity represents event severity
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// Event represents a SIEM-compatible security event
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      EventType              `json:"type"`
	Severity  Severity               `json:"severity"`
	Source    EventSource            `json:"source"`
	Target    EventTarget            `json:"target"`
	Action    string                 `json:"action"`
	Outcome   string                 `json:"outcome"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	MITRE     []string               `json:"mitre,omitempty"`
}

// EventSource represents the source of an event
type EventSource struct {
	IP        string `json:"ip"`
	Port      int    `json:"port,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Country   string `json:"country,omitempty"`
	ASN       string `json:"asn,omitempty"`
}

// EventTarget represents the target of an event
type EventTarget struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Host   string `json:"host,omitempty"`
}

// Connector represents a SIEM connector
type Connector interface {
	Send(event *Event) error
	Name() string
	Enabled() bool
}

// Integration is the SIEM integration hub
type Integration struct {
	connectors []Connector
	eventQueue chan *Event
	enabled    bool

	// Stats
	eventsSent int64
	errorCount int64

	shutdown chan struct{}
	wg       sync.WaitGroup
}

// Config holds integration configuration
type Config struct {
	Enabled    bool
	QueueSize  int
	Connectors []ConnectorConfig
}

// ConnectorConfig holds connector-specific config
type ConnectorConfig struct {
	Type     string
	Endpoint string
	APIKey   string
	Enabled  bool
}

// NewIntegration creates a new SIEM integration
func NewIntegration(cfg *Config) *Integration {
	queueSize := cfg.QueueSize
	if queueSize == 0 {
		queueSize = 1000
	}

	i := &Integration{
		connectors: make([]Connector, 0),
		eventQueue: make(chan *Event, queueSize),
		enabled:    cfg.Enabled,
		shutdown:   make(chan struct{}),
	}

	// Create connectors
	for _, cc := range cfg.Connectors {
		if !cc.Enabled {
			continue
		}

		switch cc.Type {
		case "webhook":
			i.connectors = append(i.connectors, NewWebhookConnector(cc.Endpoint, cc.APIKey))
		case "syslog":
			i.connectors = append(i.connectors, NewSyslogConnector(cc.Endpoint))
		case "elastic":
			i.connectors = append(i.connectors, NewElasticConnector(cc.Endpoint, cc.APIKey))
		}
	}

	// Start worker
	if cfg.Enabled {
		i.wg.Add(1)
		go i.worker()
	}

	return i
}

// Emit sends an event to all connected SIEMs
func (i *Integration) Emit(event *Event) {
	if !i.enabled || len(i.connectors) == 0 {
		return
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate ID if not set
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), event.Type)
	}

	// Non-blocking send to queue
	select {
	case i.eventQueue <- event:
	default:
		// Queue full, drop event
		i.errorCount++
	}
}

// worker processes events from the queue
func (i *Integration) worker() {
	defer i.wg.Done()

	for {
		select {
		case event := <-i.eventQueue:
			for _, connector := range i.connectors {
				if connector.Enabled() {
					if err := connector.Send(event); err != nil {
						i.errorCount++
					} else {
						i.eventsSent++
					}
				}
			}
		case <-i.shutdown:
			return
		}
	}
}

// Stop shuts down the integration
func (i *Integration) Stop() {
	close(i.shutdown)
	i.wg.Wait()
}

// Stats returns integration statistics
func (i *Integration) Stats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     i.enabled,
		"connectors":  len(i.connectors),
		"events_sent": i.eventsSent,
		"errors":      i.errorCount,
		"queue_size":  len(i.eventQueue),
	}
}

// WebhookConnector sends events via HTTP webhook
type WebhookConnector struct {
	endpoint string
	apiKey   string
	client   *http.Client
	enabled  bool
}

// NewWebhookConnector creates a new webhook connector
func NewWebhookConnector(endpoint, apiKey string) *WebhookConnector {
	return &WebhookConnector{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
		enabled:  true,
	}
}

func (w *WebhookConnector) Send(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", w.endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if w.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+w.apiKey)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook error: %d", resp.StatusCode)
	}

	return nil
}

func (w *WebhookConnector) Name() string  { return "webhook" }
func (w *WebhookConnector) Enabled() bool { return w.enabled }

// SyslogConnector sends events via syslog (placeholder)
type SyslogConnector struct {
	endpoint string
	enabled  bool
}

func NewSyslogConnector(endpoint string) *SyslogConnector {
	return &SyslogConnector{endpoint: endpoint, enabled: true}
}

func (s *SyslogConnector) Send(event *Event) error {
	// TODO: Implement syslog sending
	return nil
}

func (s *SyslogConnector) Name() string  { return "syslog" }
func (s *SyslogConnector) Enabled() bool { return s.enabled }

// ElasticConnector sends events to Elasticsearch
type ElasticConnector struct {
	endpoint string
	apiKey   string
	client   *http.Client
	enabled  bool
}

func NewElasticConnector(endpoint, apiKey string) *ElasticConnector {
	return &ElasticConnector{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: 10 * time.Second},
		enabled:  true,
	}
}

func (e *ElasticConnector) Send(event *Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/svalinn-events/_doc", e.endpoint)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (e *ElasticConnector) Name() string  { return "elasticsearch" }
func (e *ElasticConnector) Enabled() bool { return e.enabled }
