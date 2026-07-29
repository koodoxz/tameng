/*
Package db implements database operations for SVALINN.

Migrated from:
- core/database.js
- core/db-init.js
*/
package db

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database is the SVALINN database wrapper
type Database struct {
	db   *sql.DB
	path string
	lock sync.RWMutex
}

// Config holds database configuration
type Config struct {
	Type     string
	Path     string
	InMemory bool
}

// New creates a new database connection
func New(cfg *Config) (*Database, error) {
	var dsn string
	if cfg.InMemory {
		dsn = ":memory:"
	} else {
		dsn = cfg.Path
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	d := &Database{
		db:   db,
		path: cfg.Path,
	}

	// Initialize schema
	if err := d.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return d, nil
}

// initSchema creates the database tables
func (d *Database) initSchema() error {
	schemas := []string{
		// Threats table
		`CREATE TABLE IF NOT EXISTS threats (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			ip TEXT NOT NULL,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			score REAL,
			path TEXT,
			payload TEXT,
			user_agent TEXT,
			country TEXT,
			mitre_ids TEXT,
			blocked BOOLEAN DEFAULT FALSE
		)`,

		// Actors table
		`CREATE TABLE IF NOT EXISTS actors (
			ip TEXT PRIMARY KEY,
			first_seen DATETIME,
			last_seen DATETIME,
			request_count INTEGER DEFAULT 0,
			threat_score REAL DEFAULT 0,
			is_blocked BOOLEAN DEFAULT FALSE,
			blocked_until DATETIME,
			block_reason TEXT,
			country TEXT,
			asn TEXT
		)`,

		// Signatures table
		`CREATE TABLE IF NOT EXISTS signatures (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			category TEXT NOT NULL,
			severity TEXT NOT NULL,
			pattern TEXT NOT NULL,
			enabled BOOLEAN DEFAULT TRUE,
			hit_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Gray zone table
		`CREATE TABLE IF NOT EXISTS gray_zone (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			ip TEXT NOT NULL,
			method TEXT,
			path TEXT,
			body TEXT,
			score REAL,
			reason TEXT,
			analyzed BOOLEAN DEFAULT FALSE,
			verdict TEXT
		)`,

		// Stats table
		`CREATE TABLE IF NOT EXISTS stats (
			id INTEGER PRIMARY KEY,
			date DATE UNIQUE,
			requests INTEGER DEFAULT 0,
			blocked INTEGER DEFAULT 0,
			challenges INTEGER DEFAULT 0,
			threats INTEGER DEFAULT 0
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_actors_threat_score ON actors(threat_score)`,
		`CREATE INDEX IF NOT EXISTS idx_gray_zone_analyzed ON gray_zone(analyzed)`,
	}

	for _, schema := range schemas {
		if _, err := d.db.Exec(schema); err != nil {
			return err
		}
	}

	return nil
}

// InsertThreat inserts a threat record
func (d *Database) InsertThreat(threat *Threat) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO threats (id, ip, type, severity, score, path, payload, user_agent, country, mitre_ids, blocked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, threat.ID, threat.IP, threat.Type, threat.Severity, threat.Score,
		threat.Path, threat.Payload, threat.UserAgent, threat.Country,
		threat.MITREIDs, threat.Blocked)

	return err
}

// Threat represents a threat record
type Threat struct {
	ID        string
	Timestamp time.Time
	IP        string
	Type      string
	Severity  string
	Score     float64
	Path      string
	Payload   string
	UserAgent string
	Country   string
	MITREIDs  string
	Blocked   bool
}

// GetRecentThreats returns recent threats
func (d *Database) GetRecentThreats(limit int) ([]Threat, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, timestamp, ip, type, severity, score, path, payload, user_agent, country, mitre_ids, blocked
		FROM threats
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []Threat
	for rows.Next() {
		var t Threat
		if err := rows.Scan(&t.ID, &t.Timestamp, &t.IP, &t.Type, &t.Severity,
			&t.Score, &t.Path, &t.Payload, &t.UserAgent, &t.Country,
			&t.MITREIDs, &t.Blocked); err != nil {
			continue
		}
		threats = append(threats, t)
	}

	return threats, nil
}

// UpsertActor inserts or updates an actor
func (d *Database) UpsertActor(actor *Actor) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO actors (ip, first_seen, last_seen, request_count, threat_score, is_blocked, country, asn)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_seen = excluded.last_seen,
			request_count = request_count + 1,
			threat_score = excluded.threat_score
	`, actor.IP, actor.FirstSeen, actor.LastSeen, actor.RequestCount,
		actor.ThreatScore, actor.IsBlocked, actor.Country, actor.ASN)

	return err
}

// Actor represents an actor record
type Actor struct {
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	RequestCount int64
	ThreatScore  float64
	IsBlocked    bool
	BlockedUntil time.Time
	BlockReason  string
	Country      string
	ASN          string
}

// GetBlockedActors returns blocked actors
func (d *Database) GetBlockedActors() ([]Actor, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT ip, first_seen, last_seen, request_count, threat_score, is_blocked, blocked_until, block_reason, country, asn
		FROM actors
		WHERE is_blocked = TRUE
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actors []Actor
	for rows.Next() {
		var a Actor
		if err := rows.Scan(&a.IP, &a.FirstSeen, &a.LastSeen, &a.RequestCount,
			&a.ThreatScore, &a.IsBlocked, &a.BlockedUntil, &a.BlockReason,
			&a.Country, &a.ASN); err != nil {
			continue
		}
		actors = append(actors, a)
	}

	return actors, nil
}

// InsertGrayZone inserts a gray zone entry
func (d *Database) InsertGrayZone(entry *GrayZoneEntry) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO gray_zone (id, ip, method, path, body, score, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, entry.IP, entry.Method, entry.Path, entry.Body, entry.Score, entry.Reason)

	return err
}

// GrayZoneEntry represents a gray zone entry
type GrayZoneEntry struct {
	ID        string
	Timestamp time.Time
	IP        string
	Method    string
	Path      string
	Body      string
	Score     float64
	Reason    string
	Analyzed  bool
	Verdict   string
}

// GetUnanalyzedGrayZone returns unanalyzed gray zone entries
func (d *Database) GetUnanalyzedGrayZone(limit int) ([]GrayZoneEntry, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	rows, err := d.db.Query(`
		SELECT id, timestamp, ip, method, path, body, score, reason, analyzed, verdict
		FROM gray_zone
		WHERE analyzed = FALSE
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []GrayZoneEntry
	for rows.Next() {
		var e GrayZoneEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.IP, &e.Method, &e.Path,
			&e.Body, &e.Score, &e.Reason, &e.Analyzed, &e.Verdict); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// UpdateDailyStats updates daily statistics
func (d *Database) UpdateDailyStats(requests, blocked, challenges, threats int) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	today := time.Now().Format("2006-01-02")

	_, err := d.db.Exec(`
		INSERT INTO stats (date, requests, blocked, challenges, threats)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(date) DO UPDATE SET
			requests = requests + excluded.requests,
			blocked = blocked + excluded.blocked,
			challenges = challenges + excluded.challenges,
			threats = threats + excluded.threats
	`, today, requests, blocked, challenges, threats)

	return err
}

// GetStats returns database statistics
func (d *Database) GetStats() (map[string]interface{}, error) {
	d.lock.RLock()
	defer d.lock.RUnlock()

	var threatCount, actorCount, grayZoneCount int

	d.db.QueryRow("SELECT COUNT(*) FROM threats").Scan(&threatCount)
	d.db.QueryRow("SELECT COUNT(*) FROM actors").Scan(&actorCount)
	d.db.QueryRow("SELECT COUNT(*) FROM gray_zone WHERE analyzed = FALSE").Scan(&grayZoneCount)

	return map[string]interface{}{
		"total_threats":     threatCount,
		"total_actors":      actorCount,
		"pending_gray_zone": grayZoneCount,
	}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}
