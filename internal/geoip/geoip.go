// Package geoip provides IP geolocation using MaxMind GeoLite2 database.
package geoip

import (
	"net"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Reader provides GeoIP lookup functionality.
type Reader struct {
	db *maxminddb.Reader
	mu sync.RWMutex
}

// GeoInfo contains geolocation data for an IP.
type GeoInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city,omitempty"`
	Region      string `json:"region,omitempty"`
}

// Database record structure
type geoRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// New creates a new GeoIP reader.
// dbPath should point to GeoLite2-Country.mmdb or GeoLite2-City.mmdb
func New(dbPath string) (*Reader, error) {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, err
	}

	return &Reader{db: db}, nil
}

// Lookup returns geolocation info for an IP address.
func (r *Reader) Lookup(ipStr string) *GeoInfo {
	if r == nil || r.db == nil {
		return nil
	}

	// Handle comma-separated IPs (X-Forwarded-For format)
	// Take the first IP (real client IP)
	if strings.Contains(ipStr, ",") {
		parts := strings.Split(ipStr, ",")
		ipStr = strings.TrimSpace(parts[0])
	}

	// Parse IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Skip private/local IPs
	if isPrivateIP(ip) {
		return &GeoInfo{
			Country:     "Private",
			CountryCode: "XX",
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var record geoRecord
	err := r.db.Lookup(ip, &record)
	if err != nil {
		return nil
	}

	info := &GeoInfo{
		CountryCode: record.Country.ISOCode,
	}

	// Get country name (prefer English)
	if name, ok := record.Country.Names["en"]; ok {
		info.Country = name
	}

	// Get city name if available
	if name, ok := record.City.Names["en"]; ok {
		info.City = name
	}

	// Get region/subdivision if available
	if len(record.Subdivisions) > 0 {
		if name, ok := record.Subdivisions[0].Names["en"]; ok {
			info.Region = name
		}
	}

	return info
}

// LookupCode returns just the country code (e.g., "US", "RU", "CN")
func (r *Reader) LookupCode(ipStr string) string {
	info := r.Lookup(ipStr)
	if info == nil {
		return ""
	}
	return info.CountryCode
}

// Close closes the database.
func (r *Reader) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// isPrivateIP checks if IP is private/local
func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, block := range privateBlocks {
		_, cidr, _ := net.ParseCIDR(block)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
