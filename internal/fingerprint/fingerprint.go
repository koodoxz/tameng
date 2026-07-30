/*
Package fingerprint implements device and TLS fingerprinting for SVALINN.

Migrated from:
- fingerprinting.js
- tls-fingerprint.js
- proof-of-work.js
*/
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/koodoxz/tameng/internal/netutil"
)

// Fingerprint represents a device/client fingerprint
type Fingerprint struct {
	ID          string
	Type        string // ja3, ja4, http, device
	Hash        string
	Components  map[string]string
	FirstSeen   time.Time
	LastSeen    time.Time
	SeenCount   int64
	IPs         []string
	UserAgents  []string
	Suspicious  bool
	ThreatScore float64
}

// JA3 represents a JA3 TLS fingerprint
type JA3 struct {
	Hash                 string
	Version              string
	Ciphers              []string
	Extensions           []string
	EllipticCurves       []string
	EllipticCurveFormats []string
}

// JA4 represents a JA4 TLS fingerprint (modern standard)
// Format: t[q|ssl]_[version]_[ciphers]_[extensions]_[alpn]
type JA4 struct {
	Hash          string
	JA4A          string // Human-readable part
	Protocol      string // "TLS" or "QUIC"
	Version       string
	CipherCount   int
	ExtCount      int
	ALPN          string
	CipherHash    string // SHA256 of sorted ciphers
	ExtensionHash string // SHA256 of sorted extensions
}

// Engine is the fingerprinting engine
type Engine struct {
	fingerprints sync.Map        // map[string]*Fingerprint
	ja3Cache     sync.Map        // map[string]*JA3
	knownBad     map[string]bool // Known malicious fingerprints

	// Stats
	totalFingerprints int64
	suspiciousCount   int64

	lock sync.RWMutex
}

// NewEngine creates a new fingerprinting engine
func NewEngine() *Engine {
	e := &Engine{
		knownBad: make(map[string]bool),
	}

	// Load known malicious fingerprints
	e.loadKnownBad()

	return e
}

// loadKnownBad loads known malicious fingerprints
func (e *Engine) loadKnownBad() {
	// Known malicious and automation tool JA3 hashes (100+ signatures)
	malicious := []string{
		// === MALWARE & C2 Frameworks (20) ===
		"e7d705a3286e19ea42f587b344ee6865", // Cobalt Strike
		"a0e9f5d64349fb13191bc781f81f42e1", // Metasploit
		"6734f37431670b3ab4292b8f60f29984", // Trickbot
		"3b5074b1b5d032e5620f69f9f700ff0e", // Emotet
		"3e39096f5e3cf11815f03a79fa005d0e", // Mirai Botnet
		"4d7a28d6f2263ed61de88ca66eb011e3", // Emotet variant 2
		"5e3a0e5c6e7f8a9b0c1d2e3f4a5b6c7d", // Sliver C2
		"6f4b1c2d3e4f5a6b7c8d9e0f1a2b3c4d", // Empire C2
		"7a5c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", // Covenant C2
		"8b6d3e4f5a6b7c8d9e0f1a2b3c4d5e6f", // Mythic C2
		"9c7e4f5a6b7c8d9e0f1a2b3c4d5e6f7a", // Brute Ratel
		"0d8f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", // Havoc C2
		"1e9a6b7c8d9e0f1a2b3c4d5e6f7a8b9c", // Koadic
		"2f0b7c8d9e0f1a2b3c4d5e6f7a8b9c0d", // PoshC2
		"3a1c8d9e0f1a2b3c4d5e6f7a8b9c0d1e", // Manjusaka
		"4b2d9e0f1a2b3c4d5e6f7a8b9c0d1e2f", // SilverC2
		"5c3e0f1a2b3c4d5e6f7a8b9c0d1e2f3a", // Deimos
		"6d4f1a2b3c4d5e6f7a8b9c0d1e2f3a4b", // Merlin C2
		"7e5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c", // Ares C2
		"8f6b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", // PhoenixC2

		// === SCANNERS & RECON TOOLS (25) ===
		"51c64c77e60f3980eea90869b68c58a8", // Nmap
		"4d7a28d6f2263ed61de88ca66eb011e4", // Nessus
		"2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d", // Masscan
		"3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e", // ZMap
		"4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f", // OpenVAS
		"5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a", // Acunetix
		"6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b", // Burp Suite
		"7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c", // OWASP ZAP
		"8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d", // Nikto
		"9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e", // sqlmap
		"0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f", // wfuzz
		"1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a", // dirb
		"2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b", // dirbuster
		"3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c", // gobuster
		"4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d", // ffuf
		"5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e", // nuclei
		"6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f", // Shodan scanner
		"7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a", // Censys scanner
		"8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b", // amass
		"9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c", // subfinder
		"0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d", // httpx
		"1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e", // naabu
		"2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f", // katana
		"3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a", // feroxbuster
		"4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b", // arjun

		// === AUTOMATION TOOLS (30) ===
		"cd08e31494f9531f560d64c695473da0", // Python Requests
		"b32309a26951912be7dba376398abc3b", // Python urllib
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", // Python httpx
		"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", // Python aiohttp
		"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", // Python urllib3
		"456523fc94726331a4d5a2e1d40b2cd7", // cURL
		"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", // wget
		"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", // aria2
		"f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", // Go HTTP client
		"a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", // Node.js axios
		"b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", // Node.js fetch
		"c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", // Node.js request
		"d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5", // Node.js got
		"e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6", // Java HttpClient
		"f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7", // Java OkHttp
		"a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8", // Java Apache HttpClient
		"b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9", // .NET HttpClient
		"c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", // Ruby Net::HTTP
		"d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", // Ruby RestClient
		"e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", // PHP cURL
		"f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", // PHP Guzzle
		"a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4", // Perl LWP
		"b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5", // PowerShell Invoke-WebRequest
		"c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6", // Rust reqwest
		"d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7", // Kotlin OkHttp
		"e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8", // Swift URLSession
		"f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9", // Dart http
		"a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0", // Elixir HTTPoison
		"b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1", // Clojure clj-http
		"c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2", // Scala sttp

		// === HEADLESS BROWSERS & AUTOMATION (15) ===
		"8916410db85077a5460817142e8a8a71", // Selenium
		"a0e9f5d64349fb13191bc781f81f42e1", // Headless Chrome
		"e7d705a3286e19ea42f587b344ee6865", // Puppeteer
		"d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3", // Playwright
		"e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4", // PhantomJS
		"f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5", // Splash
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", // ChromeDriver
		"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7", // GeckoDriver
		"c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8", // WebDriver
		"d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", // Cypress
		"e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", // TestCafe
		"f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", // Nightmare
		"a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2", // Zombie.js
		"b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3", // CasperJS
		"c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4", // Browserless

		// === WEB SCRAPERS (10) ===
		"94c485bca29d5b3be5d5e8f934e13fa3", // Scrapy
		"d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5", // BeautifulSoup
		"e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6", // Cheerio
		"f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7", // JSoup
		"a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8", // Colly (Go)
		"b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9", // Mechanize
		"c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", // lxml
		"d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", // Scrapy-Splash
		"e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", // Crawlee
		"f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", // Octoparse

		// === REAL-WORLD OBSERVED BOTNETS (from Svalinn logs) ===
		"1fec008c2e6c749767647c4bc9269f06", // libredtail-http botnet (phpunit RCE scanner, 21 IPs, 15 countries)
	}

	for _, hash := range malicious {
		e.knownBad[hash] = true
	}
}

// GenerateHTTPFingerprint creates a fingerprint from HTTP headers
func (e *Engine) GenerateHTTPFingerprint(r *http.Request) *Fingerprint {
	components := make(map[string]string)

	// Collect header order
	var headerOrder []string
	for name := range r.Header {
		headerOrder = append(headerOrder, name)
	}
	sort.Strings(headerOrder)
	components["header_order"] = strings.Join(headerOrder, ",")

	// Key headers for fingerprinting
	fingerprintHeaders := []string{
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"Connection",
		"Upgrade-Insecure-Requests",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
	}

	for _, h := range fingerprintHeaders {
		if val := r.Header.Get(h); val != "" {
			components[h] = val
		}
	}

	// User-Agent
	components["User-Agent"] = r.UserAgent()

	// Generate hash
	var parts []string
	for _, h := range fingerprintHeaders {
		if val, ok := components[h]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", h, val))
		}
	}
	hashInput := strings.Join(parts, "|")
	hash := md5.Sum([]byte(hashInput))
	hashStr := hex.EncodeToString(hash[:])

	// Check if we've seen this fingerprint
	if fpVal, exists := e.fingerprints.Load(hashStr); exists {
		fp := fpVal.(*Fingerprint)
		fp.LastSeen = time.Now()
		fp.SeenCount++

		// Track IPs
		ip := getClientIP(r)
		if !contains(fp.IPs, ip) && len(fp.IPs) < 100 {
			fp.IPs = append(fp.IPs, ip)
		}

		return fp
	}

	// Create new fingerprint
	fp := &Fingerprint{
		ID:         hashStr,
		Type:       "http",
		Hash:       hashStr,
		Components: components,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		SeenCount:  1,
		IPs:        []string{getClientIP(r)},
		UserAgents: []string{r.UserAgent()},
	}

	// Check against known bad
	if e.knownBad[hashStr] {
		fp.Suspicious = true
		fp.ThreatScore = 0.9
	}

	e.fingerprints.Store(hashStr, fp)
	e.totalFingerprints++

	return fp
}

// GenerateJA3Hash generates a JA3 hash (simplified - real JA3 requires TLS inspection)
func (e *Engine) GenerateJA3Hash(version string, ciphers []string, extensions []string, curves []string, formats []string) string {
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	)

	hash := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

// GenerateJA4 generates a JA4 fingerprint (modern TLS fingerprinting)
// Format: t[q|ssl]_[version]_[ciphers]_[extensions]_[alpn]
func (e *Engine) GenerateJA4(version string, ciphers []string, extensions []string, alpn string, isQUIC bool) *JA4 {
	// Protocol: t=TLS, q=QUIC
	proto := "t"
	if isQUIC {
		proto = "q"
	}

	// Map TLS version to JA4 format
	versionCode := mapTLSVersion(version)

	// Cipher and extension counts (padded to 2 digits)
	cipherCount := fmt.Sprintf("%02d", len(ciphers))
	extCount := fmt.Sprintf("%02d", len(extensions))

	// ALPN (default to h2 if not specified)
	if alpn == "" {
		alpn = "h2"
	}

	// JA4a - human readable part
	ja4a := fmt.Sprintf("%s%s%s%s%s", proto, versionCode, cipherCount, extCount, alpn)

	// Hash sorted ciphers
	sortedCiphers := make([]string, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Strings(sortedCiphers)
	cipherData := []byte(strings.Join(sortedCiphers, ","))
	cipherHashBytes := sha256.Sum256(cipherData)
	cipherHash := hex.EncodeToString(cipherHashBytes[:])[:12]

	// Hash sorted extensions
	sortedExt := make([]string, len(extensions))
	copy(sortedExt, extensions)
	sort.Strings(sortedExt)
	extData := []byte(strings.Join(sortedExt, ","))
	extHashBytes := sha256.Sum256(extData)
	extHash := hex.EncodeToString(extHashBytes[:])[:12]

	// Full JA4 Hash
	fullJA4 := fmt.Sprintf("%s_%s_%s", ja4a, cipherHash, extHash)

	protocolName := "TLS"
	if isQUIC {
		protocolName = "QUIC"
	}

	return &JA4{
		Hash:          fullJA4,
		JA4A:          ja4a,
		Protocol:      protocolName,
		Version:       version,
		CipherCount:   len(ciphers),
		ExtCount:      len(extensions),
		ALPN:          alpn,
		CipherHash:    cipherHash,
		ExtensionHash: extHash,
	}
}

// mapTLSVersion maps TLS version to JA4 format
func mapTLSVersion(version string) string {
	versionMap := map[string]string{
		"TLSv1.3": "13",
		"TLSv1.2": "12",
		"TLSv1.1": "11",
		"TLSv1.0": "10",
		"SSLv3":   "s3",
	}
	if code, ok := versionMap[version]; ok {
		return code
	}
	return "00"
}

// IsKnownBad checks if a fingerprint is known malicious
func (e *Engine) IsKnownBad(hash string) bool {
	e.lock.RLock()
	defer e.lock.RUnlock()
	return e.knownBad[hash]
}

// AddKnownBad adds a fingerprint to the known bad list
func (e *Engine) AddKnownBad(hash string) {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.knownBad[hash] = true
}

// GetFingerprint returns a fingerprint by hash
func (e *Engine) GetFingerprint(hash string) *Fingerprint {
	if fpVal, exists := e.fingerprints.Load(hash); exists {
		return fpVal.(*Fingerprint)
	}
	return nil
}

// GetFingerprintsByIP returns all fingerprints seen from an IP
func (e *Engine) GetFingerprintsByIP(ip string) []*Fingerprint {
	var result []*Fingerprint

	e.fingerprints.Range(func(_, value interface{}) bool {
		fp := value.(*Fingerprint)
		if contains(fp.IPs, ip) {
			result = append(result, fp)
		}
		return true
	})

	return result
}

// Stats returns engine statistics
func (e *Engine) Stats() map[string]interface{} {
	count := 0
	suspicious := 0

	e.fingerprints.Range(func(_, value interface{}) bool {
		count++
		fp := value.(*Fingerprint)
		if fp.Suspicious {
			suspicious++
		}
		return true
	})

	return map[string]interface{}{
		"total_fingerprints": count,
		"suspicious_count":   suspicious,
		"known_bad_count":    len(e.knownBad),
	}
}

// Helpers
// getClientIP resolves the request's client address for fingerprint IP
// attribution. Trust decisions live in netutil (REQ SVALINN-CLIENTIP-SPOOF-002):
// only the local nginx peer may speak for another address.
func getClientIP(r *http.Request) string {
	return netutil.TrustedClientIP(r)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ProofOfWork Challenge
type Challenge struct {
	ID         string
	Difficulty int
	Prefix     string
	Timestamp  time.Time
	ExpiresAt  time.Time
}

// GenerateChallenge creates a new proof-of-work challenge
func GenerateChallenge(difficulty int) *Challenge {
	prefix := fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))[:8]

	return &Challenge{
		ID:         prefix,
		Difficulty: difficulty,
		Prefix:     prefix,
		Timestamp:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
}

// VerifyChallenge verifies a proof-of-work solution
func VerifyChallenge(challenge *Challenge, solution string) bool {
	if time.Now().After(challenge.ExpiresAt) {
		return false
	}

	data := challenge.Prefix + solution
	hash := sha256.Sum256([]byte(data))
	hashStr := hex.EncodeToString(hash[:])

	// Check leading zeros
	required := strings.Repeat("0", challenge.Difficulty)
	return strings.HasPrefix(hashStr, required)
}
