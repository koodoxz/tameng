# SVALINN-GO 🛡️

**Security Shield - AEGIS Ecosystem**

SVALINN is a high-performance Web Application Firewall (WAF) with ML-powered threat detection, written in Go for memory safety and blazing performance.

---

## 📊 Migration Status

Migrated from Node.js SVALINN (123 modules) to Go.

### Core Features Implemented:

| Package | Description | Lines | Status |
|---------|-------------|-------|--------|
| `cmd/svalinn` | Entry point with banner | 80 | ✅ |
| `internal/config` | YAML configuration | 200 | ✅ |
| `internal/logger` | Structured logging | 180 | ✅ |
| `internal/server` | HTTP/TLS server + middleware | 600 | ✅ |
| `internal/actor` | Memory-safe actor tracking | 500 | ✅ |
| `internal/waf` | Signature engine (25+ patterns) | 400 | ✅ |
| `internal/ddos` | EWMA + 3-phase escalation | 350 | ✅ |
| `internal/ml` | Python ML bridge | 200 | ✅ |
| `internal/intel` | MITRE ATT&CK + IOC | 300 | ✅ |
| `internal/behavior` | Behavioral analysis | 250 | ✅ |
| `internal/fingerprint` | JA3/HTTP fingerprinting | 280 | ✅ |
| `internal/deception` | Honeypots + canaries | 300 | ✅ |
| `internal/protocol` | Request smuggling detection | 350 | ✅ |
| `internal/detect` | Kill chain + C2 detection | 400 | ✅ |
| `internal/db` | SQLite persistence | 300 | ✅ |
| `internal/siem` | SIEM integration | 250 | ✅ |
| `internal/collector` | Threat intel collectors | 250 | ✅ |
| `internal/hardening` | Memory + security hardening | 200 | ✅ |
| **Total** | **22 Go files** | **~5100** | ✅ |

---

## 🚀 Quick Start

### Run Locally

```bash
# Build
go build -o svalinn ./cmd/svalinn

# Run
./svalinn -config configs/svalinn.yaml
```

### Docker

```bash
# Build and run
docker-compose up -d

# Check health
curl http://localhost:10000/health
```

---

## 📁 Project Structure

```
S.V.A.L.L.I.N.N-GO/
├── cmd/
│   └── svalinn/
│       └── main.go           # Entry point
├── configs/
│   └── svalinn.yaml          # Configuration
├── internal/
│   ├── actor/                # Actor tracking
│   │   ├── actor.go          # Two-stage tracking
│   │   ├── grayzone.go       # Uncertain events buffer
│   │   └── mitnick.go        # Advanced attacker tracking
│   ├── behavior/             # Behavioral analysis
│   │   └── detector.go
│   ├── collector/            # Threat intel collectors
│   │   └── collector.go
│   ├── config/               # Configuration
│   │   └── config.go
│   ├── db/                   # Database
│   │   └── database.go
│   ├── ddos/                 # DDoS protection
│   │   └── engine.go
│   ├── deception/            # Honeypots & canaries
│   │   └── engine.go
│   ├── detect/               # Attack detection
│   │   └── analyzer.go
│   ├── fingerprint/          # Device fingerprinting
│   │   └── fingerprint.go
│   ├── hardening/            # Security hardening
│   │   └── hardening.go
│   ├── intel/                # Threat intelligence
│   │   └── hub.go
│   ├── logger/               # Logging
│   │   └── logger.go
│   ├── ml/                   # ML Engine bridge
│   │   └── bridge.go
│   ├── protocol/             # Protocol security
│   │   └── guard.go
│   ├── server/               # HTTP server
│   │   ├── server.go
│   │   ├── middleware.go
│   │   └── handlers.go
│   ├── siem/                 # SIEM integration
│   │   └── integration.go
│   └── waf/                  # WAF signatures
│       └── signature.go
├── data/                     # Runtime data
├── Dockerfile
├── docker-compose.yml
└── go.mod
```

---

## 🔐 Security Features

### WAF Signatures (25+)
- SQL Injection (union, comments, functions, sleep)
- XSS (script tags, event handlers, SVG)
- Path Traversal (../, encoded variants)
- Command Injection (pipes, shell commands)
- SSRF (internal IPs, cloud metadata)
- Log4Shell (JNDI injection)
- Scanner/Bot detection

### DDoS Protection
- EWMA rate detection
- 3-phase escalation: Challenge → Throttle → Block
- Per-IP state tracking
- Automatic cleanup

### Actor Tracking
- Two-stage: Lightweight counters → Full profiles
- Memory-safe with LRU eviction
- Mitnick-level correlation
- Behavioral DNA fingerprinting

### Threat Intelligence
- MITRE ATT&CK mapping
- IOC (Indicators of Compromise)
- CVE feed integration
- Threat actor database

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/api/v1/stats` | GET | Server statistics |
| `/api/v1/threats` | GET | Recent threats |
| `/api/v1/actors` | GET | Active actors |
| `/api/v1/config` | GET | Current config |
| `/api/v9/reload` | POST | Reload config (God Mode) |
| `/api/v9/block` | POST | Block IP (God Mode) |
| `/api/v9/unblock` | POST | Unblock IP (God Mode) |
| `/mitnick/actors` | GET | Mitnick actor details |
| `/mitnick/graph` | GET | Actor relationship graph |

---

## ⚙️ Configuration

See `configs/svalinn.yaml` for all options:

```yaml
server:
  http_addr: ":10000"
  https_addr: ":10443"

waf:
  enabled: true
  block_threshold: 0.8

ddos:
  enabled: true
  phase3_enabled: true
  threshold_rps: 1000
  block_duration: 5m

actor:
  enabled: true
  max_actors: 100000
  mitnick_enabled: true

ml:
  enabled: true
  engine_url: "http://localhost:8000"
```

---

## 🔄 Pending Features

The following Node.js modules have been consolidated into Go packages:

- 96 JS engine modules → 12 Go packages
- Python ML engine → Keep as-is (via bridge.go)
- Dashboard → Keep as static (can be served separately)

---

## 📜 License

MIT - AEGIS Security Ecosystem

---

*Built with 💙 for the AEGIS Ecosystem*
