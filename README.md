# Tameng - Web Application Firewall

**Dokumentasi dalam Bahasa Indonesia di bawah / See Indonesian documentation below**

---

## Language / Bahasa

- [**English**](#english) — [Scroll down to English section](#english)
- [**Bahasa Indonesia**](#bahasa-indonesia)

---

# Bahasa Indonesia

## Tameng 🛡️

**Perisai Web Application Firewall dengan Deteksi Ancaman Bertenaga ML**

Tameng adalah Web Application Firewall (WAF) berkinerja tinggi dengan deteksi ancaman berbasis machine learning, ditulis dalam Go untuk keamanan memori dan performa yang luar biasa.

Tameng menawarkan perlindungan lapisan aplikasi yang komprehensif melalui satu biner Go tunggal, satu file YAML, dan satu layanan systemd — tanpa ketergantungan sidecar eksternal.

> **Catatan Penamaan:** Nama internal (module Go, binary, komentar kode) tetap menggunakan "Svalinn" (nama penutup dalam mitologi Nordik yang melindungi matahari dari kehancuran). Ini adalah keputusan deliberate untuk menghindari refactoring invasif pada sistem produksi aktif. Dokumentasi publik dan branding menggunakan "Tameng" (perisai dalam bahasa Indonesia).

### Differensiator Teknis

Dibandingkan dengan WAF open-source lainnya seperti **Coraza** (library WAF murni, kompatibel ModSecurity):

- **Baterai Lengkap:** Satu biner menggabungkan mesin WAF + penilaian ML + pelacakan aktor dua-tahap + eskalasi DDoS 3-fase + lapisan honeypot/deception + integrasi threat intelligence (STIX/TAXII) + pemetaan MITRE ATT&CK
- **Keamanan Regex:** Engine WAF menggunakan Re2 Go (bukan Oniguruma/PCRE) — ReDoS (regex backtracking bencana) adalah mustahil secara struktural, bukan hanya mitigated
- **ML Asli:** Inferensi model berbasis LightGBM berjalan asli dalam Go (via library `leaves`) — tidak ada proses Python sidecar di runtime
- **Tracking Aktor:** Melacak aktor dalam dua tahap (lightweight counters → full profiles) dengan eviction LRU aman memori, bahkan di bawah beban korban DDoS
- **Transparansi Pengujian Adversarial:** Historik pengujian mendalam dengan alat pembuat serangan khusus (built by same author). Termasuk failed optimization attempts yang dipublikasikan—kebanyakan security tools tidak pernah mengumumkan ketika percobaan optimization tidak membantu.

### Fitur Keamanan Inti

| Fitur | Deskripsi |
|-------|-----------|
| **Mesin WAF (25+)** | SQL Injection, XSS, Path Traversal, Command Injection, SSRF, Log4Shell, Scanner/Bot detection |
| **Proteksi DDoS** | Deteksi EWMA + eskalasi 3-fase (Challenge → Throttle → Block) |
| **Pelacakan Aktor** | Dua-tahap dengan fingerprinting behavioral DNA, penyimpanan memory-safe, integrasi Mitnick |
| **Deception Layer** | 100+ honeypot/canary traps untuk mengalihkan dan mengidentifikasi penyerang |
| **Fingerprinting** | JA3 TLS + HTTP behavior profiling |
| **Deteksi Kill Chain** | Korelasi serangan multi-tahap, deteksi Command & Control (C2) |
| **Threat Intelligence** | Integrasi STIX/TAXII, pemetaan MITRE ATT&CK, feed IOC |
| **Guard Protokol** | Deteksi request smuggling, GraphQL depth limiting, WebSocket rate limiting |
| **Analisis Behavioral** | Baseline deviation detection, credential stuffing identification, anomaly correlation |

### Lisensi

**AGPL-3.0** — Kode sumber harus tersedia untuk semua pengguna dari versi yang dimodifikasi, **termasuk ketika dijalankan sebagai layanan jaringan** (ini yang membedakan AGPL dari GPL biasa). Provider hosting/cloud tidak dapat mengambil kode ini, memodifikasinya, dan menawarkannya sebagai layanan bersaing tanpa merilis modifikasi mereka.

### Mulai Cepat

#### Prasyarat

- **Go 1.21+** (build dari sumber)
- **Docker & Docker Compose** (Docker deployment) — tidak perlu Go installed
- **SQLite3** (embedded di binary Go, CGO diperlukan untuk build)

#### Opsi 1: Docker (Direkomendasikan)

```bash
# Clone repo
git clone https://github.com/koodoxz/tameng.git
cd tameng

# Copy environment template
cp .env.example .env

# Edit .env dengan nilai Anda (SVALINN_GOD_KEY, SVALINN_API_KEY, dll)
nano .env

# Build dan jalankan
docker-compose up -d

# Periksa health
curl http://localhost:10000/health

# Lihat logs
docker-compose logs -f svalinn
```

**Port default:** `10000` (HTTP), `10443` (HTTPS)

#### Opsi 2: Dari Sumber

```bash
# Prerequisites
go 1.21+ (dengan CGO enabled untuk sqlite3)

# Clone
git clone https://github.com/koodoxz/tameng.git
cd tameng

# Copy .env
cp .env.example .env
nano .env

# Build (CGO_ENABLED diperlukan)
CGO_ENABLED=1 go build -o tameng ./cmd/svalinn

# Run
./tameng -config configs/svalinn.yaml
```

### Konfigurasi

Semua konfigurasi melalui **environment variables** dan file `configs/svalinn.yaml`. Lihat `.env.example` untuk daftar lengkap:

**Kunci Wajib:**
- `SVALINN_GOD_KEY` — Kunci autentikasi untuk `/api/v9/*` endpoints (admin saja)
- `SVALINN_API_KEY` — Kunci untuk akses programmatic (threat reporting, actor queries)

**Kunci Opsional (Ekosistem MECOB):**
- `SVALINN_MITNICK_USER` / `SVALINN_MITNICK_PASS` — Modul tracking advanced
- `ODIN_API_KEY` — Integrasi ODIN DNS Intelligence

**Konfigurasi Tuning:**
- `WAF_BLOCK_THRESHOLD` — Confidence threshold (0.0-1.0; default 0.8)
- `DDOS_CHALLENGE_THRESHOLD` — RPS sebelum challenge (default 50)
- `DDOS_THROTTLE_THRESHOLD` — RPS sebelum throttle (default 100)
- `DDOS_BLOCK_THRESHOLD` — RPS sebelum block (default 200)
- `MAX_ACTORS` — Max aktor di memory (default 100000)
- `ML_ENABLED` — Toggle ML threat scoring (default true)
- `DECEPTION_ENABLED` — Toggle honeypots (default true)

Lihat `configs/svalinn.yaml` untuk opsi lanjutan (TLS, SIEM, CVE feeds, dll).

### Endpoint API

| Endpoint | Metode | Deskripsi |
|----------|--------|-----------|
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/api/v1/stats` | GET | Server statistics |
| `/api/v1/threats` | GET | Recent threats |
| `/api/v1/actors` | GET | Active actors |
| `/api/v1/config` | GET | Current config |
| `/api/v9/reload` | POST | Reload config (God Mode) |
| `/api/v9/block` | POST | Block IP (God Mode) |
| `/mitnick/actors` | GET | Mitnick actor details |
| `/mitnick/graph` | GET | Actor relationship graph |

### Arsitektur

```
internal/
├── actor/          # Two-stage actor tracking (lightweight → full profiles)
├── behavior/       # Behavioral baseline + deviation analysis
├── collector/      # Threat intelligence collectors
├── config/         # YAML config loader with env expansion
├── countermeasures/ # Active response mechanisms
├── db/             # SQLite persistence
├── ddos/           # EWMA + 3-phase escalation
├── deception/      # Honeypots + canary tokens
├── detect/         # Kill chain + C2 detection
├── ecosystem/      # MECOB integration (ODIN, MIMIR)
├── egress/         # Egress filtering
├── fingerprint/    # JA3 + HTTP fingerprinting
├── geoip/          # MaxMind GeoIP lookups
├── hardening/      # Memory + security hardening
├── heuristics/     # Threat scoring heuristics
├── honeypot/       # Dedicated honeypot engine
├── intel/          # MITRE ATT&CK + IOC + STIX
├── logger/         # zerolog structured logging
├── logic/          # Business logic abuse detection
├── malware/        # Malware behavior analysis
├── ml/             # LightGBM ML bridge (native Go)
├── observatory/    # Top actors cache (Hall of Fame)
├── orchestrator/   # Detection orchestration
├── payload/        # YARA/Sigma/Snort signatures
├── preattack/      # Pre-attack detection (recon/scanning)
├── protocol/       # Request smuggling, GraphQL depth, WebSocket
├── response/       # Response encryption + PoW challenges
├── security/       # Security hardening utilities
├── semantic/       # Semantic payload analysis
├── server/         # HTTP/TLS server + middleware pipeline
├── session/        # Session tracking
├── siem/           # SIEM integration
└── waf/            # WAF signature engine (25+)
```

**Data Flow:** Request masuk → middleware pipeline → WAF signature check + ML scoring → actor tracking + behavioral analysis → DDoS detection → deception/honeypot checks → response shaping (encryption, PoW) → SIEM/intel logging → forward to backend (atau block/challenge).

### Testing

```bash
# Unit tests
go test ./internal/...

# Dengan race detector
go test -race ./internal/...

# Coverage
go test -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out

# Specific package
go test ./internal/waf/...

# Benchmarks
go test -bench=. -benchmem ./internal/...
```

Lihat file `*_test.go` untuk differential fuzz tests, mutation tests, dan adversarial test cases.

### Berkontribusi

Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan lengkap: proses issue/PR, gaya kode Go, running tests.

Secara singkat:
- Fork, branch, commit dengan pesan deskriptif
- Jalankan `go fmt`, `go vet`, `go test -race`
- Coverage minimal 80% untuk kode baru
- Describe changes clearly in PR, including security implications if any

### License

[AGPL-3.0](LICENSE) — Source-available dengan copyleft jaringan.

---

---

# English

## Tameng 🛡️

**Web Application Firewall with ML-Powered Threat Detection**

Tameng is a high-performance Web Application Firewall (WAF) with machine learning-powered threat detection, written in Go for memory safety and exceptional performance.

Tameng delivers comprehensive application-layer protection through a single Go binary, one YAML file, and one systemd service — with no external sidecar dependencies.

> **Naming Note:** The internal codebase (Go module path, binary name, code comments) still uses the codename "Svalinn" (the shield in Norse mythology that protects the sun from destruction). This is a deliberate choice to avoid invasive refactoring on a live production system. Public documentation and branding use "Tameng" (shield in Indonesian).

### Technical Differentiation

Compared to other open-source WAFs like **Coraza** (a pure WAF library, ModSecurity-compatible):

- **Batteries Included:** One binary combines WAF signature engine + ML threat scoring + two-stage actor tracking + 3-phase DDoS escalation (Challenge → Throttle → Block) + honeypot/deception layer + STIX/TAXII threat intelligence + MITRE ATT&CK mapping
- **Regex Safety:** WAF engine uses Go's Re2 regex engine (not Oniguruma/PCRE) — ReDoS (catastrophic backtracking) is structurally impossible, not just mitigated
- **Native ML:** LightGBM model inference runs natively in Go (via the `leaves` library) — no Python sidecar process required at runtime
- **Actor Tracking:** Tracks threat actors in two stages (lightweight counters → full behavioral profiles) with memory-safe LRU eviction, even under DDoS victim load
- **Adversarial Testing Transparency:** Deep red-team history with a purpose-built companion attack tool. Includes published failed optimization attempts — most security tools never announce when an optimization attempt didn't help. This honest-failure track record is itself a credibility signal.

### Core Security Features

| Feature | Description |
|---------|-------------|
| **WAF Signatures (25+)** | SQL Injection, XSS, Path Traversal, Command Injection, SSRF, Log4Shell, Scanner/Bot detection |
| **DDoS Protection** | EWMA rate detection + 3-phase escalation (Challenge → Throttle → Block) |
| **Actor Tracking** | Two-stage with behavioral DNA fingerprinting, memory-safe storage, Mitnick integration |
| **Deception Layer** | 100+ honeypots and canary tokens for actor redirection and identification |
| **Fingerprinting** | JA3 TLS + HTTP behavior profiling |
| **Kill Chain Detection** | Multi-stage attack correlation, Command & Control (C2) detection |
| **Threat Intelligence** | STIX/TAXII integration, MITRE ATT&CK mapping, IOC feeds |
| **Protocol Guards** | Request smuggling detection, GraphQL depth limiting, WebSocket rate limiting |
| **Behavioral Analysis** | Baseline deviation detection, credential stuffing identification, anomaly correlation |

### License

**AGPL-3.0** — Source code must be available to all users of any modified version, **including when run as a network service** (this is what distinguishes AGPL from plain GPL). A cloud/hosting provider cannot take this code, modify it, and offer it as a competing service without releasing their modifications.

### Quick Start

#### Prerequisites

- **Go 1.21+** (to build from source)
- **Docker & Docker Compose** (Docker deployment) — Go not required
- **SQLite3** (embedded in Go binary; CGO required for building)

#### Option 1: Docker (Recommended)

```bash
# Clone repo
git clone https://github.com/koodoxz/tameng.git
cd tameng

# Copy environment template
cp .env.example .env

# Edit .env with your values (SVALINN_GOD_KEY, SVALINN_API_KEY, etc.)
nano .env

# Build and run
docker-compose up -d

# Check health
curl http://localhost:10000/health

# View logs
docker-compose logs -f svalinn
```

**Default ports:** `10000` (HTTP), `10443` (HTTPS)

#### Option 2: From Source

```bash
# Prerequisites
go 1.21+ (with CGO enabled for sqlite3)

# Clone
git clone https://github.com/koodoxz/tameng.git
cd tameng

# Copy .env
cp .env.example .env
nano .env

# Build (CGO_ENABLED required)
CGO_ENABLED=1 go build -o tameng ./cmd/svalinn

# Run
./tameng -config configs/svalinn.yaml
```

### Configuration

All configuration is via **environment variables** and the `configs/svalinn.yaml` file. See `.env.example` for the complete list:

**Required Keys:**
- `SVALINN_GOD_KEY` — Authentication key for `/api/v9/*` endpoints (admin only)
- `SVALINN_API_KEY` — Key for programmatic access (threat reporting, actor queries)

**Optional Keys (MECOB Ecosystem):**
- `SVALINN_MITNICK_USER` / `SVALINN_MITNICK_PASS` — Advanced actor tracking module
- `ODIN_API_KEY` — ODIN DNS Intelligence integration

**Tuning Configuration:**
- `WAF_BLOCK_THRESHOLD` — Confidence threshold (0.0-1.0; default 0.8)
- `DDOS_CHALLENGE_THRESHOLD` — RPS before challenge (default 50)
- `DDOS_THROTTLE_THRESHOLD` — RPS before throttle (default 100)
- `DDOS_BLOCK_THRESHOLD` — RPS before block (default 200)
- `MAX_ACTORS` — Max actors in memory (default 100000)
- `ML_ENABLED` — Toggle ML threat scoring (default true)
- `DECEPTION_ENABLED` — Toggle honeypots (default true)

See `configs/svalinn.yaml` for advanced options (TLS, SIEM, CVE feeds, etc.).

### API Endpoints

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
| `/mitnick/actors` | GET | Mitnick actor details |
| `/mitnick/graph` | GET | Actor relationship graph |

### Architecture

```
internal/
├── actor/          # Two-stage actor tracking (lightweight → full profiles)
├── behavior/       # Behavioral baseline + deviation analysis
├── collector/      # Threat intelligence collectors
├── config/         # YAML config loader with env expansion
├── countermeasures/ # Active response mechanisms
├── db/             # SQLite persistence
├── ddos/           # EWMA + 3-phase escalation
├── deception/      # Honeypots + canary tokens
├── detect/         # Kill chain + C2 detection
├── ecosystem/      # MECOB integration (ODIN, MIMIR)
├── egress/         # Egress filtering
├── fingerprint/    # JA3 + HTTP fingerprinting
├── geoip/          # MaxMind GeoIP lookups
├── hardening/      # Memory + security hardening
├── heuristics/     # Threat scoring heuristics
├── honeypot/       # Dedicated honeypot engine
├── intel/          # MITRE ATT&CK + IOC + STIX
├── logger/         # zerolog structured logging
├── logic/          # Business logic abuse detection
├── malware/        # Malware behavior analysis
├── ml/             # LightGBM ML bridge (native Go)
├── observatory/    # Top actors cache (Hall of Fame)
├── orchestrator/   # Detection orchestration
├── payload/        # YARA/Sigma/Snort signatures
├── preattack/      # Pre-attack detection (recon/scanning)
├── protocol/       # Request smuggling, GraphQL depth, WebSocket
├── response/       # Response encryption + PoW challenges
├── security/       # Security hardening utilities
├── semantic/       # Semantic payload analysis
├── server/         # HTTP/TLS server + middleware pipeline
├── session/        # Session tracking
├── siem/           # SIEM integration
└── waf/            # WAF signature engine (25+)
```

**Data Flow:** Incoming request → middleware pipeline → WAF signature check + ML scoring → actor tracking + behavioral analysis → DDoS detection → deception/honeypot checks → response shaping (encryption, PoW) → SIEM/intel logging → forward to backend (or block/challenge).

### Testing

```bash
# Unit tests
go test ./internal/...

# With race detector
go test -race ./internal/...

# Coverage
go test -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out

# Specific package
go test ./internal/waf/...

# Benchmarks
go test -bench=. -benchmem ./internal/...
```

See `*_test.go` files for differential fuzz tests, mutation tests, and adversarial test cases.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines: issue/PR process, Go code style, running tests.

In short:
- Fork, branch, commit with descriptive messages
- Run `go fmt`, `go vet`, `go test -race`
- Minimum 80% coverage for new code
- Describe changes clearly in PR, including security implications if any

### License

[AGPL-3.0](LICENSE) — Source-available with network copyleft.
