# Security Policy

To report a vulnerability, please email **koodoxz@gmail.com** instead of opening a public issue. Initial response target: 24 hours. Triage target: 72 hours.

Full policy, scope, and known limitations: see [Security & Vulnerability Reporting](README.md#security--vulnerability-reporting) (English) / [Keamanan & Pelaporan Kerentanan](README.md#keamanan--pelaporan-kerentanan) (Bahasa Indonesia) in the README.

Note: Tameng also serves `/.well-known/security.txt` (RFC 9116) on each running instance -- that's a feature for the *deployer's* own site, not a reporting channel for this project itself.

---

## Security Hall of Fame / Acknowledgements

We gratefully acknowledge independent security researchers who responsibly disclose vulnerabilities:

- **[kta1kri](https://github.com/kta1kri)** — Reported SQL injection comment delimiter evasion (`UNION/**/SELECT`), uninspected HTTP header targets, and LightGBM model loader compatibility (November 2026).

