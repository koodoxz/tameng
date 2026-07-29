package logger

import (
	"strings"
)

// ANSI Color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorGray   = "\033[90m"

	// Bright colors
	ColorBrightRed    = "\033[91m"
	ColorBrightGreen  = "\033[92m"
	ColorBrightYellow = "\033[93m"
	ColorBrightBlue   = "\033[94m"
	ColorBrightPurple = "\033[95m"
	ColorBrightCyan   = "\033[96m"

	// Background colors
	BgRed    = "\033[41m"
	BgYellow = "\033[43m"
	BgGreen  = "\033[42m"

	// Bold/Underline
	Bold      = "\033[1m"
	Underline = "\033[4m"
)

// Rich logging helpers for attack detection - Node.js style!
func (l *Logger) AttackDetected(attackType, ip, path string, details map[string]interface{}) {
	emoji := "🚨"
	switch strings.ToLower(attackType) {
	case "sqli", "sql injection":
		emoji = "💉"
	case "xss":
		emoji = "📜"
	case "rce", "command injection":
		emoji = "⚡"
	case "scanner", "recon":
		emoji = "🔍"
	case "honeypot":
		emoji = "🍯"
	case "c2", "beacon":
		emoji = "📡"
	case "fingerprint":
		emoji = "👁️"
	}

	l.log.Warn().
		Str("type", attackType).
		Str("ip", ip).
		Str("path", path).
		Fields(details).
		Msgf("%s %s[THREAT DETECTED]%s %s from %s%s%s → %s",
			emoji,
			ColorBrightRed+Bold,
			ColorReset,
			attackType,
			ColorBrightYellow,
			ip,
			ColorReset,
			path)
}

func (l *Logger) HoneypotTriggered(ip, trap string, score int) {
	l.log.Warn().
		Str("ip", ip).
		Str("trap", trap).
		Int("score", score).
		Msgf("🍯 %s[HONEYPOT TRAP]%s %s stepped on %s%s%s | Risk Score: %s%d%s",
			ColorBrightYellow+Bold,
			ColorReset,
			ip,
			ColorBrightCyan,
			trap,
			ColorReset,
			ColorBrightRed,
			score,
			ColorReset)
}

func (l *Logger) EvolutionIntel(intelType, ip, riskLevel string, details map[string]string) {
	emoji := "🔍"
	if strings.Contains(intelType, "honeypot") {
		emoji = "🍯"
	}

	l.log.Info().
		Str("type", intelType).
		Str("ip", ip).
		Str("risk", riskLevel).
		Fields(details).
		Msgf("%s %s[Evolution]%s %s | IP: %s%s%s | Risk: %s",
			emoji,
			ColorBrightPurple,
			ColorReset,
			intelType,
			ColorBrightYellow,
			ip,
			ColorReset,
			riskLevel)
}

func (l *Logger) C2BeaconDetected(ip string, interval string) {
	l.log.Warn().
		Str("ip", ip).
		Str("interval", interval).
		Msgf("📡 %s[C2Detector]%s BEACON DETECTED: %s%s%s - interval: %s%s%s",
			ColorBrightRed+Bold,
			ColorReset,
			ColorBrightYellow,
			ip,
			ColorReset,
			ColorBrightCyan,
			interval,
			ColorReset)
}

func (l *Logger) FingerprintSuspicious(ip, fingerprintID, riskLevel string) {
	l.log.Warn().
		Str("ip", ip).
		Str("fingerprint", fingerprintID).
		Str("risk", riskLevel).
		Msgf("👁️ %s[FINGERPRINT]%s Suspicious fingerprint detected: %s%s%s | Risk: %s%s%s",
			ColorBrightCyan,
			ColorReset,
			ColorYellow,
			fingerprintID,
			ColorReset,
			ColorBrightRed+Bold,
			riskLevel,
			ColorReset)
}

func (l *Logger) DeceptionTrap(ip, trapType string) {
	l.log.Info().
		Str("ip", ip).
		Str("trap", trapType).
		Msgf("🎯 %s[DECEPTION-INTEL]%s TRAP HIT [%s]: %s%s%s",
			ColorBrightYellow+Bold,
			ColorReset,
			trapType,
			ColorBrightRed,
			ip,
			ColorReset)
}

func (l *Logger) AttackerMemory(ip, behavior string) {
	l.log.Warn().
		Str("ip", ip).
		Str("behavior", behavior).
		Msgf("📋 %s[ATTACKER-MEMORY]%s Actor %s%s%s flagged: %s",
			ColorBrightPurple,
			ColorReset,
			ColorBrightYellow,
			ip,
			ColorReset,
			behavior)
}

func (l *Logger) ExternalIntel(intelType, data string, count int) {
	l.log.Info().
		Str("type", intelType).
		Str("data", data).
		Int("count", count).
		Msgf("📋 %s[EXTERNAL-INTEL]%s %s: %s%d patterns%s",
			ColorBrightCyan,
			ColorReset,
			intelType,
			ColorBrightGreen,
			count,
			ColorReset)
}

func (l *Logger) MLScoreHigh(ip string, mlScore, finalScore float64) {
	l.log.Warn().
		Str("ip", ip).
		Float64("ml_score", mlScore).
		Float64("final_score", finalScore).
		Msgf("🤖 %s[ML THREAT SCORER]%s HIGH THREAT: %s%s%s | ML Score: %s%.1f%s | Final: %s%.1f%s",
			ColorBrightPurple+Bold,
			ColorReset,
			ColorBrightYellow,
			ip,
			ColorReset,
			ColorBrightRed,
			mlScore,
			ColorReset,
			ColorBrightRed+Bold,
			finalScore,
			ColorReset)
}

func (l *Logger) AttackChainAdvanced(ip, phase string, confidence float64) {
	l.log.Warn().
		Str("ip", ip).
		Str("phase", phase).
		Float64("confidence", confidence).
		Msgf("⚔️ %s[ATTACK CHAIN]%s %s%s%s advanced to phase: %s%s%s (%.0f%% confidence)",
			ColorBrightRed+Bold,
			ColorReset,
			ColorBrightYellow,
			ip,
			ColorReset,
			ColorBrightPurple+Bold,
			phase,
			ColorReset,
			confidence*100)
}

func (l *Logger) BlockedAttacker(ip, reason string, duration string) {
	l.log.Warn().
		Str("ip", ip).
		Str("reason", reason).
		Str("duration", duration).
		Msgf("🛡️ %s[BLOCKED]%s IP %s%s%s banned for %s | Reason: %s",
			BgRed+ColorWhite+Bold,
			ColorReset,
			ColorBrightYellow,
			ip,
			ColorReset,
			duration,
			reason)
}
