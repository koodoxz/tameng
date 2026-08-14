package intel

import (
	"sync"
	"testing"
)

// REQ SVALINN-INTEL-HUB-WIRE-001
//
// Hub was fully built (MITRE mapping, IOC blocklist, threat scoring) but had
// zero callers anywhere in the codebase and zero test coverage. This file is
// the first test coverage for this package, written as part of wiring
// IsBlockedIP/IsBlockedDomain into the live request path.

func TestThreatLevel_String(t *testing.T) {
	cases := []struct {
		level ThreatLevel
		want  string
	}{
		{ThreatLow, "low"},
		{ThreatMedium, "medium"},
		{ThreatHigh, "high"},
		{ThreatCritical, "critical"},
		{ThreatUnknown, "unknown"},
		{ThreatLevel(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.want {
			t.Errorf("ThreatLevel(%d).String() = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestNewHub_LoadsMITREWhenEnabled(t *testing.T) {
	h := NewHub(&Config{Enabled: true, MITREEnabled: true})
	if got := h.GetTechnique("T1190"); got == nil {
		t.Fatal("NewHub with MITREEnabled=true did not load built-in technique T1190")
	}
}

func TestNewHub_SkipsMITREWhenDisabled(t *testing.T) {
	h := NewHub(&Config{Enabled: true, MITREEnabled: false})
	if got := h.GetTechnique("T1190"); got != nil {
		t.Fatal("NewHub with MITREEnabled=false loaded a technique anyway")
	}
}

func TestGetTechnique_UnknownIDReturnsNil(t *testing.T) {
	h := NewHub(&Config{Enabled: true, MITREEnabled: true})
	if got := h.GetTechnique("T9999-does-not-exist"); got != nil {
		t.Fatalf("GetTechnique for unknown ID = %+v, want nil", got)
	}
}

func TestMapToMITRE_CategoryBranches(t *testing.T) {
	h := NewHub(&Config{Enabled: true, MITREEnabled: true})

	cases := []struct {
		category   string
		wantTechID string
	}{
		{"sqli", "T1190"},
		{"xss", "T1190"},
		{"path_traversal", "T1190"},
		{"cmd_injection", "T1190"},
		{"scanner", "T1046"},
		{"brute_force", "T1110"},
		{"ssrf", "T1090"},
	}
	for _, c := range cases {
		result := h.MapToMITRE("sig-1", c.category)
		if len(result) != 1 || result[0].ID != c.wantTechID {
			t.Errorf("MapToMITRE(_, %q) = %+v, want single technique %q", c.category, result, c.wantTechID)
		}
	}

	if result := h.MapToMITRE("sig-1", "unrecognized_category"); len(result) != 0 {
		t.Errorf("MapToMITRE for unrecognized category = %+v, want empty", result)
	}
}

func TestAddIOC_AndIsBlockedIP(t *testing.T) {
	h := NewHub(&Config{Enabled: true})

	if _, blocked := h.IsBlockedIP("203.0.113.5"); blocked {
		t.Fatal("IsBlockedIP true before AddIOC")
	}

	h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.5", ThreatLevel: ThreatHigh, Source: "test"})

	ioc, blocked := h.IsBlockedIP("203.0.113.5")
	if !blocked {
		t.Fatal("IsBlockedIP false after AddIOC")
	}
	if ioc.ThreatLevel != ThreatHigh {
		t.Errorf("IsBlockedIP threat level = %v, want ThreatHigh", ioc.ThreatLevel)
	}
}

func TestAddIOC_AndIsBlockedDomain(t *testing.T) {
	h := NewHub(&Config{Enabled: true})

	h.AddIOC(&IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: ThreatCritical, Source: "test"})

	ioc, blocked := h.IsBlockedDomain("evil.example.com")
	if !blocked {
		t.Fatal("IsBlockedDomain false after AddIOC")
	}
	if ioc.ThreatLevel != ThreatCritical {
		t.Errorf("IsBlockedDomain threat level = %v, want ThreatCritical", ioc.ThreatLevel)
	}
}

func TestAddIOC_OtherTypeNotAddedToEitherBlocklist(t *testing.T) {
	h := NewHub(&Config{Enabled: true})

	h.AddIOC(&IOC{Type: "hash", Value: "deadbeef", ThreatLevel: ThreatHigh, Source: "test"})

	if _, blocked := h.IsBlockedIP("deadbeef"); blocked {
		t.Fatal("a hash IOC leaked into the IP blocklist")
	}
	if _, blocked := h.IsBlockedDomain("deadbeef"); blocked {
		t.Fatal("a hash IOC leaked into the domain blocklist")
	}
	stats := h.GetIOCStats()
	if stats["total_iocs"] != 1 {
		t.Errorf("total_iocs = %d, want 1 (hash IOC must still be tracked)", stats["total_iocs"])
	}
}

func TestRemoveIOC_IP(t *testing.T) {
	h := NewHub(&Config{Enabled: true})
	h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.9", ThreatLevel: ThreatHigh, Source: "test"})

	if ok := h.RemoveIOC("ip", "203.0.113.9"); !ok {
		t.Fatal("RemoveIOC returned false for an IOC that exists")
	}
	if _, blocked := h.IsBlockedIP("203.0.113.9"); blocked {
		t.Fatal("IP still blocked after RemoveIOC")
	}
}

func TestRemoveIOC_Domain(t *testing.T) {
	h := NewHub(&Config{Enabled: true})
	h.AddIOC(&IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: ThreatHigh, Source: "test"})

	if ok := h.RemoveIOC("domain", "evil.example.com"); !ok {
		t.Fatal("RemoveIOC returned false for an IOC that exists")
	}
	if _, blocked := h.IsBlockedDomain("evil.example.com"); blocked {
		t.Fatal("domain still blocked after RemoveIOC")
	}
}

func TestRemoveIOC_NonexistentReturnsFalse(t *testing.T) {
	h := NewHub(&Config{Enabled: true})
	if ok := h.RemoveIOC("ip", "203.0.113.99"); ok {
		t.Fatal("RemoveIOC returned true for an IOC that was never added")
	}
}

func TestRemoveIOC_RemovesFromTotalCount(t *testing.T) {
	h := NewHub(&Config{Enabled: true})
	h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.10", ThreatLevel: ThreatHigh, Source: "test"})

	h.RemoveIOC("ip", "203.0.113.10")

	if stats := h.GetIOCStats(); stats["total_iocs"] != 0 {
		t.Errorf("total_iocs after RemoveIOC = %d, want 0", stats["total_iocs"])
	}
}

func TestGetIOCStats(t *testing.T) {
	h := NewHub(&Config{Enabled: true, MITREEnabled: true})
	h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.1", ThreatLevel: ThreatHigh, Source: "test"})
	h.AddIOC(&IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: ThreatHigh, Source: "test"})

	stats := h.GetIOCStats()
	if stats["total_iocs"] != 2 {
		t.Errorf("total_iocs = %d, want 2", stats["total_iocs"])
	}
	if stats["blocked_ips"] != 1 {
		t.Errorf("blocked_ips = %d, want 1", stats["blocked_ips"])
	}
	if stats["blocked_domains"] != 1 {
		t.Errorf("blocked_domains = %d, want 1", stats["blocked_domains"])
	}
	if stats["mitre_techniques"] == 0 {
		t.Error("mitre_techniques = 0, want > 0 with MITREEnabled")
	}
}

func TestThreatScore(t *testing.T) {
	h := NewHub(&Config{Enabled: true})

	if score := h.ThreatScore("1.2.3.4", "clean.example.com", "ua"); score != 0 {
		t.Errorf("ThreatScore for unknown ip/domain = %v, want 0", score)
	}

	h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.1", ThreatLevel: ThreatCritical, Source: "test"})
	h.AddIOC(&IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: ThreatCritical, Source: "test"})

	cases := []struct {
		name   string
		ip     string
		domain string
		want   float64
	}{
		{"ip critical only", "203.0.113.1", "clean.example.com", 1.0},
		{"domain critical only", "1.2.3.4", "evil.example.com", 0.8},
		{"both critical", "203.0.113.1", "evil.example.com", 1.8},
	}
	for _, c := range cases {
		if got := h.ThreatScore(c.ip, c.domain, "ua"); got != c.want {
			t.Errorf("%s: ThreatScore = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestThreatScore_AllThreatLevelBranches(t *testing.T) {
	levels := []struct {
		level        ThreatLevel
		wantIPScore  float64
		wantDomScore float64
	}{
		{ThreatLow, 0.2, 0.2},
		{ThreatMedium, 0.5, 0.4},
		{ThreatHigh, 0.8, 0.6},
		{ThreatCritical, 1.0, 0.8},
	}
	for _, lv := range levels {
		h := NewHub(&Config{Enabled: true})
		h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.1", ThreatLevel: lv.level, Source: "test"})
		if got := h.ThreatScore("203.0.113.1", "clean.example.com", "ua"); got != lv.wantIPScore {
			t.Errorf("ip level %v: ThreatScore = %v, want %v", lv.level, got, lv.wantIPScore)
		}

		h2 := NewHub(&Config{Enabled: true})
		h2.AddIOC(&IOC{Type: "domain", Value: "evil.example.com", ThreatLevel: lv.level, Source: "test"})
		if got := h2.ThreatScore("1.2.3.4", "evil.example.com", "ua"); got != lv.wantDomScore {
			t.Errorf("domain level %v: ThreatScore = %v, want %v", lv.level, got, lv.wantDomScore)
		}
	}
}

// TestHub_ConcurrentAccess exercises AddIOC/RemoveIOC/IsBlockedIP/GetIOCStats
// from multiple goroutines under -race to prove the existing sync.RWMutex
// discipline holds for the new RemoveIOC method too.
func TestHub_ConcurrentAccess(t *testing.T) {
	h := NewHub(&Config{Enabled: true})
	var wg sync.WaitGroup

	for i := range 50 {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			h.AddIOC(&IOC{Type: "ip", Value: "203.0.113.1", ThreatLevel: ThreatHigh, Source: "test"})
		}(i)
		go func(n int) {
			defer wg.Done()
			h.RemoveIOC("ip", "203.0.113.1")
		}(i)
		go func(n int) {
			defer wg.Done()
			h.IsBlockedIP("203.0.113.1")
			h.GetIOCStats()
		}(i)
	}
	wg.Wait()
}
