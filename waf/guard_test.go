package waf

import (
	"testing"
	"time"
)

func resetGuardForTest() {
	ConfigureGuard(GuardSettings{BanEnabled: false, RateLimit: 0, Burst: 1})
	Unban("203.0.113.50")
	Unban("198.51.100.9")
}

func TestGuardAutoBan(t *testing.T) {
	resetGuardForTest()
	t.Cleanup(resetGuardForTest)
	ConfigureGuard(GuardSettings{BanEnabled: true, Threshold: 2, Window: time.Minute, BanFor: time.Minute})

	ip := "203.0.113.50"
	if ok, _ := GuardAllow(ip); !ok {
		t.Fatal("fresh IP should be allowed")
	}
	if banned, _ := RecordBlock(ip); banned {
		t.Fatal("first hit must not ban")
	}
	banned, until := RecordBlock(ip)
	if !banned || until.IsZero() {
		t.Fatal("second hit should ban")
	}
	if ok, retry := GuardAllow(ip); ok || retry <= 0 {
		t.Fatalf("banned IP allowed: ok=%v retry=%d", ok, retry)
	}
	sawBan := false
	for _, ban := range Bans() {
		if ban.IP == ip {
			sawBan = true
		}
	}
	if !sawBan {
		t.Fatal("ban not listed")
	}
	Unban(ip)
	if ok, _ := GuardAllow(ip); !ok {
		t.Fatal("unban failed")
	}
}

func TestGuardWhitelistAndRate(t *testing.T) {
	resetGuardForTest()
	t.Cleanup(resetGuardForTest)
	ConfigureGuard(GuardSettings{
		BanEnabled: true, Threshold: 1, Window: time.Minute, BanFor: time.Minute,
		RateLimit: 1, Burst: 1, Whitelist: ParseCIDRs([]string{"198.51.100.0/24"}),
	})

	if banned, _ := RecordBlock("198.51.100.9"); banned {
		t.Fatal("whitelisted IP must not be banned")
	}
	if ok, _ := GuardAllow("198.51.100.9"); !ok {
		t.Fatal("whitelisted IP must skip rate limit")
	}

	ip := "203.0.113.50"
	if ok, _ := GuardAllow(ip); !ok {
		t.Fatal("first request should pass")
	}
	if ok, retry := GuardAllow(ip); ok || retry < 1 {
		t.Fatalf("second request should be rate limited: ok=%v retry=%d", ok, retry)
	}
	if banned, _ := RecordBlock(ip); !banned {
		t.Fatal("threshold 1 should ban")
	}
}
