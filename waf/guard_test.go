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

func TestIsLocalIP(t *testing.T) {
	local := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.5.4", "192.168.1.10",
		"169.254.10.1", "fe80::1", "100.64.3.7", "100.127.255.254", "0.0.0.0",
	}
	for _, value := range local {
		if !IsLocalIP(value) {
			t.Fatalf("%s should be local", value)
		}
	}
	remote := []string{"8.8.8.8", "1.1.1.1", "203.0.113.50", "100.63.255.255", "100.128.0.1", "2400:3200::1"}
	for _, value := range remote {
		if IsLocalIP(value) {
			t.Fatalf("%s should be public", value)
		}
	}
	// 带端口 / 方括号 IPv6 也要能识别。
	if !IsLocalIP("192.168.1.10:8080") || !IsLocalIP("[::1]:80") {
		t.Fatal("address with port should still be recognised")
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
