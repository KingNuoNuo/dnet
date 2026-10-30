package waf

import (
	"testing"
	"time"
)

func resetStatsForTest() {
	blockStats.Lock()
	blockStats.since = time.Now()
	blockStats.total = 0
	blockStats.bySite = map[string]int64{}
	blockStats.ips = map[string]*IPStat{}
	blockStats.recent = nil
	blockStats.Unlock()
}

func TestBlockStatsAggregates(t *testing.T) {
	resetStatsForTest()

	Record(BlockEvent{Site: "web", IP: "203.0.113.9", Method: "GET", Path: "/?id=1", Rules: "942100", Status: 403})
	Record(BlockEvent{Site: "web", IP: "203.0.113.9", Method: "GET", Path: "/?q=x", Rules: "941100", Status: 403})
	Record(BlockEvent{Site: "nas", IP: "198.51.100.7", Method: "POST", Path: "/login", Rules: "942100", Status: 403})

	stats := Snapshot()
	if stats.Total != 3 {
		t.Fatalf("total = %d", stats.Total)
	}
	if stats.UniqueIPs != 2 {
		t.Fatalf("unique ips = %d", stats.UniqueIPs)
	}
	if len(stats.TopIPs) != 2 || stats.TopIPs[0].IP != "203.0.113.9" || stats.TopIPs[0].Count != 2 {
		t.Fatalf("top ips = %+v", stats.TopIPs)
	}
	if len(stats.Sites) != 2 || stats.Sites[0].Site != "web" || stats.Sites[0].Count != 2 {
		t.Fatalf("sites = %+v", stats.Sites)
	}
	if len(stats.Recent) != 3 || stats.Recent[0].IP != "198.51.100.7" {
		t.Fatalf("recent = %+v", stats.Recent)
	}
	if stats.GeoReady {
		t.Fatal("geo should be disabled without a database")
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:1234":  "203.0.113.9",
		"[2001:db8::1]:443": "2001:db8::1",
		"[2001:db8::1]":     "2001:db8::1",
		"":                  "unknown",
	}
	for in, want := range cases {
		if got := normalizeIP(in); got != want {
			t.Errorf("normalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}
