package waf

import (
	"os"
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

func TestGeoIPCountryLookup(t *testing.T) {
	path := os.Getenv("DNET_GEOIP_TEST_DB")
	if path == "" {
		t.Skip("set DNET_GEOIP_TEST_DB to an mmdb file to run")
	}
	if err := SetGeoIP(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		blockStats.Lock()
		db := blockStats.geo
		blockStats.geo = nil
		blockStats.geoPath = ""
		blockStats.Unlock()
		if db != nil {
			db.Close()
		}
	})
	resetStatsForTest()
	Record(BlockEvent{Site: "t", IP: "8.8.8.8"})
	stats := Snapshot()
	if !stats.GeoReady || len(stats.TopIPs) != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.TopIPs[0].Code != "US" {
		t.Fatalf("8.8.8.8 country = %q %q", stats.TopIPs[0].Code, stats.TopIPs[0].Country)
	}
}

func TestExcludedSourcesSkipped(t *testing.T) {
	resetStatsForTest()
	if err := SetExcludedIPs([]string{"203.0.113.9", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = SetExcludedIPs(nil)
		blockStats.Lock()
		blockStats.publicIPs = map[string]bool{}
		blockStats.localNets = nil
		blockStats.Unlock()
	})

	for _, ip := range []string{"203.0.113.9", "198.51.100.7", "192.168.1.5", "127.0.0.1"} {
		if Record(BlockEvent{Site: "t", IP: ip}) {
			t.Errorf("%s should be excluded", ip)
		}
	}
	if !Record(BlockEvent{Site: "t", IP: "8.8.8.8"}) {
		t.Fatal("public IP should be recorded")
	}
	stats := Snapshot()
	if stats.Total != 1 || stats.UniqueIPs != 1 {
		t.Fatalf("stats = total %d, ips %d", stats.Total, stats.UniqueIPs)
	}
	manual, _ := Exclusions()
	if len(manual) != 2 || manual[0] != "203.0.113.9" {
		t.Fatalf("manual exclusions = %v", manual)
	}
}

func TestNormalizeExclusions(t *testing.T) {
	got, err := NormalizeExclusions([]string{" 203.0.113.9 ", "198.51.100.0/24", "203.0.113.9", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("normalized = %v", got)
	}
	if _, err := NormalizeExclusions([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid entry must fail")
	}
}
