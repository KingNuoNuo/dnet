package waf

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// BlockEvent 是一次 WAF 拦截的明细，保留最近若干条供页面展示。
type BlockEvent struct {
	Time    time.Time `json:"time"`
	Site    string    `json:"site"`
	IP      string    `json:"ip"`
	Country string    `json:"country"`
	Code    string    `json:"code"`
	Method  string    `json:"method"`
	Path    string    `json:"path"`
	RuleID  int       `json:"rule_id"`
	Rules   string    `json:"rules"`
	Status  int       `json:"status"`
}

// IPStat 是按来源 IP 聚合的拦截次数。
type IPStat struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country"`
	Code     string    `json:"code"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
	LastSite string    `json:"last_site"`
	LastPath string    `json:"last_path"`
}

// CountryStat 是按国家聚合的拦截次数。
type CountryStat struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// SiteStat 是按 Web 服务（规则备注）聚合的拦截次数。
type SiteStat struct {
	Site  string `json:"site"`
	Count int    `json:"count"`
}

// Stats 是 WAF 拦截统计快照。
type Stats struct {
	Total     int64         `json:"total"`
	Since     time.Time     `json:"since"`
	UniqueIPs int           `json:"unique_ips"`
	Sites     []SiteStat    `json:"sites"`
	Countries []CountryStat `json:"countries"`
	TopIPs    []IPStat      `json:"top_ips"`
	Recent    []BlockEvent  `json:"recent"`
	GeoReady  bool          `json:"geo_ready"`
	GeoPath   string        `json:"geo_path,omitempty"`
}

const (
	maxRecentEvents = 200
	maxTrackedIPs   = 2000
	topIPsLimit     = 15
	topCountries    = 10
	topSitesLimit   = 10
)

var blockStats = struct {
	sync.Mutex
	since   time.Time
	total   int64
	bySite  map[string]int64
	ips     map[string]*IPStat
	recent  []BlockEvent
	geo     *geoip2.Reader
	geoPath string
}{since: time.Now(), bySite: map[string]int64{}, ips: map[string]*IPStat{}}

// SetGeoIP 加载离线 GeoLite2 / DB-IP 国家库（mmdb）。path 为空表示不启用。
func SetGeoIP(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	db, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	blockStats.Lock()
	old := blockStats.geo
	blockStats.geo = db
	blockStats.geoPath = path
	blockStats.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// GeoIPPath 返回当前加载的国家库路径。
func GeoIPPath() string {
	blockStats.Lock()
	defer blockStats.Unlock()
	return blockStats.geoPath
}

// Record 记录一次拦截。调用方不应持有 blockStats 的锁。
func Record(ev BlockEvent) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.IP = normalizeIP(ev.IP)
	blockStats.Lock()
	defer blockStats.Unlock()

	blockStats.total++
	blockStats.bySite[ev.Site]++
	stat := blockStats.ips[ev.IP]
	if stat == nil {
		if len(blockStats.ips) >= maxTrackedIPs {
			evictOldestIPLocked()
		}
		stat = &IPStat{IP: ev.IP}
		blockStats.ips[ev.IP] = stat
	}
	stat.Count++
	stat.LastSeen = ev.Time
	stat.LastSite = ev.Site
	stat.LastPath = ev.Path
	stat.Code, stat.Country = lookupCountryLocked(ev.IP)
	ev.Code, ev.Country = stat.Code, stat.Country

	blockStats.recent = append(blockStats.recent, ev)
	if len(blockStats.recent) > maxRecentEvents {
		blockStats.recent = blockStats.recent[len(blockStats.recent)-maxRecentEvents:]
	}
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if value == "" {
		return "unknown"
	}
	return value
}

func evictOldestIPLocked() {
	var oldestKey string
	var oldest time.Time
	for key, stat := range blockStats.ips {
		if oldestKey == "" || stat.LastSeen.Before(oldest) {
			oldestKey, oldest = key, stat.LastSeen
		}
	}
	if oldestKey != "" {
		delete(blockStats.ips, oldestKey)
	}
}

func lookupCountryLocked(ipValue string) (code, name string) {
	if blockStats.geo == nil {
		return "", ""
	}
	ip := net.ParseIP(ipValue)
	if ip == nil {
		return "", ""
	}
	record, err := blockStats.geo.Country(ip)
	if err != nil || record == nil {
		return "", ""
	}
	code = strings.ToUpper(record.Country.IsoCode)
	name = record.Country.Names["zh-CN"]
	if name == "" {
		name = record.Country.Names["en"]
	}
	if name == "" {
		name = code
	}
	return code, name
}

// Snapshot 返回当前统计的拷贝，供 HTTP 接口序列化。
func Snapshot() Stats {
	blockStats.Lock()
	defer blockStats.Unlock()

	out := Stats{
		Total:     blockStats.total,
		Since:     blockStats.since,
		UniqueIPs: len(blockStats.ips),
		GeoReady:  blockStats.geo != nil,
		GeoPath:   blockStats.geoPath,
		Sites:     make([]SiteStat, 0, len(blockStats.bySite)),
		TopIPs:    make([]IPStat, 0, len(blockStats.ips)),
		Countries: []CountryStat{},
		Recent:    make([]BlockEvent, 0, len(blockStats.recent)),
	}
	for site, count := range blockStats.bySite {
		out.Sites = append(out.Sites, SiteStat{Site: site, Count: int(count)})
	}
	sort.Slice(out.Sites, func(i, j int) bool {
		if out.Sites[i].Count != out.Sites[j].Count {
			return out.Sites[i].Count > out.Sites[j].Count
		}
		return out.Sites[i].Site < out.Sites[j].Site
	})
	if len(out.Sites) > topSitesLimit {
		out.Sites = out.Sites[:topSitesLimit]
	}

	countries := map[string]*CountryStat{}
	for _, stat := range blockStats.ips {
		out.TopIPs = append(out.TopIPs, *stat)
		key := stat.Code
		if key == "" {
			key = "??"
		}
		item := countries[key]
		if item == nil {
			name := stat.Country
			if name == "" {
				name = "未知"
			}
			item = &CountryStat{Code: key, Name: name}
			countries[key] = item
		}
		item.Count += stat.Count
	}
	sort.Slice(out.TopIPs, func(i, j int) bool {
		if out.TopIPs[i].Count != out.TopIPs[j].Count {
			return out.TopIPs[i].Count > out.TopIPs[j].Count
		}
		return out.TopIPs[i].LastSeen.After(out.TopIPs[j].LastSeen)
	})
	if len(out.TopIPs) > topIPsLimit {
		out.TopIPs = out.TopIPs[:topIPsLimit]
	}
	for _, item := range countries {
		out.Countries = append(out.Countries, *item)
	}
	sort.Slice(out.Countries, func(i, j int) bool {
		if out.Countries[i].Count != out.Countries[j].Count {
			return out.Countries[i].Count > out.Countries[j].Count
		}
		return out.Countries[i].Code < out.Countries[j].Code
	})
	if len(out.Countries) > topCountries {
		out.Countries = out.Countries[:topCountries]
	}

	// 最近的放前面，页面直接渲染。
	for i := len(blockStats.recent) - 1; i >= 0 && len(out.Recent) < maxRecentEvents; i-- {
		out.Recent = append(out.Recent, blockStats.recent[i])
	}
	return out
}
