package waf

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"

	"github.com/cxbdasheng/dnet/helper"
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
	since      time.Time
	total      int64
	bySite     map[string]int64
	ips        map[string]*IPStat
	recent     []BlockEvent
	geo        *geoip2.Reader
	geoPath    string
	manual     []string
	manualNets []*net.IPNet
	localNets  []*net.IPNet
	publicIPs  map[string]bool
}{since: time.Now(), bySite: map[string]int64{}, ips: map[string]*IPStat{}, publicIPs: map[string]bool{}}

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

// NormalizeExclusions 校验并去重手动排除的 IP / CIDR。
func NormalizeExclusions(entries []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		canonical := ""
		if strings.Contains(value, "/") {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				return nil, fmt.Errorf("无效的网段: %s", value)
			}
			canonical = network.String()
		} else {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("无效的 IP: %s", value)
			}
			canonical = ip.String()
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out, nil
}

func parseExclusions(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, value := range entries {
		if strings.Contains(value, "/") {
			if _, network, err := net.ParseCIDR(value); err == nil {
				nets = append(nets, network)
			}
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

// SetExcludedIPs 替换手动的来源排除列表（IP 或 CIDR）。
func SetExcludedIPs(entries []string) error {
	canonical, err := NormalizeExclusions(entries)
	if err != nil {
		return err
	}
	blockStats.Lock()
	blockStats.manual = canonical
	blockStats.manualNets = parseExclusions(canonical)
	blockStats.Unlock()
	return nil
}

// RefreshLocalNetworks 记录本机网段（内网 IPv4、全局 IPv6 前缀），统计时自动排除。
func RefreshLocalNetworks() {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	nets := make([]*net.IPNet, 0, len(addresses))
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip := network.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if ip.To4() != nil && !ip.IsPrivate() {
			continue
		}
		nets = append(nets, network)
	}
	blockStats.Lock()
	blockStats.localNets = nets
	blockStats.Unlock()
}

// RefreshPublicIPs 通过 ipify 获取本机公网 IPv4 / IPv6，作为统计排除项。
// 家里通常是 PPPoE + 运营商 NAT，公网地址不在本机网卡上，只能外部探测。
func RefreshPublicIPs(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	found := map[string]bool{}

	// 国外 echo 服务（ipify / ip-api）在这类网络上可能被代理，返回的是代理出口 IP；
	// 国内服务走直连，拿到的才是运营商分配的公网地址。
	for _, endpoint := range []string{
		"https://ip.3322.net",
		"https://ddns.oray.com/checkip",
		"https://myip.ipip.net",
	} {
		if ip := fetchEchoIP(ctx, client, endpoint); ip != nil {
			found[ip.String()] = true
			break
		}
	}
	if len(found) == 0 {
		if ip := fetchEchoIP(ctx, client, "https://api.ipify.org"); ip != nil {
			found[ip.String()] = true
		}
	}
	if ip := fetchEchoIP(ctx, client, "https://api6.ipify.org"); ip != nil {
		found[ip.String()] = true
	}
	if len(found) == 0 {
		return
	}
	ips := make([]string, 0, len(found))
	for ip := range found {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	blockStats.Lock()
	blockStats.publicIPs = found
	blockStats.Unlock()
	helper.Info(helper.LogTypeWebService, "WAF 统计已排除本机公网 IP: %s", strings.Join(ips, ", "))
}

var echoIPRe = regexp.MustCompile(`[0-9a-fA-F:.]+`)

// fetchEchoIP 请求 IP echo 服务并提取第一个可解析的地址。
func fetchEchoIP(ctx context.Context, client *http.Client, endpoint string) net.IP {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return nil
	}
	for _, token := range echoIPRe.FindAllString(string(body), -1) {
		token = strings.Trim(token, ".,;")
		if ip := net.ParseIP(token); ip != nil {
			return ip
		}
	}
	return nil
}

// Exclusions 返回手动排除列表与自动识别到的本机地址 / 网段。
func Exclusions() (manual, auto []string) {
	blockStats.Lock()
	defer blockStats.Unlock()
	manual = append([]string(nil), blockStats.manual...)
	auto = make([]string, 0, len(blockStats.localNets)+len(blockStats.publicIPs))
	for _, network := range blockStats.localNets {
		auto = append(auto, network.String())
	}
	for ip := range blockStats.publicIPs {
		auto = append(auto, ip)
	}
	sort.Strings(auto)
	return manual, auto
}

// CountryOf 查询 IP 的国家代码与名称；未加载归属地库时返回空。
func CountryOf(value string) (code, name string) {
	blockStats.Lock()
	defer blockStats.Unlock()
	return lookupCountryLocked(normalizeIP(value))
}

// excludedLocked 判断来源是否属于本机/内网/手动排除范围。调用方需持有锁。
func excludedLocked(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockStats.localNets {
		if network.Contains(ip) {
			return true
		}
	}
	for _, network := range blockStats.manualNets {
		if network.Contains(ip) {
			return true
		}
	}
	return blockStats.publicIPs[ip.String()]
}

// Record 记录一次拦截。调用方不应持有 blockStats 的锁。
func Record(ev BlockEvent) bool {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	ev.IP = normalizeIP(ev.IP)
	blockStats.Lock()
	if excludedLocked(ev.IP) {
		blockStats.Unlock()
		return false
	}
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
	return true
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
