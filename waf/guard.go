package waf

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// GuardSettings 是自动封禁 / 限速的运行时配置。
type GuardSettings struct {
	BanEnabled bool
	Threshold  int
	Window     time.Duration
	BanFor     time.Duration
	RateLimit  float64 // 每秒请求数，0 表示不限速
	Burst      int
	Whitelist  []*net.IPNet
}

// Ban 是一条临时封禁记录。
type Ban struct {
	IP     string    `json:"ip"`
	Until  time.Time `json:"until"`
	Count  int       `json:"count"`
	Reason string    `json:"reason,omitempty"`
}

type hitWindow struct {
	start time.Time
	count int
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

var guardState = struct {
	sync.Mutex
	settings GuardSettings
	bans     map[string]*Ban
	hits     map[string]*hitWindow
	buckets  map[string]*rateBucket
	notifier func(ip string, until time.Time)
}{bans: map[string]*Ban{}, hits: map[string]*hitWindow{}, buckets: map[string]*rateBucket{}}

// ConfigureGuard 更新封禁/限速参数。
func ConfigureGuard(settings GuardSettings) {
	if settings.Threshold <= 0 {
		settings.Threshold = 10
	}
	if settings.Window <= 0 {
		settings.Window = 10 * time.Minute
	}
	if settings.BanFor <= 0 {
		settings.BanFor = 30 * time.Minute
	}
	if settings.Burst <= 0 {
		settings.Burst = 20
	}
	if settings.RateLimit < 0 {
		settings.RateLimit = 0
	}
	guardState.Lock()
	guardState.settings = settings
	guardState.Unlock()
}

// SetBanNotifier 设置封禁通知回调（Webhook 等）。
func SetBanNotifier(fn func(ip string, until time.Time)) {
	guardState.Lock()
	guardState.notifier = fn
	guardState.Unlock()
}

// ParseCIDRs 解析 IP / CIDR 列表，非法项直接忽略（配置由 UI 校验）。
func ParseCIDRs(entries []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
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

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// GuardAllow 判断请求是否放行：先看封禁，再做令牌桶限速。
// 返回 false 时第二个值是需要等待的秒数（用于 Retry-After）。
func GuardAllow(value string) (bool, int) {
	now := time.Now()
	guardState.Lock()
	defer guardState.Unlock()
	settings := guardState.settings
	ip := net.ParseIP(normalizeIP(value))
	if ip == nil {
		return true, 0
	}
	if ipInNets(ip, settings.Whitelist) {
		return true, 0
	}
	key := ip.String()
	if ban := guardState.bans[key]; ban != nil {
		if now.Before(ban.Until) {
			wait := int(time.Until(ban.Until).Seconds()) + 1
			return false, wait
		}
		delete(guardState.bans, key)
	}
	if settings.RateLimit <= 0 {
		return true, 0
	}
	bucket := guardState.buckets[key]
	if bucket == nil {
		if len(guardState.buckets) > 5000 {
			guardState.buckets = map[string]*rateBucket{}
		}
		bucket = &rateBucket{tokens: float64(settings.Burst), last: now}
		guardState.buckets[key] = bucket
	}
	bucket.tokens += now.Sub(bucket.last).Seconds() * settings.RateLimit
	if bucket.tokens > float64(settings.Burst) {
		bucket.tokens = float64(settings.Burst)
	}
	bucket.last = now
	if bucket.tokens < 1 {
		wait := int((1-bucket.tokens)/settings.RateLimit) + 1
		return false, wait
	}
	bucket.tokens--
	return true, 0
}

// RecordBlock 记录一次 WAF 拦截；达到阈值时临时封禁该来源。
func RecordBlock(value string) (bool, time.Time) {
	ipValue := normalizeIP(value)
	ip := net.ParseIP(ipValue)
	if ip == nil {
		return false, time.Time{}
	}
	now := time.Now()
	guardState.Lock()
	settings := guardState.settings
	if !settings.BanEnabled || ipInNets(ip, settings.Whitelist) {
		guardState.Unlock()
		return false, time.Time{}
	}
	window := guardState.hits[ipValue]
	if window == nil || now.Sub(window.start) > settings.Window {
		window = &hitWindow{start: now}
		guardState.hits[ipValue] = window
	}
	window.count++
	until := time.Time{}
	if window.count >= settings.Threshold {
		until = now.Add(settings.BanFor)
		guardState.bans[ipValue] = &Ban{IP: ipValue, Until: until, Count: window.count}
		delete(guardState.hits, ipValue)
	}
	notifier := guardState.notifier
	guardState.Unlock()
	if !until.IsZero() && notifier != nil {
		go notifier(ipValue, until)
	}
	return !until.IsZero(), until
}

// Bans 返回当前封禁列表（已清理过期项）。
func Bans() []Ban {
	now := time.Now()
	guardState.Lock()
	defer guardState.Unlock()
	out := make([]Ban, 0, len(guardState.bans))
	for key, ban := range guardState.bans {
		if now.After(ban.Until) {
			delete(guardState.bans, key)
			continue
		}
		out = append(out, *ban)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	return out
}

// Unban 立即解除某个来源的封禁。
func Unban(value string) {
	key := normalizeIP(value)
	guardState.Lock()
	delete(guardState.bans, key)
	delete(guardState.hits, key)
	delete(guardState.buckets, key)
	guardState.Unlock()
}

// GuardSettingsFrom 构造运行时设置（避免 waf 包反向依赖 config）。
func GuardSettingsFrom(enabled bool, threshold, windowMinutes, banMinutes, rateLimit, burst int, whitelist []string) GuardSettings {
	return GuardSettings{
		BanEnabled: enabled,
		Threshold:  threshold,
		Window:     time.Duration(windowMinutes) * time.Minute,
		BanFor:     time.Duration(banMinutes) * time.Minute,
		RateLimit:  float64(rateLimit),
		Burst:      burst,
		Whitelist:  ParseCIDRs(whitelist),
	}
}
