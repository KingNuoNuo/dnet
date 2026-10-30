package config

import "strings"

// WAFGuard 是 WAF 自动封禁与来源限速设置。
type WAFGuard struct {
	// BanEnabled 同一来源在窗口内命中 WAF 阈值次数后临时封禁。
	BanEnabled bool `json:"ban_enabled" yaml:"ban_enabled,omitempty"`
	// Threshold 窗口内允许的拦截次数，超过即封禁。
	Threshold int `json:"threshold" yaml:"threshold,omitempty"`
	// WindowMinutes 统计窗口（分钟）。
	WindowMinutes int `json:"window_minutes" yaml:"window_minutes,omitempty"`
	// BanMinutes 封禁时长（分钟）。
	BanMinutes int `json:"ban_minutes" yaml:"ban_minutes,omitempty"`
	// RateLimit 每来源每秒请求数，0 表示不限速。
	RateLimit int `json:"rate_limit" yaml:"rate_limit,omitempty"`
	// Burst 限速的突发容量。
	Burst int `json:"burst" yaml:"burst,omitempty"`
	// Whitelist 不受封禁/限速影响的 IP / CIDR。
	Whitelist []string `json:"whitelist" yaml:"whitelist,omitempty"`
}

// Security 是 DWS 的全局 TLS 与响应头加固选项。
type Security struct {
	HSTS       bool `json:"hsts" yaml:"hsts,omitempty"`
	HSTSMaxAge int  `json:"hsts_max_age" yaml:"hsts_max_age,omitempty"`
	HideServer bool `json:"hide_server" yaml:"hide_server,omitempty"`
	// TLSMinVersion 支持 "1.2" / "1.3"，空值按 1.2。
	TLSMinVersion string `json:"tls_min_version" yaml:"tls_min_version,omitempty"`
}

// Normalized 补齐默认值，避免零值配置把防护关死或除零。
func (g WAFGuard) Normalized() WAFGuard {
	if g.Threshold <= 0 {
		g.Threshold = 10
	}
	if g.WindowMinutes <= 0 {
		g.WindowMinutes = 10
	}
	if g.BanMinutes <= 0 {
		g.BanMinutes = 30
	}
	if g.Burst <= 0 {
		g.Burst = 20
	}
	if g.RateLimit < 0 {
		g.RateLimit = 0
	}
	clean := make([]string, 0, len(g.Whitelist))
	for _, item := range g.Whitelist {
		if value := strings.TrimSpace(item); value != "" {
			clean = append(clean, value)
		}
	}
	g.Whitelist = clean
	return g
}

// Normalized 补齐 TLS / HSTS 默认值。
func (s Security) Normalized() Security {
	if s.HSTSMaxAge <= 0 {
		s.HSTSMaxAge = 15552000 // 180 天
	}
	s.TLSMinVersion = strings.TrimSpace(s.TLSMinVersion)
	if s.TLSMinVersion == "" {
		s.TLSMinVersion = "1.2"
	}
	return s
}
