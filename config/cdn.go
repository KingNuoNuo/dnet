package config

import (
	"strings"
)

type DCDNConfig struct {
	DCDNEnabled bool  `json:"dcdn_enable"`
	DCDN        []CDN `json:"dcdn"`
	// Credentials 与 DDNSConfig.Credentials 同一套结构：按服务商存一份 API 凭据，
	// 统一在「系统设置 → 服务商凭据」里维护，动态 CDN 的域名行只挑服务商。
	// json/yaml tag 用 cdn_credentials：Config 同时内嵌 DCDNConfig 和 DDNSConfig，
	// 两边都叫 credentials 会撞 tag。
	Credentials []DNSCredential `json:"cdn_credentials,omitempty" yaml:"cdn_credentials,omitempty"`
	// 强制同步计数器初始值
	CacheTimes int `json:"dcdn_cache_times,omitempty" yaml:"dcdn_cache_times,omitempty"`
}

type CDN struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Domain       string   `json:"domain"`
	Service      string   `json:"service"`
	AccessKey    string   `json:"access_key"`
	AccessSecret string   `json:"access_secret"`
	CDNType      string   `json:"cdn_type"`
	Sources      []Source `json:"sources"`
	CName        string   `json:"cname"`
}

// GetRootDomain 获取域名的根域名
// 例如：test.example.com -> example.com
//
//	example.com -> example.com
func (c *CDN) GetRootDomain() string {
	if c.Domain == "" {
		return ""
	}

	parts := strings.Split(c.Domain, ".")
	if len(parts) <= 2 {
		// 已经是根域名或无效域名
		return c.Domain
	}

	// 返回最后两段作为根域名
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// Source 源站配置
type Source struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Regex     string `json:"regex"` // IPv6 正则表达式匹配（仅用于 dynamic_ipv6_interface）
	Priority  string `json:"priority"`
	Weight    string `json:"weight"`
	Port      string `json:"port"`       // HTTP 端口
	HttpsPort string `json:"https_port"` // HTTPS 端口
	Protocol  string `json:"protocol"`   // HTTP、HTTPS、AUTO（协议跟随），默认 http
}

// maskSensitiveString 对敏感字符串进行脱敏处理
// 规则：保留前4位和后4位，中间用 * 代替；长度 <= 8 时全部用 * 代替
func maskSensitiveString(s string) string {
	if s == "" {
		return ""
	}

	length := len(s)
	if length <= 8 {
		// 如果长度 <= 8，全部用 * 代替
		return strings.Repeat("*", length)
	}

	// 保留前4位和后4位，中间用 * 代替
	maskCount := length - 8
	return s[:4] + strings.Repeat("*", maskCount) + s[length-4:]
}

// CredentialFor 取某个 CDN 服务商的全局凭据
func (conf DCDNConfig) CredentialFor(service string) (DNSCredential, bool) {
	for _, item := range conf.Credentials {
		if item.Service == service {
			return item, true
		}
	}
	return DNSCredential{}, false
}

// MigrateLegacyCDNCredentials 把动态 CDN 配置里残留的凭据收到全局一份。
// 逻辑与 MigrateLegacyCredentials 相同 —— 凭据统一到系统设置后，老配置里
// 还写在域名行上的密钥顺手提上来，只补全局还没有的服务商。
func MigrateLegacyCDNCredentials(conf *DCDNConfig) int {
	if conf == nil {
		return 0
	}
	known := make(map[string]bool, len(conf.Credentials))
	for _, item := range conf.Credentials {
		known[item.Service] = true
	}
	moved := 0
	for i := range conf.DCDN {
		cdn := &conf.DCDN[i]
		if cdn.Service == "" || LegacyCredentialServices[cdn.Service] {
			continue
		}
		if known[cdn.Service] {
			// 全局已经有了：行上这一份就是迁移后的残留，清掉
			cdn.AccessKey = ""
			cdn.AccessSecret = ""
			continue
		}
		if cdn.AccessKey == "" && cdn.AccessSecret == "" {
			continue
		}
		conf.Credentials = append(conf.Credentials, DNSCredential{
			Service:      cdn.Service,
			AccessKey:    cdn.AccessKey,
			AccessSecret: cdn.AccessSecret,
		})
		known[cdn.Service] = true
		moved++
		// 收归全局之后行上不再留密钥 —— 与 DDNS 同理，同一服务的密钥只留一处
		cdn.AccessKey = ""
		cdn.AccessSecret = ""
	}
	return moved
}

// RestoreSensitiveFields 恢复脱敏字段的原始值
// 通过比对新值与旧值的脱敏结果，判断用户是否真正修改了敏感字段
// 只有当新值与旧值脱敏后完全一致时，才使用旧值的原始值
func RestoreSensitiveFields(newConf, oldConf DCDNConfig) DCDNConfig {
	// 创建映射以快速查找旧配置
	oldCDNMap := make(map[string]CDN)
	for _, cdn := range oldConf.DCDN {
		oldCDNMap[cdn.ID] = cdn
	}

	// 恢复每个 CDN 配置的敏感字段
	for i := range newConf.DCDN {
		if oldCDN, exists := oldCDNMap[newConf.DCDN[i].ID]; exists {
			// 检查 AccessKey：如果新值与旧值脱敏后完全一致，说明未修改，恢复原始值
			oldAccessKeyMasked := maskSensitiveString(oldCDN.AccessKey)
			if newConf.DCDN[i].AccessKey == oldAccessKeyMasked {
				newConf.DCDN[i].AccessKey = oldCDN.AccessKey
			}
			// 检查 AccessSecret：如果新值与旧值脱敏后完全一致，说明未修改，恢复原始值
			oldAccessSecretMasked := maskSensitiveString(oldCDN.AccessSecret)
			if newConf.DCDN[i].AccessSecret == oldAccessSecretMasked {
				newConf.DCDN[i].AccessSecret = oldCDN.AccessSecret
			}
			// 检查 Domain：如果新值与旧值不相等，说明已修改，将 CName 设置为空
			if oldCDN.Domain != newConf.DCDN[i].Domain {
				newConf.DCDN[i].CName = ""
			}
		}
	}

	// 全局凭据同理：系统设置页拿到的是打码值，原样提交回来时按脱敏结果
	// 判断「没动过」，还原成原始值（与 RestoreSensitiveFieldsForDDNS 一致）
	oldCredMap := make(map[string]DNSCredential, len(oldConf.Credentials))
	for _, item := range oldConf.Credentials {
		oldCredMap[item.Service] = item
	}
	for i := range newConf.Credentials {
		old, exists := oldCredMap[newConf.Credentials[i].Service]
		if !exists {
			continue
		}
		if newConf.Credentials[i].AccessKey == maskSensitiveString(old.AccessKey) {
			newConf.Credentials[i].AccessKey = old.AccessKey
		}
		if newConf.Credentials[i].AccessSecret == maskSensitiveString(old.AccessSecret) {
			newConf.Credentials[i].AccessSecret = old.AccessSecret
		}
	}

	return newConf
}
