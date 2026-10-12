package config

import (
	"encoding/json"

	"github.com/cxbdasheng/dnet/helper"
)

type DDNSConfig struct {
	DDNSEnabled bool       `json:"ddns_enable"`
	DDNS        []DNSGroup `json:"ddns"`
	// Credentials 按服务商保存的 API 凭据，统一在「系统设置 → DNS 服务商」里维护。
	// 域名配置只挑服务商，不再各存一份 —— 同一个服务商换密钥时只改一处，
	// 也不会出现「同一个阿里云账号在五个域名下填了五遍」。
	Credentials []DNSCredential `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	// 强制同步计数器初始值
	CacheTimes int `json:"ddns_cache_times,omitempty" yaml:"ddns_cache_times,omitempty"`
}

// DNSCredential 一个 DNS 服务商的 API 凭据。
//
// 注意 callback 服务商不在这个体系里：它的 AccessKey 其实是回调 URL、
// AccessSecret 是请求体，天然每个域名都不一样，共用一份没有意义 ——
// 它的凭据仍然留在自己的配置行上。
type DNSCredential struct {
	Service      string `json:"service" yaml:"service"`
	AccessKey    string `json:"access_key" yaml:"access_key"`
	AccessSecret string `json:"access_secret" yaml:"access_secret"`
}

// CredentialFor 取某个服务商的全局凭据
func (conf DDNSConfig) CredentialFor(service string) (DNSCredential, bool) {
	for _, item := range conf.Credentials {
		if item.Service == service {
			return item, true
		}
	}
	return DNSCredential{}, false
}

// LegacyCredentialServices 列出哪些服务商不需要全局凭据（凭据是每域名独立的）
var LegacyCredentialServices = map[string]bool{
	"callback": true,
}

// MigrateLegacyCredentials 把域名配置里残留的凭据收到全局一份。
//
// 凭据从「每行一份」改成「每服务商一份」（系统设置里统一配）之后，老配置里
// 还带着密钥。保存 DDNS 时顺手把它们提上来 —— 只补全局还没有的服务商，
// 用户不用手动重填一遍。返回提上来的服务商数量。
func MigrateLegacyCredentials(conf *DDNSConfig) int {
	if conf == nil {
		return 0
	}
	known := make(map[string]bool, len(conf.Credentials))
	for _, item := range conf.Credentials {
		known[item.Service] = true
	}
	moved := 0
	for i := range conf.DDNS {
		group := &conf.DDNS[i]
		if group.Service == "" || LegacyCredentialServices[group.Service] {
			continue
		}
		if known[group.Service] {
			// 全局已经有了：行上这一份就是迁移后的残留，清掉
			group.AccessKey = ""
			group.AccessSecret = ""
			continue
		}
		if group.AccessKey == "" && group.AccessSecret == "" {
			continue
		}
		conf.Credentials = append(conf.Credentials, DNSCredential{
			Service:      group.Service,
			AccessKey:    group.AccessKey,
			AccessSecret: group.AccessSecret,
		})
		known[group.Service] = true
		moved++
		// 收归全局之后行上不再留密钥 —— 配置里同一个服务的密钥只该有一处，
		// 否则用户改了全局那份，行上这份还会被读出来（applyGlobalCredential
		// 只在全局为空时才回退），下次迁移又把它提上来，等于删不掉。
		group.AccessKey = ""
		group.AccessSecret = ""
	}
	return moved
}

// RestoreSensitiveFieldsForDDNS 恢复 DDNS 脱敏字段的原始值
// 通过比对新值与旧值的脱敏结果，判断用户是否真正修改了敏感字段
// 只有当新值与旧值脱敏后完全一致时，才使用旧值的原始值
func RestoreSensitiveFieldsForDDNS(newConf, oldConf DDNSConfig) DDNSConfig {
	// 创建映射以快速查找旧配置
	oldGroupMap := make(map[string]DNSGroup)
	for _, group := range oldConf.DDNS {
		oldGroupMap[group.ID] = group
	}

	// 恢复每个 DNS 配置组的敏感字段
	for i := range newConf.DDNS {
		if oldGroup, exists := oldGroupMap[newConf.DDNS[i].ID]; exists {
			// 检查 AccessKey：如果新值与旧值脱敏后完全一致，说明未修改，恢复原始值
			oldAccessKeyMasked := maskSensitiveString(oldGroup.AccessKey)
			if newConf.DDNS[i].AccessKey == oldAccessKeyMasked {
				newConf.DDNS[i].AccessKey = oldGroup.AccessKey
			}
			// 检查 AccessSecret：如果新值与旧值脱敏后完全一致，说明未修改，恢复原始值
			oldAccessSecretMasked := maskSensitiveString(oldGroup.AccessSecret)
			if newConf.DDNS[i].AccessSecret == oldAccessSecretMasked {
				newConf.DDNS[i].AccessSecret = oldGroup.AccessSecret
			}
		}
	}

	// 全局凭据同理：系统设置页拿到的是打码值，原样提交回来时按脱敏结果
	// 判断「没动过」，还原成原始值。
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

// GetDCDNConfigJSON 将 DCDN 配置转换为 JSON 字符串（敏感信息脱敏）
func GetDCDNConfigJSON(DCDNConf DCDNConfig) string {
	// 如果 DCDN 数组为空，初始化为空数组而不是 null
	if DCDNConf.DCDN == nil {
		DCDNConf.DCDN = []CDN{}
	}

	// 创建副本以避免修改原始配置
	// CacheTimes 由「系统设置」页面管理，DCDN 页面不消费，无需序列化
	maskedConf := DCDNConfig{
		DCDNEnabled: DCDNConf.DCDNEnabled,
		DCDN:        make([]CDN, len(DCDNConf.DCDN)),
	}
	// 页面只需要知道「哪些 CDN 服务商已经配好了凭据」，好把没配的标出来、
	// 把人引到系统设置去。凭据本身不下发到页面，密钥留在服务端。
	configuredProviders := make([]string, 0, len(DCDNConf.Credentials))
	for _, credential := range DCDNConf.Credentials {
		if credential.Service == "" {
			continue
		}
		if credential.AccessKey == "" && credential.AccessSecret == "" {
			continue
		}
		configuredProviders = append(configuredProviders, credential.Service)
	}

	// 复制并脱敏每个 CDN 配置
	for i, cdn := range DCDNConf.DCDN {
		maskedConf.DCDN[i] = CDN{
			ID:           cdn.ID,
			Name:         cdn.Name,
			Domain:       cdn.Domain,
			CName:        cdn.CName,
			Service:      cdn.Service,
			AccessKey:    maskSensitiveString(cdn.AccessKey),
			AccessSecret: maskSensitiveString(cdn.AccessSecret),
			CDNType:      cdn.CDNType,
			Sources:      cdn.Sources,
		}
	}

	page := struct {
		DCDNConfig
		// ConfiguredProviders 已配好凭据的 CDN 服务商 id 清单（只有 id，没有凭据）
		ConfiguredProviders []string `json:"configured_providers"`
	}{maskedConf, configuredProviders}

	data, err := json.Marshal(page)
	if err != nil {
		helper.Error(helper.LogTypeDCDN, "序列化DCDN配置失败: %v", err)
		// 返回包含空数组的默认配置
		return `{"dcdn_enable":false,"dcdn":[],"configured_providers":[]}`
	}
	return string(data)
}

// DNSGroup 表示一个域名的配置组，包含多条记录
type DNSGroup struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Domain       string      `json:"domain"`
	Service      string      `json:"service"`
	AccessKey    string      `json:"access_key"`
	AccessSecret string      `json:"access_secret"`
	TTL          string      `json:"ttl"`
	Records      []DNSRecord `json:"records"` // 该域名的多条 DNS 记录
}

// DNSRecord 表示单条 DNS 记录
type DNSRecord struct {
	Type   string `json:"type"`    // 记录类型：A, AAAA, CNAME, TXT
	IPType string `json:"ip_type"` // IP 获取方式：static_ipv4, dynamic_ipv4_url, dynamic_ipv4_interface, dynamic_ipv4_command, static_ipv6, dynamic_ipv6_url, dynamic_ipv6_interface, dynamic_ipv6_command
	Value  string `json:"value"`   // 值：IP地址、URL、网卡名称、命令、CNAME值、TXT 值
	Regex  string `json:"regex"`   // IPv6 正则表达式匹配（仅用于 dynamic_ipv6_interface）
}

// DNSConfig DNS 完整配置（用于传递给 DDNS 处理器）
// 将 DNSGroup 和单个 DNSRecord 合并为一个扁平结构
type DNSConfig struct {
	ID           string
	Name         string
	Domain       string
	Service      string
	AccessKey    string
	AccessSecret string
	TTL          string
	Type         string // 当前记录类型
	IPType       string
	Value        string
	Regex        string
}

// BuildDNSConfig 从 DNSGroup 和 DNSRecord 构建 DNSConfig
func (g *DNSGroup) BuildDNSConfig(record *DNSRecord) DNSConfig {
	return DNSConfig{
		ID:           g.ID,
		Name:         g.Name,
		Domain:       g.Domain,
		Service:      g.Service,
		AccessKey:    g.AccessKey,
		AccessSecret: g.AccessSecret,
		TTL:          g.TTL,
		Type:         record.Type,
		IPType:       record.IPType,
		Value:        record.Value,
		Regex:        record.Regex,
	}
}

// MaskSensitiveString 导出的脱敏包装，供 web 层比对「打码值」用
func MaskSensitiveString(s string) string {
	return maskSensitiveString(s)
}

// GetDNSCredentialsJSON 返回脱敏后的服务商凭据，供「系统设置 → DNS 服务商」展示。
// 密钥只回显打码值；用户没动过的话，提交回来会被 RestoreSensitiveFieldsForDDNS
// 认出来并还原成原始值。
func GetDNSCredentialsJSON(DDNSConf DDNSConfig) string {
	masked := make([]DNSCredential, 0, len(DDNSConf.Credentials))
	for _, item := range DDNSConf.Credentials {
		masked = append(masked, DNSCredential{
			Service:      item.Service,
			AccessKey:    maskSensitiveString(item.AccessKey),
			AccessSecret: maskSensitiveString(item.AccessSecret),
		})
	}
	data, err := json.Marshal(masked)
	if err != nil {
		helper.Error(helper.LogTypeDDNS, "序列化DNS凭据失败: %v", err)
		return "[]"
	}
	return string(data)
}

// GetCDNCredentialsJSON 返回脱敏后的 CDN 服务商凭据，供「系统设置 → 服务商凭据」
// 的 CDN 分区展示。规则与 GetDNSCredentialsJSON 相同。
func GetCDNCredentialsJSON(DCDNConf DCDNConfig) string {
	masked := make([]DNSCredential, 0, len(DCDNConf.Credentials))
	for _, item := range DCDNConf.Credentials {
		masked = append(masked, DNSCredential{
			Service:      item.Service,
			AccessKey:    maskSensitiveString(item.AccessKey),
			AccessSecret: maskSensitiveString(item.AccessSecret),
		})
	}
	data, err := json.Marshal(masked)
	if err != nil {
		helper.Error(helper.LogTypeDCDN, "序列化CDN凭据失败: %v", err)
		return "[]"
	}
	return string(data)
}

// GetDDNSConfigJSON 把 DDNS 配置序列化成页面用的 JSON。
//
// 凭据本身不进页面 —— DDNS 页只需要知道「哪些服务商已经配好了凭据」，
// 好把没配的标出来、把人引到系统设置去。密钥留在服务端。
// CacheTimes 由「系统设置」页面管理，DDNS 页面不消费，无需序列化。
func GetDDNSConfigJSON(DDNSConf DDNSConfig) string {
	page := struct {
		DDNSEnabled bool       `json:"ddns_enable"`
		DDNS        []DNSGroup `json:"ddns"`
		// ConfiguredProviders 已配好凭据的服务商 id 清单（只有 id，没有凭据）
		ConfiguredProviders []string `json:"configured_providers"`
	}{
		DDNSEnabled:         DDNSConf.DDNSEnabled,
		DDNS:                make([]DNSGroup, len(DDNSConf.DDNS)),
		ConfiguredProviders: make([]string, 0, len(DDNSConf.Credentials)),
	}

	// 复制并脱敏每个 DNS 配置组
	for i, group := range DDNSConf.DDNS {
		page.DDNS[i] = DNSGroup{
			ID:           group.ID,
			Name:         group.Name,
			Domain:       group.Domain,
			Service:      group.Service,
			AccessKey:    maskSensitiveString(group.AccessKey),
			AccessSecret: maskSensitiveString(group.AccessSecret),
			TTL:          group.TTL,
			Records:      make([]DNSRecord, len(group.Records)),
		}
		// 复制记录数组
		copy(page.DDNS[i].Records, group.Records)
	}

	for _, credential := range DDNSConf.Credentials {
		if credential.Service == "" {
			continue
		}
		if credential.AccessKey == "" && credential.AccessSecret == "" {
			continue
		}
		page.ConfiguredProviders = append(page.ConfiguredProviders, credential.Service)
	}

	data, err := json.Marshal(page)
	if err != nil {
		helper.Error(helper.LogTypeDDNS, "序列化DDNS配置失败: %v", err)
		return `{"ddns_enable":false,"ddns":[],"configured_providers":[]}`
	}
	return string(data)
}
