package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/helper"
)

// cliOverride 读取 CLI 锁定 env 变量，返回 (locked, cliValue)
func cliOverride(envName string) (bool, int) {
	raw := os.Getenv(envName)
	if raw == "" {
		return false, 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return false, 0
	}
	return true, v
}

//go:embed settings.html
var settingsEmbedFile embed.FS

type SettingsRequest struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	NotAllowWanAccess bool   `json:"not_allow_wan_access"`
	Every             int    `json:"every"`
	DCDNCacheTimes    int    `json:"dcdn_cache_times"`
	DDNSCacheTimes    int    `json:"ddns_cache_times"`
	// DNSCredentials 一组服务商凭据，整体覆盖 —— 页面上的增删就是最终结果
	DNSCredentials []config.DNSCredential `json:"dns_credentials"`
	// CDNCredentials CDN 服务商凭据，与 DNSCredentials 同一套结构、分开存
	CDNCredentials []config.DNSCredential `json:"cdn_credentials"`
}

func (s *Server) Settings(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		s.handleSettingsGet(writer, request)
	case http.MethodPost:
		s.handleSettingsPost(writer, request)
	default:
		helper.ReturnError(writer, "不支持的请求方法")
		return
	}
}

func (s *Server) handleSettingsGet(writer http.ResponseWriter, request *http.Request) {
	tmpl, err := template.ParseFS(settingsEmbedFile, "settings.html")
	if err != nil {
		helper.Error(helper.LogTypeConfig, "解析 settings.html 模板失败: %v", err)
		return
	}
	conf, err := s.configRepo.Load()
	if err != nil {
		helper.Error(helper.LogTypeConfig, "获取配置失败: %v", err)
		return
	}

	// 未配置时填充默认值，前端直接展示"生效值"
	settings := conf.Settings
	if settings.Every == 0 {
		settings.Every = config.DefaultEvery
	}
	dcdnCacheTimes := conf.DCDNConfig.CacheTimes
	if dcdnCacheTimes == 0 {
		dcdnCacheTimes = config.DefaultCacheTimes
	}
	ddnsCacheTimes := conf.DDNSConfig.CacheTimes
	if ddnsCacheTimes == 0 {
		ddnsCacheTimes = config.DefaultCacheTimes
	}

	// 如果 CLI 显式锁定了对应参数，展示 CLI 值（Web UI 修改无效）
	everyLocked, cliEvery := cliOverride(config.CLIEveryENV)
	if everyLocked {
		settings.Every = cliEvery
	}
	dcdnLocked, cliDCDN := cliOverride(config.CLIDCDNCacheTimesENV)
	if dcdnLocked {
		dcdnCacheTimes = cliDCDN
	}
	ddnsLocked, cliDDNS := cliOverride(config.CLIDDNSCacheTimesENV)
	if ddnsLocked {
		ddnsCacheTimes = cliDDNS
	}

	err = tmpl.Execute(writer, struct {
		config.User
		config.Settings
		DCDNCacheTimes       int
		DDNSCacheTimes       int
		EveryLocked          bool
		DCDNCacheTimesLocked bool
		DDNSCacheTimesLocked bool
		// DNSCreds 服务商凭据（已脱敏）。只给「系统设置 → 服务商凭据」这一块用。
		DNSCreds template.JS
		// CDNCreds CDN 服务商凭据（已脱敏），同一个 tab 里的 CDN 分区用。
		CDNCreds template.JS
	}{
		conf.User,
		settings,
		dcdnCacheTimes,
		ddnsCacheTimes,
		everyLocked,
		dcdnLocked,
		ddnsLocked,
		template.JS(config.GetDNSCredentialsJSON(conf.DDNSConfig)),
		template.JS(config.GetCDNCredentialsJSON(conf.DCDNConfig)),
	})
	if err != nil {
		helper.Error(helper.LogTypeConfig, "执行 settings 模板失败: %v", err)
	}
}

func (s *Server) handleSettingsPost(writer http.ResponseWriter, request *http.Request) {
	var settingsReq SettingsRequest
	if err := json.NewDecoder(request.Body).Decode(&settingsReq); err != nil {
		helper.Error(helper.LogTypeConfig, "请求解析失败: %v", err)
		helper.ReturnError(writer, "请求格式错误")
		return
	}
	conf, err := s.configRepo.Load()
	if err != nil {
		helper.Error(helper.LogTypeConfig, "获取配置失败: %v", err)
		helper.ReturnError(writer, "获取配置失败")
		return
	}
	if settingsReq.Every != 0 && (settingsReq.Every < 10 || settingsReq.Every > 86400) {
		helper.ReturnError(writer, "同步间隔需在 10 – 86400 秒之间")
		return
	}
	if settingsReq.DCDNCacheTimes != 0 && (settingsReq.DCDNCacheTimes < 1 || settingsReq.DCDNCacheTimes > 1000) {
		helper.ReturnError(writer, "DCDN 强制同步次数需在 1 – 1000 之间")
		return
	}
	if settingsReq.DDNSCacheTimes != 0 && (settingsReq.DDNSCacheTimes < 1 || settingsReq.DDNSCacheTimes > 1000) {
		helper.ReturnError(writer, "DDNS 强制同步次数需在 1 – 1000 之间")
		return
	}
	conf.NotAllowWanAccess = settingsReq.NotAllowWanAccess
	conf.Username = settingsReq.Username

	// DNS 服务商凭据：页面上传的是打码值（没改过）或新填的明文，先按脱敏结果
	// 还原，再整体覆盖。校验放在前面，坏数据不进配置。
	credentials, errMsg := normalizeDNSCredentials(settingsReq.DNSCredentials, conf.DDNSConfig.Credentials)
	if errMsg != "" {
		helper.ReturnError(writer, errMsg)
		return
	}
	credentialsChanged := !reflect.DeepEqual(credentials, conf.DDNSConfig.Credentials)
	conf.DDNSConfig.Credentials = credentials

	// CDN 服务商凭据：同一套校验与脱敏还原规则（callback 同样不允许进全局）
	cdnCredentials, cdnErrMsg := normalizeDNSCredentials(settingsReq.CDNCredentials, conf.DCDNConfig.Credentials)
	if cdnErrMsg != "" {
		helper.ReturnError(writer, cdnErrMsg)
		return
	}
	cdnCredentialsChanged := !reflect.DeepEqual(cdnCredentials, conf.DCDNConfig.Credentials)
	conf.DCDNConfig.Credentials = cdnCredentials
	// CLI 锁定的字段不接受 Web UI 更新，保留用户已有的 config 值
	// （用户后续移除 CLI 参数重启后，仍能拿回之前的配置）
	if everyLocked, _ := cliOverride(config.CLIEveryENV); !everyLocked {
		conf.Every = settingsReq.Every
	}
	if dcdnLocked, _ := cliOverride(config.CLIDCDNCacheTimesENV); !dcdnLocked {
		conf.DCDNConfig.CacheTimes = settingsReq.DCDNCacheTimes
	}
	if ddnsLocked, _ := cliOverride(config.CLIDDNSCacheTimesENV); !ddnsLocked {
		conf.DDNSConfig.CacheTimes = settingsReq.DDNSCacheTimes
	}
	if settingsReq.Password != "" {
		hashedPwd, err := conf.GeneratePassword(settingsReq.Password)
		if err != nil {
			helper.ReturnError(writer, "密码加密失败")
			return
		}
		conf.Password = hashedPwd
	}
	// 保存配置
	if err := s.configRepo.Save(&conf); err != nil {
		helper.Error(helper.LogTypeConfig, "保存配置失败: %v", err)
		helper.ReturnError(writer, "保存配置失败")
		return
	}

	// 凭据改了就立刻用新密钥同步一次，不必等下一个周期、也不用重启
	// （syncer 允许为 nil —— 测试构造 Server 时不带同步器）
	if s.syncer != nil {
		if credentialsChanged {
			s.syncer.TriggerDDNSSyncAsync()
		}
		if cdnCredentialsChanged {
			s.syncer.TriggerDCDNSyncAsync()
		}
	}

	helper.ReturnSuccess(writer, "配置保存成功", nil)
}

// normalizeDNSCredentials 校验一组服务商凭据，并把「没改过的打码值」还原成明文。
// DNS 与 CDN 两个分区共用同一套规则。
//
// 页面上的密钥是打码回显的（见 GetDNSCredentialsJSON）。用户没动过就一直带着
// 那串星号提交回来，这里按脱敏结果比对认出来，换回库里的原始值 —— 与 DDNS
// 页面走的是同一套规则，免得出现「在设置页点一下保存，密钥就变成一串星号」。
func normalizeDNSCredentials(input []config.DNSCredential, oldCreds []config.DNSCredential) ([]config.DNSCredential, string) {
	oldCredMap := make(map[string]config.DNSCredential, len(oldCreds))
	for _, item := range oldCreds {
		oldCredMap[item.Service] = item
	}
	restored := make([]config.DNSCredential, len(input))
	copy(restored, input)
	for i := range restored {
		old, exists := oldCredMap[restored[i].Service]
		if !exists {
			continue
		}
		if restored[i].AccessKey == config.MaskSensitiveString(old.AccessKey) {
			restored[i].AccessKey = old.AccessKey
		}
		if restored[i].AccessSecret == config.MaskSensitiveString(old.AccessSecret) {
			restored[i].AccessSecret = old.AccessSecret
		}
	}

	seen := make(map[string]bool, len(restored))
	out := make([]config.DNSCredential, 0, len(restored))
	for _, credential := range restored {
		service := strings.TrimSpace(credential.Service)
		if service == "" {
			return nil, "请选择 DNS 服务商"
		}
		if config.LegacyCredentialServices[service] {
			return nil, "该服务商的凭据按域名单独配置，不能在这里统一设置"
		}
		if seen[service] {
			return nil, "同一个服务商只能配置一份凭据"
		}
		if strings.TrimSpace(credential.AccessKey) == "" && strings.TrimSpace(credential.AccessSecret) == "" {
			return nil, "凭据不能为空"
		}
		seen[service] = true
		out = append(out, config.DNSCredential{
			Service:      service,
			AccessKey:    credential.AccessKey,
			AccessSecret: credential.AccessSecret,
		})
	}
	return out, ""
}
