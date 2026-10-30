package web

import (
	"embed"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/waf"
	"github.com/cxbdasheng/dnet/webservice"
)

//go:embed waf.html
var wafFiles embed.FS

func (s *Server) WAFPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := wafFiles.ReadFile("waf.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(body)
}

// WAFAPI 管理全局 WAF 策略；保存后立即重建引擎并重新应用 Web 服务。
func (s *Server) WAFAPI(w http.ResponseWriter, r *http.Request) {
	if s.WebServices == nil {
		http.Error(w, "Web 服务未初始化", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.webServiceMu.Lock()
	defer s.webServiceMu.Unlock()
	conf, err := s.configRepo.Load()
	if err != nil {
		helper.ReturnError(w, "加载配置失败")
		return
	}
	conf.NormalizeWAF()
	if r.Method == http.MethodPost {
		media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if media != "application/json" {
			http.Error(w, "请使用 JSON 提交", http.StatusUnsupportedMediaType)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "请求来源不匹配", http.StatusForbidden)
				return
			}
		}
		var payload struct {
			Action        string       `json:"action"`
			Policies      []waf.Policy `json:"policies"`
			ExcludeIPs    []string     `json:"exclude_ips"`
			BanEnabled    bool         `json:"ban_enabled"`
			Threshold     int          `json:"threshold"`
			WindowMinutes int          `json:"window_minutes"`
			BanMinutes    int          `json:"ban_minutes"`
			RateLimit     int          `json:"rate_limit"`
			Burst         int          `json:"burst"`
			Whitelist     []string     `json:"whitelist"`
			HSTS          bool         `json:"hsts"`
			HSTSMaxAge    int          `json:"hsts_max_age"`
			HideServer    bool         `json:"hide_server"`
			TLSMinVersion string       `json:"tls_min_version"`
			IP            string       `json:"ip"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			helper.ReturnError(w, "配置格式错误")
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			helper.ReturnError(w, "请求只能包含一个 JSON 对象")
			return
		}
		switch payload.Action {
		case "exclude_save":
			normalized, err := waf.NormalizeExclusions(payload.ExcludeIPs)
			if err != nil {
				helper.ReturnError(w, err.Error())
				return
			}
			if err := waf.SetExcludedIPs(normalized); err != nil {
				helper.ReturnError(w, err.Error())
				return
			}
			conf.WAFExcludeIPs = normalized
			if err := s.configRepo.Save(&conf); err != nil {
				helper.ReturnError(w, "保存失败: "+err.Error())
				return
			}
			helper.Info(helper.LogTypeWebService, "WAF 统计排除列表已更新 [%d 项]", len(normalized))
		case "guard_save":
			guard := config.WAFGuard{
				BanEnabled:    payload.BanEnabled,
				Threshold:     payload.Threshold,
				WindowMinutes: payload.WindowMinutes,
				BanMinutes:    payload.BanMinutes,
				RateLimit:     payload.RateLimit,
				Burst:         payload.Burst,
				Whitelist:     payload.Whitelist,
			}.Normalized()
			security := config.Security{
				HSTS:          payload.HSTS,
				HSTSMaxAge:    payload.HSTSMaxAge,
				HideServer:    payload.HideServer,
				TLSMinVersion: payload.TLSMinVersion,
			}.Normalized()
			conf.WAFGuard = guard
			conf.Security = security
			waf.ConfigureGuard(waf.GuardSettingsFrom(guard.BanEnabled, guard.Threshold, guard.WindowMinutes, guard.BanMinutes, guard.RateLimit, guard.Burst, guard.Whitelist))
			s.WebServices.SetSecurity(webservice.SecurityOptions{
				HSTS:          security.HSTS,
				HSTSMaxAge:    security.HSTSMaxAge,
				HideServer:    security.HideServer,
				TLSMinVersion: webservice.TLSVersion(security.TLSMinVersion),
			})
			if err := s.configRepo.Save(&conf); err != nil {
				helper.ReturnError(w, "保存失败: "+err.Error())
				return
			}
			active := conf.WebServiceRules
			if !conf.WebServiceEnabled {
				active = nil
			}
			if err := s.WebServices.ApplyCertificates(active, conf.Certificates, nil); err != nil {
				helper.ReturnError(w, "设置已保存，但应用失败: "+err.Error())
				return
			}
			helper.Info(helper.LogTypeWebService, "WAF 防护设置已保存 [封禁=%t, 阈值=%d, 限速=%d/s, TLS=%s]",
				guard.BanEnabled, guard.Threshold, guard.RateLimit, security.TLSMinVersion)
		case "unban":
			if strings.TrimSpace(payload.IP) == "" {
				helper.ReturnError(w, "缺少要解封的 IP")
				return
			}
			waf.Unban(payload.IP)
			helper.Info(helper.LogTypeWebService, "WAF 已手动解封 [%s]", payload.IP)
		default:
			policies, err := normalizePolicies(payload.Policies)
			if err != nil {
				helper.ReturnError(w, err.Error())
				return
			}
			conf.WAFPolicies = policies
			known := make(map[string]bool, len(policies))
			for _, policy := range policies {
				known[policy.ID] = true
			}
			for i := range conf.WebServiceRules {
				rule := &conf.WebServiceRules[i]
				if rule.WAFPolicyID != "" && !known[rule.WAFPolicyID] {
					rule.WAFPolicyID = ""
					rule.WAFEnabled = false
				}
			}
			s.WebServices.SetWAFPolicies(policies)
			active := conf.WebServiceRules
			if !conf.WebServiceEnabled {
				active = nil
			}
			if err := s.WebServices.ApplyCertificates(active, conf.Certificates, func() error { return s.configRepo.Save(&conf) }); err != nil {
				helper.Error(helper.LogTypeWebService, "WAF 策略应用失败: %v", err)
				helper.ReturnError(w, err.Error())
				return
			}
			helper.Info(helper.LogTypeWebService, "WAF 策略已保存并应用 [策略数=%d]", len(policies))
		}
	}
	groups, err := waf.Catalog()
	if err != nil {
		helper.ReturnError(w, err.Error())
		return
	}
	manual, auto := waf.Exclusions()
	guard := conf.WAFGuard.Normalized()
	security := conf.Security.Normalized()
	helper.ReturnSuccess(w, "", struct {
		Groups   []waf.RuleGroup `json:"groups"`
		Policies []waf.Policy    `json:"policies"`
		Stats    waf.Stats       `json:"stats"`
		Excluded struct {
			Manual []string `json:"manual"`
			Auto   []string `json:"auto"`
		} `json:"excluded"`
		Guard    config.WAFGuard `json:"guard"`
		Security config.Security `json:"security"`
		Bans     []waf.Ban       `json:"bans"`
	}{groups, conf.WAFPolicies, waf.Snapshot(), struct {
		Manual []string `json:"manual"`
		Auto   []string `json:"auto"`
	}{manual, auto}, guard, security, waf.Bans()})
}
