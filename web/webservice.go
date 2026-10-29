package web

import (
	"embed"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/cxbdasheng/dnet/forward"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/webservice"
)

//go:embed webservice.html
var webServiceFiles embed.FS

func (s *Server) WebServicePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := webServiceFiles.ReadFile("webservice.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(body)
}
func (s *Server) WebServiceAPI(w http.ResponseWriter, r *http.Request) {
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
			Enabled      bool              `json:"enabled"`
			AutoFirewall bool              `json:"auto_firewall"`
			Rules        []webservice.Rule `json:"rules"`
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
		rules, err := webservice.Prepare(payload.Rules, conf.WebServiceRules)
		if err != nil {
			helper.ReturnError(w, err.Error())
			return
		}
		conf.WebServiceEnabled = payload.Enabled
		conf.WebAutoFirewall = payload.AutoFirewall
		conf.WebServiceRules = rules
		active := rules
		if !payload.Enabled {
			active = nil
		}
		// 防火墙放行：与端口转发共用 forward.SyncFirewall 的对账机制，
		// 这里只维护 Web 服务自己的期望端口（禁用或关闭开关时清空）。
		forward.SetExtraFirewallPorts(webservice.FirewallPorts(conf.WebAutoFirewall && payload.Enabled, active))
		if err := s.WebServices.ApplyCertificates(active, conf.Certificates, func() error { return s.configRepo.Save(&conf) }); err != nil {
			helper.Error(helper.LogTypeWebService, "配置应用失败: %v", err)
			helper.ReturnError(w, err.Error())
			return
		}
		helper.Info(helper.LogTypeWebService, "配置保存并应用成功 [开启=%t, 配置数=%d, WAF=%d]", payload.Enabled, len(rules), wafCount(rules))
	}
	helper.ReturnSuccess(w, "", struct {
		Enabled      bool                `json:"enabled"`
		AutoFirewall bool                `json:"auto_firewall"`
		Rules        []webservice.Rule   `json:"rules"`
		Status       []webservice.Status `json:"status"`
	}{conf.WebServiceEnabled, conf.WebAutoFirewall, webservice.PublicRules(conf.WebServiceRules), s.WebServices.Status()})
}

// wafCount 统计启用 Coraza WAF 的服务数，只用于保存日志。
func wafCount(rules []webservice.Rule) int {
	count := 0
	for _, rule := range rules {
		if rule.WAFEnabled {
			count++
		}
	}
	return count
}
