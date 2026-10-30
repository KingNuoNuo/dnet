package web

import (
	"embed"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/waf"
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
			Policies []waf.Policy `json:"policies"`
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
		policies, err := normalizePolicies(payload.Policies)
		if err != nil {
			helper.ReturnError(w, err.Error())
			return
		}
		conf.WAFPolicies = policies
		// 删除策略后，引用它的服务回退为「不启用」。
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
	groups, err := waf.Catalog()
	if err != nil {
		helper.ReturnError(w, err.Error())
		return
	}
	helper.ReturnSuccess(w, "", struct {
		Groups   []waf.RuleGroup `json:"groups"`
		Policies []waf.Policy    `json:"policies"`
	}{groups, conf.WAFPolicies})
}
