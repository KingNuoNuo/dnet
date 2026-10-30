package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cxbdasheng/dnet/forward"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/webservice"
)

// forwardConvertInput 是「端口转发 → Web 服务」一键转换的入参。
type forwardConvertInput struct {
	ForwardID          string `json:"forward_id"`
	Domain             string `json:"domain"`
	TargetScheme       string `json:"target_scheme"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	TLS                bool   `json:"tls"`
	CertificateID      string `json:"certificate_id"`
	ForceHTTPS         bool   `json:"force_https"`
	WAFPolicyID        string `json:"waf_policy_id"`
}

// ForwardConvertAPI 把一条已启用的 TCP 端口转发规则转换成 DWS 反向代理：
// 监听端口/备注不变，目标改成 HTTP(S) URL，并挂上证书与 WAF 策略；
// 原转发规则会停用（不删除），方便回滚。
func (s *Server) ForwardConvertAPI(w http.ResponseWriter, r *http.Request) {
	if s.Forwarder == nil || s.WebServices == nil {
		http.Error(w, "服务未初始化", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
	var input forwardConvertInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		helper.ReturnError(w, "请求格式错误")
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		helper.ReturnError(w, "请求只能包含一个 JSON 对象")
		return
	}

	scheme := strings.ToLower(strings.TrimSpace(input.TargetScheme))
	if scheme == "" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		helper.ReturnError(w, "目标协议只能是 http 或 https")
		return
	}

	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	s.webServiceMu.Lock()
	defer s.webServiceMu.Unlock()

	conf, err := s.configRepo.Load()
	if err != nil {
		helper.ReturnError(w, "加载配置失败")
		return
	}
	index := -1
	for i := range conf.ForwardRules {
		if conf.ForwardRules[i].ID == input.ForwardID {
			index = i
			break
		}
	}
	if index < 0 {
		helper.ReturnError(w, "端口转发规则不存在")
		return
	}
	fw := conf.ForwardRules[index]
	if strings.HasPrefix(strings.ToLower(fw.Network), "udp") {
		helper.ReturnError(w, "UDP 转发不能转换为 Web 服务（WAF 只检查 HTTP）")
		return
	}
	network := fw.Network
	address := fw.ListenAddress
	if network == "tcp" && address != "::" {
		if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
	}
	certID := strings.TrimSpace(input.CertificateID)
	if input.TLS && certID == "" {
		helper.ReturnError(w, "启用 HTTPS 需要选择一张证书")
		return
	}
	if certID != "" {
		found := false
		for _, c := range conf.Certificates {
			if c.ID == certID {
				found = true
				break
			}
		}
		if !found {
			helper.ReturnError(w, "所选证书不存在")
			return
		}
	}
	wafID := strings.TrimSpace(input.WAFPolicyID)
	if wafID != "" {
		found := false
		for _, policy := range conf.WAFPolicies {
			if policy.ID == wafID {
				found = true
				break
			}
		}
		if !found {
			helper.ReturnError(w, "所选 WAF 策略不存在")
			return
		}
	}
	name := strings.TrimSpace(fw.Name)
	if name == "" {
		name = "转发 " + strconv.Itoa(fw.ListenPort)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		helper.ReturnError(w, "生成配置 ID 失败")
		return
	}
	rule := webservice.Rule{
		ID:            hex.EncodeToString(b),
		Name:          name,
		Type:          "proxy",
		Domain:        strings.TrimSpace(input.Domain),
		Network:       network,
		ListenAddress: address,
		ListenPort:    fw.ListenPort,
		Target:        scheme + "://" + net.JoinHostPort(fw.TargetHost, strconv.Itoa(fw.TargetPort)),
		PreserveHost:  true,
		// 只有 HTTPS 上游才有证书校验的意义。
		InsecureSkipVerify: input.InsecureSkipVerify && scheme == "https",
		TimeoutSec:         30,
		TLS:                input.TLS,
		ForceHTTPS:         input.ForceHTTPS && input.TLS,
		CertificateID:      certID,
		WAFPolicyID:        wafID,
	}

	oldRules := conf.WebServiceRules
	oldWSEnabled := conf.WebServiceEnabled
	nextRules, err := webservice.Prepare(append(append([]webservice.Rule(nil), oldRules...), rule), oldRules)
	if err != nil {
		helper.ReturnError(w, err.Error())
		return
	}

	// 1) 先停原转发监听，释放端口（保存动作交给下一步成功后再做）。
	conf.ForwardRules[index].Enabled = false
	conf.WebServiceEnabled = true
	conf.WebServiceRules = nextRules
	if err := s.Forwarder.Apply(conf.ActiveForwardRules(), nil); err != nil {
		conf.ForwardRules[index].Enabled = fw.Enabled
		conf.WebServiceEnabled = oldWSEnabled
		conf.WebServiceRules = oldRules
		helper.ReturnError(w, "停止原端口转发失败: "+err.Error())
		return
	}
	// 2) 启动 DWS；失败则恢复原转发。
	if err := s.WebServices.ApplyCertificates(nextRules, conf.Certificates, func() error { return s.configRepo.Save(&conf) }); err != nil {
		conf.ForwardRules[index].Enabled = fw.Enabled
		conf.WebServiceEnabled = oldWSEnabled
		conf.WebServiceRules = oldRules
		if rollbackErr := s.configRepo.Save(&conf); rollbackErr != nil {
			helper.Error(helper.LogTypeDPF, "转换回滚保存失败: %v", rollbackErr)
		}
		if rollbackErr := s.Forwarder.Apply(conf.ActiveForwardRules(), nil); rollbackErr != nil {
			helper.Error(helper.LogTypeDPF, "转换回滚恢复转发失败: %v", rollbackErr)
		}
		helper.ReturnError(w, "启动 Web 服务失败: "+err.Error())
		return
	}
	// 3) 防火墙对账：转发端口撤掉，Web 服务端口按开关补上。
	forward.SetExtraFirewallPorts(webservice.FirewallPorts(conf.WebAutoFirewall && conf.WebServiceEnabled, conf.WebServiceRules))
	forward.SyncFirewall(conf.ForwardAutoFirewall, conf.ActiveForwardRules())
	helper.Info(helper.LogTypeDPF, "端口转发已转换为 Web 服务 [%s, 端口=%d, 域名=%s, WAF=%s]", name, fw.ListenPort, rule.Domain, wafID)
	helper.ReturnSuccess(w, "已转换为 Web 服务，原端口转发已停用", struct {
		ForwardID string          `json:"forward_id"`
		Rule      webservice.Rule `json:"rule"`
	}{fw.ID, rule})
}
