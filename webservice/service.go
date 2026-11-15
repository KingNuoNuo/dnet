// Package webservice manages domain-routed HTTP(S) services.
package webservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cxbdasheng/dnet/certificates"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/waf"
	"golang.org/x/crypto/bcrypt"
)

type Rule struct {
	ForceHTTPS    bool   `json:"force_https" yaml:"force_https,omitempty"`
	CertificateID string `json:"certificate_id" yaml:"certificate_id,omitempty"`
	managedCert   *tls.Certificate
	Type          string `json:"type" yaml:"type,omitempty"`
	RedirectCode  int    `json:"redirect_code" yaml:"redirect_code,omitempty"`
	ID            string `json:"id" yaml:"id"`
	Name          string `json:"name" yaml:"name"`
	Domain        string `json:"domain" yaml:"domain"`
	Network       string `json:"network" yaml:"network"`
	ListenAddress string `json:"listen_address" yaml:"listen_address"`
	ListenPort    int    `json:"listen_port" yaml:"listen_port"`
	Target        string `json:"target" yaml:"target"`
	PreserveHost  bool   `json:"preserve_host" yaml:"preserve_host"`
	// InsecureSkipVerify 跳过上游 HTTPS 证书校验。家里 NAS / 路由器面板常见自签名证书，
	// 或者证书名与服务地址不一致（如用 IP 访问），不打开这个开关反代会返回 502。
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" yaml:"insecure_skip_verify,omitempty"`
	AuthEnabled        bool   `json:"auth_enabled" yaml:"auth_enabled"`
	Username           string `json:"username" yaml:"username"`
	Password           string `json:"password,omitempty" yaml:"-"`
	PasswordHash       string `json:"-" yaml:"password_hash,omitempty"`
	HasPassword        bool   `json:"has_password" yaml:"-"`
	TLS                bool   `json:"tls" yaml:"tls"`
	Certificate        string `json:"certificate" yaml:"certificate"`
	Key                string `json:"key" yaml:"key"`
	TimeoutSec         int    `json:"timeout_sec" yaml:"timeout_sec"`
	// WAFPolicyID 指向一套 WAF 策略；空表示该服务不启用 WAF。
	WAFPolicyID string `json:"waf_policy_id" yaml:"waf_policy_id,omitempty"`
	// WAFEnabled 是 v0.2.2 及之前的开关，仅用于旧配置迁移，
	// 现在由 WAFPolicyID 是否为空推导，对前端保持只读。
	WAFEnabled bool `json:"waf_enabled,omitempty" yaml:"waf_enabled,omitempty"`
	// CountryPolicy 形如 "allow:CN,HK" 或 "deny:RU,KP"，空表示不限制。
	CountryPolicy string `json:"country_policy,omitempty" yaml:"country_policy,omitempty"`
}

func (r Rule) serviceType() string {
	if r.Type == "" {
		return "proxy"
	}
	return r.Type
}

func (r Rule) address() string   { return net.JoinHostPort(r.ListenAddress, strconv.Itoa(r.ListenPort)) }
func (r Rule) groupKey() string  { return r.Network + "/" + r.address() }
func domain(value string) string { return strings.ToLower(strings.TrimSuffix(value, ".")) }
func validDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// listenerRules expands dual-stack rules into explicit IPv4 and IPv6 sockets.
// Both sockets must bind successfully before any configuration is committed.
func listenerRules(rules []Rule) []Rule {
	out := make([]Rule, 0, len(rules)*2)
	for _, r := range rules {
		if r.Network == "tcp" {
			r.Network, r.ListenAddress = "tcp4", "0.0.0.0"
			out = append(out, r)
			r.Network, r.ListenAddress = "tcp6", "::"
		}
		out = append(out, r)
	}
	return out
}

func PublicRules(rules []Rule) []Rule {
	out := slices.Clone(rules)
	for i := range out {
		out[i].HasPassword = out[i].PasswordHash != ""
		out[i].PasswordHash = ""
		out[i].Password = ""
	}
	return out
}

const (
	// DefaultPolicyID 是 v0.2.2 全局 WAF 配置迁移后生成的策略 ID。
	DefaultPolicyID = "default"
)

func Prepare(rules, previous []Rule) ([]Rule, error) {
	out := slices.Clone(rules)
	for i := range out {
		r := &out[i]
		r.PasswordHash = ""
		r.HasPassword = false
		r.Domain = domain(r.Domain)
		// 旧配置只有 on/off 开关：迁移到默认策略，之后按策略选择。
		if r.WAFPolicyID == "" && r.WAFEnabled {
			r.WAFPolicyID = DefaultPolicyID
		}
		r.WAFPolicyID = strings.TrimSpace(r.WAFPolicyID)
		r.WAFEnabled = r.WAFPolicyID != ""
		for _, old := range previous {
			if old.ID == r.ID {
				r.PasswordHash = old.PasswordHash
				break
			}
		}
		if r.Password != "" {
			if len(r.Password) > 72 {
				return nil, fmt.Errorf("%s: 密码不能超过 72 字节", r.Name)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(r.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			r.PasswordHash = string(hash)
		}
		r.Password = ""
	}
	return out, Validate(out)
}
func Validate(rules []Rule) error {
	if len(rules) > 128 {
		return fmt.Errorf("最多支持 128 条 Web 服务配置")
	}
	ids, routes, groups := map[string]bool{}, map[string]bool{}, map[string]Rule{}
	for _, r := range rules {
		if r.ID == "" || ids[r.ID] {
			return fmt.Errorf("配置 ID 为空或重复")
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("配置名称不能为空")
		}
		if !validDomain(r.Domain) {
			return fmt.Errorf("%s: 请填写域名，不含协议、端口、路径或通配符", r.Name)
		}
		if r.Network != "tcp" && r.Network != "tcp4" && r.Network != "tcp6" {
			return fmt.Errorf("%s: 监听协议无效", r.Name)
		}
		ip := net.ParseIP(r.ListenAddress)
		if r.Network == "tcp" && r.ListenAddress != "::" {
			return fmt.Errorf("%s: IPv4 + IPv6 模式的监听地址必须为 ::（全部接口）", r.Name)
		}
		if ip == nil || (r.Network != "tcp" && (r.Network == "tcp4") != (ip.To4() != nil)) {
			return fmt.Errorf("%s: 监听 IP 与协议不匹配", r.Name)
		}
		if r.ListenPort < 1 || r.ListenPort > 65535 {
			return fmt.Errorf("%s: 端口必须为 1–65535", r.Name)
		}
		if r.serviceType() != "proxy" && r.serviceType() != "redirect" && r.serviceType() != "jump" && r.serviceType() != "speedtest" {
			return fmt.Errorf("%s: 服务类型无效", r.Name)
		}
		if r.serviceType() == "redirect" && r.RedirectCode != 0 && r.RedirectCode != 301 && r.RedirectCode != 302 && r.RedirectCode != 307 && r.RedirectCode != 308 {
			return fmt.Errorf("%s: 重定向状态码必须为 301、302、307 或 308", r.Name)
		}
		if r.serviceType() != "speedtest" {
			target, err := url.Parse(r.Target)
			if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || (r.serviceType() == "proxy" && (target.Fragment != "" || target.RawQuery != "")) {
				return fmt.Errorf("%s: 目标必须为 HTTP/HTTPS 地址且不含账号；反向代理目标不能含查询参数或片段", r.Name)
			}
			if net.ParseIP(target.Hostname()) == nil && !validDomain(target.Hostname()) {
				return fmt.Errorf("%s: 目标主机名无效", r.Name)
			}
			if port := target.Port(); port != "" {
				p, err := strconv.Atoi(port)
				if err != nil || p < 1 || p > 65535 {
					return fmt.Errorf("%s: 目标端口无效", r.Name)
				}
			}
		}
		if r.serviceType() == "proxy" && (r.TimeoutSec < 1 || r.TimeoutSec > 300) {
			return fmt.Errorf("%s: 响应头超时必须为 1–300 秒", r.Name)
		}
		if r.AuthEnabled && (r.Username == "" || strings.Contains(r.Username, ":") || r.PasswordHash == "") {
			return fmt.Errorf("%s: 请设置访问账号和密码", r.Name)
		}
		if err := ValidateCountryPolicy(r.CountryPolicy); err != nil {
			return fmt.Errorf("%s: %v", r.Name, err)
		}
		if r.ForceHTTPS && !r.TLS {
			return fmt.Errorf("%s: 强制 HTTPS 需要先启用 HTTPS", r.Name)
		}
		if r.TLS && r.CertificateID == "" && (r.Certificate == "" || r.Key == "") {
			return fmt.Errorf("%s: 请设置 PEM 证书及私钥路径", r.Name)
		}
		for _, r := range listenerRules([]Rule{r}) {
			key := r.groupKey()
			route := key + "/" + domain(r.Domain)
			if routes[route] {
				return fmt.Errorf("%s: 同一监听入口的域名重复", r.Name)
			}
			routes[route] = true
			if old, ok := groups[key]; ok && (old.TLS != r.TLS || old.Certificate != r.Certificate || old.Key != r.Key || old.CertificateID != r.CertificateID) {
				return fmt.Errorf("%s: 同一监听入口必须使用相同的 HTTPS 设置和证书", r.Name)
			}
			groups[key] = r
		}
	}
	return nil
}

type site struct {
	rule      Rule
	handler   http.Handler
	transport *http.Transport
	stats     *ruleStats
}

var jumpPage = template.Must(template.New("jump").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>正在跳转</title></head><body><p>正在跳转，如未自动跳转，请<a href="{{.}}">点击继续</a>。</p><script>window.location.replace({{.}});</script></body></html>`))

// countingConn 按连接统计原始收发字节（含请求/响应头、分块信息与 TLS 记录）。
// 这才是路由器接口计数器能对上的「流量」：原来按请求体计数，GET 请求上行恒为 0，
// WebSocket 升级后的数据更是完全不计。
type countingConn struct {
	net.Conn
	read    atomic.Int64
	written atomic.Int64

	mu          sync.Mutex
	owner       *ruleStats // 当前字节归属的规则
	flushedUp   int64      // 已经计入 owner 的上行字节
	flushedDown int64      // 已经计入 owner 的下行字节
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.written.Add(int64(n))
	}
	return n, err
}

// Close 在关闭前把剩余字节结算掉，WebSocket 这类长连接靠这一步收尾。
func (c *countingConn) Close() error {
	connRegistry.drop(c)
	c.flush()
	return c.Conn.Close()
}

// attribute 把之后产生的字节记到 st 名下。同端口多域名时，同一连接换站点会改写归属。
func (c *countingConn) attribute(st *ruleStats) {
	if st == nil {
		return
	}
	c.mu.Lock()
	c.owner = st
	c.mu.Unlock()
}

// flush 把上次结算之后新增的字节加给当前归属对象。只加增量，重复调用不会重复计；
// 没有归属时也推进水位，避免这部分字节记到后来的规则头上。
func (c *countingConn) flush() {
	c.mu.Lock()
	up, down := c.read.Load(), c.written.Load()
	deltaUp, deltaDown := up-c.flushedUp, down-c.flushedDown
	c.flushedUp, c.flushedDown = up, down
	owner := c.owner
	c.mu.Unlock()
	if owner == nil {
		return
	}
	if deltaUp > 0 {
		owner.upload.Add(uint64(deltaUp))
	}
	if deltaDown > 0 {
		owner.download.Add(uint64(deltaDown))
	}
}

// connRegistry 记录活跃连接，供 Status() 主动结算。
// http.Server 会把响应写进自己的 bufio 缓冲，等 handler 返回之后才落到 conn 上，
// 所以不能在请求结束时结算（那时字节还没写出去），只能在读状态时结算。
type connSet struct {
	sync.Mutex
	conns map[*countingConn]struct{}
}

var connRegistry = &connSet{conns: map[*countingConn]struct{}{}}

func (r *connSet) add(c *countingConn) {
	r.Lock()
	r.conns[c] = struct{}{}
	r.Unlock()
}

func (r *connSet) drop(c *countingConn) {
	r.Lock()
	delete(r.conns, c)
	r.Unlock()
}

// settle 把全部活跃连接的新增字节归属掉，返回本次新增的上行 / 下行合计。
func (r *connSet) settle() {
	r.Lock()
	conns := make([]*countingConn, 0, len(r.conns))
	for c := range r.conns {
		conns = append(conns, c)
	}
	r.Unlock()
	for _, c := range conns {
		c.flush()
	}
}

// countingListener 套在监听器最内层（TLS 之下），统计的是网卡视角的原始字节。
type countingListener struct {
	net.Listener
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc := &countingConn{Conn: c}
	connRegistry.add(cc)
	return cc, nil
}

// connContextKey 用于把连接放进请求 context，供 handler 找到它的计数器。
type connContextKey struct{}

// connStatsOf 从任意一层包装里找出 countingConn。
// TLS 连接是 tls.Conn，往下是 peekConn / trackedConn，都实现了 Unwrap。
func connStatsOf(c net.Conn) *countingConn {
	for range 8 {
		if c == nil {
			return nil
		}
		if cc, ok := c.(*countingConn); ok {
			return cc
		}
		switch v := c.(type) {
		case interface{ Unwrap() net.Conn }:
			c = v.Unwrap()
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		default:
			return nil
		}
	}
	return nil
}

func newSite(r Rule, rules []Rule, engine *waf.Engine, policy waf.Policy, st *ruleStats, security SecurityOptions) *site {
	target, _ := url.Parse(r.Target)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if r.InsecureSkipVerify {
		cfg := transport.TLSClientConfig
		if cfg != nil {
			cfg = cfg.Clone()
		} else {
			cfg = &tls.Config{}
		}
		cfg.InsecureSkipVerify = true
		transport.TLSClientConfig = cfg
	}
	listeners := slices.Clone(rules)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		remote := conn.RemoteAddr().(*net.TCPAddr)
		local := conn.LocalAddr().(*net.TCPAddr)
		for _, listener := range listeners {
			ip := net.ParseIP(listener.ListenAddress)
			if remote.Port == listener.ListenPort && (remote.IP.Equal(ip) || (ip.IsUnspecified() && remote.IP.Equal(local.IP))) {
				conn.Close()
				return nil, fmt.Errorf("目标指向 Web 服务监听入口")
			}
		}
		return conn, nil
	}
	transport.ResponseHeaderTimeout = time.Duration(r.TimeoutSec) * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(target)
			if r.PreserveHost {
				p.Out.Host = p.In.Host
			}
			p.SetXForwarded()
			p.Out.Header.Del("X-Real-IP")
			if host, _, err := net.SplitHostPort(p.In.RemoteAddr); err == nil {
				p.Out.Header.Set("X-Real-IP", host)
			}
			if r.AuthEnabled {
				p.Out.Header.Del("Authorization")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if security.HideServer {
				resp.Header.Del("Server")
				resp.Header.Del("X-Powered-By")
			}
			if security.HSTS {
				resp.Header.Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d", security.HSTSMaxAge))
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if req.Context().Err() != nil {
				return
			}
			helper.Info(helper.LogTypeWebService, "[%s] 代理请求失败: %v", r.Name, err)
			http.Error(w, "目标服务暂时不可用", http.StatusBadGateway)
		},
	}
	s := &site{rule: r, transport: transport, stats: st}
	auth := newAccessAuth()
	s.handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if security.HSTS && r.TLS {
			w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d", security.HSTSMaxAge))
		}
		if st != nil {
			st.active.Add(1)
			defer st.active.Add(-1)
		}
		if r.AuthEnabled {
			if code := auth.check(req, r, time.Now()); code != 0 {
				if code == http.StatusTooManyRequests {
					w.Header().Set("Retry-After", "60")
					http.Error(w, "认证尝试过于频繁，请稍后重试", code)
				} else {
					w.Header().Set("WWW-Authenticate", `Basic realm="D-NET Web", charset="UTF-8"`)
					http.Error(w, "需要访问账号认证", code)
				}
				return
			}
		}
		switch r.serviceType() {
		case "speedtest":
			speedTestManaged(w, req)
		case "redirect":
			code := r.RedirectCode
			if code == 0 {
				code = http.StatusFound
			}
			http.Redirect(w, req, r.Target, code)
		case "jump":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			if req.Method != http.MethodHead {
				_ = jumpPage.Execute(w, r.Target)
			}
		default:
			proxy.ServeHTTP(w, req)
		}
	})
	if engine != nil {
		// 引擎在 Apply 阶段按服务所选策略构建好，这里只包裹这一条路由。
		// WAF 放在认证之前：恶意请求不必先通过一次 bcrypt 校验。
		s.handler = engine.Handler(r.Name, s.handler)
	}
	// 封禁/限速/地区限制放在最外层：被封禁的来源不必再走 WAF 检查。
	s.handler = guardHandler(r, policy, s.handler)
	return s
}

// prepareWAF 在开监听前为所有策略构建引擎；策略编译失败会让 Apply 整体失败，
// 不会留下半套监听，也不会把坏配置留到运行期。没有配置策略时跳过，避免不启用
// WAF 的用户承担 CRS 的初始化开销。服务引用了不存在的策略时仅告警并跳过。
func (m *Manager) prepareWAF(rules []Rule) (map[string]*waf.Engine, error) {
	if len(m.wafPolicies) == 0 {
		for _, r := range rules {
			if r.WAFPolicyID != "" {
				helper.Warn(helper.LogTypeWebService, "服务 %s 引用的 WAF 策略 %q 不存在，该服务不启用 WAF", r.Name, r.WAFPolicyID)
			}
		}
		return nil, nil
	}
	engines := make(map[string]*waf.Engine, len(m.wafPolicies))
	for _, policy := range m.wafPolicies {
		engine, err := waf.EngineFor(policy)
		if err != nil {
			return nil, fmt.Errorf("WAF 策略 %q: %w", policy.Name, err)
		}
		engines[policy.ID] = engine
	}
	warned := map[string]bool{}
	for _, r := range rules {
		if r.WAFPolicyID != "" && engines[r.WAFPolicyID] == nil && !warned[r.WAFPolicyID] {
			warned[r.WAFPolicyID] = true
			helper.Warn(helper.LogTypeWebService, "服务 %s 引用的 WAF 策略 %q 不存在，该服务不启用 WAF", r.Name, r.WAFPolicyID)
		}
	}
	return engines, nil
}

// SetWAFPolicies 更新全局 WAF 策略列表。与 Apply 一起在配置保存时调用；
// 每个策略的引擎按内容缓存，选择没变就不会重建。
func (m *Manager) SetWAFPolicies(policies []waf.Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]waf.Policy, 0, len(policies))
	for _, policy := range policies {
		out = append(out, waf.NormalizePolicy(policy))
	}
	m.wafPolicies = out
}

// wafPolicyFor 按 ID 取策略；取不到时返回零值，等价于该策略没有额外限制。
// 调用方必须已持有 m.mu（Apply 里在用）。
func (m *Manager) wafPolicyFor(id string) waf.Policy {
	if id == "" {
		return waf.Policy{}
	}
	for _, policy := range m.wafPolicies {
		if policy.ID == id {
			return policy
		}
	}
	return waf.Policy{}
}

type group struct {
	mu          sync.RWMutex
	rule        Rule
	sites       map[string]*site
	tlsConfig   *tls.Config
	listener    net.Listener
	server      *http.Server
	connections map[net.Conn]bool
	closing     bool
	listening   bool
}

// Track sockets below TLS so shutdown also closes hijacked WebSocket streams.
type trackedListener struct {
	net.Listener
	group *group
}
type trackedConn struct {
	net.Conn
	group *group
	once  sync.Once
}

// Unwrap 让 connStatsOf 能穿过这一层找到 countingConn。
func (c *trackedConn) Unwrap() net.Conn { return c.Conn }

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.group.mu.Lock(); delete(c.group.connections, c); c.group.mu.Unlock() })
	return err
}
func (l trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	t := &trackedConn{Conn: c, group: l.group}
	l.group.mu.Lock()
	if l.group.closing {
		l.group.mu.Unlock()
		c.Close()
		return nil, net.ErrClosed
	}
	l.group.connections[t] = true
	l.group.mu.Unlock()
	return t, nil
}
func (g *group) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	g.mu.RLock()
	s := g.sites[domain(host)]
	g.mu.RUnlock()
	if s == nil {
		http.NotFound(w, r)
		return
	}
	if s.rule.TLS && r.TLS == nil {
		if !s.rule.ForceHTTPS {
			http.Error(w, "Please use HTTPS", http.StatusBadRequest)
			return
		}
		host := domain(s.rule.Domain)
		if _, port, err := net.SplitHostPort(r.Host); err == nil {
			p, e := strconv.Atoi(port)
			if e != nil || p < 1 || p > 65535 {
				http.Error(w, "Invalid Host port", http.StatusBadRequest)
				return
			}
			host = net.JoinHostPort(host, port)
		}
		target := &url.URL{Scheme: "https", Host: host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery, ForceQuery: r.URL.ForceQuery}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
		return
	}
	// 连接级的真实流量按请求归属。这里只登记归属，不结算：http.Server 会把响应
	// 写进自己的 bufio 缓冲，等 handler 返回之后才落到 conn 上，过早结算会漏掉
	// 整个响应体。实际结算发生在 Status() 轮询与连接关闭时。
	if s.stats != nil {
		if raw, ok := r.Context().Value(connContextKey{}).(net.Conn); ok {
			if conn := connStatsOf(raw); conn != nil {
				conn.attribute(s.stats)
			}
		}
	}
	s.handler.ServeHTTP(w, r)
}
func (g *group) close() {
	g.mu.Lock()
	g.closing = true
	g.listening = false
	connections := make([]net.Conn, 0, len(g.connections))
	for c := range g.connections {
		connections = append(connections, c)
	}
	sites := g.sites
	g.mu.Unlock()
	g.server.Close()
	g.listener.Close()
	for _, c := range connections {
		c.Close()
	}
	for _, s := range sites {
		s.transport.CloseIdleConnections()
	}
}

type Status struct {
	ID          string `json:"id"`
	Listening   bool   `json:"listening"`
	Connections int    `json:"connections"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
}

// ruleStats 是单条 Web 服务的累计流量与当前并发请求数。
type ruleStats struct {
	upload   atomic.Uint64
	download atomic.Uint64
	active   atomic.Int64
}

type Manager struct {
	mu          sync.Mutex
	groups      map[string]*group
	closed      bool
	wafPolicies []waf.Policy
	stats       map[string]*ruleStats
	security    SecurityOptions
}

// SecurityOptions 是 DWS 的全局 TLS / 响应头加固参数。
type SecurityOptions struct {
	HSTS          bool
	HSTSMaxAge    int
	HideServer    bool
	TLSMinVersion uint16
}

func (m *Manager) SetSecurity(options SecurityOptions) {
	m.mu.Lock()
	m.security = options
	m.mu.Unlock()
}

func (m *Manager) tlsMinVersion() uint16 {
	if m.security.TLSMinVersion == tls.VersionTLS13 {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// TLSVersion 把 "1.2" / "1.3" 转成 crypto/tls 常量，其它值按 1.2。
func TLSVersion(value string) uint16 {
	if strings.TrimSpace(value) == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func (m *Manager) statsFor(id string) *ruleStats {
	if m.stats == nil {
		m.stats = map[string]*ruleStats{}
	}
	st := m.stats[id]
	if st == nil {
		st = &ruleStats{}
		m.stats[id] = st
	}
	return st
}

func NewManager() *Manager {
	return &Manager{groups: map[string]*group{}, stats: map[string]*ruleStats{}}
}
func (m *Manager) Status() []Status {
	// 先把活跃连接上还没归属的字节结算掉，否则页面上的数字会落后于实际。
	connRegistry.settle()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Status{}
	indexes := map[string]int{}
	for _, g := range m.groups {
		g.mu.RLock()
		for _, s := range g.sites {
			if index, ok := indexes[s.rule.ID]; ok {
				out[index].Listening = out[index].Listening && g.listening
			} else {
				indexes[s.rule.ID] = len(out)
				out = append(out, Status{ID: s.rule.ID, Listening: g.listening})
			}
		}
		g.mu.RUnlock()
	}
	for i := range out {
		if st := m.stats[out[i].ID]; st != nil {
			out[i].Connections = int(st.active.Load())
			out[i].Upload = int64(st.upload.Load())
			out[i].Download = int64(st.download.Load())
		}
	}
	return out
}
func (m *Manager) Apply(rules []Rule, save func() error) error {
	if err := Validate(rules); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("Web 服务已停止")
	}
	engines, err := m.prepareWAF(rules)
	if err != nil {
		return err
	}
	rules = listenerRules(rules)
	next := map[string]*group{}
	routes := map[string]map[string]*site{}
	certs := map[string]*tls.Config{}
	created := []*group{}
	rollback := func() {
		for _, g := range created {
			g.listener.Close()
		}
		for _, ss := range routes {
			for _, s := range ss {
				s.transport.CloseIdleConnections()
			}
		}
	}
	for _, r := range rules {
		key := r.groupKey()
		if routes[key] == nil {
			routes[key] = map[string]*site{}
		}
		routes[key][domain(r.Domain)] = newSite(r, rules, engines[r.WAFPolicyID], m.wafPolicyFor(r.WAFPolicyID), m.statsFor(r.ID), m.security)
		if next[key] != nil {
			continue
		}
		if r.TLS {
			var cert tls.Certificate
			var err error
			if r.CertificateID != "" {
				if r.managedCert == nil {
					err = fmt.Errorf("托管证书未加载")
				} else {
					cert = *r.managedCert
				}
			} else {
				cert, err = tls.LoadX509KeyPair(r.Certificate, r.Key)
			}
			if err != nil {
				rollback()
				return fmt.Errorf("%s: 证书或私钥无法加载: %w", r.Name, err)
			}
			certs[key] = &tls.Config{MinVersion: m.tlsMinVersion(), Certificates: []tls.Certificate{cert}}
		}
		if old := m.groups[key]; old != nil {
			if old.rule.TLS != r.TLS {
				rollback()
				return fmt.Errorf("%s: 切换 HTTP/HTTPS 前请先关闭全局开关并提交", r.Name)
			}
			next[key] = old
			continue
		}
		listener, err := net.Listen(r.Network, r.address())
		if err != nil {
			rollback()
			return fmt.Errorf("%s: 监听失败: %w", r.Name, err)
		}
		g := &group{rule: r, connections: map[net.Conn]bool{}, listening: true}
		g.listener = trackedListener{countingListener{listener}, g}
		if r.TLS {
			g.listener = newMixedListener(g.listener, &tls.Config{MinVersion: m.tlsMinVersion(), GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				g.mu.RLock()
				defer g.mu.RUnlock()
				return g.tlsConfig, nil
			}})
		}
		g.server = &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, BaseContext: func(net.Listener) context.Context { return context.Background() }, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey{}, c)
		}}
		next[key] = g
		created = append(created, g)
	}
	if save != nil {
		if err := save(); err != nil {
			rollback()
			return err
		}
	}
	for key, g := range next {
		g.mu.Lock()
		old := g.sites
		g.sites = routes[key]
		g.tlsConfig = certs[key]
		g.mu.Unlock()
		for _, s := range old {
			s.transport.CloseIdleConnections()
		}
	}
	for key, g := range m.groups {
		if next[key] != g {
			g.close()
			helper.Info(helper.LogTypeWebService, "停止监听 %s", g.rule.address())
		}
	}
	m.groups = next
	for _, g := range created {
		helper.Info(helper.LogTypeWebService, "开始监听 %s", g.rule.address())
		go func(g *group) {
			err := g.server.Serve(g.listener)
			g.mu.Lock()
			g.listening = false
			g.mu.Unlock()
			if err != nil && err != http.ErrServerClosed {
				helper.Error(helper.LogTypeWebService, "监听异常: %v", err)
			}
		}(g)
	}
	return nil
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, g := range m.groups {
		g.close()
	}
	m.groups = map[string]*group{}
}

// ApplyCertificates resolves shared certificate IDs without persisting certificate material in rules.
func (m *Manager) ApplyCertificates(rules []Rule, certs []certificates.Certificate, save func() error) error {
	resolved, err := ResolveCertificates(rules, certs)
	if err != nil {
		return err
	}
	return m.Apply(resolved, save)
}
func ResolveCertificates(rules []Rule, certs []certificates.Certificate) ([]Rule, error) {
	out := slices.Clone(rules)
	loaded := map[string]*tls.Certificate{}
	for i := range out {
		r := &out[i]
		if !r.TLS || r.CertificateID == "" {
			continue
		}
		pair := loaded[r.CertificateID]
		if pair == nil {
			var found *certificates.Certificate
			for j := range certs {
				if certs[j].ID == r.CertificateID {
					found = &certs[j]
					break
				}
			}
			if found == nil {
				return nil, fmt.Errorf("%s: 所选证书不存在", r.Name)
			}
			value, err := certificates.Load(*found)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", r.Name, err)
			}
			pair = &value
			loaded[r.CertificateID] = pair
		}
		if err := pair.Leaf.VerifyHostname(r.Domain); err != nil {
			return nil, fmt.Errorf("%s: 证书未覆盖域名 %s", r.Name, r.Domain)
		}
		if time.Now().Before(pair.Leaf.NotBefore) || !time.Now().Before(pair.Leaf.NotAfter) {
			return nil, fmt.Errorf("%s: 证书尚未生效或已过期", r.Name)
		}
		r.managedCert = pair
	}
	return out, nil
}

type countryPolicy struct {
	allow bool
	codes map[string]bool
}

// parseCountryPolicy accepts "allow:CN,HK" or "deny:RU,KP".
func parseCountryPolicy(value string) *countryPolicy {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	mode, list, ok := strings.Cut(value, ":")
	if !ok {
		return nil
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "allow" && mode != "deny" {
		return nil
	}
	codes := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		code := strings.ToUpper(strings.TrimSpace(item))
		if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
			codes[code] = true
		}
	}
	if len(codes) == 0 {
		return nil
	}
	return &countryPolicy{allow: mode == "allow", codes: codes}
}

func (p *countryPolicy) allows(code string) bool {
	if p.allow {
		return p.codes[code]
	}
	return !p.codes[code]
}

// ValidateCountryPolicy validates the rule's country policy syntax.
func ValidateCountryPolicy(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if parseCountryPolicy(value) == nil {
		return fmt.Errorf("country policy must be allow:CN,HK or deny:RU,KP")
	}
	return nil
}

// effectiveCountryPolicy 决定一条服务最终使用的地区限制：服务行上的
// country_policy 优先，其次看所选 WAF 策略上的「仅允许中国大陆」开关。
func effectiveCountryPolicy(rule Rule, policy waf.Policy) string {
	if value := strings.TrimSpace(rule.CountryPolicy); value != "" {
		return value
	}
	if policy.AllowOnlyCN {
		return "allow:CN"
	}
	return ""
}

// geoWarnOnce 保证「开了地区限制但没放国家库」只告警一次，避免刷日志。
var geoWarnOnce sync.Once

// guardHandler applies temporary bans, per-IP rate limiting and country rules
// before the request reaches WAF or the upstream service.
func guardHandler(rule Rule, wafPolicy waf.Policy, next http.Handler) http.Handler {
	region := parseCountryPolicy(effectiveCountryPolicy(rule, wafPolicy))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ip := waf.ClientIP(req)
		if ok, retry := waf.GuardAllow(ip); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			http.Error(w, "too many requests or temporarily banned", http.StatusTooManyRequests)
			return
		}
		// 内网 / 环回 / CGNAT 没有归属地，地区限制对它们不生效，
		// 否则开了「仅允许中国 IP」连局域网访问都会被挡住。
		if region != nil && !waf.IsLocalIP(ip) {
			code, _ := waf.CountryOf(ip)
			if code == "" {
				// 没放 GeoLite2 / DB-IP 库时查不到归属地，此时放行比全站 403 安全。
				if waf.GeoIPPath() == "" {
					geoWarnOnce.Do(func() {
						helper.Warn(helper.LogTypeWebService, "地区限制已启用但未加载 IP 归属地库，请求将全部放行；请把 GeoLite2-Country.mmdb 或 dbip-country-lite.mmdb 放到配置目录后重启")
					})
					next.ServeHTTP(w, req)
					return
				}
				code = "??"
			}
			if !region.allows(code) {
				http.Error(w, "access denied for this region", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}
