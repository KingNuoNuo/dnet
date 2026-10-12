package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/config"
)

// 各页面的 GET handler。这里直接用方法名而不是走路由表，是为了绕开 Auth
// 中间件（测试里没有登录 Cookie），把请求打到渲染逻辑本身。
func pageHandlers(s *Server) []struct {
	path string
	get  ViewFunc
} {
	return []struct {
		path string
		get  ViewFunc
	}{
		{"/", s.Home},
		{"/overview", s.OverviewPage},
		{"/dcdn", s.DCDN},
		{"/ddns", s.DDNS},
		{"/webservice", s.WebServicePage},
		{"/forward", s.ForwardPage},
		{"/certificates", s.CertificatesPage},
		{"/webhook", s.Webhook},
		{"/settings", s.Settings},
		{"/logs", s.Logs},
	}
}

// localhostGet 造一个来自私网的 GET 请求 —— 私网地址不会被
// notallowwanaccess 拦掉，能一路走到模板渲染。
func localhostGet(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.168.1.5:12345"
	return req
}

func lastBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// TestPageTemplatesRender 用 Go 自己的模板引擎把每个页面完整渲一遍。
//
// 为什么需要这个测试：这几个页面先前只用 Python 假服务器渲染验证，而假服务器
// 不执行 Go 模板。于是当 ddns.html / dcdn.html 的 HTML 注释里写了模板动作时，
// 假服务器全绿、真机却整页渲染中断 —— Go 模板**不会跳过 HTML 注释**，注释里的
// 动作照样求值，而那个位置的点是顶层数据、并没有该字段。结果是响应写到一半
// 就断了，页面成了半截，行列表的脚本压根没下发，点「添加一行」自然全报错。
// 这里直接调真实 handler，让这一类错误在提交前就暴露。
func TestPageTemplatesRender(t *testing.T) {
	full := config.Config{
		DCDNConfig: config.DCDNConfig{
			DCDNEnabled: true,
			DCDN: []config.CDN{{
				ID:           "a1",
				Name:         "站点 A",
				Domain:       "a.example.com",
				Service:      "aliyun",
				CDNType:      "CDN",
				AccessKey:    "AKxxxxxxxxxxxxxxxx1",
				AccessSecret: "SKxxxxxxxxxxxxxxxx1",
				CName:        "a.example.com.w.cdngslb.com",
				Sources: []config.Source{
					{
						Type: "domain", Value: "origin.example.com",
						Priority: "main", Weight: "10",
						Port: "80", HttpsPort: "443", Protocol: "HTTP",
					},
					{
						Type: "dynamic_ipv6_interface", Value: "eth0", Regex: "@1",
						Priority: "backup", Weight: "10",
						Port: "80", HttpsPort: "443", Protocol: "AUTO",
					},
				},
			}},
		},
		DDNSConfig: config.DDNSConfig{
			DDNSEnabled: true,
			DDNS: []config.DNSGroup{{
				ID:           "g1",
				Name:         "家里",
				Domain:       "home.example.com",
				Service:      "cloudflare",
				TTL:          "AUTO",
				AccessKey:    "AKxxxxxxxxxxxxxxxx1",
				AccessSecret: "SKxxxxxxxxxxxxxxxx1",
				Records: []config.DNSRecord{
					{Type: "A", IPType: "dynamic_ipv4_interface", Value: "eth0"},
					{Type: "AAAA", IPType: "dynamic_ipv6_interface", Value: "eth0", Regex: "@1"},
					{Type: "TXT", IPType: "static_ipv4", Value: "v=spf1 -all"},
				},
			}},
		},
	}

	for _, tc := range []struct {
		name string
		conf config.Config
	}{
		// 真机上 dcdn / ddns 当时就是空列表 —— 空态是最该覆盖的一档
		{"空配置", config.Config{}},
		{"有配置", full},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(&stubRepository{conf: tc.conf}, nil)
			for _, page := range pageHandlers(s) {
				t.Run(page.path, func(t *testing.T) {
					rec := httptest.NewRecorder()
					func() {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("渲染 %s 时 panic: %v", page.path, r)
							}
						}()
						page.get(rec, localhostGet(page.path))
					}()

					body := rec.Body.String()
					if rec.Code != http.StatusOK {
						t.Fatalf("%s 返回 %d，正文末尾: %s", page.path, rec.Code, lastBytes(body, 300))
					}
					// 模板执行出错时 handler 只把错误记进日志，响应已经写了一部分，
					// 客户端拿到的是半截 HTML —— 用结尾标记判断有没有被截断。
					// 不要在这里搜「渲染模板失败」之类的日志文案：渲染错误本身会
					// 被写进日志缓冲区，/logs 页面会把它当内容吐出来，会误伤。
					if !strings.Contains(body, "</html>") {
						t.Fatalf("%s 渲染被截断（找不到 </html>），正文末尾: %s",
							page.path, lastBytes(body, 300))
					}
				})
			}
		})
	}
}

// TestRowListPagesInjectConfigAndIfaces 单独盯住两个行列表页面。
// 它们的初始配置和网卡清单全靠模板注入，而注入点紧挨着曾经会炸的注释，
// 只断言 </html> 不够 —— 这里逐项确认注入内容真的到了页面里。
func TestRowListPagesInjectConfigAndIfaces(t *testing.T) {
	s := NewServer(&stubRepository{conf: config.Config{}}, nil)

	for _, tc := range []struct {
		path string
		get  ViewFunc
		want []string
	}{
		{
			path: "/dcdn",
			get:  s.DCDN,
			want: []string{
				`var configData = {"dcdn_enable"`, `id="iface-ipv4"`, `id="iface-ipv6"`,
				// 「添加一行」的绑定写在文件最末尾 —— 模板一旦中途中断，
				// 先丢掉的就是这几行，表现正是「点添加一行没反应 / 报错」
				`id="add-row"`, `document.querySelector("#add-row").onclick = addRow`,
			},
		},
		{
			path: "/ddns",
			get:  s.DDNS,
			want: []string{
				`var configData = {"ddns_enable"`, `id="iface-ipv4"`, `id="iface-ipv6"`,
				`id="add-row"`, `document.querySelector("#add-row").onclick = addRow`,
			},
		},
	} {
		rec := httptest.NewRecorder()
		tc.get(rec, localhostGet(tc.path))
		body := rec.Body.String()

		for _, want := range append(tc.want, "</html>") {
			if !strings.Contains(body, want) {
				t.Errorf("%s 渲染结果里缺少 %s —— 模板在那之前就中断了", tc.path, want)
			}
		}
	}
}
