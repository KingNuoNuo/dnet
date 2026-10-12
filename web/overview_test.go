package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/certificates"
	"github.com/cxbdasheng/dnet/forward"
)

func callOverview(t *testing.T, s *Server) overviewData {
	t.Helper()

	w := httptest.NewRecorder()
	s.OverviewAPI(w, httptest.NewRequest("GET", "/api/overview", nil))

	result := decodeResult(t, w)
	if !result.Status {
		t.Fatalf("overview failed: %s", w.Body.String())
	}

	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data overviewData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func overviewServiceByID(t *testing.T, data overviewData, id string) overviewService {
	t.Helper()

	for _, service := range data.Services {
		if service.ID == id {
			return service
		}
	}
	t.Fatalf("service %q missing from overview", id)
	return overviewService{}
}

// 全部模块都关掉时，顶栏不能显示「运行中」。
func TestOverviewAllDisabled(t *testing.T) {
	s := NewServer(&stubRepository{}, nil)

	data := callOverview(t, s)

	if data.State != overviewStateOff || data.Text != "服务已全部停用" {
		t.Fatalf("state=%q text=%q", data.State, data.Text)
	}
	if data.Sub != "0 / 5 个服务已启用" {
		t.Fatalf("sub=%q", data.Sub)
	}
	for _, service := range data.Services {
		if service.Enabled {
			t.Fatalf("service %q should be disabled", service.ID)
		}
	}
}

func TestOverviewRunning(t *testing.T) {
	repo := &stubRepository{}
	repo.conf.DCDNEnabled = true
	repo.conf.DDNSEnabled = true
	repo.conf.ForwardEnabled = true

	m := forward.NewManager()
	defer m.Close()

	s := NewServer(repo, nil)
	s.Forwarder = m

	data := callOverview(t, s)

	if data.State != overviewStateOn || data.Text != "服务运行中" {
		t.Fatalf("state=%q text=%q", data.State, data.Text)
	}
	// DCDN + DDNS + DPF 三个开关打开，证书与 Web 服务为空
	if data.Sub != "3 / 5 个服务已启用" {
		t.Fatalf("sub=%q", data.Sub)
	}
	if len(data.Services) != 5 {
		t.Fatalf("service count = %d", len(data.Services))
	}
}

// 全局开关打开、规则也保存了，但运行时没监听上 —— 要报「部分未监听」而不是「运行中」。
func TestOverviewForwardNotListening(t *testing.T) {
	repo := &stubRepository{}
	repo.conf.ForwardEnabled = true
	repo.conf.ForwardRules = []forward.Rule{
		{ID: "a", Name: "A", Enabled: true},
		{ID: "b", Name: "B", Enabled: true},
	}

	m := forward.NewManager()
	defer m.Close()

	s := NewServer(repo, nil)
	s.Forwarder = m

	data := callOverview(t, s)

	if data.State != overviewStateWarn || data.Text != "服务告警" {
		t.Fatalf("state=%q text=%q", data.State, data.Text)
	}
	if data.Sub != "端口转发 需要处理" {
		t.Fatalf("sub=%q", data.Sub)
	}

	service := overviewServiceByID(t, data, "dpf")
	if service.Text != "部分未监听" || !strings.Contains(service.Meta, "2 条未监听") {
		t.Fatalf("dpf text=%q meta=%q", service.Text, service.Meta)
	}
}

// 关掉全局开关后，规则仍然保存着，但状态必须是「未启用」。
func TestOverviewForwardDisabledKeepsMetadata(t *testing.T) {
	repo := &stubRepository{}
	repo.conf.ForwardEnabled = false
	repo.conf.ForwardRules = []forward.Rule{{ID: "a", Name: "A", Enabled: true}}

	s := NewServer(repo, nil)

	service := overviewServiceByID(t, callOverview(t, s), "dpf")

	if service.State != overviewStateOff || service.Text != "未启用" {
		t.Fatalf("state=%q text=%q", service.State, service.Text)
	}
	if !strings.Contains(service.Meta, "1 条规则已保存") {
		t.Fatalf("meta=%q", service.Meta)
	}
}

// ACME 证书尚未签发，属于「待处理」，不是故障。
func TestOverviewCertificateWaiting(t *testing.T) {
	repo := &stubRepository{}
	repo.conf.Certificates = []certificates.Certificate{
		{ID: "acme", Name: "待签发", Source: "acme"},
	}

	s := NewServer(repo, nil)
	data := callOverview(t, s)

	if data.State != overviewStateWarn {
		t.Fatalf("state=%q text=%q", data.State, data.Text)
	}

	service := overviewServiceByID(t, data, "dssl")
	if service.Text != "证书待处理" {
		t.Fatalf("dssl text=%q meta=%q", service.Text, service.Meta)
	}
}

// 证书解析失败属于故障，且要压过其他模块的告警。
func TestOverviewCertificateBrokenOutranksWarning(t *testing.T) {
	repo := &stubRepository{}
	repo.conf.ForwardEnabled = true
	repo.conf.ForwardRules = []forward.Rule{{ID: "a", Name: "A", Enabled: true}}
	repo.conf.Certificates = []certificates.Certificate{
		{ID: "bad", Name: "坏证书", Source: "upload", CertPEM: "not-a-pem", KeyPEM: "not-a-key"},
	}

	m := forward.NewManager()
	defer m.Close()

	s := NewServer(repo, nil)
	s.Forwarder = m

	data := callOverview(t, s)

	if data.State != overviewStateErr || data.Text != "服务异常" {
		t.Fatalf("state=%q text=%q", data.State, data.Text)
	}
	// 受影响模块按 services 顺序排列：DPF 在前，DSSL 在后
	if data.Sub != "端口转发、证书管理 需要处理" {
		t.Fatalf("sub=%q", data.Sub)
	}
}

func TestOverviewRejectsNonGet(t *testing.T) {
	s := NewServer(&stubRepository{}, nil)

	w := httptest.NewRecorder()
	s.OverviewAPI(w, httptest.NewRequest("POST", "/api/overview", strings.NewReader("{}")))

	if decodeResult(t, w).Status {
		t.Fatal("POST should be rejected")
	}
}

// 新接口要挂鉴权，未登录必须被重定向而不是直接返回状态。
func TestOverviewRequiresAuth(t *testing.T) {
	resetAuthStateForTest()

	s := NewServer(&stubRepository{}, nil)
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/overview", nil))

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("unauthenticated overview status = %d", w.Code)
	}
}
