package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/forward"
	"github.com/cxbdasheng/dnet/webservice"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestForwardConvertToWebService(t *testing.T) {
	port := freeTCPPort(t)
	repo := &stubRepository{conf: config.Config{
		ForwardEnabled: true,
		ForwardRules: []forward.Rule{{
			ID: "f1", Name: "NAS 面板", Enabled: true,
			Network: "tcp4", ListenAddress: "127.0.0.1", ListenPort: port,
			TargetHost: "127.0.0.1", TargetPort: 65001,
			DialTimeoutSec: 5, MaxConnections: 10,
		}},
	}}
	forwarder := forward.NewManager()
	defer forwarder.Close()
	if err := forwarder.Apply(repo.conf.ActiveForwardRules(), nil); err != nil {
		t.Fatal(err)
	}
	services := webservice.NewManager()
	defer services.Close()
	server := NewServer(repo, nil)
	server.Forwarder = forwarder
	server.WebServices = services

	body, _ := json.Marshal(map[string]any{
		"forward_id": "f1",
		"domain":     "nas.example",
		"tls":        false,
	})
	w := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/forward/convert", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	server.ForwardConvertAPI(w, request)

	if result := decodeResult(t, w); !result.Status {
		t.Fatalf("convert failed: %s", w.Body.String())
	}
	if len(repo.conf.WebServiceRules) != 1 {
		t.Fatalf("web service rules = %d", len(repo.conf.WebServiceRules))
	}
	rule := repo.conf.WebServiceRules[0]
	if rule.ListenPort != port || rule.Network != "tcp4" || rule.Domain != "nas.example" {
		t.Fatalf("unexpected rule: %+v", rule)
	}
	if rule.Target != fmt.Sprintf("http://127.0.0.1:65001") {
		t.Fatalf("target = %q", rule.Target)
	}
	if rule.Name != "NAS 面板" {
		t.Fatalf("name = %q", rule.Name)
	}
	if repo.conf.ForwardRules[0].Enabled {
		t.Fatal("original forward rule should be disabled")
	}
	if !repo.conf.WebServiceEnabled {
		t.Fatal("web service should be enabled after conversion")
	}

	// 端口应该已经由 DWS 接管。
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("DWS is not listening on the converted port: %v", err)
	}
	conn.Close()
}

func TestForwardConvertRejectsUDP(t *testing.T) {
	port := freeTCPPort(t)
	repo := &stubRepository{conf: config.Config{
		ForwardEnabled: true,
		ForwardRules: []forward.Rule{{
			ID: "u1", Name: "DNS", Enabled: true,
			Network: "udp4", ListenAddress: "127.0.0.1", ListenPort: port,
			TargetHost: "127.0.0.1", TargetPort: 53, MaxConnections: 10,
		}},
	}}
	server := NewServer(repo, nil)
	server.Forwarder = forward.NewManager()
	defer server.Forwarder.Close()
	server.WebServices = webservice.NewManager()
	defer server.WebServices.Close()

	body, _ := json.Marshal(map[string]any{"forward_id": "u1", "domain": "dns.example"})
	w := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/forward/convert", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	server.ForwardConvertAPI(w, request)
	if result := decodeResult(t, w); result.Status {
		t.Fatal("UDP rule must not be convertible")
	}
	if len(repo.conf.WebServiceRules) != 0 {
		t.Fatal("no rule should be created")
	}
}

func TestForwardConvertRequiresCertificateForTLS(t *testing.T) {
	port := freeTCPPort(t)
	repo := &stubRepository{conf: config.Config{
		ForwardEnabled: true,
		ForwardRules: []forward.Rule{{
			ID: "f2", Name: "面板", Enabled: true,
			Network: "tcp4", ListenAddress: "127.0.0.1", ListenPort: port,
			TargetHost: "127.0.0.1", TargetPort: 443, MaxConnections: 10,
		}},
	}}
	server := NewServer(repo, nil)
	server.Forwarder = forward.NewManager()
	defer server.Forwarder.Close()
	server.WebServices = webservice.NewManager()
	defer server.WebServices.Close()

	body, _ := json.Marshal(map[string]any{"forward_id": "f2", "domain": "panel.example", "tls": true})
	w := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/forward/convert", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	server.ForwardConvertAPI(w, request)
	if result := decodeResult(t, w); result.Status {
		t.Fatal("TLS without certificate must fail")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("证书")) {
		t.Fatalf("unexpected error: %s", w.Body.String())
	}
}
