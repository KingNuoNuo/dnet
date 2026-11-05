package certdeploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cxbdasheng/dnet/certificates"
	"github.com/cxbdasheng/dnet/config"
)

func testCertificatePEM(t *testing.T, domains ...string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM)
}

type esaState struct {
	mu       sync.Mutex
	exists   bool
	setCalls int
	name     string
	typ      string
	id       string
	site     string
}

func TestDeployAliyunESA(t *testing.T) {
	certPEM, keyPEM := testCertificatePEM(t, "*.c90.top")

	var state esaState
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		switch r.Form.Get("Action") {
		case "ListSites":
			json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 1,
				"Sites":      []map[string]any{{"SiteId": 1234567890123, "SiteName": "c90.top"}},
			})
		case "ListCertificates":
			if state.exists {
				json.NewEncoder(w).Encode(map[string]any{
					"TotalCount": 1,
					"Result":     []map[string]any{{"Id": "cert-1", "Name": "dnet-c90", "Type": "upload"}},
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"TotalCount": 0, "Result": []any{}})
		case "SetCertificate":
			state.setCalls++
			state.name = r.Form.Get("Name")
			state.typ = r.Form.Get("Type")
			state.id = r.Form.Get("Id")
			state.site = r.Form.Get("SiteId")
			if r.Form.Get("Certificate") == "" || r.Form.Get("PrivateKey") == "" {
				t.Error("certificate/private key not sent")
			}
			state.exists = true
			json.NewEncoder(w).Encode(map[string]any{"Id": "cert-1"})
		default:
			http.Error(w, "unexpected action "+r.Form.Get("Action"), http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	oldEndpoint := esaEndpoint
	esaEndpoint = srv.URL
	defer func() { esaEndpoint = oldEndpoint }()

	conf := config.Config{DCDNConfig: config.DCDNConfig{
		Credentials: []config.DNSCredential{{Service: "aliyun", AccessKey: "ak", AccessSecret: "sk"}},
	}}
	cert := certificates.Certificate{
		ID: "c1", Name: "c90", Source: "acme",
		Domains: []string{"*.c90.top"},
		CertPEM: certPEM, KeyPEM: keyPEM,
		Deploy: []certificates.DeployTarget{{Provider: ProviderAliyunESA}},
	}

	reports, err := Deploy(context.Background(), conf, cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Updated {
		t.Fatalf("first deploy reports = %+v", reports)
	}
	state.mu.Lock()
	if state.name != "dnet-c90" || state.typ != "upload" || state.id != "" || state.site != "1234567890123" {
		t.Fatalf("create params name=%q type=%q id=%q site=%q", state.name, state.typ, state.id, state.site)
	}
	state.mu.Unlock()

	// 第二次应带上已有证书 ID，避免重复创建。
	reports, err = Deploy(context.Background(), conf, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !reports[0].Updated {
		t.Fatalf("expected update, reports=%+v", reports)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.id != "cert-1" || state.setCalls != 2 {
		t.Fatalf("update params id=%q setCalls=%d", state.id, state.setCalls)
	}
}

// 列表接口搜不到同名证书（Keyword 不覆盖 Name 字段），创建时撞上
// Certificate.Duplicated —— 必须重新拉全量再按 Id 覆盖，而不是直接失败。
func TestDeployAliyunESADuplicateFallsBackToUpdate(t *testing.T) {
	certPEM, keyPEM := testCertificatePEM(t, "*.c90.top")

	var listCalls, setCalls int
	var usedID, forcedName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		switch r.Form.Get("Action") {
		case "ListSites":
			json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 1,
				"Sites":      []map[string]any{{"SiteId": 42, "SiteName": "c90.top"}},
			})
		case "ListCertificates":
			listCalls++
			if listCalls == 1 {
				json.NewEncoder(w).Encode(map[string]any{"TotalCount": 0, "Result": []any{}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 1,
				"Result": []map[string]any{{
					"Id": "cert-9", "Name": "dnet-c90", "Type": "upload",
					"Status": "Expired", "NotAfter": "2026-11-01 00:00:00",
				}},
			})
		case "SetCertificate":
			setCalls++
			forcedName = r.Form.Get("Name")
			if r.Form.Get("Id") == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{
					"Code":    "Certificate.Duplicated",
					"Message": "The certificate name already exists.",
				})
				return
			}
			usedID = r.Form.Get("Id")
			json.NewEncoder(w).Encode(map[string]any{"Id": usedID})
		default:
			http.Error(w, "unexpected action "+r.Form.Get("Action"), http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	oldEndpoint := esaEndpoint
	esaEndpoint = srv.URL
	defer func() { esaEndpoint = oldEndpoint }()

	conf := config.Config{DCDNConfig: config.DCDNConfig{
		Credentials: []config.DNSCredential{{Service: "aliyun", AccessKey: "ak", AccessSecret: "sk"}},
	}}
	cert := certificates.Certificate{
		ID: "c1", Name: "c90", Source: "acme",
		Domains: []string{"*.c90.top"},
		CertPEM: certPEM, KeyPEM: keyPEM,
		Deploy: []certificates.DeployTarget{{Provider: ProviderAliyunESA}},
	}

	reports, err := Deploy(context.Background(), conf, cert)
	if err != nil {
		t.Fatalf("撞到 Duplicated 后应回退为更新，却报错: %v", err)
	}
	if len(reports) != 1 || !reports[0].Updated {
		t.Fatalf("reports = %+v", reports)
	}
	if reports[0].PrevNotAfter != "2026-11-01 00:00:00" {
		t.Fatalf("旧证书到期未回传: %+v", reports[0])
	}
	if usedID != "cert-9" || setCalls != 2 || forcedName != "dnet-c90" {
		t.Fatalf("id=%q setCalls=%d name=%q", usedID, setCalls, forcedName)
	}
}

// 同名证书不是 upload 类型（免费证书 / 云证书）时，别静默失败，要给出可操作的提示。
func TestDeployAliyunESANonUploadNameConflict(t *testing.T) {
	certPEM, keyPEM := testCertificatePEM(t, "*.c90.top")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		switch r.Form.Get("Action") {
		case "ListSites":
			json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 1,
				"Sites":      []map[string]any{{"SiteId": 42, "SiteName": "c90.top"}},
			})
		case "ListCertificates":
			json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 1,
				"Result": []map[string]any{{
					"Id": "cert-free", "Name": "dnet-c90", "Type": "free",
					"Status": "OK", "NotAfter": "2026-12-01 00:00:00",
				}},
			})
		case "SetCertificate":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"Code":    "InvalidParameter.Type",
				"Message": "certificate type mismatched.",
			})
		default:
			http.Error(w, "unexpected action "+r.Form.Get("Action"), http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	oldEndpoint := esaEndpoint
	esaEndpoint = srv.URL
	defer func() { esaEndpoint = oldEndpoint }()

	conf := config.Config{DCDNConfig: config.DCDNConfig{
		Credentials: []config.DNSCredential{{Service: "aliyun", AccessKey: "ak", AccessSecret: "sk"}},
	}}
	cert := certificates.Certificate{
		ID: "c1", Name: "c90", Source: "acme", CertPEM: certPEM, KeyPEM: keyPEM,
		Domains: []string{"*.c90.top"},
		Deploy:  []certificates.DeployTarget{{Provider: ProviderAliyunESA}},
	}

	_, err := Deploy(context.Background(), conf, cert)
	if err == nil {
		t.Fatal("应返回错误")
	}
	msg := err.Error()
	for _, want := range []string{"同名证书", "free", "ESA 证书名"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息缺少 %q: %s", want, msg)
		}
	}
}

func TestFindCertByName(t *testing.T) {
	certs := []esaCert{
		{ID: "a", Name: "other", Type: "upload"},
		{ID: "b", Name: "dnet-c90", Type: "free"},
		{ID: "c", Name: "DNET-C90", Type: "upload"},
	}
	if got := findCertByName(certs, "dnet-c90"); got == nil || got.ID != "c" {
		t.Fatalf("应优先返回 upload 类型，got=%+v", got)
	}
	if got := findCertByName(certs, "missing"); got != nil {
		t.Fatalf("不应命中，got=%+v", got)
	}
	if got := findCertByName([]esaCert{{ID: "x", Name: "n", Type: "cas"}}, "n"); got == nil || got.ID != "x" {
		t.Fatalf("非 upload 也应返回用于报错提示，got=%+v", got)
	}
}

func TestIsDuplicateCertError(t *testing.T) {
	yes := []string{
		"SetCertificate: Certificate.Duplicated: The certificate name already exists.",
		"setcertificate: certificate name already exists.",
	}
	for _, s := range yes {
		if !isDuplicateCertError(errors.New(s)) {
			t.Fatalf("应识别为重复: %s", s)
		}
	}
	if isDuplicateCertError(errors.New("SetCertificate: InvalidParameter: bad")) {
		t.Fatal("普通错误不应识别为重复")
	}
}

func TestPendingFollowsFingerprint(t *testing.T) {
	cert := certificates.Certificate{
		CertPEM: "cert", KeyPEM: "key",
		Deploy: []certificates.DeployTarget{{Provider: ProviderAliyunESA}},
	}
	if !Pending(cert) {
		t.Fatal("fresh certificate should be pending")
	}
	cert.DeployedFingerprint = Fingerprint(cert)
	if Pending(cert) {
		t.Fatal("deployed certificate should not be pending")
	}
	cert.CertPEM = "renewed"
	if !Pending(cert) {
		t.Fatal("renewed certificate should be pending")
	}
	cert.Deploy[0].Disabled = true
	if Pending(cert) || Active(cert) {
		t.Fatal("disabled target should not be pending/active")
	}
}

func TestSiteNameInference(t *testing.T) {
	cert := certificates.Certificate{Domains: []string{"*.c90.top"}}
	if got := siteName(cert, certificates.DeployTarget{}); got != "c90.top" {
		t.Fatalf("inferred site = %q", got)
	}
	if got := siteName(cert, certificates.DeployTarget{Site: "example.co.uk"}); got != "example.co.uk" {
		t.Fatalf("explicit site = %q", got)
	}
	if got := certificateName(cert, certificates.DeployTarget{}); got != "dnet-c90.top" {
		t.Fatalf("default cert name = %q", got)
	}
}
