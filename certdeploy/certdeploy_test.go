package certdeploy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
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
