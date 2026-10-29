package config

import (
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/webservice"
	"gopkg.in/yaml.v3"
)

func TestWebServiceConfigSnapshotAndYAML(t *testing.T) {
	conf := Config{WebServiceEnabled: true, WebServiceRules: []webservice.Rule{{ID: "one", Name: "1", Password: "not-persisted", PasswordHash: "stored-hash"}}}
	snapshot := conf.clone()
	snapshot.WebServiceRules[0].Name = "changed"
	if conf.WebServiceRules[0].Name != "1" {
		t.Fatal("snapshot aliases rules")
	}
	body, err := yaml.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "not-persisted") {
		t.Fatal("plaintext password persisted")
	}
	var loaded Config
	if err := yaml.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if !loaded.WebServiceEnabled || len(loaded.WebServiceRules) != 1 || loaded.WebServiceRules[0].PasswordHash != "stored-hash" {
		t.Fatal("Web service config lost on YAML round trip")
	}
}

func TestWebServiceWAFSwitchPersists(t *testing.T) {
	conf := Config{
		WebServiceEnabled: true,
		WebServiceRules:   []webservice.Rule{{ID: "one", Name: "1", WAFEnabled: true}, {ID: "two", Name: "2"}},
	}
	body, err := yaml.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "waf_enabled: true") {
		t.Fatal("WAF switch not written to YAML")
	}
	var loaded Config
	if err := yaml.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.WebServiceRules) != 2 || !loaded.WebServiceRules[0].WAFEnabled || loaded.WebServiceRules[1].WAFEnabled {
		t.Fatal("WAF switch lost on YAML round trip")
	}
}
