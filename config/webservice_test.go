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

func TestWAFSelectionPersists(t *testing.T) {
	conf := Config{
		WAFDisabledGroups:   []int{942, 930},
		WAFCustomDirectives: `SecRule ARGS:probe "@rx x" "id:199999,phase:2,deny"`,
	}
	snapshot := conf.clone()
	snapshot.WAFDisabledGroups[0] = 941
	if conf.WAFDisabledGroups[0] != 942 {
		t.Fatal("snapshot aliases WAF group list")
	}
	body, err := yaml.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "waf_disabled_groups:") || !strings.Contains(string(body), "waf_custom_directives:") {
		t.Fatal("WAF selection not written to YAML")
	}
	var loaded Config
	if err := yaml.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.WAFDisabledGroups) != 2 || loaded.WAFDisabledGroups[1] != 930 || loaded.WAFCustomDirectives != conf.WAFCustomDirectives {
		t.Fatal("WAF selection lost on YAML round trip")
	}
}
