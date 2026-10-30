package config

import (
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/waf"
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
		WAFPolicies: []waf.Policy{{
			ID:               "strict",
			Name:             "严格",
			DisabledGroups:   []int{942, 930},
			CustomDirectives: `SecRule ARGS:probe "@rx x" "id:199999,phase:2,deny"`,
		}},
		WebServiceRules: []webservice.Rule{{ID: "one", Name: "1", WAFPolicyID: "strict"}},
	}
	snapshot := conf.clone()
	snapshot.WAFPolicies[0].DisabledGroups[0] = 941
	if conf.WAFPolicies[0].DisabledGroups[0] != 942 {
		t.Fatal("snapshot aliases WAF policy groups")
	}
	body, err := yaml.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "waf_policies:") || !strings.Contains(string(body), "waf_policy_id: strict") {
		t.Fatal("WAF policies not written to YAML")
	}
	var loaded Config
	if err := yaml.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if len(loaded.WAFPolicies) != 1 || loaded.WAFPolicies[0].ID != "strict" ||
		len(loaded.WAFPolicies[0].DisabledGroups) != 2 || loaded.WAFPolicies[0].DisabledGroups[1] != 930 ||
		loaded.WAFPolicies[0].CustomDirectives == "" ||
		loaded.WebServiceRules[0].WAFPolicyID != "strict" {
		t.Fatal("WAF selection lost on YAML round trip")
	}
}

// v0.2.2 的全局 WAF 配置升级成「默认策略」，旧开关映射为引用默认策略。
func TestNormalizeWAFMigratesLegacyGlobalConfig(t *testing.T) {
	conf := Config{
		WAFDisabledGroups:   []int{942},
		WAFCustomDirectives: `SecRule ARGS:x "@rx y" "id:199999,phase:2,deny"`,
		WebServiceRules: []webservice.Rule{
			{ID: "one", Name: "one", WAFEnabled: true},
			{ID: "two", Name: "two", WAFPolicyID: "missing"},
		},
	}
	conf.NormalizeWAF()
	if len(conf.WAFPolicies) != 1 || conf.WAFPolicies[0].ID != webservice.DefaultPolicyID {
		t.Fatalf("legacy config not migrated: %+v", conf.WAFPolicies)
	}
	if len(conf.WAFPolicies[0].DisabledGroups) != 1 || conf.WAFPolicies[0].DisabledGroups[0] != 942 {
		t.Fatal("legacy disabled groups lost")
	}
	if conf.WAFDisabledGroups != nil || conf.WAFCustomDirectives != "" {
		t.Fatal("legacy fields not cleared")
	}
	if conf.WebServiceRules[0].WAFPolicyID != webservice.DefaultPolicyID || !conf.WebServiceRules[0].WAFEnabled {
		t.Fatal("legacy switch not mapped to default policy")
	}
	// 不存在的策略引用不再在启动时被静默清除，保留原值以便用户修正。
	if conf.WebServiceRules[1].WAFPolicyID != "missing" || !conf.WebServiceRules[1].WAFEnabled {
		t.Fatal("dangling policy reference should be preserved for user to fix")
	}
}
