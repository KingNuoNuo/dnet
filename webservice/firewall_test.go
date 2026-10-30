package webservice

import "testing"

func TestFirewallPortsUseRemark(t *testing.T) {
	rules := []Rule{
		{ID: "id-a", Name: "emby", ListenAddress: "::", ListenPort: 28096},
		{ID: "id-b", Name: "emby", ListenAddress: "::", ListenPort: 28097},
		{ID: "id-c", ListenAddress: "::", ListenPort: 28098},
		{ID: "id-d", Name: "lan-only", ListenAddress: "10.0.0.99", ListenPort: 28099},
	}
	got := FirewallPorts(true, rules)
	if got["dnet-web-emby"] != "tcp/28096" {
		t.Fatalf("remark not used: %v", got)
	}
	if got["dnet-web-emby-2"] != "tcp/28097" {
		t.Fatalf("duplicate remark not suffixed: %v", got)
	}
	if got["dnet-id-c"] != "tcp/28098" {
		t.Fatalf("missing remark should fall back to id: %v", got)
	}
	if len(got) != 3 {
		t.Fatalf("bound listener should be skipped: %v", got)
	}
	if FirewallPorts(false, rules) != nil {
		t.Fatal("disabled firewall ports must be empty")
	}
}
