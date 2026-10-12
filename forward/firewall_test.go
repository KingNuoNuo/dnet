package forward

import "testing"

func TestFWRuleName(t *testing.T) {
	cases := map[string]string{
		"abc-123":       "dnet-abc-123",
		"R_1 2-3":       "dnet-r-1-2-3",
		"大小写Mixed_9":    "dnet-mixed-9", // 非 ASCII 逐字符替换成 -，头尾再裁掉
		"--weird--":     "dnet-weird",
		"018f3c1e-a7b8": "dnet-018f3c1e-a7b8",
	}
	for in, want := range cases {
		if got := fwRuleName(in); got != want {
			t.Errorf("fwRuleName(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFWProto(t *testing.T) {
	for _, n := range []string{"tcp4", "tcp6"} {
		if fwProto(n) != "tcp" {
			t.Errorf("fwProto(%s) != tcp", n)
		}
	}
	for _, n := range []string{"udp4", "udp6"} {
		if fwProto(n) != "udp" {
			t.Errorf("fwProto(%s) != udp", n)
		}
	}
}

func TestFWWanted(t *testing.T) {
	rules := []Rule{
		{ID: "a1", Enabled: true, Network: "tcp4", ListenAddress: "0.0.0.0", ListenPort: 18096},
		{ID: "a2", Enabled: true, Network: "udp6", ListenAddress: "::", ListenPort: 5353},
		{ID: "a3", Enabled: false, Network: "tcp4", ListenAddress: "0.0.0.0", ListenPort: 22},
		{ID: "a4", Enabled: true, Network: "tcp4", ListenAddress: "192.168.1.1", ListenPort: 80},
	}
	got := fwWanted(rules)
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %v", got)
	}
	if got["dnet-a1"] != "tcp/18096" || got["dnet-a2"] != "udp/5353" {
		t.Fatalf("unexpected mapping: %v", got)
	}
}

func TestParseUCIHas(t *testing.T) {
	out := `firewall.@rule[0].name='Allow-DHCP-Relay'
firewall.@rule[0].src='wan'
firewall.cfg0abc12.name='dnet-a1'
firewall.cfg0abc12.proto='tcp'
firewall.cfg0abc12.dest_port='18096'
firewall.cfg0def34.name='dnet-a2'
firewall.cfg0def34.proto='udp'
firewall.cfg0def34.dest_port='53'
firewall.cfg0ghi56.name='user-rule-not-ours'
`
	got := parseUCIHas(out)
	if len(got) != 2 {
		t.Fatalf("want 2 dnet sections, got %v", got)
	}
	if got["cfg0abc12"].name != "dnet-a1" || got["cfg0abc12"].proto != "tcp" || got["cfg0abc12"].port != "18096" {
		t.Fatalf("cfg0abc12 parsed wrong: %+v", got["cfg0abc12"])
	}
	if got["cfg0def34"].proto != "udp" || got["cfg0def34"].port != "53" {
		t.Fatalf("cfg0def34 parsed wrong: %+v", got["cfg0def34"])
	}
}
