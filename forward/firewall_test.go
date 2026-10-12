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

func TestDetectBackendOrder(t *testing.T) {
	orig := fwDetector
	defer func() { fwDetector = orig }()
	for _, c := range []struct {
		in      []string
		restore bool
		want    string
	}{
		{in: []string{"fw4", "nft", "iptables"}, want: "fw4"},
		{in: []string{"fw3", "nft", "iptables"}, want: "fw3"},
		{in: []string{"nft", "iptables"}, want: "nft"},
		{in: []string{"iptables"}, want: "iptables"},
		{in: []string{}, want: "none"},
	} {
		fwDetector = func(bin string) bool {
			for _, b := range c.in {
				if b == bin {
					return true
				}
			}
			return false
		}
		fwBackend = ""
		if got := detectBackend(); got != c.want {
			t.Errorf("detectBackend(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestParseNFTHas(t *testing.T) {
	out := `
	table ip filter { # handle 3
	}
	table inet dnet { # handle 11
		chain input { # handle 1
			tcp dport 18096 accept comment "dnet-a1" # handle 4
			udp dport 5353 accept comment "dnet-a2" # handle 5
			tcp dport 22 accept comment "user-rule" # handle 6
		}
	}
`
	got := parseNFTHas(out)
	if len(got) != 2 {
		t.Fatalf("want 2 dnet rules, got %v", got)
	}
	if got["dnet-a1"] != "18096/4" || got["dnet-a2"] != "5353/5" {
		t.Fatalf("parsed wrong: %v", got)
	}
}

func TestParseIPTHas(t *testing.T) {
	out := `-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 18096 -m comment --comment dnet-a1 -j ACCEPT
-A INPUT -p udp -m udp --dport 5353 -m comment --comment dnet-a2 -j ACCEPT
`
	got := parseIPTHas(out)
	if len(got) != 2 {
		t.Fatalf("want 2 dnet rules, got %v", got)
	}
	if iptPort(got["dnet-a1"]) != "18096" {
		t.Fatalf("port parsed wrong: %q", got["dnet-a1"])
	}
	if got["dnet-a2"] != "-p udp -m udp --dport 5353 -m comment --comment dnet-a2 -j ACCEPT" {
		t.Fatalf("spec parsed wrong: %q", got["dnet-a2"])
	}
}
