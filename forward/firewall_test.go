package forward

import (
	"strings"
	"testing"
)

func TestFWRuleName(t *testing.T) {
	cases := []struct {
		label, id, want string
	}{
		{"emby", "9059ddc5", "dnet-emby"},
		{"R_1 2-3", "id1", "dnet-r-1-2-3"},
		{"电影服务器", "id2", "dnet-电影服务器"},
		{"  ", "018f3c1e-a7b8", "dnet-018f3c1e-a7b8"}, // 备注为空时退回 ID
		{"a'b\"c\\d", "id3", "dnet-abc-d"},            // 引号被丢弃，反斜杠归一成 -
	}
	for _, c := range cases {
		if got := fwRuleName(c.label, c.id); got != c.want {
			t.Errorf("fwRuleName(%q, %q)=%q want %q", c.label, c.id, got, c.want)
		}
	}
	long := fwRuleName(strings.Repeat("长", 60), "id")
	if len([]rune(long)) > len("dnet-")+48 {
		t.Errorf("fwRuleName should cap length, got %d runes", len([]rune(long)))
	}
}

func TestFWWantedUsesRemarkAndDedupes(t *testing.T) {
	rules := []Rule{
		{ID: "id-a", Name: "emby", Enabled: true, Network: "tcp6", ListenAddress: "::", ListenPort: 30001},
		{ID: "id-b", Name: "emby", Enabled: true, Network: "tcp6", ListenAddress: "::", ListenPort: 30002},
		{ID: "id-c", Name: "", Enabled: true, Network: "udp4", ListenAddress: "0.0.0.0", ListenPort: 5353},
	}
	got := fwWanted(rules)
	if got["dnet-emby"] != "tcp/30001" {
		t.Fatalf("first rule name wrong: %v", got)
	}
	if _, ok := got["dnet-emby-2"]; !ok {
		t.Fatalf("duplicate remark not suffixed: %v", got)
	}
	if got["dnet-id-c"] != "udp/5353" {
		t.Fatalf("fallback to id failed: %v", got)
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
	bySec := map[string]fwSection{}
	for _, sec := range got {
		bySec[sec.sec] = sec
	}
	if bySec["cfg0abc12"].name != "dnet-a1" || bySec["cfg0abc12"].proto != "tcp" || bySec["cfg0abc12"].port != "18096" {
		t.Fatalf("cfg0abc12 parsed wrong: %+v", bySec["cfg0abc12"])
	}
	if bySec["cfg0def34"].proto != "udp" || bySec["cfg0def34"].port != "53" {
		t.Fatalf("cfg0def34 parsed wrong: %+v", bySec["cfg0def34"])
	}
}

func TestPlanUCIDedupesAndKeepsOneRulePerName(t *testing.T) {
	// 历史上按索引删除没删干净，同一个 name 堆了多条；端口正确的那条要保留，
	// 其余全部删除，且匿名段索引按从大到小排序（避免删除时索引前移）。
	current := []fwSection{
		{sec: "@rule[5]", name: "dnet-a1", proto: "tcp", port: "18096"},
		{sec: "@rule[9]", name: "dnet-a1", proto: "tcp", port: "18096"},
		{sec: "@rule[3]", name: "dnet-a1", proto: "tcp", port: "18096"},
		{sec: "@rule[7]", name: "dnet-gone", proto: "tcp", port: "8080"},
		{sec: "cfg0abc12", name: "dnet-moved", proto: "tcp", port: "1111"},
		{sec: "@rule[11]", name: "dnet-moved", proto: "tcp", port: "2222"},
	}
	wanted := map[string]string{
		"dnet-a1":    "tcp/18096",
		"dnet-moved": "tcp/2222",
		"dnet-new":   "udp/5353",
	}
	plan := planUCI(current, wanted)
	if len(plan.anonDeletes) != 3 {
		t.Fatalf("anonDeletes = %v, want 3 entries", plan.anonDeletes)
	}
	for i := 1; i < len(plan.anonDeletes); i++ {
		if plan.anonDeletes[i-1] <= plan.anonDeletes[i] {
			t.Fatalf("anonDeletes not descending: %v", plan.anonDeletes)
		}
	}
	if len(plan.namedDeletes) != 1 || plan.namedDeletes[0] != "cfg0abc12" {
		t.Fatalf("namedDeletes = %v", plan.namedDeletes)
	}
	if len(plan.adds) != 1 || plan.adds["dnet-new"] != "udp/5353" {
		t.Fatalf("adds = %v", plan.adds)
	}
	if len(wanted) != 3 {
		t.Fatal("planUCI must not mutate the caller's wanted map")
	}
}

func TestPlanUCIAddsWhenMissing(t *testing.T) {
	plan := planUCI(nil, map[string]string{"dnet-a1": "tcp/18096"})
	if len(plan.anonDeletes) != 0 || len(plan.namedDeletes) != 0 {
		t.Fatalf("unexpected deletes: %+v", plan)
	}
	if plan.adds["dnet-a1"] != "tcp/18096" {
		t.Fatalf("missing add: %+v", plan)
	}
}

func TestAnonRuleIndex(t *testing.T) {
	if idx, ok := anonRuleIndex("@rule[17]"); !ok || idx != 17 {
		t.Fatalf("anonRuleIndex(@rule[17]) = %d, %v", idx, ok)
	}
	if _, ok := anonRuleIndex("cfg0abc12"); ok {
		t.Fatal("named section treated as anonymous")
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
	byName := map[string]nftRule{}
	for _, rule := range got {
		byName[rule.name] = rule
	}
	if byName["dnet-a1"].port != "18096" || byName["dnet-a1"].handle != "4" {
		t.Fatalf("parsed wrong: %+v", byName["dnet-a1"])
	}
	if byName["dnet-a2"].port != "5353" || byName["dnet-a2"].handle != "5" {
		t.Fatalf("parsed wrong: %+v", byName["dnet-a2"])
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
	byName := map[string]iptRule{}
	for _, rule := range got {
		byName[rule.name] = rule
	}
	if iptPort(byName["dnet-a1"].spec) != "18096" {
		t.Fatalf("port parsed wrong: %q", byName["dnet-a1"].spec)
	}
	if byName["dnet-a2"].spec != "-p udp -m udp --dport 5353 -m comment --comment dnet-a2 -j ACCEPT" {
		t.Fatalf("spec parsed wrong: %q", byName["dnet-a2"].spec)
	}
}
