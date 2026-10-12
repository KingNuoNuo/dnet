package forward

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cxbdasheng/dnet/helper"
)

// 防火墙自动放行：按能力四级检测，检测到哪个就用哪个：
//   1. fw4  —— OpenWrt nftables 后端，uci 写配置 + fw4 reload（重启后仍在）
//   2. fw3  —— OpenWrt iptables 后端，同一份 /etc/config/firewall
//   3. nft  —— 通用 Linux nftables，建 inet dnet 表插运行时规则
//   4. iptables —— 通用 Linux iptables，往 INPUT 链头插运行时规则
// 都检测不到就跳过（与未开启同效），不影响转发本身。
//
// 通用后端（nft/iptables）只做运行时放行：规则在内存里，重启即失效，
// dnet 不代写 /etc/nftables.conf、rc.local 之类的持久化文件 —— 那会和
// ufw/firewalld 等发行版自带的管理工具打架，只在日志里提示一次。
//
// 我们管理的规则一律带 dnet-<规则id> 标识（uci 的 name / nft 的 comment /
// iptables 的 --comment），对账时只碰自己的，用户的规则不碰。

var (
	fwMu          sync.Mutex
	fwDetector    func(string) bool = fileInPath // 测试可替换
	fwBackend     string                         // "" 表示未检测；fw4 / fw3 / nft / iptables / none
	fwWarned      bool                           // 首次启用提示只发一次
	fwExtraWarned bool                           // Web 服务放行提示只发一次
	fwPersistWarn bool                           // 通用后端的「重启失效」提示只发一次
	ruleNameRe    = regexp.MustCompile(`[^A-Za-z0-9-]+`)
	uciSectionRe  = regexp.MustCompile(`(?m)^firewall\.([^\s.]+)\.name='(dnet-[^']*)'$`)
	uciFieldRe    = regexp.MustCompile(`(?m)^firewall\.([^\s.]+)\.(dest_port|proto)='([^']*)'$`)
	// nft -a list 的规则行：`tcp dport 8080 accept comment "dnet-x" # handle 12`
	nftRuleRe = regexp.MustCompile(`(?m)^\s*(?:meta l4proto )?(tcp|udp) dport (\d+) accept comment "(dnet-[^"]+)"\s*# handle (\d+)`)
	// iptables -S 的规则行：`-A INPUT -p tcp -m tcp --dport 8080 -m comment --comment dnet-x -j ACCEPT`
	iptRuleRe = regexp.MustCompile(`(?m)^-A INPUT (.+--comment\s+dnet-[^\s]+.+)$`)
)

// fwRuleName 生成我们托管的防火墙规则名（uci name 只能字母数字下划线，
// 但 uci 的 show 输出按引号原样返回，用连字符即可）。
func fwRuleName(id string) string {
	return "dnet-" + strings.Trim(ruleNameRe.ReplaceAllString(strings.ToLower(id), "-"), "-")
}

// fwProto 把规则的监听协议归并成防火墙的 proto 字段（fw 不区分 v4/v6）。
func fwProto(network string) string {
	if strings.HasPrefix(network, "udp") {
		return "udp"
	}
	return "tcp"
}

// fwWanted 汇总需要放行的端口：仅统计「已启用且监听在通配地址」的规则 ——
// 绑定在具体内网 IP 上的规则从 WAN 根本进不来，开了白开。
func fwWanted(rules []Rule) map[string]string {
	out := map[string]string{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		ip := net.ParseIP(r.ListenAddress)
		if ip == nil || !ip.IsUnspecified() {
			continue
		}
		out[fwRuleName(r.ID)] = fmt.Sprintf("%s/%d", fwProto(r.Network), r.ListenPort)
	}
	return out
}

type fwSection struct {
	name  string
	proto string
	port  string
}

// parseUCIHas 把 `uci -X show firewall` 的输出还原成我们托管的那部分规则。
func parseUCIHas(output string) map[string]fwSection {
	out := map[string]fwSection{}
	for _, m := range uciSectionRe.FindAllStringSubmatch(output, -1) {
		out[m[1]] = fwSection{name: m[2]}
	}
	for _, m := range uciFieldRe.FindAllStringSubmatch(output, -1) {
		if s, ok := out[m[1]]; ok {
			if m[2] == "dest_port" {
				s.port = m[3]
			} else {
				s.proto = m[3]
			}
			out[m[1]] = s
		}
	}
	return out
}

// parseNFTHas 把 `nft -a list table inet dnet` 的输出还原成我们托管的规则。
// 返回 名字 -> handle，handle 用于精准删除。
func parseNFTHas(output string) map[string]string {
	out := map[string]string{}
	for _, m := range nftRuleRe.FindAllStringSubmatch(output, -1) {
		out[m[3]] = m[2] + "/" + m[4] // "端口/handle"
	}
	return out
}

// parseIPTHas 把 `iptables -S INPUT` 的输出还原成我们托管的规则。
// 返回 名字 -> 完整规则参数（去掉 `-A INPUT ` 前缀，可直接用于 -D）。
func parseIPTHas(output string) map[string]string {
	out := map[string]string{}
	for _, m := range iptRuleRe.FindAllStringSubmatch(output, -1) {
		spec := m[1]
		if cm := regexp.MustCompile(`--comment\s+(dnet-[^\s]+)`).FindStringSubmatch(spec); cm != nil {
			out[cm[1]] = spec
		}
	}
	return out
}

func fileInPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// detectBackend 返回 fw4 / fw3 / nft / iptables / none。
func detectBackend() string {
	if fwBackend != "" {
		return fwBackend
	}
	switch {
	case fwDetector("fw4"):
		fwBackend = "fw4"
	case fwDetector("fw3"):
		fwBackend = "fw3"
	case fwDetector("nft"):
		fwBackend = "nft"
	case fwDetector("iptables"):
		fwBackend = "iptables"
	default:
		fwBackend = "none"
	}
	return fwBackend
}

func fwRun(script string) (string, error) {
	cmd := exec.Command("sh", "-c", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fwExtra 是其它模块（如 Web 服务）追加的放行端口，名字 -> "proto/port"。
// 由 SetExtraFirewallPorts 维护，与端口转发的期望集合合并后统一对账。
var fwExtra map[string]string

// SetExtraFirewallPorts 更新额外放行端口（传 nil 即全部撤掉）并触发一次对账。
// 供端口转发之外的模块（Web 服务等）复用同一套防火墙放行机制。
func SetExtraFirewallPorts(extra map[string]string) {
	fwMu.Lock()
	defer fwMu.Unlock()
	fwExtra = extra
	syncFirewallLocked(true)
}

// SyncFirewall 把防火墙放行规则对账到期望状态：
// enabled=false 时撤掉我们托管的所有规则；否则按规则清单增删改。
// 任何失败都只记日志，不影响转发本身。
func SyncFirewall(enabled bool, rules []Rule) {
	fwMu.Lock()
	defer fwMu.Unlock()
	fwLastEnabled = enabled
	fwLastRules = rules
	syncFirewallLocked(enabled)
}

// fwLastEnabled / fwLastRules 缓存最近一次 SyncFirewall 的入参，
// 便于 SetExtraFirewallPorts 单独触发时仍带着端口转发的期望集合。
var (
	fwLastEnabled bool
	fwLastRules   []Rule
)

func syncFirewallLocked(enabled bool) {
	backend := detectBackend()
	if backend == "none" {
		if !fwWarned {
			fwWarned = true
			if enabled {
				helper.Debug(helper.LogTypeDPF, "未检测到可用防火墙（fw4/fw3/nft/iptables），跳过自动放行")
			}
		}
		return
	}

	wanted := map[string]string{}
	if enabled {
		wanted = fwWanted(fwLastRules)
	}
	for name, spec := range fwExtra {
		wanted[name] = spec
	}
	if !fwWarned {
		fwWarned = true
		helper.Info(helper.LogTypeDPF, "防火墙自动放行已启用 [后端=%s, 放行端口=%d]", backend, len(wanted))
		if backend == "nft" || backend == "iptables" {
			// 持久化边界：运行时放行够用但不抗重启，持久化留给用户，
			// 代写发行版配置文件会和 ufw/firewalld 打架。
			fwPersistWarn = true
			helper.Warn(helper.LogTypeDPF, "运行时放行说明 [后端=%s] 放行规则仅本次开机内有效，重启后需重新保存端口转发配置（或自行持久化防火墙规则）", backend)
		}
	} else if len(fwExtra) > 0 && !fwExtraWarned {
		fwExtraWarned = true
		helper.Info(helper.LogTypeDPF, "Web 服务防火墙放行已启用 [放行端口=%d]", len(fwExtra))
	}

	var err error
	switch backend {
	case "fw4", "fw3":
		err = syncUCI(wanted, backend)
	case "nft":
		err = syncNFT(wanted)
	case "iptables":
		err = syncIPT(wanted)
	}
	if err != nil {
		helper.Warn(helper.LogTypeDPF, "更新防火墙放行失败 [%s]: %v", backend, err)
	}
}

// ---- 后端 1/2：OpenWrt uci（fw4 / fw3 共用） ----

func syncUCI(wanted map[string]string, backend string) error {
	showOut, err := fwRun("uci -X show firewall 2>/dev/null")
	if err != nil && showOut == "" {
		return fmt.Errorf("读取防火墙配置失败: %w", err)
	}
	current := parseUCIHas(showOut)

	var script strings.Builder
	changed := false
	// 删：我们管的、但不在期望清单里，或端口/协议已变的。
	for sec, s := range current {
		want, ok := wanted[s.name]
		if ok && s.proto+"/"+s.port == want {
			continue
		}
		fmt.Fprintf(&script, "uci -q delete firewall.%s\n", sec)
		changed = true
		if ok {
			delete(wanted, s.name) // 下面按「新增」重建
		}
	}
	// 增：缺的。
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts := strings.SplitN(wanted[name], "/", 2)
		fmt.Fprintf(&script, "sec=$(uci -q add firewall rule); "+
			"uci -q set firewall.$sec.name='%s'; "+
			"uci -q set firewall.$sec.src='wan'; "+
			"uci -q set firewall.$sec.proto='%s'; "+
			"uci -q set firewall.$sec.dest_port='%s'; "+
			"uci -q set firewall.$sec.target='ACCEPT'; "+
			"uci -q set firewall.$sec.enabled='1'\n",
			name, parts[0], parts[1])
		changed = true
	}
	if !changed {
		helper.Debug(helper.LogTypeDPF, "防火墙放行已是期望状态 [后端=%s]", backend)
		return nil
	}
	script.WriteString("uci -q commit firewall\n")
	switch backend {
	case "fw4":
		script.WriteString("fw4 reload >/dev/null 2>&1")
	default:
		script.WriteString("/etc/init.d/firewall restart >/dev/null 2>&1")
	}
	if out, err := fwRun(script.String()); err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	helper.Info(helper.LogTypeDPF, "防火墙放行已更新 [后端=%s]", backend)
	return nil
}

// ---- 后端 3：通用 Linux nftables ----

// syncNFT 在独立的 inet dnet 表里对账运行时放行规则。
// 不碰系统已有表（firewalld/ufw 的表我们不动），并排共存。
func syncNFT(wanted map[string]string) error {
	ensure := func() error {
		if out, err := fwRun("nft list table inet dnet 2>/dev/null"); err != nil || out == "" {
			// 表不存在则建表建链：链挂在 input 钩子上，priority 与 filter 相同。
			if out, err := fwRun("nft add table inet dnet && nft add chain inet dnet input '{ type filter hook input priority filter; policy accept; }'"); err != nil {
				return fmt.Errorf("创建 nft 表失败: %v %s", err, strings.TrimSpace(out))
			}
		}
		return nil
	}
	if err := ensure(); err != nil {
		return err
	}
	listOut, err := fwRun("nft -a list table inet dnet 2>/dev/null")
	if err != nil && listOut == "" {
		return fmt.Errorf("读取 nft 表失败: %w", err)
	}
	current := parseNFTHas(listOut)

	var cmds []string
	for name, cur := range current {
		port := strings.SplitN(cur, "/", 2)[0]
		want, ok := wanted[name]
		wantPort := ""
		if ok {
			wantPort = strings.SplitN(want, "/", 2)[1]
		}
		if ok && wantPort == port {
			delete(wanted, name)
			continue
		}
		cmds = append(cmds, "nft delete rule inet dnet input handle "+strings.SplitN(cur, "/", 2)[1])
	}
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts := strings.SplitN(wanted[name], "/", 2)
		cmds = append(cmds, fmt.Sprintf("nft add rule inet dnet input %s dport %s accept comment '%s'", parts[0], parts[1], name))
	}
	if len(cmds) == 0 {
		helper.Debug(helper.LogTypeDPF, "防火墙放行已是期望状态 [后端=nft]")
		return nil
	}
	if out, err := fwRun(strings.Join(cmds, " && ")); err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	helper.Info(helper.LogTypeDPF, "防火墙放行已更新 [后端=nft, 变更=%d]", len(cmds))
	return nil
}

// ---- 后端 4：通用 Linux iptables ----

// syncIPT 往 INPUT 链头插运行时放行规则。iptables（IPv4）必做；
// ip6tables 存在时 IPv6 也做同一套对账。
func syncIPT(wanted map[string]string) error {
	families := []string{"iptables"}
	if fwDetector("ip6tables") {
		families = append(families, "ip6tables")
	}
	var cmds []string
	changed := false
	for _, bin := range families {
		listOut, err := fwRun(bin + " -S INPUT 2>/dev/null")
		if err != nil && listOut == "" {
			if bin == "ip6tables" {
				continue // 有二进制但执行不了，退化为只管 IPv4
			}
			return fmt.Errorf("读取 %s 失败: %w", bin, err)
		}
		current := parseIPTHas(listOut)
		// 删：端口/协议变了或已不需要的
		for name, spec := range current {
			want, ok := wanted[name]
			wantPort := ""
			if ok {
				wantPort = strings.SplitN(want, "/", 2)[1]
			}
			if ok && iptPort(spec) == wantPort {
				continue
			}
			cmds = append(cmds, bin+" -D INPUT "+spec)
			changed = true
		}
		// 增：缺的（每个家族各自补全，wanted 只读）
		names := make([]string, 0, len(wanted))
		for name := range wanted {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			parts := strings.SplitN(wanted[name], "/", 2)
			cmds = append(cmds, fmt.Sprintf("%s -I INPUT 1 -p %s --dport %s -j ACCEPT -m comment --comment %s", bin, parts[0], parts[1], name))
			changed = true
		}
	}
	if !changed {
		helper.Debug(helper.LogTypeDPF, "防火墙放行已是期望状态 [后端=iptables]")
		return nil
	}
	if out, err := fwRun(strings.Join(cmds, " && ")); err != nil {
		return fmt.Errorf("%v %s", err, strings.TrimSpace(out))
	}
	helper.Info(helper.LogTypeDPF, "防火墙放行已更新 [后端=iptables, 变更=%d]", len(cmds))
	return nil
}

// iptPort 从 iptables -S 的规则参数里抠出目标端口。
func iptPort(spec string) string {
	if m := regexp.MustCompile(`--dport\s+(\d+)`).FindStringSubmatch(spec); m != nil {
		return m[1]
	}
	return ""
}
