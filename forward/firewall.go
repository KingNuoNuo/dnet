package forward

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"

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
	anonRuleRe    = regexp.MustCompile(`^@rule\[(\d+)\]$`)
	iptCommentRe  = regexp.MustCompile(`--comment\s+(dnet-[^\s]+)`)
	// nft -a list 的规则行：`tcp dport 8080 accept comment "dnet-x" # handle 12`
	nftRuleRe = regexp.MustCompile(`(?m)^\s*(?:meta l4proto )?(tcp|udp) dport (\d+) accept comment "(dnet-[^"]+)"\s*# handle (\d+)`)
	// iptables -S 的规则行：`-A INPUT -p tcp -m tcp --dport 8080 -m comment --comment dnet-x -j ACCEPT`
	iptRuleRe = regexp.MustCompile(`(?m)^-A INPUT (.+--comment\s+dnet-[^\s]+.+)$`)
)

// fwRuleName 生成我们托管的防火墙规则名：优先用规则备注，备注为空时退回规则 ID。
// 只保留字母/数字/汉字，空白与常见分隔符归一成 -，其余字符（引号、反斜杠、
// 控制字符等）直接丢弃，避免写进 uci / nft / iptables 时破坏引号。
func fwRuleName(label, id string) string {
	base := strings.TrimSpace(label)
	if base == "" {
		base = id
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(base) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == '.' || unicode.IsSpace(r) || strings.ContainsRune("/:|\\", r):
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = strings.Trim(ruleNameRe.ReplaceAllString(strings.ToLower(id), "-"), "-")
	}
	// iptables 的 comment 有 256 字节上限，留足余量。
	if runes := []rune(name); len(runes) > 48 {
		name = string(runes[:48])
	}
	return "dnet-" + name
}

// FirewallRuleName 供其它模块（Web 服务等）生成同一套命名的防火墙规则名，
// 便于在防火墙界面里一眼看出是哪条备注。
func FirewallRuleName(label, id string) string {
	return fwRuleName(label, id)
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
	used := map[string]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		ip := net.ParseIP(r.ListenAddress)
		if ip == nil || !ip.IsUnspecified() {
			continue
		}
		name := fwRuleName(r.Name, r.ID)
		base := name
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		used[name] = true
		out[name] = fmt.Sprintf("%s/%d", fwProto(r.Network), r.ListenPort)
	}
	return out
}

type fwSection struct {
	sec   string // uci 段标识：匿名段是 @rule[N]，具名段就是段名
	name  string
	proto string
	port  string
}

type nftRule struct {
	name   string
	port   string
	handle string
}

type iptRule struct {
	name string
	spec string
}

// anonRuleIndex 把 `@rule[17]` 解析成 17；具名段返回 false。
func anonRuleIndex(sec string) (int, bool) {
	m := anonRuleRe.FindStringSubmatch(sec)
	if m == nil {
		return 0, false
	}
	idx, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return idx, true
}

// parseUCIHas 把 `uci -X show firewall` 的输出还原成我们托管的那部分规则。
// 这里保留所有重复段（同一个 name 可能出现多次），交给对账逻辑去重。
func parseUCIHas(output string) []fwSection {
	index := map[string]int{}
	out := []fwSection{}
	for _, m := range uciSectionRe.FindAllStringSubmatch(output, -1) {
		index[m[1]] = len(out)
		out = append(out, fwSection{sec: m[1], name: m[2]})
	}
	for _, m := range uciFieldRe.FindAllStringSubmatch(output, -1) {
		at, ok := index[m[1]]
		if !ok {
			continue
		}
		if m[2] == "dest_port" {
			out[at].port = m[3]
		} else {
			out[at].proto = m[3]
		}
	}
	return out
}

// parseNFTHas 把 `nft -a list table inet dnet` 的输出还原成我们托管的规则。
// 同一 name 的重复规则全部保留，对账时只留一条。
func parseNFTHas(output string) []nftRule {
	out := []nftRule{}
	for _, m := range nftRuleRe.FindAllStringSubmatch(output, -1) {
		out = append(out, nftRule{name: m[3], port: m[2], handle: m[4]})
	}
	return out
}

// parseIPTHas 把 `iptables -S INPUT` 的输出还原成我们托管的规则。
// 同一条规则重复出现时全部保留，对账时只留一条。
func parseIPTHas(output string) []iptRule {
	out := []iptRule{}
	for _, m := range iptRuleRe.FindAllStringSubmatch(output, -1) {
		spec := m[1]
		if cm := iptCommentRe.FindStringSubmatch(spec); cm != nil {
			out = append(out, iptRule{name: cm[1], spec: spec})
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
		// Web 服务等模块的备注可能与端口转发重名，追加序号避免互相覆盖。
		final := name
		for i := 2; ; i++ {
			if _, exists := wanted[final]; !exists {
				break
			}
			final = fmt.Sprintf("%s-%d", name, i)
		}
		wanted[final] = spec
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

// uciPlan 是 syncUCI 算出的对账动作，抽成纯函数便于单测。
type uciPlan struct {
	anonDeletes  []int
	namedDeletes []string
	adds         map[string]string
}

// planUCI 把「现有段」和「期望集合」对账成删除/新增动作。
// 同一个 name 的重复段只保留一条端口正确的，其余全部删除，
// 这样历史上堆积的重复规则会在下一次同步时被清掉。
func planUCI(current []fwSection, wanted map[string]string) uciPlan {
	plan := uciPlan{adds: map[string]string{}}
	for name, spec := range wanted {
		plan.adds[name] = spec
	}
	byName := map[string][]fwSection{}
	for _, sec := range current {
		byName[sec.name] = append(byName[sec.name], sec)
	}
	for name, sections := range byName {
		keep := false
		want, wantedName := plan.adds[name]
		for _, sec := range sections {
			if wantedName && !keep && sec.proto+"/"+sec.port == want {
				keep = true
				continue
			}
			if idx, ok := anonRuleIndex(sec.sec); ok {
				plan.anonDeletes = append(plan.anonDeletes, idx)
			} else {
				plan.namedDeletes = append(plan.namedDeletes, sec.sec)
			}
		}
		if keep {
			delete(plan.adds, name)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(plan.anonDeletes)))
	sort.Strings(plan.namedDeletes)
	return plan
}

func syncUCI(wanted map[string]string, backend string) error {
	showOut, err := fwRun("uci -X show firewall 2>/dev/null")
	if err != nil && showOut == "" {
		return fmt.Errorf("读取防火墙配置失败: %w", err)
	}
	plan := planUCI(parseUCIHas(showOut), wanted)

	var script strings.Builder
	changed := false
	// 匿名段按索引删除：必须从大到小，避免删掉一条后后面的索引整体前移。
	for _, idx := range plan.anonDeletes {
		fmt.Fprintf(&script, "uci -q delete firewall.@rule[%d]\n", idx)
		changed = true
	}
	for _, sec := range plan.namedDeletes {
		fmt.Fprintf(&script, "uci -q delete firewall.%s\n", sec)
		changed = true
	}
	// 增：缺的。
	names := make([]string, 0, len(plan.adds))
	for name := range plan.adds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		parts := strings.SplitN(plan.adds[name], "/", 2)
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

	// 同一 name 的重复规则只保留一条端口正确的，其余按 handle 删除。
	byName := map[string][]nftRule{}
	for _, rule := range current {
		byName[rule.name] = append(byName[rule.name], rule)
	}
	var cmds []string
	for name, rules := range byName {
		want, ok := wanted[name]
		keep := false
		for _, rule := range rules {
			if ok && !keep && strings.SplitN(want, "/", 2)[1] == rule.port {
				keep = true
				continue
			}
			cmds = append(cmds, "nft delete rule inet dnet input handle "+rule.handle)
		}
		if keep {
			delete(wanted, name)
		}
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
		// 同一 name 的重复规则只保留一条端口正确的，其余删除。
		byName := map[string][]iptRule{}
		for _, rule := range current {
			byName[rule.name] = append(byName[rule.name], rule)
		}
		for name, rules := range byName {
			want, ok := wanted[name]
			keep := false
			for _, rule := range rules {
				if ok && !keep && iptPort(rule.spec) == strings.SplitN(want, "/", 2)[1] {
					keep = true
					continue
				}
				cmds = append(cmds, bin+" -D INPUT "+rule.spec)
				changed = true
			}
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
