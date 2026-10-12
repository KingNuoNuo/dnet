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

// 防火墙自动放行：dnet 只在 OpenWrt 上动防火墙，通过 uci 增删「通信规则」，
// 让 WAN 能进到本机的监听端口。fw3（iptables）与 fw4（nftables）共用同一份
// /etc/config/firewall，所以增删逻辑一致，只有 reload 命令不同。
// 我们管理的规则名一律以 dnet- 前缀开头，对账时只碰自己的，用户的规则不碰。

var (
	fwMu         sync.Mutex
	fwDetector   func(string) bool = fileInPath // 测试可替换
	fwBackend    string                         // "" 表示未检测；fw4 / fw3 / none
	fwWarned     bool                           // 非 OpenWrt 环境只提示一次
	ruleNameRe   = regexp.MustCompile(`[^A-Za-z0-9-]+`)
	uciSectionRe = regexp.MustCompile(`(?m)^firewall\.([^\s.]+)\.name='(dnet-[^']*)'$`)
	uciFieldRe   = regexp.MustCompile(`(?m)^firewall\.([^\s.]+)\.(dest_port|proto)='([^']*)'$`)
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

func fileInPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// detectBackend 返回 fw4 / fw3 / none。
func detectBackend() string {
	if fwBackend != "" {
		return fwBackend
	}
	switch {
	case fwDetector("fw4"):
		fwBackend = "fw4"
	case fwDetector("fw3"):
		fwBackend = "fw3"
	case fwDetector("uci"):
		// 有 uci 却没有 fw4/fw3 可执行文件：罕见（fw4 的入口在 /usr/sbin，
		// LookPath 一般能找到），按 fw4 的 reload 试试也无妨 —— 但保守起见
		// 归为 none，免得在非标准环境乱重启防火墙。
		fwBackend = "none"
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

// SyncFirewall 把防火墙放行规则对账到期望状态：
// enabled=false 时撤掉我们托管的所有规则；否则按规则清单增删改。
// 任何失败都只记日志，不影响转发本身。
func SyncFirewall(enabled bool, rules []Rule) {
	fwMu.Lock()
	defer fwMu.Unlock()

	backend := detectBackend()
	if backend == "none" {
		if !fwWarned {
			fwWarned = true
			if enabled {
				helper.Debug(helper.LogTypeDPF, "未检测到 OpenWrt 防火墙（fw4/fw3/uci），跳过自动放行")
			}
		}
		return
	}

	wanted := map[string]string{}
	if enabled {
		wanted = fwWanted(rules)
	}
	if !fwWarned {
		fwWarned = true
		helper.Info(helper.LogTypeDPF, "防火墙自动放行已启用 [后端=%s, 放行端口=%d]", backend, len(wanted))
	}

	showOut, err := fwRun("uci -X show firewall 2>/dev/null")
	if err != nil && showOut == "" {
		helper.Warn(helper.LogTypeDPF, "读取防火墙配置失败: %v", err)
		return
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
		return
	}
	script.WriteString("uci -q commit firewall\n")
	switch backend {
	case "fw4":
		script.WriteString("fw4 reload >/dev/null 2>&1")
	default:
		script.WriteString("/etc/init.d/firewall restart >/dev/null 2>&1")
	}
	if out, err := fwRun(script.String()); err != nil {
		helper.Warn(helper.LogTypeDPF, "更新防火墙放行失败 [%s]: %v %s", backend, err, strings.TrimSpace(out))
		return
	}
	helper.Info(helper.LogTypeDPF, "防火墙放行已更新 [后端=%s]", backend)
}
