package webservice

import (
	"net"
	"strconv"
	"strings"

	"github.com/cxbdasheng/dnet/forward"
)

// FirewallPorts 把 Web 服务规则转成防火墙期望端口表（规则名 -> "proto/port"）：
// 仅放行监听在通配地址的规则（Web 服务只有 TCP），与端口转发共用 dnet- 前缀。
// 规则名取备注（形如 dnet-web-emby），重名时追加序号；没有备注时退回规则 ID。
func FirewallPorts(enabled bool, rules []Rule) map[string]string {
	if !enabled {
		return nil
	}
	out := map[string]string{}
	used := map[string]bool{}
	for _, r := range rules {
		ip := net.ParseIP(r.ListenAddress)
		if ip == nil || !ip.IsUnspecified() {
			continue
		}
		label := strings.TrimSpace(r.Name)
		if label != "" {
			label = "web-" + label
		}
		name := forward.FirewallRuleName(label, r.ID)
		base := name
		for i := 2; used[name]; i++ {
			name = base + "-" + strconv.Itoa(i)
		}
		used[name] = true
		out[name] = "tcp/" + strconv.Itoa(r.ListenPort)
	}
	return out
}
