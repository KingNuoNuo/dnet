package webservice

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

var fwNameRe = regexp.MustCompile(`[^a-z0-9]+`)

// FirewallPorts 把 Web 服务规则转成防火墙期望端口表（名字 -> "proto/port"）：
// 仅放行监听在通配地址的规则（Web 服务只有 TCP），与端口转发共用 dnet- 前缀。
func FirewallPorts(enabled bool, rules []Rule) map[string]string {
	if !enabled {
		return nil
	}
	out := map[string]string{}
	for _, r := range rules {
		ip := net.ParseIP(r.ListenAddress)
		if ip == nil || !ip.IsUnspecified() {
			continue
		}
		name := strings.Trim(fwNameRe.ReplaceAllString(strings.ToLower(r.ID), "-"), "-")
		out["dnet-"+name] = "tcp/" + strconv.Itoa(r.ListenPort)
	}
	return out
}
