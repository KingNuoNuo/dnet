package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/helper"
)

// 本文件提供「解析状态」探测：把配置里写的期望值，和域名当前在公网的实际
// 解析结果比对一次。和 /api/forward/probe 是同一套思路 —— 按需探测、不落库、
// 不改调度器状态，所以随时点随时新。
//
// 为什么不读调度器的上次结果：调度器只在 IP 真正变化时才动记录，结果不持久化、
// 进程重启即丢，而且关掉全局开关后根本没有结果。用户问的「解析状态」其实是
// 「我的域名现在解析到哪儿」，这个问题任何时刻都该能答。

// 探测状态取值。前端按这个决定颜色与文案。
const (
	// probeOK 线上解析结果与期望值一致
	probeOK = "ok"
	// probeStale 能解析到，但和期望值不一致（等下一次同步）
	probeStale = "stale"
	// probeMissing 线上查不到这条记录，或解析查询本身失败
	probeMissing = "missing"
	// probeUnknown 期望值取不到（动态取值失败），只能报告实际解析结果
	probeUnknown = "unknown"
)

// 单条记录一次 DNS 查询给 4 秒（查询本身是毫秒级，余量留给慢递归）；
// 整个请求再加一道 12 秒总闸，避免动态取值打外部接口时把请求拖死。
const (
	probeRecordTimeout = 4 * time.Second
	probeTotalTimeout  = 12 * time.Second
)

// errNoAnswer 表示查询成功但线上没有对应记录（NXDOMAIN / 空应答）
var errNoAnswer = errors.New("线上没有该记录")

// DDNSProbeResult 单条解析记录的探测结果
type DDNSProbeResult struct {
	Type    string   `json:"type"`    // 记录类型
	Status  string   `json:"status"`  // ok / stale / missing / unknown
	Expect  string   `json:"expect"`  // 期望值；动态取值失败时为空
	Actual  []string `json:"actual"`  // 线上实际解析到的值（可能多条）
	Message string   `json:"message"` // 人类可读的说明，前端放 tooltip
}

// DDNSProbe 探测一个域名配置组的解析状态。
// 请求体就是页面上那一行的原样数据（config.DNSGroup），不需要先保存 ——
// 这样「填完先看一眼对不对」和「改完看生效没有」用的是同一条路径。
func (s *Server) DDNSProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var group config.DNSGroup
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&group); err != nil {
		helper.ReturnError(w, "配置格式错误")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		helper.ReturnError(w, "请求只能包含一个 JSON 对象")
		return
	}

	domain := strings.TrimSpace(group.Domain)
	// 这里只做「能不能拿去查」的最低限度检查：空、带空白、带路径分隔符的
	// 一概拒绝。真正的域名合法性由保存时的校验负责，探测不该比保存更严。
	if domain == "" || strings.ContainsAny(domain, " \t/\\") {
		helper.ReturnError(w, "请填写正确域名")
		return
	}
	if len(group.Records) > 20 {
		helper.ReturnError(w, "一个域名最多 20 条记录")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTotalTimeout)
	defer cancel()

	results := make([]DDNSProbeResult, 0, len(group.Records))
	for _, record := range group.Records {
		results = append(results, probeDNSRecord(ctx, domain, record))
	}

	helper.ReturnSuccess(w, "", map[string]any{
		"domain":  domain,
		"records": results,
	})
}

// probeDNSRecord 探测单条记录
func probeDNSRecord(ctx context.Context, domain string, record config.DNSRecord) DDNSProbeResult {
	recordCtx, cancel := context.WithTimeout(ctx, probeRecordTimeout)
	defer cancel()

	out := DDNSProbeResult{Type: record.Type}
	out.Expect = expectedValue(record)

	values, err := lookupRecord(recordCtx, domain, record.Type)
	if err != nil {
		out.Status = probeMissing
		if errors.Is(err, errNoAnswer) {
			out.Message = "线上没有解析到该记录"
		} else {
			out.Message = "解析查询失败：" + err.Error()
		}
		return out
	}
	out.Actual = values

	// 期望值取不到就没法判断「对不对」，只能如实报告线上现在解析成什么。
	// 常见于「动态 IPv4：接口获取」在探测时外部接口不通。
	if out.Expect == "" {
		out.Status = probeUnknown
		out.Message = "无法确定期望值（动态取值未成功），以下仅是线上当前解析结果"
		return out
	}

	for _, value := range values {
		if valueMatches(record.Type, value, out.Expect) {
			out.Status = probeOK
			out.Message = "线上解析结果与期望值一致"
			return out
		}
	}
	out.Status = probeStale
	out.Message = "线上解析值与期望不一致，下一次同步会自动纠正"
	return out
}

// expectedValue 计算一条记录「应该」解析成什么。
//
// 静态记录和 CNAME / TXT 直接用配置值；动态记录调用与调度器同一套取址函数
// （带全局缓存，一个周期内不会重复打同一个接口）。注意 dynamic_*_command
// 会真的执行配置里的命令 —— 这与后台调度器的行为一致，并未因为多了这个
// 探测接口而放宽任何权限：能配命令的人本来就能让调度器去执行它。
func expectedValue(record config.DNSRecord) string {
	value := strings.TrimSpace(record.Value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(record.IPType, "dynamic_") {
		if addr, ok := helper.GetOrSetDynamicIPWithCacheAndRegex(record.IPType, value, record.Regex); ok {
			return strings.TrimSpace(addr)
		}
		return ""
	}
	return value
}

// lookupRecord 查询域名在公网的实际解析结果。
// 返回全部应答值：A / AAAA 可能有多条，比对时按「期望值是否在应答里」判断。
func lookupRecord(ctx context.Context, domain, recordType string) ([]string, error) {
	resolver := net.DefaultResolver
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "A":
		ips, err := resolver.LookupIP(ctx, "ip4", domain)
		if err != nil {
			return nil, normalizeDNSError(err)
		}
		return formatIPs(ips), nil

	case "AAAA":
		ips, err := resolver.LookupIP(ctx, "ip6", domain)
		if err != nil {
			return nil, normalizeDNSError(err)
		}
		return formatIPs(ips), nil

	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err != nil {
			return nil, normalizeDNSError(err)
		}
		cname = strings.TrimSuffix(strings.TrimSpace(cname), ".")
		// LookupCNAME 在没有 CNAME 时不会报错，而是把域名本身回给你 ——
		// 这种情况必须当成「没有该记录」，否则每条 A 记录都会被判成 CNAME 一致。
		if cname == "" || strings.EqualFold(cname, strings.TrimSuffix(domain, ".")) {
			return nil, errNoAnswer
		}
		return []string{cname}, nil

	case "TXT":
		txts, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			return nil, normalizeDNSError(err)
		}
		if len(txts) == 0 {
			return nil, errNoAnswer
		}
		return txts, nil

	default:
		return nil, errors.New("不支持的记录类型 " + recordType)
	}
}

// formatIPs 把 IP 列表转成字符串，顺手按 DNS 规范压缩 IPv6 的写法
func formatIPs(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// normalizeDNSError 把「域名不存在 / 没有该类型记录」统一收敛成 errNoAnswer，
// 其余（超时、网络不通、SERVFAIL）原样返回，好让前端区分「没配」和「查不动」。
func normalizeDNSError(err error) error {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return errNoAnswer
	}
	return err
}

// valueMatches 比对单条应答值。
// IP 用语义比对而不是字符串比对 —— 否则 240e:3b3:2e70:1c20::5 和
// 240e:03b3:2e70:1c20:0000::5 会被判成不一致，白报一个「待同步」。
func valueMatches(recordType, actual, expect string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "A", "AAAA":
		a, b := net.ParseIP(actual), net.ParseIP(expect)
		if a != nil && b != nil {
			return a.Equal(b)
		}
	}
	return strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(expect))
}
