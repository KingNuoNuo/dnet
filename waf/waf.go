// Package waf wraps HTTP handlers with the OWASP Coraza engine.
//
// The embedded OWASP Core Rule Set (github.com/corazawaf/coraza-coreruleset,
// the same pack Lucky embeds) is parsed once per process, so every Web service
// that turns the switch on shares the same WAF instance while each request
// still gets its own transaction. Rule-file groups and extra SecLang
// directives are configurable globally; the shared engine is rebuilt only
// when the selection actually changes.
package waf

import (
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/cxbdasheng/dnet/helper"
)

// ruleDir is where the embedded CRS rule files live inside coreruleset.FS.
// The filesystem only exposes the rules directory, so custom directives can
// never read arbitrary OS paths.
const ruleDir = "@owasp_crs"

var crsFS fs.FS = coreruleset.FS

var (
	ruleIDPattern       = regexp.MustCompile(`(?:^|[,\s])id:(\d+)`)
	updateTargetPattern = regexp.MustCompile(`(?i)^\s*SecRuleUpdateTargetById\s+(\d+)`)
)

// groupLabels maps CRS rule-file prefixes to display names.
var groupLabels = map[string]string{
	"905": "常见误报豁免",
	"911": "HTTP 方法管控",
	"913": "扫描器与常见工具探测",
	"920": "协议合规强制",
	"921": "协议攻击",
	"922": "Multipart 请求攻击",
	"930": "文件包含（LFI）",
	"931": "远程文件包含（RFI）",
	"932": "远程命令执行（RCE）",
	"933": "PHP 攻击",
	"934": "通用应用攻击",
	"941": "XSS 跨站脚本",
	"942": "SQL 注入",
	"943": "会话固定",
	"944": "Java 攻击",
	"999": "常见误报豁免（收尾）",
}

// mandatoryGroups are CRS framework files that detection rules depend on;
// they are always loaded, matching Lucky's "901 和 949 必须勾选" 的约定。
// 959/980 只作用于响应侧评估（本集成不检查响应体），同样随框架常驻。
var mandatoryGroups = map[string]bool{
	"901": true,
	"949": true,
	"959": true,
	"980": true,
}

// RuleGroup describes one CRS rule-file group. Mandatory framework groups are
// always loaded and are shown read-only in the UI.
type RuleGroup struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Mandatory bool   `json:"mandatory"`
}

// Engine is a shareable Coraza instance. Transactions are created per request.
type Engine struct {
	waf coraza.WAF
}

type groupFile struct {
	id   int
	file string
}

var (
	catalogOnce    sync.Once
	catalogDefs    []RuleGroup
	catalogErr     error
	defaultOnIDs   []int
	groupFileNames map[int]string
)

func loadGroups() error {
	catalogOnce.Do(func() {
		entries, err := fs.ReadDir(crsFS, ruleDir)
		if err != nil {
			catalogErr = fmt.Errorf("读取内置 CRS 规则目录失败: %w", err)
			return
		}
		groupFileNames = map[int]string{}
		var groups []groupFile
		for _, entry := range entries {
			name := entry.Name()
			parts := strings.SplitN(name, "-", 3)
			if len(parts) < 3 || (parts[0] != "REQUEST" && parts[0] != "RESPONSE") {
				continue
			}
			id, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			label := strconv.Itoa(id)
			_, selectable := groupLabels[label]
			if !selectable && !mandatoryGroups[label] {
				continue
			}
			groups = append(groups, groupFile{id: id, file: name})
			groupFileNames[id] = name
		}
		sort.Slice(groups, func(i, j int) bool { return groups[i].id < groups[j].id })
		for _, g := range groups {
			label := strconv.Itoa(g.id)
			mandatory := mandatoryGroups[label]
			name := groupLabels[label]
			if name == "" {
				name = label
			}
			catalogDefs = append(catalogDefs, RuleGroup{ID: g.id, Name: name, Mandatory: mandatory})
			if !mandatory {
				defaultOnIDs = append(defaultOnIDs, g.id)
			}
		}
	})
	return catalogErr
}

// Catalog returns the CRS rule-file groups (toggleable detection groups plus
// read-only framework groups), sorted by group ID.
func Catalog() ([]RuleGroup, error) {
	if err := loadGroups(); err != nil {
		return nil, err
	}
	return append([]RuleGroup(nil), catalogDefs...), nil
}

// NormalizeDisabled dedups, sorts and drops unknown or mandatory group IDs so
// stale configuration can neither block startup nor unload the framework.
func NormalizeDisabled(disabled []int) []int {
	if err := loadGroups(); err != nil {
		return nil
	}
	selectable := make(map[int]bool, len(defaultOnIDs))
	for _, id := range defaultOnIDs {
		selectable[id] = true
	}
	out := make([]int, 0, len(disabled))
	for _, id := range disabled {
		if !selectable[id] {
			continue
		}
		if len(out) > 0 && out[len(out)-1] == id {
			continue
		}
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

func buildDirectives(disabled []int, custom string) (string, error) {
	if err := loadGroups(); err != nil {
		return "", err
	}
	off := make(map[int]bool, len(disabled))
	for _, id := range disabled {
		off[id] = true
	}

	var directives strings.Builder
	directives.WriteString("Include @coraza.conf-recommended\n")
	directives.WriteString("Include @crs-setup.conf.example\n")

	// 900/901...949 这些规则文件必须用 Include 加载：Coraza 只有在解析文件时
	// 才知道文件所在目录，@pmFromFile 之类内置数据文件（如 scanners-user-agents.data）
	// 才能从嵌入文件系统里解析。用通配符（Glob）形式是为了绕开 Coraza 在 Windows
	// 上对非 Glob 相对路径执行 filepath.Join 的问题。
	ruleIDs := map[int]bool{}
	for _, def := range catalogDefs {
		if def.ID == 999 || off[def.ID] {
			continue
		}
		name := groupFileNames[def.ID]
		if name == "" {
			continue
		}
		directives.WriteString(fmt.Sprintf("Include %s/*-%d-*.conf\n", ruleDir, def.ID))
		body, err := fs.ReadFile(crsFS, ruleDir+"/"+name)
		if err != nil {
			return "", fmt.Errorf("读取内置规则 %s 失败: %w", name, err)
		}
		for _, match := range ruleIDPattern.FindAllStringSubmatch(string(body), -1) {
			id, _ := strconv.Atoi(match[1])
			ruleIDs[id] = true
		}
	}

	// 999 收尾组含大量 SecRuleUpdateTargetById，指向被关闭组的规则会变成
	// 悬空引用并导致编译失败，所以改为内联加载并剔除这些行。
	if !off[999] {
		name := groupFileNames[999]
		body, err := fs.ReadFile(crsFS, ruleDir+"/"+name)
		if err != nil {
			return "", fmt.Errorf("读取内置规则 %s 失败: %w", name, err)
		}
		directives.WriteString("# ==== " + name + " ====\n")
		directives.WriteString(filterDanglingTargets(string(body), ruleIDs))
	}

	// 内嵌的 @coraza.conf-recommended 默认是 DetectionOnly（只记日志不拦截），
	// 这里显式打开拦截；CRS 的检测规则用 block 占位、由 949/959 评估规则 deny，
	// 所以 SecDefaultAction 保持 crs-setup 的 pass 不动。
	directives.WriteString("SecRuleEngine On\n")

	// 让大文件上传不被 WAF 整体拒绝：前 13 MiB 检查，超出部分继续放行。
	// 响应体检查在当前集成里并未回传给 Coraza，保持关闭避免误解。
	directives.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	directives.WriteString("SecResponseBodyAccess Off\n")

	if custom = strings.TrimSpace(custom); custom != "" {
		directives.WriteString("\n# 用户自定义 SecLang 规则\n")
		directives.WriteString(custom)
		directives.WriteString("\n")
	}
	return directives.String(), nil
}

// filterDanglingTargets 移除指向未加载规则 ID 的 SecRuleUpdateTargetById 行。
func filterDanglingTargets(body string, ruleIDs map[int]bool) string {
	if !strings.Contains(body, "SecRuleUpdateTargetById") {
		return body
	}
	var out strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if match := updateTargetPattern.FindStringSubmatch(line); match != nil {
			id, _ := strconv.Atoi(match[1])
			if !ruleIDs[id] {
				continue
			}
		}
		out.WriteString(line + "\n")
	}
	return out.String()
}

// Policy 是一套命名的 WAF 规则选择：关闭哪些 CRS 规则组 + 追加的 SecLang
// 规则。Web 服务按 ID 引用策略，因此不同站点可以套用不同策略。
type Policy struct {
	ID               string `json:"id" yaml:"id"`
	Name             string `json:"name" yaml:"name"`
	DisabledGroups   []int  `json:"disabled" yaml:"disabled,omitempty"`
	CustomDirectives string `json:"custom" yaml:"custom,omitempty"`
}

var (
	engineMu    sync.Mutex
	engineCache = map[string]*Engine{}
)

// EngineFor builds (or reuses) the engine for a policy selection. Engines are
// keyed by their effective directives, so policies with identical settings
// share one instance and unchanged settings never rebuild.
func EngineFor(policy Policy) (*Engine, error) {
	disabled := NormalizeDisabled(policy.DisabledGroups)
	custom := strings.TrimSpace(policy.CustomDirectives)
	key := strings.Join(intSliceToStrings(disabled), ",") + "\x00" + custom

	engineMu.Lock()
	defer engineMu.Unlock()
	if engine, ok := engineCache[key]; ok {
		return engine, nil
	}
	directives, err := buildDirectives(disabled, custom)
	if err != nil {
		return nil, err
	}
	engine, err := New(directives)
	if err != nil {
		return nil, err
	}
	// 缓存只用于复用；策略数量可控，超过阈值时直接清空重建。
	if len(engineCache) >= 16 {
		engineCache = map[string]*Engine{}
	}
	engineCache[key] = engine
	return engine, nil
}

// NormalizePolicy 修剪策略字段并丢弃未知/框架组 ID，保证落盘内容稳定。
func NormalizePolicy(policy Policy) Policy {
	policy.ID = strings.TrimSpace(policy.ID)
	policy.Name = strings.TrimSpace(policy.Name)
	policy.CustomDirectives = strings.TrimSpace(policy.CustomDirectives)
	policy.DisabledGroups = NormalizeDisabled(policy.DisabledGroups)
	return policy
}

// New parses the supplied SecLang directives into an engine. Includes resolve
// against the embedded CRS filesystem only.
func New(directives string) (*Engine, error) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(directives).
		WithRootFS(crsFS).
		WithErrorCallback(func(rule types.MatchedRule) {
			helper.Debug(helper.LogTypeWebService, "Coraza WAF 规则 %d: %s", rule.Rule().ID(), rule.Message())
		}))
	if err != nil {
		return nil, fmt.Errorf("Coraza WAF 规则加载失败: %w", err)
	}
	return &Engine{waf: w}, nil
}

// Handler inspects each request before it reaches next. A rule hit answers with
// 403 (or the status the rule asks for) instead of forwarding the request.
func (e *Engine) Handler(name string, next http.Handler) http.Handler {
	if e == nil || next == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The transaction owns the request body buffer, so it has to outlive the
		// downstream handler that still reads from that buffer.
		tx := e.waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			if err := tx.Close(); err != nil {
				helper.Debug(helper.LogTypeWebService, "Coraza WAF 事务关闭失败: %v", err)
			}
		}()
		it, err := inspect(tx, r)
		if err != nil {
			// Inspection must not silently degrade into "no protection": a body
			// that cannot be checked is not forwarded.
			helper.Error(helper.LogTypeWebService, "[%s] Coraza WAF 检查请求失败，已拒绝: %v", name, err)
			Record(BlockEvent{
				Site: name, IP: clientIP(r), Method: r.Method, Path: r.URL.RequestURI(),
				Rules: "检查失败: " + err.Error(), Status: http.StatusForbidden,
			})
			block(w, http.StatusForbidden)
			return
		}
		if it != nil {
			status := it.Status
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			summary := matchedSummary(tx)
			helper.Warn(helper.LogTypeWebService, "[%s] Coraza WAF 拦截 %s %s（来源 %s，规则 %d，动作 %s%s）",
				name, r.Method, r.URL.RequestURI(), clientIP(r), it.RuleID, it.Action, summary)
			Record(BlockEvent{
				Site: name, IP: clientIP(r), Method: r.Method, Path: r.URL.RequestURI(),
				RuleID: it.RuleID, Rules: summary, Status: status,
			})
			block(w, status)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func block(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-DNET-WAF", "blocked")
	http.Error(w, "请求已被 Coraza WAF 拦截", status)
}

// matchedSummary 概述触发拦截的规则消息，便于在日志里定位误报来源。
func matchedSummary(tx types.Transaction) string {
	var parts []string
	for _, rule := range tx.MatchedRules() {
		message := strings.TrimSpace(rule.Message())
		if message == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", rule.Rule().ID(), message))
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "，命中：" + strings.Join(parts, "；")
}

// inspect runs phases 0–2 and leaves r.Body readable for downstream handlers.
func inspect(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	if tx.IsRuleEngineOff() {
		return nil, nil
	}

	client, port := splitAddress(r.RemoteAddr)
	tx.ProcessConnection(client, port, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	if r.Host != "" {
		// net/http removes Host from the header map and promotes it to the field.
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for key, values := range r.Header {
		for _, value := range values {
			tx.AddRequestHeader(key, value)
		}
	}
	// net/http also strips Transfer-Encoding; rules looking for request
	// smuggling need to see it.
	for _, value := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", value)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if !tx.IsRequestBodyAccessible() || r.Body == nil || r.Body == http.NoBody {
		return tx.ProcessRequestBody()
	}
	it, _, err := tx.ReadRequestBodyFrom(r.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}
	if it != nil {
		return it, nil
	}
	buffered, err := tx.RequestBodyReader()
	if err != nil {
		return nil, fmt.Errorf("回放请求体失败: %w", err)
	}
	// Hand the backend the checked head plus everything still unread.
	r.Body = io.NopCloser(io.MultiReader(buffered, r.Body))
	return tx.ProcessRequestBody()
}

// intSliceToStrings renders the disabled-group key used for engine caching.
func intSliceToStrings(values []int) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strconv.Itoa(v)
	}
	return out
}

func splitAddress(remote string) (string, int) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		return strings.Trim(remote, "[]"), 0
	}
	value, _ := strconv.Atoi(port)
	return host, value
}

func clientIP(r *http.Request) string {
	// CDN（阿里云 ESA 等）回源时把真实客户端地址放在这些头里；直连时
	// 这些头可能被伪造，但这里只用于日志与统计，不参与放行判断。
	for _, header := range []string{"Ali-CDN-Real-IP", "X-Real-IP", "X-Forwarded-For"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		if header == "X-Forwarded-For" {
			value = strings.TrimSpace(strings.Split(value, ",")[0])
		}
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = host
		}
		value = strings.Trim(value, "[]")
		if net.ParseIP(value) != nil {
			return value
		}
	}
	host, _ := splitAddress(r.RemoteAddr)
	return host
}
