// Package waf wraps HTTP handlers with the OWASP Coraza engine.
//
// The rule set is embedded at build time and parsed once per process, so every
// Web service that turns the switch on shares the same WAF instance while each
// request still gets its own transaction.
package waf

import (
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/cxbdasheng/dnet/helper"
)

//go:embed rules.conf
var defaultDirectives string

// requestBodyLimit caps how much of a request body is buffered and inspected.
// Bodies larger than this are processed partially: the head is checked and the
// untouched remainder keeps streaming to the backend.
const requestBodyLimit = 1 << 20

// Engine is a shareable Coraza instance. Transactions are created per request.
type Engine struct {
	waf coraza.WAF
}

var (
	sharedOnce sync.Once
	shared     *Engine
	sharedErr  error
)

// Shared returns the process-wide engine backed by the embedded rule set.
// A rule syntax error is reported once and remembered.
func Shared() (*Engine, error) {
	sharedOnce.Do(func() { shared, sharedErr = New(defaultDirectives) })
	return shared, sharedErr
}

// New parses the supplied SecLang directives into an engine.
func New(directives string) (*Engine, error) {
	w, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(directives).
		WithRequestBodyAccess().
		WithRequestBodyLimit(requestBodyLimit).
		WithRequestBodyInMemoryLimit(requestBodyLimit).
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
			block(w, http.StatusForbidden)
			return
		}
		if it != nil {
			status := it.Status
			if status < 400 || status > 599 {
				status = http.StatusForbidden
			}
			helper.Warn(helper.LogTypeWebService, "[%s] Coraza WAF 拦截 %s %s（来源 %s，规则 %d，动作 %s）",
				name, r.Method, r.URL.RequestURI(), clientIP(r), it.RuleID, it.Action)
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
	// net/http also strips Transfer-Encoding; rules that look for request
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

func splitAddress(remote string) (string, int) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		return strings.Trim(remote, "[]"), 0
	}
	value, _ := strconv.Atoi(port)
	return host, value
}

func clientIP(r *http.Request) string {
	host, _ := splitAddress(r.RemoteAddr)
	return host
}
