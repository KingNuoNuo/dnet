package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := Shared()
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func serve(t *testing.T, engine *Engine, r *http.Request) (int, string) {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	rec := httptest.NewRecorder()
	engine.Handler("test", next).ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

func TestSharedRulesetLoads(t *testing.T) {
	if testEngine(t) == nil {
		t.Fatal("nil engine")
	}
}

func TestBenignRequestsPassThrough(t *testing.T) {
	engine := testEngine(t)
	cases := []struct {
		method, target, body, contentType string
	}{
		{"GET", "/index.html?q=hello&lang=zh-CN", "", ""},
		{"GET", "/api/v1/items/42", "", ""},
		{"POST", "/login", `{"username":"alice","password":"s3cret"}`, "application/json"},
		{"POST", "/search", "keyword=select+from+the+list&page=2", "application/x-www-form-urlencoded"},
		{"HEAD", "/", "", ""},
		{"DELETE", "/api/items/7", "", ""},
		{"PROPFIND", "/dav/", "", ""},
		// 普通查询参数不能被命令注入规则误伤
		{"GET", "/item?tag=a&id=1&cat=books", "", ""},
		// 人类语言里的 select ... from 不是 SQL
		{"GET", "/search?q=select+name+from+the+list", "", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "http://nas.example"+c.target, strings.NewReader(c.body))
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		code, got := serve(t, engine, req)
		if code != http.StatusOK {
			t.Fatalf("%s %s blocked: %d %s", c.method, c.target, code, got)
		}
		if got != c.body {
			t.Fatalf("%s %s body changed: %q", c.method, c.target, got)
		}
	}
}

func TestAttackPatternsBlocked(t *testing.T) {
	engine := testEngine(t)
	cases := []struct {
		name, method, target, body, agent, contentType string
	}{
		{"sqli query", "GET", `/search?q=1%27%20or%20%271%27%3D%271`, "", "", ""},
		{"sqli body", "POST", "/login", "username=admin' OR 1=1 --", "", "application/x-www-form-urlencoded"},
		{"sqli json", "POST", "/login", `{"username":"admin' OR 1=1 --"}`, "", "application/json"},
		{"union select", "GET", "/item?id=1+union+select+password+from+users", "", "", ""},
		{"xss", "GET", `/search?q=%3Cscript%3Ealert(1)%3C/script%3E`, "", "", ""},
		{"path traversal", "GET", "/static/../../etc/passwd", "", "", ""},
		{"git probe", "GET", "/.git/config", "", "", ""},
		{"command injection", "GET", "/ping?host=127.0.0.1;whoami", "", "", ""},
		{"webshell body", "POST", "/upload", "<?php system($_GET['c']); ?>", "", "application/x-www-form-urlencoded"},
		{"scanner", "GET", "/", "", "sqlmap/1.8", ""},
		{"trace method", "TRACE", "/", "", "", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "http://nas.example"+c.target, strings.NewReader(c.body))
		if c.contentType != "" {
			req.Header.Set("Content-Type", c.contentType)
		}
		if c.agent != "" {
			req.Header.Set("User-Agent", c.agent)
		}
		code, _ := serve(t, engine, req)
		if code != http.StatusForbidden {
			t.Fatalf("%s not blocked: %d", c.name, code)
		}
	}
}

func TestLargeBodyStillReachesBackend(t *testing.T) {
	engine := testEngine(t)
	payload := strings.Repeat("a", 3<<20)
	req := httptest.NewRequest("POST", "http://nas.example/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if len(body) != len(payload) {
			t.Errorf("body truncated: %d != %d", len(body), len(payload))
		}
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	engine.Handler("test", next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("large body rejected: %d", rec.Code)
	}
}

func TestRuleSyntaxErrorsSurface(t *testing.T) {
	if _, err := New("SecRule ARGS \"@rx x\" \"id:1,phase:2,block,msg:'x'\""); err != nil {
		t.Fatal(err)
	}
	if _, err := New("This is not SecLang"); err == nil {
		t.Fatal("invalid directives accepted")
	}
}
