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
	engine, err := EngineFor(Policy{})
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

func requestFor(method, target, body, agent, contentType string) *http.Request {
	req := httptest.NewRequest(method, "http://nas.example"+target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if agent != "" {
		req.Header.Set("User-Agent", agent)
	}
	return req
}

func groupByID(t *testing.T, id int) RuleGroup {
	t.Helper()
	for _, group := range mustCatalog(t) {
		if group.ID == id {
			return group
		}
	}
	t.Fatalf("CRS group %d not found", id)
	return RuleGroup{}
}

func mustCatalog(t *testing.T) []RuleGroup {
	t.Helper()
	groups, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	return groups
}

func TestCatalogListsCRSGroups(t *testing.T) {
	groups := mustCatalog(t)
	byID := map[int]RuleGroup{}
	for _, group := range groups {
		byID[group.ID] = group
	}
	// 检测组必须出现且带中文名。
	for _, id := range []int{905, 911, 913, 920, 921, 922, 930, 931, 932, 933, 934, 941, 942, 943, 944, 999} {
		group, ok := byID[id]
		if !ok {
			t.Fatalf("CRS group %d missing from catalog", id)
		}
		if group.Mandatory {
			t.Fatalf("CRS group %d should be selectable", id)
		}
		if group.Name == "" {
			t.Fatalf("CRS group %d has no name", id)
		}
	}
	// 框架组只读。
	for _, id := range []int{901, 949, 959, 980} {
		group, ok := byID[id]
		if !ok {
			t.Fatalf("framework group %d missing from catalog", id)
		}
		if !group.Mandatory {
			t.Fatalf("framework group %d should be mandatory", id)
		}
	}
	// 响应侧数据泄露组（950/951/952/953/954/955/956）不参与本集成。
	for _, id := range []int{950, 951, 952, 953, 954, 955, 956} {
		if _, ok := byID[id]; ok {
			t.Fatalf("response group %d should not be listed", id)
		}
	}
	for i := 1; i < len(groups); i++ {
		if groups[i-1].ID >= groups[i].ID {
			t.Fatal("catalog not sorted by group id")
		}
	}
}

func TestNormalizeDisabled(t *testing.T) {
	got := NormalizeDisabled([]int{424242, 942, 901, 942})
	if len(got) != 1 || got[0] != 942 {
		t.Fatalf("NormalizeDisabled = %v, want [942]", got)
	}
}

func TestBenignRequestsPassThrough(t *testing.T) {
	engine := testEngine(t)
	// 注意：CRS 默认只放行 GET/HEAD/POST/OPTIONS（911 组），PUT/DELETE/WebDAV
	// 需要去掉 911 组或自定义规则放行，所以这里不放 DELETE 用例。
	cases := []struct{ method, target, body, contentType string }{
		{"GET", "/index.html?q=hello&lang=zh-CN", "", ""},
		{"GET", "/api/v1/items/42", "", ""},
		{"OPTIONS", "/api/items/7", "", ""},
		{"POST", "/login", `{"username":"alice","password":"s3cret"}`, "application/json"},
		{"HEAD", "/", "", ""},
	}
	for _, c := range cases {
		req := requestFor(c.method, c.target, c.body, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", c.contentType)
		code, got := serve(t, engine, req)
		if code != http.StatusOK {
			t.Fatalf("%s %s blocked: %d %s", c.method, c.target, code, got)
		}
		if got != c.body {
			t.Fatalf("%s %s body changed: %q", c.method, c.target, got)
		}
	}
}

func TestAttacksBlocked(t *testing.T) {
	engine := testEngine(t)
	cases := []struct{ name, method, target, body, contentType string }{
		{"sqli libinjection", "GET", `/search?id=1%27%20or%20%271%27%3D%271`, "", ""},
		{"sqli union", "GET", "/?id=1+union+select+user,password+from+users", "", ""},
		{"sqli body", "POST", "/login", "username=admin' OR 1=1 --", "application/x-www-form-urlencoded"},
		{"xss", "GET", `/search?q=%3Csvg%2Fonload%3Dalert(1)%3E`, "", ""},
		{"path traversal", "GET", "/try?test=%3C..%3E%2F..%2F", "", ""},
		{"path traversal literal", "GET", "/try?test=../../", "", ""},
		{"shell probe", "GET", "/ping?cmd=%7Cwhoami", "", ""},
		{"scanner ua", "GET", "/", "", ""},
	}
	for _, c := range cases {
		req := requestFor(c.method, c.target, c.body, "curl/8.6", c.contentType)
		if c.name == "scanner ua" {
			req = requestFor(c.method, c.target, c.body, "sqlmap/1.8", c.contentType)
		}
		code, got := serve(t, engine, req)
		if code != http.StatusForbidden {
			t.Fatalf("%s not blocked: %d %s", c.name, code, got)
		}
		if got == "" {
			t.Fatalf("%s blocked with empty body", c.name)
		}
	}
}

func TestDisabledGroupsLetAttacksThrough(t *testing.T) {
	engine, err := EngineFor(Policy{DisabledGroups: []int{942, 930}})
	if err != nil {
		t.Fatal(err)
	}
	// 942/930 被关掉后，SQL 注入和路径穿越直通后端。
	for _, target := range []string{`/search?id=1%27%20or%20%271%27%3D%271`, "/try?test=../../"} {
		code, _ := serve(t, engine, requestFor("GET", target, "", "Mozilla/5.0", ""))
		if code != http.StatusOK {
			t.Fatalf("%s still blocked after disabling groups: %d", target, code)
		}
	}
	// 其余组（如 XSS）继续生效。
	req := requestFor("GET", `/search?q=%3Csvg%2Fonload%3Dalert(1)%3E`, "", "Mozilla/5.0", "")
	if code, _ := serve(t, engine, req); code != http.StatusForbidden {
		t.Fatalf("xss not blocked: %d", code)
	}
}

func TestCustomDirectivesApply(t *testing.T) {
	custom := `SecRule ARGS:probe "@rx winbeat" "id:199999,phase:2,deny,log,msg:'自定义探测规则'"`
	engine, err := EngineFor(Policy{CustomDirectives: custom})
	if err != nil {
		t.Fatal(err)
	}
	req := requestFor("GET", "/?probe=winbeat", "", "Mozilla/5.0", "")
	if code, _ := serve(t, engine, req); code != http.StatusForbidden {
		t.Fatalf("custom rule not applied: %d", code)
	}
	without, err := EngineFor(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := serve(t, without, requestFor("GET", "/?probe=winbeat", "", "Mozilla/5.0", "")); code != http.StatusOK {
		t.Fatalf("custom rule leaked into default engine: %d", code)
	}
}

func TestCustomDirectivesSyntaxSurfaces(t *testing.T) {
	if _, err := EngineFor(Policy{CustomDirectives: "This is not SecLang"}); err == nil {
		t.Fatal("invalid custom directives accepted")
	}
}

func TestLargeBodyStillReachesBackend(t *testing.T) {
	engine := testEngine(t)
	// CRS 默认（920 组）只接受白名单内的 Content-Type，二进制直传会被
	// 920420 拦下，所以这里用真实上传的 multipart 形式验证"大请求体不截断"。
	const boundary = "dnetwafboundary"
	payload := strings.Repeat("a", 3<<20)
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"blob.bin\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		payload + "\r\n--" + boundary + "--\r\n"
	req := requestFor("POST", "/upload", body, "Mozilla/5.0", "multipart/form-data; boundary="+boundary)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		if len(got) != len(body) {
			t.Errorf("body truncated: %d != %d", len(got), len(body))
		}
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	engine.Handler("test", next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("large body rejected: %d", rec.Code)
	}
}

func TestConfigureReusesEngineWhileSelectionUnchanged(t *testing.T) {
	first, err := EngineFor(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := EngineFor(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	// 空切片与 nil 是同一个选择，不能每次重建引擎。
	if first != second {
		t.Fatal("engine rebuilt with unchanged selection")
	}
	other, err := EngineFor(Policy{DisabledGroups: []int{942}})
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatal("engine not rebuilt after selection change")
	}
	if again, err := EngineFor(Policy{DisabledGroups: []int{942}}); err != nil || again != other {
		t.Fatal("engine rebuilt with unchanged selection")
	}
}

func TestBuildDirectivesTuning(t *testing.T) {
	out, err := buildDirectives(nil, "", 2, 8, []int{942100, 941110})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"paranoia_level=2",
		"inbound_anomaly_score_threshold=8",
		"SecRuleRemoveById 941110 942100",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("directives missing %q", want)
		}
	}
}
