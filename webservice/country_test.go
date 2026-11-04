package webservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cxbdasheng/dnet/waf"
)

func TestValidateCountryPolicy(t *testing.T) {
	for _, value := range []string{"", "allow:CN", "deny:RU,KP", "allow:HK,MO"} {
		if err := ValidateCountryPolicy(value); err != nil {
			t.Fatalf("%q should be valid: %v", value, err)
		}
	}
	for _, value := range []string{"CN", "allow:", "maybe:CN", "allow:C1"} {
		if err := ValidateCountryPolicy(value); err == nil {
			t.Fatalf("%q should be invalid", value)
		}
	}
}

func TestEffectiveCountryPolicy(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		policy waf.Policy
		want   string
	}{
		{"都未设置", Rule{}, waf.Policy{}, ""},
		{"策略开关", Rule{}, waf.Policy{AllowOnlyCN: true}, "allow:CN"},
		{"行级优先", Rule{CountryPolicy: "deny:RU"}, waf.Policy{AllowOnlyCN: true}, "deny:RU"},
		{"行级空白视为未设置", Rule{CountryPolicy: "   "}, waf.Policy{AllowOnlyCN: true}, "allow:CN"},
	}
	for _, c := range cases {
		if got := effectiveCountryPolicy(c.rule, c.policy); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGuardHandlerCountryPolicy(t *testing.T) {
	if waf.GeoIPPath() != "" {
		t.Skip("已加载归属地库，此用例依赖「未加载」的默认状态")
	}
	waf.ConfigureGuard(waf.GuardSettings{BanEnabled: false, RateLimit: 0})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	cases := []struct {
		name   string
		rule   Rule
		policy waf.Policy
		remote string
		want   int
	}{
		// 没放国家库时查不到归属地，放行比全站 403 安全。
		{"行级 allow:CN 无库放行", Rule{CountryPolicy: "allow:CN"}, waf.Policy{}, "8.8.8.8:1234", http.StatusNoContent},
		{"行级 deny:CN 无库放行", Rule{CountryPolicy: "deny:CN"}, waf.Policy{}, "8.8.8.8:1234", http.StatusNoContent},
		{"策略开关无库放行", Rule{}, waf.Policy{AllowOnlyCN: true}, "8.8.8.8:1234", http.StatusNoContent},
		{"未设置地区限制", Rule{}, waf.Policy{}, "8.8.8.8:1234", http.StatusNoContent},
		// 内网 / 环回 / CGNAT 不参与地区判断，否则开了开关本地都进不来。
		{"内网地址放行", Rule{CountryPolicy: "allow:CN"}, waf.Policy{}, "192.168.1.10:1234", http.StatusNoContent},
		{"环回地址放行", Rule{CountryPolicy: "allow:CN"}, waf.Policy{}, "127.0.0.1:1234", http.StatusNoContent},
		{"CGNAT 地址放行", Rule{CountryPolicy: "allow:CN"}, waf.Policy{}, "100.64.3.7:1234", http.StatusNoContent},
	}
	for _, c := range cases {
		handler := guardHandler(c.rule, c.policy, next)
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = c.remote
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Fatalf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
}
