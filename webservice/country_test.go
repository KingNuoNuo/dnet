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

func TestGuardHandlerCountryPolicy(t *testing.T) {
	waf.ConfigureGuard(waf.GuardSettings{BanEnabled: false, RateLimit: 0})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	cases := []struct {
		policy string
		want   int
	}{
		{"", http.StatusNoContent},
		{"allow:CN", http.StatusForbidden}, // 没有 GeoIP 库时国家未知，allow 模式拒绝
		{"deny:CN", http.StatusNoContent},
	}
	for _, c := range cases {
		handler := guardHandler(Rule{CountryPolicy: c.policy}, next)
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != c.want {
			t.Fatalf("policy %q => %d, want %d", c.policy, w.Code, c.want)
		}
	}
}
