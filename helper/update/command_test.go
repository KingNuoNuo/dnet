package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/helper"
)

// startAPIStub 提供一个假的 GitHub releases/latest 接口，
// 资产按当前构建目标（windows/amd64 → x86_64）生成，避免测试触网。
func startAPIStub(t *testing.T, tag string) *httptest.Server {
	t.Helper()
	archive := "dnet_" + tag[1:] + "_windows_x86_64.zip"
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		release := GitHubRelease{
			TagName: tag,
			Assets: []struct {
				Name               string `json:"name"`
				BrowserDownloadURL string `json:"browser_download_url"`
			}{
				{Name: archive, BrowserDownloadURL: "https://example.test/releases/" + archive},
				{Name: "checksums.txt", BrowserDownloadURL: "https://example.test/releases/checksums.txt"},
			},
		}
		if err := json.NewEncoder(w).Encode(release); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func overrideLatestAPI(t *testing.T, url string) {
	t.Helper()
	previous := latestReleaseAPIURL
	latestReleaseAPIURL = url
	t.Cleanup(func() { latestReleaseAPIURL = previous })
}

func declineUpgrade(t *testing.T) {
	t.Helper()
	previous := confirmPrompt
	confirmPrompt = func() bool { return false }
	t.Cleanup(func() { confirmPrompt = previous })
}

func consoleText() string {
	var builder strings.Builder
	for _, entry := range helper.GetLogger().GetLogs() {
		builder.WriteString(entry.Message)
		builder.WriteString("\n")
	}
	return builder.String()
}

func TestCheckAndUpdateUpToDateCurrentVersion(t *testing.T) {
	url := startAPIStub(t, "v3.4.5").URL + "/releases/latest"
	overrideLatestAPI(t, url)
	declineUpgrade(t)
	if err := CheckAndUpdate("v3.4.5", false); err != nil {
		t.Fatal(err)
	}
	if got := consoleText(); !strings.Contains(got, "当前已是最新版本") {
		t.Fatalf("missing up-to-date message in log:\n%s", got)
	}
}

// 当前版本无法解析（DEV、日期构建号等）时不能再直接报错退出：
// 那类二进制会永远无法通过 -u 升级，只能提供"升级到最新版本"。
func TestCheckAndUpdateOffersUpgradeForUnparsableCurrentVersion(t *testing.T) {
	overrideLatestAPI(t, startAPIStub(t, "v0.2.1").URL+"/releases/latest")
	declineUpgrade(t)
	if err := CheckAndUpdate("invalid-version", false); err != nil {
		t.Fatalf("CheckAndUpdate() error = %v, want nil (upgrade offered, declined by stub)", err)
	}
	if got := consoleText(); !strings.Contains(got, "不是语义化版本") || !strings.Contains(got, "发现新版本") {
		t.Fatalf("missing 语义化版本 warning or 发现新版本 in log:\n%s", got)
	}
}

// 需要下载时按原路径走：确认后调用 UpdateRelease（这里改为拒绝，不触网）。
func TestCheckAndUpdateDeclinedUpgradeSkipsDownload(t *testing.T) {
	overrideLatestAPI(t, startAPIStub(t, "v0.2.1").URL+"/releases/latest")
	declineUpgrade(t)
	if err := CheckAndUpdate("v0.1.0", false); err != nil {
		t.Fatal(err)
	}
	if got := consoleText(); strings.Contains(got, "正在下载最新版本") {
		t.Fatalf("download started despite decline:\n%s", got)
	}
}
