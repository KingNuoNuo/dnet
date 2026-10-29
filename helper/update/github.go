package update

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// latestReleaseAPIURL 指向本 Fork 的发布仓库：自动更新只会升级到同一条版本线。
// 用 var 而不是 const，方便测试替换接口地址（也允许构建期按需覆盖）。
var latestReleaseAPIURL = "https://api.github.com/repos/KingNuoNuo/dnet/releases/latest"

// GitHubRelease is the subset of a GitHub release used by the updater.
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// GetLatestRelease returns the latest version and archive URL.
//
// Deprecated: use GetLatestReleaseSelection to also obtain the checksums asset
// required by the verified update flow.
func GetLatestRelease() (version *Version, downloadURL string, err error) {
	release, err := GetLatestReleaseSelection()
	if err != nil {
		return nil, "", err
	}
	return release.Version, release.Archive.URL, nil
}

// GetLatestReleaseSelection returns the archive and checksum assets selected
// exactly for the build that is currently running.
func GetLatestReleaseSelection() (*Release, error) {
	return getLatestRelease(newHTTPClient(), latestReleaseAPIURL, currentBuildTarget())
}

func getLatestRelease(client *http.Client, apiURL string, target BuildTarget) (*Release, error) {
	release, err := getLatest(client, apiURL)
	if err != nil {
		return nil, err
	}
	return selectRelease(release, target)
}

func getLatest(client *http.Client, apiURL string) (*GitHubRelease, error) {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dnet-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误状态码: %d（%s）", resp.StatusCode, apiURL)
	}
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	return &release, nil
}
