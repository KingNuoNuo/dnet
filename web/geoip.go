package web

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/geoip2-golang"

	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/waf"
)

const (
	// geoipFileName 必须与 main.go 启动时扫描的文件名一致，下载完重启也能直接命中。
	geoipFileName = "dbip-country-lite.mmdb"
	// geoipSource 是 DB-IP 免注册的 country lite 库，文件名带年月，每月 1 号更新。
	geoipSource = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz"
	// geoipMaxBytes 防止下载源异常时把磁盘写满（正常解压后约 9 MB）。
	geoipMaxBytes = 64 << 20
	// geoipProbeIP 用来确认下载到的确实是 country 库而不是城市库/损坏文件。
	geoipProbeIP = "8.8.8.8"
)

var geoipClient = &http.Client{Timeout: 90 * time.Second}

// downloadGeoIP 从 DB-IP 拉取免费 country 库：当月起往前试 3 个月（当月可能还没发布），
// 解压、校验后原子替换配置目录下的 dbip-country-lite.mmdb，并立即加载生效。
func downloadGeoIP() (waf.GeoIPStatus, error) {
	dir := filepath.Dir(config.GetConfigFilePath())
	final := filepath.Join(dir, geoipFileName)
	tmp := final + ".download"

	now := time.Now()
	var lastErr error
	for i := range 3 {
		month := now.AddDate(0, -i, 0).Format("2006-01")
		if err := fetchGeoIP(fmt.Sprintf(geoipSource, month), tmp); err != nil {
			lastErr = fmt.Errorf("%s: %w", month, err)
			continue
		}
		if err := verifyCountryDB(tmp); err != nil {
			_ = os.Remove(tmp)
			lastErr = fmt.Errorf("%s: %w", month, err)
			continue
		}
		if err := installGeoIP(tmp, final); err != nil {
			_ = os.Remove(tmp)
			return waf.GeoIPState(), err
		}
		helper.Info(helper.LogTypeWebService, "IP 归属地库已更新 [%s]", final)
		return waf.GeoIPState(), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的下载源")
	}
	_ = os.Remove(tmp)
	return waf.GeoIPState(), fmt.Errorf("下载归属地库失败: %w", lastErr)
}

// fetchGeoIP 下载并解压 gzip 到 dst，失败时清理半成品。
func fetchGeoIP(url, dst string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "dnet-geoip")
	resp, err := geoipClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	defer gz.Close()

	file, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	written, copyErr := io.Copy(file, io.LimitReader(gz, geoipMaxBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("下载中断: %w", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if written > geoipMaxBytes {
		return fmt.Errorf("文件超过 %d MB 上限", geoipMaxBytes>>20)
	}
	return nil
}

// verifyCountryDB 打开刚下载的文件并用一个已知公网 IP 查询，确认是能用的 country 库。
func verifyCountryDB(path string) error {
	db, err := geoip2.Open(path)
	if err != nil {
		return fmt.Errorf("不是有效的 mmdb: %w", err)
	}
	defer db.Close()
	record, err := db.Country(net.ParseIP(geoipProbeIP))
	if err != nil {
		return fmt.Errorf("查询测试失败: %w", err)
	}
	if record == nil || record.Country.IsoCode == "" {
		return fmt.Errorf("库中查不到国家信息，可能不是 country 库")
	}
	return nil
}

// installGeoIP 原子替换目标文件并加载。Windows 下旧库会占用目标文件，
// 此时先释放再替换，失败则恢复原来的库，避免把可用状态弄丢。
func installGeoIP(tmp, final string) error {
	if err := os.Rename(tmp, final); err == nil {
		return waf.SetGeoIP(final)
	}
	previous := waf.GeoIPPath()
	waf.CloseGeoIP()
	if err := os.Rename(tmp, final); err != nil {
		if previous != "" {
			_ = waf.SetGeoIP(previous)
		}
		return fmt.Errorf("替换归属地库失败（文件可能被占用）: %w", err)
	}
	if err := waf.SetGeoIP(final); err != nil {
		if previous != "" {
			_ = waf.SetGeoIP(previous)
		}
		return err
	}
	return nil
}
