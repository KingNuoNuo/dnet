// Package certdeploy uploads issued certificates to cloud CDN/WAF providers.
//
// 目前只支持阿里云 ESA：把证书 + 私钥通过 SetCertificate 上传成站点证书
// （Type=upload），同名证书存在时按证书 ID 更新，所以续期后不会越堆越多。
package certdeploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cxbdasheng/dnet/certificates"
	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/signer"
)

const (
	// ProviderAliyunESA 是阿里云边缘安全加速（ESA）。
	ProviderAliyunESA = "aliyun-esa"

	aliyunESAEndpoint = "https://esa.cn-hangzhou.aliyuncs.com/"
	esaAPIVersion     = "2024-09-10"
)

// esaEndpoint 单独列出来，测试里可以指向 httptest。
var esaEndpoint = aliyunESAEndpoint

// Report 描述一次成功的上传。
type Report struct {
	Provider string `json:"provider"`
	Site     string `json:"site"`
	CertName string `json:"cert_name"`
	CertID   string `json:"cert_id"`
	Updated  bool   `json:"updated"`
	// PrevNotAfter 是被覆盖的那张旧证书的到期时间（UTC，原样来自云端）。
	// 只在更新时才有值，用来在日志里对比「旧证书到期 → 新证书到期」。
	PrevNotAfter string `json:"prev_not_after,omitempty"`
}

// Fingerprint 用证书+私钥内容算指纹，用来判断「这份证书是否已经部署过」。
func Fingerprint(c certificates.Certificate) string {
	h := sha256.New()
	h.Write([]byte(c.CertPEM))
	h.Write([]byte{0})
	h.Write([]byte(c.KeyPEM))
	return hex.EncodeToString(h.Sum(nil))
}

// Active 表示证书是否配置了至少一个启用的部署目标。
func Active(c certificates.Certificate) bool {
	for _, target := range c.Deploy {
		if !target.Disabled && strings.TrimSpace(target.Provider) != "" {
			return true
		}
	}
	return false
}

// Pending 表示当前这份证书还没有成功上传过。
func Pending(c certificates.Certificate) bool {
	if !Active(c) || strings.TrimSpace(c.CertPEM) == "" || strings.TrimSpace(c.KeyPEM) == "" {
		return false
	}
	return c.DeployedFingerprint == "" || c.DeployedFingerprint != Fingerprint(c)
}

// Deploy 把证书上传到所有启用的目标。某个目标失败不影响其它目标，错误合并返回。
func Deploy(ctx context.Context, conf config.Config, cert certificates.Certificate) ([]Report, error) {
	if strings.TrimSpace(cert.CertPEM) == "" || strings.TrimSpace(cert.KeyPEM) == "" {
		return nil, fmt.Errorf("证书或私钥为空，无法上传")
	}
	if _, err := certificates.Load(cert); err != nil {
		return nil, err
	}
	var reports []Report
	var errs []error
	for _, target := range cert.Deploy {
		if target.Disabled {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(target.Provider)) {
		case ProviderAliyunESA:
			report, err := deployESA(ctx, conf, cert, target)
			if err != nil {
				errs = append(errs, fmt.Errorf("阿里云 ESA: %s", clip(err.Error(), 400)))
				continue
			}
			reports = append(reports, report)
		default:
			errs = append(errs, fmt.Errorf("不支持的部署目标: %s", target.Provider))
		}
	}
	if len(reports) == 0 && len(errs) == 0 {
		return nil, fmt.Errorf("没有启用的部署目标")
	}
	return reports, errors.Join(errs...)
}

// clip 截断过长的错误信息：阿里云的 SignatureDoesNotMatch 会把整段证书回显出来。
func clip(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}

// aliyunCredential 复用「系统设置 → 服务商凭据」里的 aliyun 凭据（DCDN 优先，其次 DDNS）。
func aliyunCredential(conf config.Config) (string, string, error) {
	for _, list := range [][]config.DNSCredential{conf.DCDNConfig.Credentials, conf.DDNSConfig.Credentials} {
		for _, cred := range list {
			if strings.EqualFold(strings.TrimSpace(cred.Service), "aliyun") &&
				strings.TrimSpace(cred.AccessKey) != "" && strings.TrimSpace(cred.AccessSecret) != "" {
				return strings.TrimSpace(cred.AccessKey), strings.TrimSpace(cred.AccessSecret), nil
			}
		}
	}
	return "", "", fmt.Errorf("未找到阿里云凭据，请先在「系统设置 → 服务商凭据」里为 aliyun 填写 AccessKey / Secret")
}

// siteName 取部署目标里的站点名；留空时按证书域名推断根域名。
// 多级后缀（如 example.co.uk）请显式填写站点名。
func siteName(cert certificates.Certificate, target certificates.DeployTarget) string {
	if s := strings.TrimSpace(target.Site); s != "" {
		return s
	}
	for _, d := range cert.Domains {
		d = strings.TrimPrefix(strings.TrimSpace(d), "*.")
		if d == "" {
			continue
		}
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return d
	}
	return ""
}

func certificateName(cert certificates.Certificate, target certificates.DeployTarget) string {
	if n := strings.TrimSpace(target.Name); n != "" {
		return n
	}
	name := strings.TrimSpace(cert.Name)
	if name == "" {
		name = strings.TrimSpace(cert.ID)
	}
	if name == "" && len(cert.Domains) > 0 {
		name = strings.TrimPrefix(strings.TrimSpace(cert.Domains[0]), "*.")
	}
	if name == "" {
		name = "cert"
	}
	return "dnet-" + name
}

type esaClient struct {
	accessKey string
	secret    string
	endpoint  string
	http      *http.Client
}

func newESAClient(accessKey, secret string) *esaClient {
	return &esaClient{
		accessKey: accessKey,
		secret:    secret,
		endpoint:  esaEndpoint,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// call 走阿里云 RPC 风格接口。
//
// ESA 网关对 SetCertificate 只接受 POST，且 Action/Version/公共签名参数必须放在
// query 上、业务参数（证书、私钥等）放在 form body 里；签名覆盖两者。GET 会被
// 拒绝成 UnsupportedHTTPMethod，所以这里按方法分别组装。
func (c *esaClient) call(ctx context.Context, method, action string, params url.Values, out any) error {
	all := url.Values{}
	for key, values := range params {
		all[key] = values
	}
	all.Set("Action", action)
	all.Set("Version", esaAPIVersion)
	signer.AliyunSigner(c.accessKey, c.secret, &all, method)

	query := all
	var payload io.Reader
	if method == http.MethodPost {
		query = url.Values{}
		form := url.Values{}
		for key, values := range all {
			switch key {
			case "Action", "Version", "Signature", "SignatureMethod", "SignatureNonce",
				"AccessKeyId", "SignatureVersion", "Timestamp", "Format", "SecurityToken":
				query[key] = values
			default:
				form[key] = values
			}
		}
		payload = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"?"+query.Encode(), payload)
	if err != nil {
		return err
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Code      string `json:"Code"`
			Message   string `json:"Message"`
			RequestId string `json:"RequestId"`
		}
		if json.Unmarshal(body, &apiErr) == nil && apiErr.Code != "" {
			return fmt.Errorf("%s: %s: %s", action, apiErr.Code, apiErr.Message)
		}
		return fmt.Errorf("%s: HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%s: 解析接口响应失败: %w", action, err)
	}
	return nil
}

func deployESA(ctx context.Context, conf config.Config, cert certificates.Certificate, target certificates.DeployTarget) (Report, error) {
	accessKey, secret, err := aliyunCredential(conf)
	if err != nil {
		return Report{}, err
	}
	site := siteName(cert, target)
	if site == "" {
		return Report{}, fmt.Errorf("无法推断 ESA 站点，请在部署设置里填写站点名（如 c90.top）")
	}
	name := certificateName(cert, target)
	client := newESAClient(accessKey, secret)

	var sites struct {
		TotalCount int `json:"TotalCount"`
		Sites      []struct {
			SiteID   int64  `json:"SiteId"`
			SiteName string `json:"SiteName"`
		} `json:"Sites"`
	}
	params := url.Values{}
	params.Set("SiteName", site)
	if err := client.call(ctx, http.MethodGet, "ListSites", params, &sites); err != nil {
		return Report{}, err
	}
	if sites.TotalCount == 0 || len(sites.Sites) == 0 {
		return Report{}, fmt.Errorf("ESA 中未找到站点 %s", site)
	}
	siteID := sites.Sites[0].SiteID

	certs, err := client.listSiteCertificates(ctx, siteID)
	if err != nil {
		return Report{}, err
	}

	setParams := url.Values{}
	setParams.Set("SiteId", strconv.FormatInt(siteID, 10))
	setParams.Set("Type", "upload")
	setParams.Set("Name", name)
	setParams.Set("Certificate", cert.CertPEM)
	setParams.Set("PrivateKey", cert.KeyPEM)

	found := findCertByName(certs, name)
	updated := false
	prevNotAfter := ""
	if found != nil {
		setParams.Set("Id", found.ID)
		updated = true
		prevNotAfter = found.NotAfter
	}
	var result struct {
		ID string `json:"Id"`
	}
	err = client.call(ctx, http.MethodPost, "SetCertificate", setParams, &result)
	if err != nil && !updated && isDuplicateCertError(err) {
		// 列表接口有延迟（或分页没覆盖到）时，同名证书可能看不见，
		// 于是走了新建分支撞上唯一键。重新拉一次全量再按 Id 更新。
		if again, listErr := client.listSiteCertificates(ctx, siteID); listErr == nil {
			if retry := findCertByName(again, name); retry != nil {
				setParams.Set("Id", retry.ID)
				prevNotAfter = retry.NotAfter
				found = retry
				if retryErr := client.call(ctx, http.MethodPost, "SetCertificate", setParams, &result); retryErr == nil {
					updated = true
					err = nil
				} else {
					err = retryErr
				}
			}
		}
	}
	if err != nil {
		if found != nil && !strings.EqualFold(strings.TrimSpace(found.Type), "upload") {
			return Report{}, fmt.Errorf(
				"%w（ESA 上已存在同名证书「%s」，类型 %s，dnet 只能覆盖自己上传的 upload 类型证书；"+
					"请在 ESA 控制台删除它，或在本证书的部署设置里改「ESA 证书名」）",
				err, name, found.Type)
		}
		return Report{}, err
	}
	return Report{
		Provider:     ProviderAliyunESA,
		Site:         site,
		CertName:     name,
		CertID:       result.ID,
		Updated:      updated,
		PrevNotAfter: prevNotAfter,
	}, nil
}

// esaCert 是 ListCertificates 返回的一条证书记录（只取用得到的字段）。
type esaCert struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	Type       string `json:"Type"`
	Status     string `json:"Status"`
	CommonName string `json:"CommonName"`
	NotAfter   string `json:"NotAfter"`
}

// listSiteCertificates 分页拉取站点下的全部证书。
//
// 不能用 Keyword 过滤：ESA 的 Keyword 匹配不到证书的 Name 字段（实测按证书名
// 搜索返回空，但用同名创建会被 Certificate.Duplicated 拒绝），一旦漏掉同名证书
// 就会误判成「不存在」，走到新建分支后必然失败。所以这里整表翻页，本地精确匹配。
func (c *esaClient) listSiteCertificates(ctx context.Context, siteID int64) ([]esaCert, error) {
	const pageSize = 100
	var all []esaCert
	for page := 1; page <= 50; page++ {
		params := url.Values{}
		params.Set("SiteId", strconv.FormatInt(siteID, 10))
		params.Set("PageNumber", strconv.Itoa(page))
		params.Set("PageSize", strconv.Itoa(pageSize))
		var resp struct {
			TotalCount int       `json:"TotalCount"`
			Result     []esaCert `json:"Result"`
		}
		if err := c.call(ctx, http.MethodGet, "ListCertificates", params, &resp); err != nil {
			return all, err
		}
		all = append(all, resp.Result...)
		if len(resp.Result) == 0 || len(all) >= resp.TotalCount {
			break
		}
	}
	return all, nil
}

// findCertByName 按证书名精确匹配，优先返回 upload 类型（只有这种能被 dnet 覆盖）。
func findCertByName(certs []esaCert, name string) *esaCert {
	want := strings.TrimSpace(name)
	var other *esaCert
	for i := range certs {
		item := &certs[i]
		if item.ID == "" || !strings.EqualFold(strings.TrimSpace(item.Name), want) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Type), "upload") {
			return item
		}
		if other == nil {
			other = item
		}
	}
	return other
}

// isDuplicateCertError 判断是否是「证书名已存在」的冲突。
func isDuplicateCertError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate.duplicated") ||
		strings.Contains(msg, "certificate name already exists")
}
