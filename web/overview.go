package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cxbdasheng/dnet/certificates"
	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/forward"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/webservice"
)

// 顶栏状态取值。与 common.css 中 .dnet-dot 的配色类一一对应：
// on 用默认（绿），off / warn / err 各有覆盖样式。
const (
	overviewStateOn   = "on"
	overviewStateOff  = "off"
	overviewStateWarn = "warn"
	overviewStateErr  = "err"
)

// overviewService 是单个模块的状态。
type overviewService struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
	Text    string `json:"text"`
	Meta    string `json:"meta,omitempty"`
}

// overviewData 是 /api/overview 的 data 载荷。
type overviewData struct {
	State    string            `json:"state"`
	Text     string            `json:"text"`
	Sub      string            `json:"sub"`
	Services []overviewService `json:"services"`
}

// OverviewAPI 汇总各模块的启用与运行状态，供外壳顶栏轮询显示。
//
// 只读取既有状态，不触发任何写操作：
//   - 启用开关来自 configRepo.Load()
//   - 实时监听状态来自 Forwarder / WebServices 的 Status()
//   - 证书状态复用 certificates.Describe()
//
// DCDN 与 DDNS 是定时同步任务，没有运行态查询方法，因此只上报启用开关。
func (s *Server) OverviewAPI(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		helper.ReturnError(writer, "不支持的请求方法")
		return
	}

	conf, err := s.configRepo.Load()
	if err != nil {
		helper.Error(helper.LogTypeSystem, "获取配置失败: %v", err)
		helper.ReturnError(writer, "获取配置失败")
		return
	}

	services := []overviewService{
		dcdnOverview(conf),
		ddnsOverview(conf),
		forwardOverview(conf, s.Forwarder),
		webServiceOverview(conf, s.WebServices),
		certificatesOverview(conf),
	}

	helper.ReturnSuccess(writer, "ok", summarizeOverview(services))
}

func dcdnOverview(conf config.Config) overviewService {
	item := overviewService{ID: "dcdn", Name: "动态 CDN", Enabled: conf.DCDNEnabled}
	count := len(conf.DCDN)

	if !conf.DCDNEnabled {
		item.State, item.Text = overviewStateOff, "未启用"
		if count > 0 {
			item.Meta = fmt.Sprintf("%d 个域名已保存", count)
		}
		return item
	}

	item.State, item.Text = overviewStateOn, "运行中"
	if count > 0 {
		item.Meta = fmt.Sprintf("%d 个域名", count)
	}
	return item
}

func ddnsOverview(conf config.Config) overviewService {
	item := overviewService{ID: "ddns", Name: "动态 DNS", Enabled: conf.DDNSEnabled}
	count := len(conf.DDNS)

	if !conf.DDNSEnabled {
		item.State, item.Text = overviewStateOff, "未启用"
		if count > 0 {
			item.Meta = fmt.Sprintf("%d 组解析已保存", count)
		}
		return item
	}

	item.State, item.Text = overviewStateOn, "运行中"
	if count > 0 {
		item.Meta = fmt.Sprintf("%d 组解析", count)
	}
	return item
}

func forwardOverview(conf config.Config, manager *forward.Manager) overviewService {
	item := overviewService{ID: "dpf", Name: "端口转发", Enabled: conf.ForwardEnabled}
	total := len(conf.ForwardRules)

	if !conf.ForwardEnabled {
		item.State, item.Text = overviewStateOff, "未启用"
		if total > 0 {
			item.Meta = fmt.Sprintf("%d 条规则已保存", total)
		}
		return item
	}

	item.State, item.Text = overviewStateOn, "运行中"
	item.Meta = fmt.Sprintf("%d 条规则", total)

	if manager == nil {
		return item
	}

	statuses := manager.Status()
	// Status() 只返回已建立监听的条目，数量缺口即启动失败的规则
	notListening := total - len(statuses)
	if notListening < 0 {
		notListening = 0
	}
	failed := 0
	for _, status := range statuses {
		if !status.Listening {
			notListening++
		}
		if status.LastError != "" {
			failed++
		}
	}

	switch {
	case failed > 0:
		item.State, item.Text = overviewStateErr, "转发异常"
		item.Meta = fmt.Sprintf("%d 条规则 · %d 条报错", total, failed)
	case notListening > 0:
		item.State, item.Text = overviewStateWarn, "部分未监听"
		item.Meta = fmt.Sprintf("%d 条规则 · %d 条未监听", total, notListening)
	}
	return item
}

func webServiceOverview(conf config.Config, manager *webservice.Manager) overviewService {
	item := overviewService{ID: "dws", Name: "Web 服务", Enabled: conf.WebServiceEnabled}
	total := len(conf.WebServiceRules)

	if !conf.WebServiceEnabled {
		item.State, item.Text = overviewStateOff, "未启用"
		if total > 0 {
			item.Meta = fmt.Sprintf("%d 个站点已保存", total)
		}
		return item
	}

	item.State, item.Text = overviewStateOn, "运行中"
	item.Meta = fmt.Sprintf("%d 个站点", total)

	if manager == nil {
		return item
	}

	statuses := manager.Status()
	notListening := total - len(statuses)
	if notListening < 0 {
		notListening = 0
	}
	for _, status := range statuses {
		if !status.Listening {
			notListening++
		}
	}

	if notListening > 0 {
		item.State, item.Text = overviewStateWarn, "部分未监听"
		item.Meta = fmt.Sprintf("%d 个站点 · %d 个未监听", total, notListening)
	}
	return item
}

func certificatesOverview(conf config.Config) overviewService {
	item := overviewService{ID: "dssl", Name: "证书管理"}
	total := len(conf.Certificates)

	if total == 0 {
		item.State, item.Text = overviewStateOff, "暂无证书"
		return item
	}

	item.Enabled = true
	item.State, item.Text = overviewStateOn, "证书有效"
	item.Meta = fmt.Sprintf("%d 张证书", total)

	now := time.Now()
	broken, waiting := 0, 0
	for _, cert := range conf.Certificates {
		switch certificates.Describe(cert, now).State {
		case "invalid", "expired":
			broken++
		case "expiring", "not_issued":
			// 即将到期与 ACME 待签发都还不算故障，归入需要留意的区间
			waiting++
		}
	}

	switch {
	case broken > 0:
		item.State, item.Text = overviewStateErr, "证书异常"
		item.Meta = fmt.Sprintf("%d 张证书 · %d 张失效", total, broken)
	case waiting > 0:
		item.State, item.Text = overviewStateWarn, "证书待处理"
		item.Meta = fmt.Sprintf("%d 张证书 · %d 张待处理", total, waiting)
	}
	return item
}

// summarizeOverview 把各模块状态收敛成顶栏那一行。
// 取最严重的那个：err > warn > 正常。
func summarizeOverview(services []overviewService) overviewData {
	data := overviewData{Services: services, State: overviewStateOn, Text: "服务运行中"}

	enabled := 0
	hasWarn, hasErr := false, false
	affected := make([]string, 0, len(services))

	for _, service := range services {
		if service.Enabled {
			enabled++
		}
		switch service.State {
		case overviewStateErr:
			hasErr = true
			affected = append(affected, service.Name)
		case overviewStateWarn:
			hasWarn = true
			affected = append(affected, service.Name)
		}
	}

	switch {
	case hasErr:
		data.State, data.Text = overviewStateErr, "服务异常"
	case hasWarn:
		data.State, data.Text = overviewStateWarn, "服务告警"
	case enabled == 0:
		data.State, data.Text = overviewStateOff, "服务已全部停用"
	}

	if len(affected) > 0 {
		data.Sub = strings.Join(affected, "、") + " 需要处理"
	} else {
		data.Sub = fmt.Sprintf("%d / %d 个服务已启用", enabled, len(services))
	}
	return data
}
