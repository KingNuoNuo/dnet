package web

import (
	"embed"
	"html/template"
	"net/http"
	"strconv"

	"github.com/cxbdasheng/dnet/helper"
)

//go:embed logs.html
var logsEmbedFile embed.FS

func (s *Server) Logs(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		s.handleLogsGet(writer, request)
	case http.MethodDelete:
		s.handleLogsAPIDelete(writer, request)
	default:
		helper.ReturnError(writer, "不支持的请求方法")
		return
	}
}

// LogsPageData 日志页面数据模型
type LogsPageData struct {
	Logs       []helper.LogEntry // 日志列表
	TotalCount int               // 日志总数
}

func (s *Server) handleLogsGet(writer http.ResponseWriter, request *http.Request) {
	tmpl, err := template.ParseFS(logsEmbedFile, "logs.html")
	if err != nil {
		helper.Error(helper.LogTypeSystem, "解析日志页面模板失败: %v", err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 获取日志数据
	memLogger := helper.GetLogger()
	logs := memLogger.GetLogs()

	// 构造页面数据
	data := LogsPageData{
		Logs:       logs,
		TotalCount: len(logs),
	}

	if err = tmpl.Execute(writer, data); err != nil {
		helper.Error(helper.LogTypeSystem, "渲染日志页面失败 [路径=%s]: %v", request.URL.Path, err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleLogsAPIDelete 清空日志
func (s *Server) handleLogsAPIDelete(writer http.ResponseWriter, request *http.Request) {
	memLogger := helper.GetLogger()

	// 记录清空前的日志数量
	oldCount := memLogger.GetCount()

	// 清空日志
	memLogger.Clear()

	// 记录清空操作
	helper.Info(helper.LogTypeSystem, "日志已清空 [操作者IP = %s, 清空数量 = %d ]", helper.GetClientIP(request), oldCount)

	// 返回成功响应
	helper.ReturnSuccess(writer, "日志已清空", nil)
}

// LogsCount 获取日志总数与最新若干条日志。
//
// 默认返回最近 10 条（外壳的未读角标与气泡提示按这个节奏轮询，不要改动默认值）；
// 需要更多的地方（如状态总览内嵌的日志框）用 ?n= 指定，取值 1 ~ helper.MaxSize。
func (s *Server) LogsCount(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		helper.ReturnError(writer, "不支持的请求方法")
		return
	}

	memLogger := helper.GetLogger()

	helper.ReturnSuccess(writer, "", map[string]interface{}{
		"count":  memLogger.GetCount(),
		"latest": memLogger.GetRecentLogs(recentLogLimit(request)),
	})
}

// recentLogLimit 解析 ?n=，缺省或非法时回落到 10。
// 上限取 helper.MaxSize（日志环形缓冲的容量），再大也没有数据。
func recentLogLimit(request *http.Request) int {
	const fallback = 10

	raw := request.URL.Query().Get("n")
	if raw == "" {
		return fallback
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if n < 1 {
		return 1
	}
	if n > helper.MaxSize {
		return helper.MaxSize
	}
	return n
}
