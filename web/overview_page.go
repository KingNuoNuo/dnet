package web

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/cxbdasheng/dnet/helper"
)

//go:embed overview.html
var overviewPageEmbedFile embed.FS

// OverviewPage 渲染状态总览页（外壳里的第一个入口）。
//
// 页面本身不含服务端数据：状态由前端向 /api/overview 取，
// 这样总览与顶栏状态条共用同一个数据源，也不会因缓存出现两处不一致。
func (s *Server) OverviewPage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		helper.ReturnError(writer, "不支持的请求方法")
		return
	}

	tmpl, err := template.ParseFS(overviewPageEmbedFile, "overview.html")
	if err != nil {
		helper.Error(helper.LogTypeSystem, "解析状态总览模板失败: %v", err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err = tmpl.Execute(writer, nil); err != nil {
		helper.Error(helper.LogTypeSystem, "渲染状态总览失败 [路径=%s]: %v", request.URL.Path, err)
		http.Error(writer, "Internal Server Error", http.StatusInternalServerError)
	}
}
