# D-NET + LuCI 图文配置教程

面向 D-NET 及其 LuCI 插件的完整配置指南，图文并茂，配 12 张真实界面截图。

## 如何查看

GitHub 不直接渲染 HTML，三种方式任选：

1. **下载后打开**：克隆仓库或下载 `D-NET配置教程.html` 与 `images/` 目录，双击 HTML 用浏览器打开。
2. **本地起服务**（推荐，图片相对路径不会出问题）：

   ```bash
   cd docs/dnet-guide
   python -m http.server 8080
   # 浏览器访问 http://127.0.0.1:8080/D-NET配置教程.html
   ```

3. **在线预览**：把本页 HTML 的 raw 地址贴到 `https://raw.githack.com/` 或 `https://htmlpreview.github.io/`。

## 内容章节

| 章节 | 说明 |
| --- | --- |
| 1 | 整体架构：LuCI 管程序、D-NET Web 管业务 |
| 2 | 安装与启动：IPK 安装、默认路径、自动下载、保存并应用 |
| 3 | LuCI 插件：基本设置 / 仪表板 / 日志 三个 Tab |
| 4 | D-NET Web 登录 |
| 5 | 总览页 |
| 6 | 动态 CDN（DCDN） |
| 7 | 动态 DNS（DDNS） |
| 8 | 端口转发 |
| 9 | Web 服务 |
| 10 | Coraza WAF 与误报例外 |
| 11 | 证书管理（ACME / ESA） |
| 12 | 设置、Webhook、日志 |
| 13 | 常见问题（6 个实战问答） |

## 说明

- 内容依据项目真实字段与界面整理，截图来自实际运行环境。
- LuCI 日志页截图中的域名与 IP 已打码处理。
- 教程仅作配置参考，涉及防火墙、WAF、证书的操作请在测试环境验证后再用于生产。
