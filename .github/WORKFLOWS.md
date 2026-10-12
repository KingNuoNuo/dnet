# GitHub 自动化

## 检查与发布

| 工作流 | 触发方式 | 检查内容 |
| --- | --- | --- |
| `test.yml` | 向 main 推送、目标为 main 的 PR | 三系统 Go 测试、Linux race、vet、跨平台 snapshot 与校验和；调用质量与漏洞检查 |
| `quality.yml` | Test / Release 调用，或手动运行 | `gofmt`、`go mod tidy -diff`、`go mod verify`、actionlint（含 ShellCheck） |
| `security.yml` | Test / Release 调用、手动运行、每周一 02:23 UTC | `govulncheck ./...`；可达漏洞使任务失败 |
| `release.yml` | 推送 `v*` 标签 | 六平台（linux amd64/arm64/armv7、darwin amd64/arm64、windows amd64）交叉编译与测试，自动发布带修改说明的 Release 与校验和 |

检查任务仅需 `contents: read`。定时漏洞检查可以在没有新提交时发现新披露的问题。工具版本固定在工作流中；更新 actionlint / govulncheck 版本后应重新验证工作流。

`govulncheck` 当前在 Linux 执行，依据选定 Go 工具链和扫描时的漏洞数据库判断；无可达漏洞不代表所有平台和所有依赖都没有漏洞。修复标准库漏洞时应同时更新 `go.mod` 的最低 Go 版本和 README 版本提示。

发布说明自动生成：正文包含本 Fork 相对上游的修改清单与 `fb76da9..tag` 的提交记录。发布新版本只需推送 `v*` 标签。

工作流文件本身不会设置仓库分支保护。需要阻止检查失败的 PR 合并时，应在 GitHub ruleset 中将相关检查设为必需；不要仅依赖跨平台打包任务的结果。
