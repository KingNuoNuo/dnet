package update

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cxbdasheng/dnet/helper"
)

// CheckAndUpdate 检查并执行更新流程
// currentVersion: 当前版本号
// autoRestart: 更新成功后是否自动重启
func CheckAndUpdate(currentVersion string, autoRestart bool) error {
	helper.Info(helper.LogTypeSystem, "正在检查更新...")
	helper.Info(helper.LogTypeSystem, "当前版本: %s", currentVersion)

	// 解析当前版本；解析不出（DEV、日期构建号等）时不再直接放弃，
	// 否则这类二进制永远无法通过 -u 升级到可管理的版本线。
	v, err := NewVersion(currentVersion)
	if err != nil {
		helper.Warn(helper.LogTypeSystem, "当前版本 '%s' 不是语义化版本，无法比较新旧", currentVersion)
		v = nil
	}

	// 获取最新版本信息
	latest, err := GetLatestReleaseSelection()
	if err != nil {
		return fmt.Errorf("获取最新版本失败: %w", err)
	}

	helper.Info(helper.LogTypeSystem, "最新版本: %s", latest.Version)

	// 比较版本
	if v != nil && v.GreaterThanOrEqual(latest.Version) {
		helper.Info(helper.LogTypeSystem, "当前已是最新版本，无需更新")
		return nil
	}

	// 显示版本变化
	helper.Info(helper.LogTypeSystem, "发现新版本: %s -> %s", currentVersion, latest.Version.String())

	// 询问用户是否确认更新
	if !confirmPrompt() {
		helper.Info(helper.LogTypeSystem, "已取消更新")
		return nil
	}

	// 获取当前可执行文件路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	// 下载、校验并替换可执行文件
	helper.Info(helper.LogTypeSystem, "正在下载最新版本...")
	if err := UpdateRelease(latest, exePath); err != nil {
		helper.Error(helper.LogTypeSystem, "更新失败: %v", err)
		helper.Info(helper.LogTypeSystem, "请尝试手动下载: %s", latest.Archive.URL)
		return fmt.Errorf("更新失败: %w", err)
	}

	helper.Info(helper.LogTypeSystem, "✓ 更新成功! 版本 %s -> %s", currentVersion, latest.Version.String())

	// 处理重启
	if autoRestart {
		helper.Info(helper.LogTypeSystem, "正在重启程序...")
		return restartProgram(exePath)
	}

	helper.Info(helper.LogTypeSystem, "请重启程序以使用新版本")
	return nil
}

// confirmUpdate 询问用户是否确认更新
var confirmPrompt = confirmUpdate

func confirmUpdate() bool {
	fmt.Print("是否确认更新? [Y/n]: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "" || input == "y" || input == "yes"
}

// restartProgram 重启当前程序
func restartProgram(exePath string) error {
	args := os.Args

	// 启动新进程
	cmd := os.Args[0]
	env := os.Environ()

	// 使用 StartProcess 而不是 Exec，以便当前进程能正常退出
	attr := &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Env:   env,
	}

	process, err := os.StartProcess(cmd, args, attr)
	if err != nil {
		return fmt.Errorf("重启程序失败: %w", err)
	}

	// 释放新进程，让其独立运行
	if err := process.Release(); err != nil {
		return fmt.Errorf("释放新进程失败: %w", err)
	}

	// 退出当前进程
	os.Exit(0)
	return nil
}
