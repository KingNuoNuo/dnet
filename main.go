package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cxbdasheng/dnet/bootstrap"
	"github.com/cxbdasheng/dnet/config"
	"github.com/cxbdasheng/dnet/dcdn"
	"github.com/cxbdasheng/dnet/ddns"
	"github.com/cxbdasheng/dnet/forward"
	"github.com/cxbdasheng/dnet/helper"
	"github.com/cxbdasheng/dnet/helper/update"
	"github.com/cxbdasheng/dnet/web"
	"github.com/cxbdasheng/dnet/webservice"
	"github.com/kardianos/service"
)

// 配置文件路径
var configFilePath = flag.String("c", config.GetConfigFilePathDefault(), "Custom configuration file path")

// 更新 D-NET
var updateFlag = flag.Bool("u", false, "Upgrade D-NET to the latest version")

// 监听地址
var listen = flag.String("l", ":9877", "Listen address")

// 更新频率(秒)
var every = flag.Int("f", config.DefaultEvery, "Update frequency(seconds)")

// 服务管理
var serviceType = flag.String("s", "", "Service management (install|uninstall|restart)")

// 重置密码
var newPassword = flag.String("resetPassword", "", "Reset password to the one entered")

// 自定义 DNS 服务器
var customDNS = flag.String("dns", "", "Custom DNS server address, example: 8.8.8.8")

// Web 服务
var noWebService = flag.Bool("noweb", false, "No web service")

// 跳过 HTTPS 证书验证
var skipVerify = flag.Bool("skipVerify", false, "Skip HTTPS certificate verification")

// dcdn 缓存次数
var dcdnCacheTimes = flag.Int("dcdnCacheTimes", config.DefaultCacheTimes, "dcdn Cache times")

// ddns 缓存次数
var ddnsCacheTimes = flag.Int("ddnsCacheTimes", config.DefaultCacheTimes, "ddns Cache times")

// D-NET 版本
var showVersion = flag.Bool("v", false, "D-NET version")

//go:embed static
var staticEmbeddedFiles embed.FS

//go:embed favicon.ico
var faviconEmbeddedFile embed.FS

// version
var version = "DEV"

var configRepo config.Repository
var syncRunner *bootstrap.Runner
var webServer *web.Server
var forwardManager = forward.NewManager()
var webServiceManager = webservice.NewManager()

// printUsage 自定义 -h 输出：flag 包默认只有一行英文简介，参数含义、默认值
// 和服务管理子命令都不直观，这里按 README「高级选项」同一套口径给出中文说明。
func printUsage() {
	fmt.Println("D-NET —— 动态 NET 解析管理系统")
	fmt.Println()
	fmt.Println("用法：")
	fmt.Println("  dnet [参数]                直接前台运行")
	fmt.Println("  dnet -s install [参数]     安装为系统服务（参数会成为服务启动参数）")
	fmt.Println()
	fmt.Println("参数说明：")
	fmt.Println("  -s <子命令>            服务管理：install / uninstall / restart")
	fmt.Println("  -c <路径>              自定义配置文件路径 (默认 " + config.GetConfigFilePathDefault() + ")")
	fmt.Println("  -l <地址>              Web 管理界面监听地址 (默认 :9877)")
	fmt.Println("  -f <秒>                同步间隔时间（秒）(默认 " + strconv.Itoa(config.DefaultEvery) + ")")
	fmt.Println("  -u                     升级 D-NET 到最新版本")
	fmt.Println("  -dns <服务器>          自定义 DNS 服务器，例：-dns 8.8.8.8")
	fmt.Println("  -noweb                 不启动 Web 管理界面")
	fmt.Println("  -skipVerify            业务请求跳过 HTTPS 证书验证（默认关闭，有中间人风险）")
	fmt.Println("  -dcdnCacheTimes <N>    每隔 N 次强制同步一次 CDN 记录")
	fmt.Println("  -ddnsCacheTimes <N>    每隔 N 次强制同步一次 DNS 记录")
	fmt.Println("  -resetPassword <密码>  重置 Web 登录密码")
	fmt.Println("  -v                     显示版本号")
	fmt.Println("  -h                     显示本帮助")
	fmt.Println()
	fmt.Println("示例：")
	fmt.Println("  dnet -s install -l :9877 -f 300 -c /path/to/config.yaml")
	fmt.Println("  dnet -s uninstall")
	fmt.Println("  dnet -resetPassword newpass")
	fmt.Println()
	fmt.Println("更多文档：https://github.com/cxbdasheng/dnet/wiki")
}

func main() {
	helper.InitLoggerWithConsole(helper.MaxSize, true)
	if !strings.EqualFold(version, "DEV") {
		helper.SetMinLevel(helper.LogLevelINFO)
	}
	flag.Usage = printUsage
	flag.Parse()
	recordCLIOverrides()

	// 显示版本
	if *showVersion {
		fmt.Println(version)
		return
	}
	// 更新 D-NET
	if *updateFlag {
		updateDNET()
		return
	}

	helper.ConfigureHTTPClients(*skipVerify)
	if *skipVerify {
		helper.Warn(helper.LogTypeNetwork, "已跳过 HTTPS 证书验证，服务端身份将不再校验，存在中间人攻击风险")
	}

	// 设置配置文件路径
	if *configFilePath != "" {
		absPath, _ := filepath.Abs(*configFilePath)
		os.Setenv(config.PathENV, absPath)
	}

	if runtime.GOOS == "android" {
		helper.FixTimezone()
	}

	// 检查监听地址，查看是否合法
	if _, err := net.ResolveTCPAddr("tcp", *listen); err != nil {
		helper.Fatalf(helper.LogTypeSystem, "Parse listen address failed! Exception: %s", err)
	}

	// 设置版本号
	os.Setenv(web.VersionEnv, version)

	// 设置端口
	os.Setenv(config.DNETPort, *listen)

	configRepo = config.NewRepository()

	// 老配置迁移：凭据统一到系统设置之前，AK/SK 是写在每个域名/CDN 行上的。
	// 只在「保存 DDNS/动态 CDN 页」时才收归全局的话，升级后第一次打开系统设置
	// 会看到凭据是空的 —— 用户明明配过。启动时先提上来并落盘。
	if conf, err := configRepo.Load(); err == nil {
		moved := config.MigrateLegacyCredentials(&conf.DDNSConfig) +
			config.MigrateLegacyCDNCredentials(&conf.DCDNConfig)
		if moved > 0 {
			if err := configRepo.Save(&conf); err != nil {
				helper.Warn(helper.LogTypeSystem, "服务商凭据迁移落盘失败: %v", err)
			} else {
				helper.Info(helper.LogTypeSystem, "已把 %d 个服务商的凭据从域名/CDN配置收归到系统设置", moved)
			}
		}
	} else {
		helper.Warn(helper.LogTypeSystem, "启动时读取配置失败，跳过服务商凭据迁移: %v", err)
	}

	syncRunner = bootstrap.NewRunner(configRepo)
	web.SetEmbeddedAssets(staticEmbeddedFiles, faviconEmbeddedFile)
	webServer = web.NewServer(configRepo, syncRunner)
	webServer.Forwarder = forwardManager
	webServer.WebServices = webServiceManager

	// 重置密码
	if *newPassword != "" {
		if err := configRepo.ResetPassword(*newPassword); err == nil {
			helper.Info(helper.LogTypeSystem, "密码已重置")
		} else {
			helper.Fatalf(helper.LogTypeSystem, "重置密码失败: %v\n", err)
		}
		return
	}
	// 设置缓存次数
	if *customDNS != "" {
		if err := helper.ValidateDNSServer(*customDNS); err != nil {
			helper.Fatalf(helper.LogTypeNetwork, "自定义 DNS 配置无效: %v", err)
		}
	}
	os.Setenv(dcdn.CacheTimesENV, strconv.Itoa(*dcdnCacheTimes))
	os.Setenv(ddns.CacheTimesENV, strconv.Itoa(*ddnsCacheTimes))

	switch *serviceType {
	case "install":
		installService()
	case "uninstall":
		uninstallService()
	case "restart":
		restartService()
	default:
		if helper.IsRunInDocker() {
			run()
		} else {
			s := getService()
			status, _ := s.Status()
			if status != service.StatusUnknown {
				// 以服务方式运行
				s.Run()
			} else {
				// 非服务方式运行
				switch s.Platform() {
				case "windows-service":
					helper.Info(helper.LogTypeSystem, "可使用 .\\dnet.exe -s install 安装服务运行")
				default:
					helper.Info(helper.LogTypeSystem, "可使用 sudo ./dnet -s install 安装服务运行")
				}
				run()
			}
		}
	}
}

func runWebServer() error {
	mux := http.NewServeMux()
	webServer.RegisterRoutes(mux)

	l, err := net.Listen("tcp", *listen)
	helper.Info(helper.LogTypeSystem, "监听 %s", *listen)
	if err != nil {
		return errors.New("监听端口发生异常, 请检查端口是否被占用!" + err.Error())
	}
	return http.Serve(l, mux)
}
func run() {
	shutdown, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	defer forwardManager.Close()
	defer webServiceManager.Close()
	go webServer.RunCertificateMaintenance(shutdown)
	if conf, err := configRepo.Load(); err == nil {
		conf.NormalizeWAF()
		if conf.WebServiceEnabled {
			webServiceManager.SetWAFPolicies(conf.WAFPolicies)
			if err := webServiceManager.ApplyCertificates(conf.WebServiceRules, conf.Certificates, nil); err != nil {
				helper.Error(helper.LogTypeWebService, "启动失败: %v", err)
			}
		}
		if err := forwardManager.Apply(conf.ActiveForwardRules(), nil); err != nil {
			helper.Error(helper.LogTypeSystem, "启动端口转发失败: %v", err)
		}
		// 自动放行对账放最后：只增删 dnet- 前缀的 uci 规则，失败不影响转发。
		// 先同步端口转发的期望集合，再追加 Web 服务的放行端口。
		forward.SyncFirewall(conf.ForwardAutoFirewall, conf.ActiveForwardRules())
		forward.SetExtraFirewallPorts(webservice.FirewallPorts(conf.WebAutoFirewall && conf.WebServiceEnabled, conf.WebServiceRules))
	}
	if !*noWebService {
		go func() {
			// 启动web服务
			err := runWebServer()
			if err != nil {
				helper.Error(helper.LogTypeSystem, "启动web服务失败: %v\n", err)
				time.Sleep(time.Minute)
				os.Exit(1)
			}
		}()
	}

	ctx, cancel := context.WithTimeout(shutdown, time.Minute)
	if err := helper.WaitInternet(ctx, *customDNS); err != nil {
		helper.Warn(helper.LogTypeNetwork, "等待网络连接未成功，将继续启动同步任务并由后续周期重试: %v", err)
	}
	cancel()

	if shutdown.Err() != nil {
		return
	}
	go syncRunner.RunTimer(intervalProvider())
	<-shutdown.Done()
}

// recordCLIOverrides 将 CLI 显式传入的调优参数写入环境变量，
// 供 bootstrap / web 判断"此字段是否被命令行锁定"。
// 环境变量存在 = 已锁定；值 = CLI 传入的生效值。
func recordCLIOverrides() {
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "f":
			os.Setenv(config.CLIEveryENV, strconv.Itoa(*every))
		case "dcdnCacheTimes":
			os.Setenv(config.CLIDCDNCacheTimesENV, strconv.Itoa(*dcdnCacheTimes))
		case "ddnsCacheTimes":
			os.Setenv(config.CLIDDNSCacheTimesENV, strconv.Itoa(*ddnsCacheTimes))
		}
	})
}

// intervalProvider 返回一个闭包，每次调用会重新计算同步间隔：
//   - 若 CLI 显式传入 -f，则始终使用该值（用户主动覆盖）
//   - 否则读取配置文件里的 every 字段（>0 生效，支持 Web UI 热更新）
//   - 都不满足则回退到 -f 的默认值 300
func intervalProvider() func() time.Duration {
	explicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "f" {
			explicit = true
		}
	})
	fallback := time.Duration(*every) * time.Second
	return func() time.Duration {
		if explicit {
			return fallback
		}
		if conf, err := configRepo.Load(); err == nil && conf.Every > 0 {
			return time.Duration(conf.Every) * time.Second
		}
		return fallback
	}
}

// program 实现 service.Interface 接口
type program struct{}

func (p *program) Start(s service.Service) error {
	// Start 不应该阻塞，异步执行实际工作
	go p.run()
	return nil
}

func (p *program) run() {
	run()
}

func (p *program) Stop(s service.Service) error {
	webServiceManager.Close()
	forwardManager.Close()
	// Stop 应该快速返回
	return nil
}

// getService 获取服务配置
func getService() service.Service {
	options := make(service.KeyValue)
	var depends []string

	// 确保服务等待网络就绪后再启动
	switch service.ChosenSystem().String() {
	case "unix-systemv":
		// System V init 脚本配置
		options["SysvScript"] = sysvScript
		options["UserService"] = false
	case "unix-upstart":
		// Upstart 配置
		options["UserService"] = false
	case "linux-systemd":
		// Systemd 配置
		depends = append(depends,
			"Requires=network.target",
			"After=network-online.target syslog.target")
		// 失败时自动重启
		options["Restart"] = "on-failure"
		// 启动失败重试间隔
		options["RestartSec"] = 10
		// 文件描述符限制
		options["LimitNOFILE"] = 65536
	case "darwin-launchd":
		// macOS LaunchDaemon 配置
		options["KeepAlive"] = true
		options["RunAtLoad"] = true
		options["UserService"] = false
	case "windows-service":
		// 将 Windows 服务的启动类型设为自动(延迟启动)
		options["DelayedAutoStart"] = true
		// 失败时自动重启
		options["OnFailure"] = "restart"
		// 延迟启动失败时重试间隔
		options["OnFailureDelayDuration"] = "10s"
		options["OnFailureResetPeriod"] = 60
	default:
		// 默认 Systemd 配置
		depends = append(depends,
			"Requires=network.target",
			"After=network-online.target")
	}

	svcConfig := &service.Config{
		Name:         "dnet",
		DisplayName:  "D-NET Service",
		Description:  "D-NET - Dynamic Network Management System",
		Arguments:    []string{"-l", *listen, "-c", *configFilePath},
		Dependencies: depends,
		Option:       options,
	}

	// 非 Web 运行
	if *noWebService {
		svcConfig.Arguments = append(svcConfig.Arguments, "-noweb")
	}
	// 添加 DNS 配置参数
	if *customDNS != "" {
		svcConfig.Arguments = append(svcConfig.Arguments, "-dns", *customDNS)
	}
	// 跳过 HTTPS 证书验证
	if *skipVerify {
		svcConfig.Arguments = append(svcConfig.Arguments, "-skipVerify")
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		helper.Fatalf(helper.LogTypeSystem, "创建系统服务失败: %v", err)
	}
	return s
}

// installService 使用service库安装系统服务
func installService() {
	helper.Info(helper.LogTypeSystem, "正在安装 D-NET 系统服务...")

	s := getService()
	status, err := s.Status()
	if err != nil && status == service.StatusUnknown {
		// 服务未知，创建服务
		if err = s.Install(); err == nil {
			if startErr := s.Start(); startErr != nil {
				helper.Error(helper.LogTypeSystem, "服务安装成功但启动失败: %v", startErr)
			}
			helper.Info(helper.LogTypeSystem, "安装 D-NET 服务成功! 请打开浏览器并进行配置")

			// System V init 系统需要额外配置开机自启
			if service.ChosenSystem().String() == "unix-systemv" {
				serviceName := "dnet"
				// 尝试使用 update-rc.d (Debian/Ubuntu)
				if _, err := exec.LookPath("update-rc.d"); err == nil {
					if out, err := exec.Command("update-rc.d", serviceName, "defaults").CombinedOutput(); err != nil {
						helper.Error(helper.LogTypeSystem, "update-rc.d 配置失败: %v, 输出: %s", err, out)
					} else {
						helper.Info(helper.LogTypeSystem, "已配置开机自启 (update-rc.d)")
					}
				} else if _, err := exec.LookPath("chkconfig"); err == nil {
					// 尝试使用 chkconfig (RedHat/CentOS)
					if out, err := exec.Command("chkconfig", "--add", serviceName).CombinedOutput(); err != nil {
						helper.Error(helper.LogTypeSystem, "chkconfig --add 失败: %v, 输出: %s", err, out)
					} else {
						if out, err := exec.Command("chkconfig", serviceName, "on").CombinedOutput(); err != nil {
							helper.Error(helper.LogTypeSystem, "chkconfig on 失败: %v, 输出: %s", err, out)
						} else {
							helper.Info(helper.LogTypeSystem, "已配置开机自启 (chkconfig)")
						}
					}
				}
			}
			return
		}
		helper.Error(helper.LogTypeSystem, "安装 D-NET 服务失败, 异常信息: %v", err)
	}

	if status != service.StatusUnknown {
		helper.Info(helper.LogTypeSystem, "D-NET 服务已安装, 无需再次安装")
	}
}

// uninstallService 使用 service 库卸载系统服务
func uninstallService() {
	helper.Info(helper.LogTypeSystem, "正在卸载 D-NET 系统服务...")

	s := getService()
	if stopErr := s.Stop(); stopErr != nil {
		helper.Warn(helper.LogTypeSystem, "停止服务时出现警告: %v", stopErr)
	}

	// System V init 系统需要额外清理
	if service.ChosenSystem().String() == "unix-systemv" {
		serviceName := "dnet"
		// 尝试使用 update-rc.d 移除 (Debian/Ubuntu)
		if _, err := exec.LookPath("update-rc.d"); err == nil {
			if out, err := exec.Command("update-rc.d", "-f", serviceName, "remove").CombinedOutput(); err != nil {
				helper.Error(helper.LogTypeSystem, "update-rc.d remove 失败: %v, 输出: %s", err, out)
			}
		} else if _, err := exec.LookPath("chkconfig"); err == nil {
			// 尝试使用 chkconfig 移除 (RedHat/CentOS)
			if out, err := exec.Command("chkconfig", "--del", serviceName).CombinedOutput(); err != nil {
				helper.Error(helper.LogTypeSystem, "chkconfig --del 失败: %v, 输出: %s", err, out)
			}
		}
	}

	if err := s.Uninstall(); err != nil {
		helper.Fatal(helper.LogTypeSystem, "D-NET 服务卸载失败: %v", err)
	}
	helper.Info(helper.LogTypeSystem, "D-NET 服务卸载成功")
}

// restartService 使用service库重启系统服务
func restartService() {
	helper.Info(helper.LogTypeSystem, "正在重启 D-NET 系统服务...")

	s := getService()
	status, err := s.Status()
	if err != nil {
		helper.Fatal(helper.LogTypeSystem, "D-NET 服务未安装, 请先安装服务")
	}

	switch status {
	case service.StatusRunning:
		// 服务正在运行，执行重启
		if err = s.Restart(); err != nil {
			helper.Fatal(helper.LogTypeSystem, "D-NET 服务重启失败: %v", err)
		}
		helper.Info(helper.LogTypeSystem, "D-NET 服务重启成功")
	case service.StatusStopped:
		// 服务已停止，执行启动
		if err = s.Start(); err != nil {
			helper.Fatal(helper.LogTypeSystem, "D-NET 服务启动失败: %v", err)
		}
		helper.Info(helper.LogTypeSystem, "D-NET 服务启动成功")
	default:
		helper.Fatal(helper.LogTypeSystem, "D-NET 服务状态未知: %v", status)
	}
}

// sysvScript 定义 System V init 脚本模板
const sysvScript = `#!/bin/sh
### BEGIN INIT INFO
# Provides:          {{.Name}}
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: {{.DisplayName}}
# Description:       {{.Description}}
### END INIT INFO

cmd="{{.Path}}{{range .Arguments}} {{.}}{{end}}"

name=$(basename $(readlink -f $0))
pid_file="/var/run/$name.pid"
stdout_log="/var/log/$name.log"
stderr_log="/var/log/$name.err"

get_pid() {
    cat "$pid_file"
}

is_running() {
    [ -f "$pid_file" ] && ps -p $(get_pid) > /dev/null 2>&1
}

case "$1" in
    start)
        if is_running; then
            echo "Already started"
        else
            echo "Starting $name"
            $cmd >> "$stdout_log" 2>> "$stderr_log" &
            echo $! > "$pid_file"
        fi
        ;;
    stop)
        if is_running; then
            echo "Stopping $name"
            kill $(get_pid)
            rm -f "$pid_file"
        else
            echo "Not running"
        fi
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        if is_running; then
            echo "Running"
        else
            echo "Stopped"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
`

// https://github.com/creativeprojects/go-selfupdate
// updateDNET 更新 D-NET 到最新版本
func updateDNET() {
	if err := update.CheckAndUpdate(version, false); err != nil {
		helper.Fatalf(helper.LogTypeSystem, "更新过程出错: %v", err)
	}
}
