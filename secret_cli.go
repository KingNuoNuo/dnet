package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cxbdasheng/dnet/config"
)

// runSecretCommand 处理 dnet -secret <init|encrypt|decrypt|status>。
//
// 设计目标：加密只保护「配置文件被看到」这类泄露（备份、网盘、发给别人排障），
// 不防 root / 拆闪存 —— 主密钥就在同一台设备上，这一点必须在文档里说清楚。
func runSecretCommand(mode string) {
	var err error
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "init":
		err = secretInit()
	case "encrypt":
		err = secretEncrypt()
	case "decrypt":
		err = secretDecrypt()
	case "status":
		err = secretStatus()
	default:
		fmt.Fprintf(os.Stderr, "未知的 -secret 子命令: %s\n可用: init / encrypt / decrypt / status\n", mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "失败: %v\n", err)
		os.Exit(1)
	}
}

func secretInit() error {
	if _, err := secretConfigPath(); err != nil {
		return err
	}
	keyPath := config.SecretKeyPath()
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("主密钥已存在: %s\n如需轮换：先用旧密钥执行 dnet -secret decrypt，再备份并删除该文件后重新 init", keyPath)
	}
	key, err := config.GenerateSecretKey()
	if err != nil {
		return err
	}
	if err := config.WriteSecretKeyFile(keyPath, key); err != nil {
		return err
	}
	fmt.Printf("已生成主密钥: %s（权限 0600）\n\n%s\n\n", keyPath, key)
	fmt.Println("请立刻离线备份该文件：丢掉它，配置里已加密的云厂商密钥和 ACME 账号密钥将无法恢复。")
	fmt.Println("之后保存配置会自动加密敏感字段；现有明文可执行 dnet -secret encrypt 就地迁移。")
	return nil
}

func secretEncrypt() error {
	path, err := secretConfigPath()
	if err != nil {
		return err
	}
	conf, err := config.LoadConfigFile(path)
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}
	if _, plain := conf.SecretStats(); plain == 0 {
		fmt.Printf("配置 %s 里的敏感字段已是密文或为空，无需加密\n", path)
		return nil
	}
	if _, ok := config.SecretKeySource(); !ok {
		return fmt.Errorf("未找到主密钥，请先执行 dnet -secret init（或设置 %s）", config.SecretKeyENV)
	}
	backup, err := backupConfigFile(path)
	if err != nil {
		return fmt.Errorf("备份配置失败: %w", err)
	}
	if err := conf.EncryptSecrets(); err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}
	if err := config.SaveConfigFile(path, &conf); err != nil {
		return fmt.Errorf("写回配置失败（明文备份在 %s）: %w", backup, err)
	}
	encrypted, plain := conf.SecretStats()
	fmt.Printf("已加密 %d 个敏感字段（仍有 %d 个为空），原文件备份：%s\n", encrypted, plain, backup)
	return nil
}

func secretDecrypt() error {
	path, err := secretConfigPath()
	if err != nil {
		return err
	}
	conf, err := config.LoadConfigFile(path)
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}
	if encrypted, _ := conf.SecretStats(); encrypted == 0 {
		fmt.Printf("配置 %s 里没有密文字段，无需解密\n", path)
		return nil
	}
	if err := conf.DecryptSecrets(); err != nil {
		return fmt.Errorf("解密失败: %w", err)
	}
	backup, err := backupConfigFile(path)
	if err != nil {
		return fmt.Errorf("备份配置失败: %w", err)
	}
	if err := config.SaveConfigFile(path, &conf); err != nil {
		return fmt.Errorf("写回配置失败: %w", err)
	}
	fmt.Printf("已解密并写回 %s，原文件备份：%s\n", path, backup)
	fmt.Println("警告：现在配置里是明文密钥，适合「换主密钥」的中间步骤，用完请尽快重新加密。")
	return nil
}

func secretStatus() error {
	path, err := secretConfigPath()
	if err != nil {
		return err
	}
	conf, err := config.LoadConfigFile(path)
	if err != nil {
		return fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}
	encrypted, plain := conf.SecretStats()
	source, ok := config.SecretKeySource()
	fmt.Printf("配置文件：%s\n", path)
	fmt.Printf("敏感字段：已加密 %d 个，明文 %d 个，空 %d 个\n", encrypted, plain, countEmptySecrets(&conf))
	if ok {
		fmt.Printf("主密钥：%s\n", source)
	} else {
		fmt.Printf("主密钥：未配置（默认路径 %s）\n", config.SecretKeyPath())
	}
	switch {
	case encrypted > 0 && !ok:
		fmt.Println("警告：配置里有密文但没有可用主密钥，dnet 会拒绝启动。")
	case plain > 0:
		fmt.Println("提示：执行 dnet -secret encrypt 可把明文密钥就地加密。")
	case ok && encrypted > 0:
		fmt.Println("状态：已加密。")
	}
	return nil
}

func countEmptySecrets(conf *config.Config) int {
	// SecretStats 会把空字段跳过，这里用总数反推，避免再暴露一份字段清单。
	// 简化处理：只在 status 里展示，不追求精确到个位。
	encrypted, plain := conf.SecretStats()
	total := len(conf.Certificates)*5 +
		len(conf.DCDNConfig.Credentials)*2 + len(conf.DDNSConfig.Credentials)*2 +
		len(conf.DCDNConfig.DCDN)*2 + len(conf.DDNSConfig.DDNS)*2 + 2
	return total - encrypted - plain
}

// secretConfigPath 返回配置文件路径，并给出「找不到文件」时的可操作提示。
// 服务通常用 -c 指定配置（OpenWrt 上是 /etc/dnet/.dnet_config.yaml），
// -secret 命令必须用同一个 -c，否则主密钥会生成到别的目录。
func secretConfigPath() (string, error) {
	path := config.GetConfigFilePath()
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("找不到配置文件 %s\n如果服务用 -c 指定了配置路径，请对 -secret 命令加同样的 -c 参数（OpenWrt 常见：-c /etc/dnet/.dnet_config.yaml）", path)
	}
	return path, nil
}

func backupConfigFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := fmt.Sprintf("%s.bak.%s", path, time.Now().Format("20060102-150405"))
	if err := os.WriteFile(backup, data, 0600); err != nil {
		return "", err
	}
	return backup, nil
}
