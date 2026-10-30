package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// 字段级加密：只加密配置里的密钥类字段，其余字段保持明文可读，便于排障。
//
// 存储格式：enc:v1:<base64url(nonce || AES-256-GCM 密文)>，密钥由主密钥经
// HKDF-SHA256 派生。主密钥来源优先级：
//
//  1. 环境变量 DNET_SECRET_KEY（十六进制、base64，或 32 字节原文）
//  2. 环境变量 DNET_SECRET_KEY_FILE 指向的文件
//  3. 配置文件同目录下的 master.key（路由器上是 /etc/dnet/master.key）
//
// 没有主密钥时保持明文（向后兼容）；一旦配置里出现密文而没有主密钥，
// 加载会直接报错，绝不把密文当明文用。
const (
	// SecretPrefix 标记一个字段已被加密。
	SecretPrefix = "enc:v1:"
	// SecretKeyENV 直接提供主密钥。
	SecretKeyENV = "DNET_SECRET_KEY"
	// SecretKeyFileENV 指定主密钥文件路径。
	SecretKeyFileENV = "DNET_SECRET_KEY_FILE"
	// SecretKeyFileName 是配置文件同目录下的默认主密钥文件名。
	SecretKeyFileName = "master.key"

	secretKeySize  = 32
	secretHKDFInfo = "dnet-config-secrets-v1"
)

var (
	// ErrNoSecretKey 表示没有配置主密钥。
	ErrNoSecretKey = errors.New("未配置主密钥")
	// ErrBadSecretKey 表示主密钥格式不正确。
	ErrBadSecretKey = errors.New("主密钥格式无效（需要 32 字节：64 位十六进制、base64 或 32 字节原文）")
	// ErrSecretDecrypt 表示密文无法解密（主密钥不匹配或数据损坏）。
	ErrSecretDecrypt = errors.New("配置解密失败")

	secretKeyMu     sync.Mutex
	secretKeyLoaded bool
	secretKeyBytes  []byte
	secretKeyOrigin string
	secretKeyErr    error
)

// SecretKeyPath 返回默认主密钥文件路径（与配置文件同目录）。
func SecretKeyPath() string {
	if p := strings.TrimSpace(os.Getenv(SecretKeyFileENV)); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(GetConfigFilePath()), SecretKeyFileName)
}

// ResetSecretKeyCache 清空主密钥缓存，测试和 CLI 切换密钥时使用。
func ResetSecretKeyCache() {
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	secretKeyLoaded = false
	secretKeyBytes = nil
	secretKeyOrigin = ""
	secretKeyErr = nil
}

// SecretKeySource 返回主密钥来源（人类可读）以及是否存在可用主密钥。
func SecretKeySource() (string, bool) {
	_, err := loadSecretKey()
	if err != nil {
		return "", false
	}
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	return secretKeyOrigin, true
}

func loadSecretKey() ([]byte, error) {
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	if secretKeyLoaded {
		return secretKeyBytes, secretKeyErr
	}
	secretKeyLoaded = true

	if raw := strings.TrimSpace(os.Getenv(SecretKeyENV)); raw != "" {
		key, err := parseSecretKey(raw)
		if err != nil {
			secretKeyErr = fmt.Errorf("%w（来源：环境变量 %s）", err, SecretKeyENV)
			return nil, secretKeyErr
		}
		secretKeyBytes, secretKeyOrigin = key, "环境变量 "+SecretKeyENV
		return secretKeyBytes, nil
	}

	path := SecretKeyPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			secretKeyErr = fmt.Errorf("%w：请运行 dnet -secret init 生成 %s，或设置 %s", ErrNoSecretKey, path, SecretKeyENV)
		} else {
			secretKeyErr = fmt.Errorf("%w：读取主密钥文件 %s 失败: %v", ErrNoSecretKey, path, err)
		}
		return nil, secretKeyErr
	}
	key, err := parseSecretKey(string(data))
	if err != nil {
		secretKeyErr = fmt.Errorf("%w（来源：%s）", err, path)
		return nil, secretKeyErr
	}
	secretKeyBytes, secretKeyOrigin = key, "文件 "+path
	return secretKeyBytes, nil
}

func parseSecretKey(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, ErrBadSecretKey
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == secretKeySize {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == secretKeySize {
			return b, nil
		}
	}
	if len(s) == secretKeySize {
		return []byte(s), nil
	}
	return nil, ErrBadSecretKey
}

// deriveSecretKey 用 HKDF-SHA256（extract + expand）从主密钥派生加密密钥。
func deriveSecretKey(master []byte) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(master)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(secretHKDFInfo))
	expand.Write([]byte{0x01})
	return expand.Sum(nil)
}

// IsEncrypted 判断字段值是否是密文。
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, SecretPrefix)
}

// EncryptSecret 加密一个字段；空值和已加密的值原样返回。
func EncryptSecret(plain string) (string, error) {
	if plain == "" || IsEncrypted(plain) {
		return plain, nil
	}
	master, err := loadSecretKey()
	if err != nil {
		return "", err
	}
	aead, err := newSecretAEAD(master)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	sealed := aead.Seal(nil, nonce, []byte(plain), []byte(secretHKDFInfo))
	return SecretPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptSecret 解密一个字段；明文原样返回。
func DecryptSecret(stored string) (string, error) {
	if stored == "" || !IsEncrypted(stored) {
		return stored, nil
	}
	master, err := loadSecretKey()
	if err != nil {
		return "", err
	}
	aead, err := newSecretAEAD(master)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(stored, SecretPrefix))
	if err != nil || len(raw) < aead.NonceSize() {
		return "", fmt.Errorf("%w：密文格式损坏", ErrSecretDecrypt)
	}
	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(secretHKDFInfo))
	if err != nil {
		return "", fmt.Errorf("%w：主密钥不匹配或密文被篡改", ErrSecretDecrypt)
	}
	return string(plain), nil
}

// IsSecretError 判断错误是否属于「配置加解密」类问题，这类错误必须阻止启动。
func IsSecretError(err error) bool {
	return errors.Is(err, ErrNoSecretKey) || errors.Is(err, ErrBadSecretKey) || errors.Is(err, ErrSecretDecrypt)
}

func newSecretAEAD(master []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveSecretKey(master))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// secretFields 列出配置里所有需要加密的字段。
// 这里显式罗列而不做反射遍历：新增敏感字段时必须手动加进来，避免误伤普通字段。
func (conf *Config) secretFields() []*string {
	fields := make([]*string, 0, 24)
	for i := range conf.Certificates {
		c := &conf.Certificates[i]
		fields = append(fields, &c.AccessKey, &c.APIToken, &c.AccountKey, &c.EABHMACKey, &c.KeyPEM)
	}
	for i := range conf.DCDNConfig.Credentials {
		cred := &conf.DCDNConfig.Credentials[i]
		fields = append(fields, &cred.AccessKey, &cred.AccessSecret)
	}
	for i := range conf.DDNSConfig.Credentials {
		cred := &conf.DDNSConfig.Credentials[i]
		fields = append(fields, &cred.AccessKey, &cred.AccessSecret)
	}
	for i := range conf.DCDNConfig.DCDN {
		cdn := &conf.DCDNConfig.DCDN[i]
		fields = append(fields, &cdn.AccessKey, &cdn.AccessSecret)
	}
	for i := range conf.DDNSConfig.DDNS {
		group := &conf.DDNSConfig.DDNS[i]
		fields = append(fields, &group.AccessKey, &group.AccessSecret)
	}
	fields = append(fields, &conf.WebhookURL, &conf.WebhookHeaders)
	return fields
}

// EncryptSecrets 就地加密配置里的敏感字段。
func (conf *Config) EncryptSecrets() error {
	for _, field := range conf.secretFields() {
		value, err := EncryptSecret(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

// DecryptSecrets 就地解密配置里的敏感字段。
func (conf *Config) DecryptSecrets() error {
	for _, field := range conf.secretFields() {
		value, err := DecryptSecret(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

// SecretStats 统计配置里已加密/仍明文的敏感字段数量（不看字段值本身）。
func (conf *Config) SecretStats() (encrypted, plain int) {
	for _, field := range conf.secretFields() {
		if *field == "" {
			continue
		}
		if IsEncrypted(*field) {
			encrypted++
		} else {
			plain++
		}
	}
	return encrypted, plain
}

// LoadConfigFile 读取并反序列化配置文件，不做解密（供 dnet -secret 迁移使用）。
func LoadConfigFile(path string) (Config, error) {
	var conf Config
	data, err := os.ReadFile(path)
	if err != nil {
		return conf, err
	}
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return conf, err
	}
	return conf, nil
}

// SaveConfigFile 原子写入配置文件（0600），供 dnet -secret 迁移使用。
func SaveConfigFile(path string, conf *Config) error {
	data, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	return savePrivateConfig(path, data)
}

// GenerateSecretKey 生成一个新的 32 字节主密钥（十六进制）。
func GenerateSecretKey() (string, error) {
	buf := make([]byte, secretKeySize)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// WriteSecretKeyFile 把主密钥写入文件（0600），已存在则报错，避免覆盖导致旧密文永久解不开。
func WriteSecretKeyFile(path, key string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("主密钥文件已存在: %s（如需轮换请先备份，再删除后重新生成）", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil && !os.IsExist(err) {
		return err
	}
	return os.WriteFile(path, []byte(key+"\n"), 0600)
}
