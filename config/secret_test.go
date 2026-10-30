package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cxbdasheng/dnet/certificates"
	"gopkg.in/yaml.v3"
)

const testSecretKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func useTestSecretKey(t *testing.T, key string) {
	t.Helper()
	if key == "" {
		t.Setenv(SecretKeyENV, "")
		t.Setenv(SecretKeyFileENV, filepath.Join(t.TempDir(), "absent.key"))
	} else {
		t.Setenv(SecretKeyENV, key)
		t.Setenv(SecretKeyFileENV, "")
	}
	ResetSecretKeyCache()
	t.Cleanup(ResetSecretKeyCache)
}

func TestSecretRoundTrip(t *testing.T) {
	useTestSecretKey(t, testSecretKeyHex)

	stored, err := EncryptSecret("LTAI5t-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(stored) {
		t.Fatalf("stored value not marked encrypted: %q", stored)
	}
	if strings.Contains(stored, "LTAI5t") {
		t.Fatal("ciphertext leaks plaintext")
	}
	plain, err := DecryptSecret(stored)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "LTAI5t-secret-token" {
		t.Fatalf("round trip mismatch: %q", plain)
	}

	// 空值、明文、已加密值都不应被重复处理。
	if v, err := EncryptSecret(""); err != nil || v != "" {
		t.Fatalf("empty encrypt = %q, %v", v, err)
	}
	if v, err := EncryptSecret(stored); err != nil || v != stored {
		t.Fatalf("double encrypt changed value: %q, %v", v, err)
	}
	if v, err := DecryptSecret("plain-token"); err != nil || v != "plain-token" {
		t.Fatalf("plain decrypt = %q, %v", v, err)
	}
	if v, err := DecryptSecret(""); err != nil || v != "" {
		t.Fatalf("empty decrypt = %q, %v", v, err)
	}

	// 每次加密 nonce 不同，密文不能相同。
	other, err := EncryptSecret("LTAI5t-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if other == stored {
		t.Fatal("encryption reused nonce")
	}
}

func TestSecretNoKeyKeepsPlaintextButRejectsCiphertext(t *testing.T) {
	useTestSecretKey(t, testSecretKeyHex)
	stored, err := EncryptSecret("top-secret")
	if err != nil {
		t.Fatal(err)
	}

	useTestSecretKey(t, "")
	if _, err := EncryptSecret("top-secret"); !errors.Is(err, ErrNoSecretKey) {
		t.Fatalf("want ErrNoSecretKey, got %v", err)
	}
	if _, err := DecryptSecret(stored); err == nil || !IsSecretError(err) {
		t.Fatalf("ciphertext without key must fail: %v", err)
	}
	if v, err := DecryptSecret("still-plain"); err != nil || v != "still-plain" {
		t.Fatalf("plaintext must pass through: %q, %v", v, err)
	}
}

func TestSecretWrongKeyFails(t *testing.T) {
	useTestSecretKey(t, testSecretKeyHex)
	stored, err := EncryptSecret("top-secret")
	if err != nil {
		t.Fatal(err)
	}

	useTestSecretKey(t, strings.Repeat("ab", 32))
	if _, err := DecryptSecret(stored); !errors.Is(err, ErrSecretDecrypt) {
		t.Fatalf("want ErrSecretDecrypt, got %v", err)
	}
}

func TestSecretKeyFromFileAndFormats(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, SecretKeyFileName)
	useTestSecretKey(t, "")
	t.Setenv(SecretKeyFileENV, keyPath)

	// 文件里可以带换行、可以是 base64。
	if err := WriteSecretKeyFile(keyPath, testSecretKeyHex); err != nil {
		t.Fatal(err)
	}
	ResetSecretKeyCache()
	if src, ok := SecretKeySource(); !ok || !strings.Contains(src, keyPath) {
		t.Fatalf("key source = %q, %v", src, ok)
	}
	info, err := os.Stat(keyPath)
	if err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("key file perm = %v", info.Mode().Perm())
	}

	if err := WriteSecretKeyFile(keyPath, testSecretKeyHex); err == nil {
		t.Fatal("must not overwrite an existing key file")
	}

	t.Setenv(SecretKeyENV, "not-a-valid-key")
	ResetSecretKeyCache()
	if _, err := EncryptSecret("x"); !errors.Is(err, ErrBadSecretKey) {
		t.Fatalf("want ErrBadSecretKey, got %v", err)
	}
}

func sampleSecretConfig() Config {
	return Config{
		Certificates: []certificates.Certificate{{
			ID:         "cert1",
			AccessKey:  "LTAI-cert-ak",
			APIToken:   "aliyun-api-token",
			AccountKey: "-----BEGIN PRIVATE KEY-----\nACME\n-----END PRIVATE KEY-----",
			EABHMACKey: "eab-hmac",
			KeyPEM:     "-----BEGIN CERTIFICATE-----\nKEY\n-----END CERTIFICATE-----",
			CertPEM:    "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----",
		}},
		DCDNConfig: DCDNConfig{
			DCDN:        []CDN{{ID: "cdn1", AccessKey: "cdn-ak", AccessSecret: "cdn-sk"}},
			Credentials: []DNSCredential{{Service: "aliyun", AccessKey: "g-ak", AccessSecret: "g-sk"}},
		},
		DDNSConfig: DDNSConfig{
			DDNS:        []DNSGroup{{ID: "dns1", AccessKey: "dns-ak", AccessSecret: "dns-sk"}},
			Credentials: []DNSCredential{{Service: "cloudflare", AccessKey: "cf-token", AccessSecret: "cf-secret"}},
		},
		Webhook: Webhook{WebhookURL: "https://hook.example.com/?token=abc", WebhookHeaders: `{"Authorization":"Bearer xyz"}`},
	}
}

func TestConfigSecretsAreEncryptedAtRest(t *testing.T) {
	useTestSecretKey(t, testSecretKeyHex)
	conf := sampleSecretConfig()

	if err := conf.EncryptSecrets(); err != nil {
		t.Fatal(err)
	}
	encrypted, plain := conf.SecretStats()
	if encrypted != 15 || plain != 0 {
		t.Fatalf("stats = %d encrypted, %d plain", encrypted, plain)
	}

	data, err := yaml.Marshal(&conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"LTAI-cert-ak", "aliyun-api-token", "ACME", "cdn-sk", "g-sk", "dns-sk", "cf-token", "token=abc", "Bearer xyz"} {
		if strings.Contains(string(data), leak) {
			t.Fatalf("yaml still contains %q:\n%s", leak, data)
		}
	}
	if !strings.Contains(string(data), SecretPrefix) {
		t.Fatal("yaml does not contain encrypted marker")
	}
	// 非敏感字段必须保持可读，方便排障。
	if !strings.Contains(string(data), "PUBLIC") {
		t.Fatal("public certificate must stay readable")
	}

	var restored Config
	if err := yaml.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.DecryptSecrets(); err != nil {
		t.Fatal(err)
	}
	if restored.Certificates[0].AccessKey != "LTAI-cert-ak" ||
		restored.Certificates[0].AccountKey != "-----BEGIN PRIVATE KEY-----\nACME\n-----END PRIVATE KEY-----" ||
		restored.DDNS[0].AccessSecret != "dns-sk" ||
		restored.WebhookHeaders != `{"Authorization":"Bearer xyz"}` {
		t.Fatalf("decrypted config mismatch: %+v", restored)
	}
}

func TestSaveConfigEncryptsAndLoadDecrypts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dnet_config.yaml")
	t.Setenv(PathENV, path)
	t.Setenv(SecretKeyFileENV, filepath.Join(dir, SecretKeyFileName))
	ResetSecretKeyCache()
	t.Cleanup(func() {
		ResetSecretKeyCache()
		globalCache = &ConfigCache{}
	})

	key, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretKeyFile(filepath.Join(dir, SecretKeyFileName), key); err != nil {
		t.Fatal(err)
	}

	conf := sampleSecretConfig()
	if err := conf.SaveConfig(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "LTAI-cert-ak") || strings.Contains(string(raw), "dns-sk") {
		t.Fatalf("plaintext secret written to disk:\n%s", raw)
	}
	info, err := os.Stat(path)
	if err == nil && runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("config perm = %v", info.Mode().Perm())
	}

	// 内存里的配置不能被加密污染。
	if conf.Certificates[0].AccessKey != "LTAI-cert-ak" {
		t.Fatalf("SaveConfig mutated caller: %q", conf.Certificates[0].AccessKey)
	}

	globalCache = &ConfigCache{}
	loaded, err := GetConfigCached()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DDNS[0].AccessSecret != "dns-sk" || loaded.Certificates[0].APIToken != "aliyun-api-token" {
		t.Fatalf("loaded config not decrypted: %+v", loaded.DDNS)
	}
}

func TestLoadConfigFailsWithoutKeyWhenEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dnet_config.yaml")
	t.Setenv(PathENV, path)
	useTestSecretKey(t, testSecretKeyHex)
	t.Cleanup(func() { globalCache = &ConfigCache{} })

	conf := sampleSecretConfig()
	if err := conf.EncryptSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfigFile(path, &conf); err != nil {
		t.Fatal(err)
	}

	// 换成一个不存在的密钥文件：必须报错而不是把密文当明文。
	t.Setenv(SecretKeyENV, "")
	t.Setenv(SecretKeyFileENV, filepath.Join(dir, "absent.key"))
	ResetSecretKeyCache()
	globalCache = &ConfigCache{}
	if _, err := GetConfigCached(); err == nil || !IsSecretError(err) {
		t.Fatalf("want secret error, got %v", err)
	}
}
