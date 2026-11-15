package waf

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// useStatePath 把持久化指向临时文件，并在用例结束后恢复纯内存模式。
func useStatePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "waf_state.json")
	statePath = path
	t.Cleanup(func() {
		statePath = ""
		stateDirty.Store(false)
	})
	return path
}

func TestStatePersistsStats(t *testing.T) {
	resetStatsForTest()
	t.Cleanup(resetStatsForTest)
	useStatePath(t)

	Record(BlockEvent{Site: "weknora", IP: "203.0.113.77", Method: "POST", Path: "/api/v1/agent-chat", RuleID: 932260, Rules: "932260", Status: 403})
	Record(BlockEvent{Site: "weknora", IP: "203.0.113.77", Method: "GET", Path: "/web", RuleID: 942100, Rules: "942100", Status: 403})
	Record(BlockEvent{Site: "dsm", IP: "203.0.113.78", Method: "GET", Path: "/", RuleID: 941100, Rules: "941100", Status: 403})

	before := Snapshot()
	if err := saveState(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 模拟进程重启：内存清零后重新加载。
	resetStatsForTest()
	if got := Snapshot(); got.Total != 0 {
		t.Fatalf("重置后总数应为 0，实际 %d", got.Total)
	}
	if err := loadState(); err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	after := Snapshot()
	if after.Total != before.Total {
		t.Fatalf("总数 = %d，期望 %d", after.Total, before.Total)
	}
	if after.UniqueIPs != before.UniqueIPs {
		t.Fatalf("来源数 = %d，期望 %d", after.UniqueIPs, before.UniqueIPs)
	}
	if len(after.Recent) != len(before.Recent) {
		t.Fatalf("明细数 = %d，期望 %d", len(after.Recent), len(before.Recent))
	}
	if after.Since.IsZero() {
		t.Fatal("起始时间未恢复")
	}
	if len(after.Sites) != 2 {
		t.Fatalf("按站点聚合 = %+v", after.Sites)
	}
	// 明细按时间倒序，最新一条应是最后记录的。
	if len(after.Recent) > 0 && after.Recent[0].IP != "203.0.113.78" {
		t.Fatalf("最新明细 = %+v", after.Recent[0])
	}
}

func TestStatePersistsBans(t *testing.T) {
	resetGuardForTest()
	t.Cleanup(resetGuardForTest)
	useStatePath(t)
	ConfigureGuard(GuardSettings{BanEnabled: true, Threshold: 1, Window: time.Minute, BanFor: time.Hour, Burst: 100})

	ip := "198.51.100.77"
	if banned, _ := RecordBlock(ip); !banned {
		t.Fatal("应当触发封禁")
	}
	if err := saveState(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 模拟重启：封禁表清空后从文件恢复。
	Unban(ip)
	if len(Bans()) != 0 {
		t.Fatal("解封后不应还有记录")
	}
	if err := loadState(); err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	bans := Bans()
	if len(bans) != 1 || bans[0].IP != ip {
		t.Fatalf("封禁未恢复: %+v", bans)
	}
}

func TestLoadStateRejectsGarbage(t *testing.T) {
	resetStatsForTest()
	t.Cleanup(resetStatsForTest)
	path := useStatePath(t)

	if err := os.WriteFile(path, []byte("这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadState(); err == nil {
		t.Fatal("损坏的文件应当报错")
	}
	if got := Snapshot().Total; got != 0 {
		t.Fatalf("加载失败后不应改动内存，总数 = %d", got)
	}
}

func TestLoadStateDropsExpiredBans(t *testing.T) {
	resetGuardForTest()
	resetStatsForTest()
	t.Cleanup(resetGuardForTest)
	t.Cleanup(resetStatsForTest)
	path := useStatePath(t)

	content := `{"version":1,"bans":[{"ip":"198.51.100.88","until":"2000-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadState(); err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if bans := Bans(); len(bans) != 0 {
		t.Fatalf("过期封禁应被丢弃: %+v", bans)
	}
}

func TestEnableStatePersistenceWithoutFile(t *testing.T) {
	resetStatsForTest()
	t.Cleanup(resetStatsForTest)
	path := filepath.Join(t.TempDir(), "nested", "waf_state.json")
	statePath = ""
	if err := EnableStatePersistence(path); err != nil {
		t.Fatalf("首次启动不应报错: %v", err)
	}
	t.Cleanup(func() {
		statePath = ""
		stateDirty.Store(false)
	})
	if statePath != path {
		t.Fatalf("路径未生效: %s", statePath)
	}
}
