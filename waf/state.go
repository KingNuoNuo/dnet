package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cxbdasheng/dnet/helper"
)

// stateVersion 是状态文件的格式版本。字段不兼容时直接丢弃旧文件，
// 避免升级后读到对不上的结构。
const stateVersion = 1

// stateSaveInterval 是刷盘间隔。拦截通常成批到来，按间隔合并写入：
// 既不丢记录，也不会每个请求都写一次闪存。
const stateSaveInterval = 5 * time.Second

// stateFile 是 WAF 运行时状态的落盘格式：拦截统计 + 临时封禁。
type stateFile struct {
	Version int              `json:"version"`
	SavedAt time.Time        `json:"saved_at"`
	Since   time.Time        `json:"since"`
	Total   int64            `json:"total"`
	BySite  map[string]int64 `json:"by_site"`
	IPs     []IPStat         `json:"ips"`
	Recent  []BlockEvent     `json:"recent"`
	Bans    []Ban            `json:"bans"`
}

var (
	statePath   string
	stateSaveMu sync.Mutex
	stateDirty  atomic.Bool
	stateOnce   sync.Once
	stateWarnMu sync.Mutex
	stateWarnAt time.Time
)

// EnableStatePersistence 从 path 恢复上次运行留下的拦截统计与临时封禁，
// 并启动后台刷盘。path 为空表示不做持久化（保持纯内存）。
func EnableStatePersistence(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	statePath = path
	if err := loadState(); err != nil {
		if os.IsNotExist(err) {
			// 第一次运行，没有历史记录，属于正常情况。
			startStateSaver()
			return nil
		}
		return err
	}
	startStateSaver()
	return nil
}

// markStateDirty 标记有改动待落盘。未启用持久化时是空操作。
func markStateDirty() {
	if statePath != "" {
		stateDirty.Store(true)
	}
}

// FlushState 立即把待写入的状态刷到磁盘，供进程退出前调用，
// 避免重启丢掉最后一个刷盘间隔内的记录。
func FlushState() {
	if statePath == "" || !stateDirty.Load() {
		return
	}
	if err := saveState(); err != nil {
		warnSaveFailure(err)
		return
	}
	stateDirty.Store(false)
}

func startStateSaver() {
	stateOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(stateSaveInterval)
			defer ticker.Stop()
			for range ticker.C {
				if !stateDirty.Load() {
					continue
				}
				if err := saveState(); err != nil {
					warnSaveFailure(err)
					continue
				}
				// 用 Load + Store 而不是 Swap：写入期间新到的拦截要保留 dirty。
				stateDirty.Store(false)
			}
		}()
	})
}

// saveState 把当前统计与封禁原子写入磁盘（先写临时文件再改名）。
func saveState() error {
	if statePath == "" {
		return nil
	}
	stateSaveMu.Lock()
	defer stateSaveMu.Unlock()

	state := stateFile{Version: stateVersion, SavedAt: time.Now()}

	blockStats.Lock()
	state.Since = blockStats.since
	state.Total = blockStats.total
	state.BySite = make(map[string]int64, len(blockStats.bySite))
	for site, count := range blockStats.bySite {
		state.BySite[site] = count
	}
	state.IPs = make([]IPStat, 0, len(blockStats.ips))
	for _, stat := range blockStats.ips {
		state.IPs = append(state.IPs, *stat)
	}
	state.Recent = append([]BlockEvent(nil), blockStats.recent...)
	blockStats.Unlock()

	now := time.Now()
	guardState.Lock()
	for _, ban := range guardState.bans {
		if ban.Until.After(now) {
			state.Bans = append(state.Bans, *ban)
		}
	}
	guardState.Unlock()

	data, err := json.Marshal(&state)
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, statePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// loadState 读取状态文件并覆盖当前内存数据。调用方通常在启动阶段调用。
func loadState() error {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var state stateFile
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("解析失败: %w", err)
	}
	if state.Version != stateVersion {
		return fmt.Errorf("版本不兼容（文件 %d，程序 %d）", state.Version, stateVersion)
	}

	blockStats.Lock()
	if !state.Since.IsZero() {
		blockStats.since = state.Since
	}
	blockStats.total = state.Total
	blockStats.bySite = make(map[string]int64, len(state.BySite))
	for site, count := range state.BySite {
		blockStats.bySite[site] = count
	}
	blockStats.ips = make(map[string]*IPStat, len(state.IPs))
	for i := range state.IPs {
		if len(blockStats.ips) >= maxTrackedIPs {
			break
		}
		if state.IPs[i].IP == "" {
			continue
		}
		stat := state.IPs[i]
		blockStats.ips[stat.IP] = &stat
	}
	if len(state.Recent) > maxRecentEvents {
		state.Recent = state.Recent[len(state.Recent)-maxRecentEvents:]
	}
	blockStats.recent = append([]BlockEvent(nil), state.Recent...)
	total, ips, recent := blockStats.total, len(blockStats.ips), len(blockStats.recent)
	blockStats.Unlock()

	now := time.Now()
	banned := 0
	guardState.Lock()
	for _, ban := range state.Bans {
		key := normalizeIP(ban.IP)
		if key == "" || !ban.Until.After(now) {
			continue
		}
		restored := ban
		restored.IP = key
		guardState.bans[key] = &restored
		banned++
	}
	guardState.Unlock()

	helper.Info(helper.LogTypeWebService, "WAF 拦截记录已恢复 [总数=%d, 来源=%d, 明细=%d, 封禁=%d]",
		total, ips, recent, banned)
	return nil
}

// warnSaveFailure 限制刷盘失败的告警频率，避免刷屏（磁盘满时必须让人看见）。
func warnSaveFailure(err error) {
	stateWarnMu.Lock()
	quiet := time.Since(stateWarnAt) < 5*time.Minute
	if !quiet {
		stateWarnAt = time.Now()
	}
	stateWarnMu.Unlock()
	if !quiet {
		helper.Warn(helper.LogTypeWebService, "WAF 拦截记录保存失败: %v", err)
	}
}
