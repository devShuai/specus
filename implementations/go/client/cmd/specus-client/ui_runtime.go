package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

type uiRuntime struct {
	mu               sync.Mutex
	path             string
	loginTimeout     int
	active           *client.Client
	cancel           context.CancelFunc
	done             chan struct{}
	revision, detail string
}

func (u *uiRuntime) snapshot() map[string]any {
	u.mu.Lock()
	defer u.mu.Unlock()
	snapshot := map[string]any{"phase": "stopped", "controlAuthenticated": false, "businessReady": false, "peers": []any{}, "services": []any{}}
	if u.active != nil {
		snapshot = u.active.DiagnosticSnapshot()
	}
	snapshot["processRunning"] = u.active != nil
	snapshot["detail"] = u.detail
	if u.active != nil && !strings.HasPrefix(u.detail, "正在断开") {
		switch snapshot["phase"] {
		case "ready":
			snapshot["detail"] = "控制与数据通道均已就绪；目标服务尚未探测"
		case "control-authenticated":
			snapshot["detail"] = "控制通道已认证，正在建立数据通道；尚不可转发"
		case "connecting":
			snapshot["detail"] = "正在建立或恢复控制通道；尚未就绪"
		default:
			snapshot["detail"] = "正在登录或等待重试；可断开后检查配置"
		}
	}
	snapshot["runningRevision"] = u.revision
	snapshot["pid"] = os.Getpid()
	return snapshot
}

// Old CLI instances expose private read-only snapshots, not an authenticated
// control channel. They are visible but never stopped or silently taken over.
func uiOtherInstances(config string) ([]map[string]any, error) {
	root, err := checkedStateRoot(false)
	if os.IsNotExist(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, errors.New("本机状态目录不可安全读取，暂不允许启动新连接")
	}
	paths, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil || len(paths) > 256 {
		return nil, errors.New("本机状态目录超限，暂不允许启动新连接")
	}
	result := []map[string]any{}
	for _, path := range paths {
		if err := checkPrivate(path, false); err != nil {
			return nil, errors.New("本机状态文件权限不安全，暂不允许启动新连接")
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
		f.Close()
		if err != nil || len(data) > 1024*1024 {
			continue
		}
		var row map[string]any
		if json.Unmarshal(data, &row) != nil {
			continue
		}
		stored, _ := row["configPath"].(string)
		pid, _ := row["pid"].(float64)
		at, _ := row["updatedAtUnixMs"].(float64)
		matches := stored == config || (runtime.GOOS == "windows" && strings.EqualFold(stored, config))
		age := time.Now().UnixMilli() - int64(at)
		if !matches || pid == float64(os.Getpid()) || pid <= 0 || age < 0 || age > 5000 || !processAlive(int(pid)) || row["schemaVersion"] != float64(1) {
			continue
		}
		result = append(result, map[string]any{"pid": int(pid), "phase": row["phase"], "controlAuthenticated": row["controlAuthenticated"], "businessReady": row["businessReady"], "readOnly": true})
	}
	return result, nil
}

func (u *uiRuntime) start(ctx context.Context, revision string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.active != nil {
		return errors.New("本页面已拥有一个连接；请先断开或重新连接")
	}
	others, err := uiOtherInstances(u.path)
	if err != nil {
		return err
	}
	if len(others) > 0 {
		return errors.New("已有其他 CLI 实例使用此配置；本页仅可查看，请先从原终端停止该实例")
	}
	data, current, err := uiReadConfig(u.path)
	if err != nil {
		return err
	}
	if revision != current {
		return errUIConflict
	}
	config, err := client.ParseConfigWithDiagnostics(data, nil)
	if err != nil {
		return errors.New("配置无效，请先校验并保存配置")
	}
	// UI-managed connections deliberately do not start an updater. A binary restart
	// must not orphan the local management process or broaden update consent.
	app := client.New(config, log.New(io.Discard, "", 0))
	app.SetInitialLoginTimeout(time.Duration(u.loginTimeout) * time.Second)
	stopState, err := publishState(u.path, app.DiagnosticSnapshot)
	if err != nil {
		return errors.New("无法创建安全的 CLI 状态文件")
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	u.active = app
	u.cancel = cancel
	u.done = done
	u.revision = current
	u.detail = "正在连接；目标服务尚未探测"
	go func() {
		defer cancel()
		err := app.Run(runCtx)
		stopState()
		u.mu.Lock()
		u.active = nil
		u.cancel = nil
		u.detail = "已断开；本地管理页面仍在运行"
		if err != nil && !errors.Is(err, context.Canceled) {
			var rejected *client.LoginFailure
			if errors.As(err, &rejected) {
				u.detail = rejected.Message
			} else {
				u.detail = fmt.Sprintf("连接已停止（退出类别 %d）；请检查配置、TLS、账户策略或在终端使用 doctor", client.ExitCode(err))
			}
		}
		u.mu.Unlock()
		close(done)
	}()
	return nil
}
func (u *uiRuntime) stop() error {
	u.mu.Lock()
	cancel, done := u.cancel, u.done
	if cancel != nil {
		u.detail = "正在断开；等待当前连接完成清理"
		cancel()
	}
	u.mu.Unlock()
	if cancel == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-time.After(8 * time.Second):
		return errors.New("连接仍在清理；不会启动第二个连接，请稍后重试")
	}
}

func uiAcquireLock(config string) (func(), error) {
	root, err := checkedStateRoot(true)
	if err != nil {
		return nil, errors.New("无法创建安全的管理状态目录；检查 SPECUS_CLI_STATE_DIR 权限")
	}
	path := filepath.Join(root, strings.TrimPrefix(statePrefix(config), "go-")+"ui.lock")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("已有管理页面或遗留锁：%s；先检查该页面/PID 是否仍运行，确认进程已退出后再移除锁", path)
	}
	_, err = fmt.Fprintf(f, "pid=%d\n", os.Getpid())
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(path)
		return nil, errors.New("无法写入管理锁")
	}
	return func() { _ = os.Remove(path) }, nil
}
