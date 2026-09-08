package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The same static files can be packaged by the other client implementations;
// their API uses only the versioned /api/* contract, never a Go-specific RPC.
//
//go:embed web/*
var uiAssets embed.FS

type localUI struct {
	ctx             context.Context
	opMu            sync.Mutex
	authMu          sync.Mutex
	bootstrap       string
	bootstrapExpiry time.Time
	sessions        map[string]time.Time
	origin          string
	path            string
	runtime         *uiRuntime
	requests        chan struct{}
}

func uiRandom() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func (u *localUI) newCode() string {
	u.authMu.Lock()
	defer u.authMu.Unlock()
	u.bootstrap = uiRandom()
	u.bootstrapExpiry = time.Now().Add(5 * time.Minute)
	return u.bootstrap
}
func (u *localUI) authorized(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	u.authMu.Lock()
	defer u.authMu.Unlock()
	expiry, ok := u.sessions[token]
	return ok && time.Now().Before(expiry)
}
func uiJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
func uiError(w http.ResponseWriter, code int, message string) {
	uiJSON(w, code, map[string]any{"schemaVersion": 1, "error": message})
}
func uiDecode(w http.ResponseWriter, r *http.Request, target any) bool {
	typeName, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" {
		uiError(w, 415, "需要 application/json 请求")
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	d.DisallowUnknownFields()
	if err = d.Decode(target); err != nil {
		uiError(w, 400, "请求格式无效或过大")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		uiError(w, 400, "请求包含多余内容")
		return false
	}
	return true
}
func (u *localUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.Host != strings.TrimPrefix(u.origin, "http://") || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != u.origin) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		uiError(w, 403, "仅允许本机管理页面访问")
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		uiError(w, 400, "不支持查询参数或编码路径")
		return
	}
	select {
	case u.requests <- struct{}{}:
		defer func() { <-u.requests }()
	default:
		uiError(w, 429, "请求过多，请稍后重试")
		return
	}
	if r.Method == http.MethodGet {
		name := map[string]string{"/": "index.html", "/app.js": "app.js", "/app.css": "app.css"}[r.URL.Path]
		if name != "" {
			data, err := uiAssets.ReadFile("web/" + name)
			if err != nil {
				uiError(w, 500, "页面资源不可用")
				return
			}
			w.Header().Set("Content-Type", map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8"}[name])
			_, _ = w.Write(data)
			return
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		uiError(w, 405, "不支持此请求方法")
		return
	}
	if r.Method == http.MethodPost && (r.Header.Get("Origin") != u.origin || r.Header.Get("X-Specus-UI") != "1") {
		uiError(w, 403, "写操作必须来自已打开的管理页面")
		return
	}
	if r.URL.Path == "/api/session" && r.Method == http.MethodPost {
		var body struct {
			Code string `json:"code"`
		}
		if !uiDecode(w, r, &body) {
			return
		}
		u.authMu.Lock()
		defer u.authMu.Unlock()
		if u.bootstrap == "" || time.Now().After(u.bootstrapExpiry) || subtle.ConstantTimeCompare([]byte(body.Code), []byte(u.bootstrap)) != 1 {
			uiError(w, 401, "连接码无效或已过期；在管理终端按回车生成新码")
			return
		}
		for token, expiry := range u.sessions {
			if time.Now().After(expiry) {
				delete(u.sessions, token)
			}
		}
		if len(u.sessions) >= 8 {
			uiError(w, 429, "页面会话已达上限；请重启管理进程后重试")
			return
		}
		u.bootstrap = ""
		token := uiRandom()
		u.sessions[token] = time.Now().Add(8 * time.Hour)
		uiJSON(w, 200, map[string]any{"schemaVersion": 1, "token": token})
		return
	}
	if !u.authorized(r) {
		uiError(w, 401, "页面已锁定；在管理终端按回车生成新码，重新授权不会断开隧道")
		return
	}
	u.opMu.Lock()
	defer u.opMu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/config":
		u.config(w)
	case r.Method == http.MethodGet && r.URL.Path == "/api/status":
		others, err := uiOtherInstances(u.path)
		warning := ""
		if err != nil {
			warning = err.Error()
		}
		uiJSON(w, 200, map[string]any{"schemaVersion": 1, "implementation": "go", "version": version, "configPath": u.path, "runtime": u.runtime.snapshot(), "otherInstances": others, "instanceWarning": warning})
	case r.Method == http.MethodPost && (r.URL.Path == "/api/config/validate" || r.URL.Path == "/api/config/save"):
		var edit uiConfigEdit
		if !uiDecode(w, r, &edit) {
			return
		}
		data, _, warnings, err := uiPrepareConfig(u.path, edit)
		if err == nil && r.URL.Path == "/api/config/save" {
			err = uiWriteConfig(u.path, edit.Revision, data)
		}
		if err != nil {
			code := 422
			if errors.Is(err, errUIConflict) {
				code = 409
			}
			uiError(w, code, err.Error())
			return
		}
		uiJSON(w, 200, map[string]any{"schemaVersion": 1, "saved": r.URL.Path == "/api/config/save", "offline": true, "warnings": warnings})
	case r.Method == http.MethodPost && r.URL.Path == "/api/connection":
		var body struct {
			Action   string `json:"action"`
			Revision string `json:"revision"`
		}
		if !uiDecode(w, r, &body) {
			return
		}
		var err error
		switch body.Action {
		case "start":
			err = u.runtime.start(u.ctx, body.Revision)
		case "stop":
			err = u.runtime.stop()
		case "restart":
			// Validate BEFORE disconnecting a working connection.
			_, _, _, err = uiPrepareConfig(u.path, uiConfigEdit{Revision: body.Revision})
			if err == nil {
				err = u.runtime.stop()
			}
			if err == nil {
				err = u.runtime.start(u.ctx, body.Revision)
			}
		default:
			uiError(w, 400, "未知连接操作")
			return
		}
		if err != nil {
			uiError(w, 409, err.Error())
			return
		}
		uiJSON(w, 200, map[string]any{"schemaVersion": 1, "accepted": true})
	case r.URL.Path == "/api/config" || r.URL.Path == "/api/status" || r.URL.Path == "/api/config/save" || r.URL.Path == "/api/config/validate" || r.URL.Path == "/api/connection":
		uiError(w, 405, "此接口不支持该方法")
	default:
		uiError(w, 404, "接口不存在")
	}
}
func (u *localUI) config(w http.ResponseWriter) {
	data, revision, err := uiReadConfig(u.path)
	if err != nil {
		uiError(w, 422, err.Error())
		return
	}
	spans, err := uiConfigSpans(data)
	if err != nil {
		uiError(w, 422, err.Error())
		return
	}
	field := func(key string) string {
		span, ok := spans[key]
		if !ok {
			return ""
		}
		var value string
		_ = json.Unmarshal(data[span.start:span.end], &value)
		return value
	}
	server := field("serverBaseUrl")
	if server != "" {
		server = safeURL(server)
	}
	device := field("peerMeshDevice")
	if device == "" {
		device = "noop"
	}
	uiJSON(w, 200, map[string]any{"schemaVersion": 1, "revision": revision, "exists": revision != "missing", "configPath": u.path, "fields": map[string]string{"serverBaseUrl": server, "peerMeshDevice": device}, "hasApiKey": field("apiKey") != "", "hasSecret": field("secret") != "", "editableFields": []string{"serverBaseUrl", "apiKey", "secret", "peerMeshDevice"}})
}
func runLocalUI(options cliOptions, path string) int {
	if err := uiCheckPath(path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	release, err := uiAcquireLock(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer release()
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", options.uiPort))
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法监听本机端口；请选择其他 --port，未启动任何连接")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	u := &localUI{ctx: ctx, path: path, origin: "http://" + listener.Addr().String(), sessions: map[string]time.Time{}, requests: make(chan struct{}, 16), runtime: &uiRuntime{path: path, loginTimeout: options.loginTimeout, detail: "尚未连接；打开页面不会自动登录"}}
	server := &http.Server{Handler: u, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	code := u.newCode()
	fmt.Printf("本地管理页面：%s\n配置：%s\n一次性连接码（5 分钟内有效）：%s\n按回车生成新码；刷新页面需重新授权。Ctrl+C 退出管理并断开本进程拥有的隧道。\n", u.origin, path, code)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				fmt.Printf("一次性连接码（5 分钟内有效）：%s\n", u.newCode())
			}
		}
	}()
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	if !options.noOpen {
		if err := uiOpenBrowser(u.origin + "/#" + code); err != nil {
			fmt.Fprintln(os.Stderr, "无法打开浏览器；请手动访问上述地址并输入连接码")
		}
	}
	result := 0
	select {
	case <-ctx.Done():
	case err = <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "本地管理服务已停止")
			result = 1
		}
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_ = server.Shutdown(shutdown)
	if err = u.runtime.stop(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		result = 1
	}
	return result
}
func uiOpenBrowser(address string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	case "darwin":
		cmd = exec.Command("open", address)
	default:
		cmd = exec.Command("xdg-open", address)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
