package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

var errUIConflict = errors.New("配置已被其他页面或程序修改，请重新载入后再保存")

type uiConfigEdit struct {
	Revision string            `json:"revision"`
	Changes  map[string]string `json:"changes"`
}
type uiSpan struct{ start, end int }

// Reject symbolic links/reparse points throughout the selected path. The UI has no
// API to change this path or to read arbitrary files. Same-user hostile filesystem
// mutation is not a supported security boundary.
func uiCheckPath(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !(current == path && os.IsNotExist(err)) {
			return errors.New("配置路径不可访问，请检查父目录和权限")
		}
		if err == nil && (info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || (current == path && !info.Mode().IsRegular())) {
			return errors.New("本地页面不管理符号链接、重解析点或非普通配置文件")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
func uiReadConfig(path string) ([]byte, string, error) {
	if err := uiCheckPath(path); err != nil {
		return nil, "", err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []byte("{}"), "missing", nil
	}
	if err != nil {
		return nil, "", errors.New("无法读取配置文件，请检查权限")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, "", errors.New("配置文件读取失败或超过 1 MiB")
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// Locate top-level values without rewriting JSONC comments, whitespace or unknown
// fields. The core parser validates the resulting document before it can be saved.
func uiConfigSpans(data []byte) (map[string]uiSpan, error) {
	p := 0
	skip := func() bool {
		for p < len(data) {
			if strings.ContainsRune(" \t\r\n", rune(data[p])) {
				p++
				continue
			}
			if p+1 < len(data) && data[p] == '/' && data[p+1] == '/' {
				for p < len(data) && data[p] != '\n' {
					p++
				}
				continue
			}
			if p+1 < len(data) && data[p] == '/' && data[p+1] == '*' {
				i := bytes.Index(data[p+2:], []byte("*/"))
				if i < 0 {
					return false
				}
				p += i + 4
				continue
			}
			break
		}
		return true
	}
	quoted := func() bool {
		if p >= len(data) || data[p] != '"' {
			return false
		}
		p++
		for p < len(data) {
			c := data[p]
			p++
			if c == '\\' {
				p++
				continue
			}
			if c == '"' {
				return true
			}
		}
		return false
	}
	invalid := errors.New("无法安全编辑此 JSONC：请检查语法、重复字段或使用外部编辑器修正")
	if !skip() || p >= len(data) || data[p] != '{' {
		return nil, invalid
	}
	p++
	spans := map[string]uiSpan{}
	for {
		if !skip() || p >= len(data) {
			return nil, invalid
		}
		if data[p] == '}' {
			p++
			if !skip() || p != len(data) {
				return nil, invalid
			}
			return spans, nil
		}
		keyStart := p
		if !quoted() {
			return nil, invalid
		}
		var key string
		if json.Unmarshal(data[keyStart:p], &key) != nil {
			return nil, invalid
		}
		if _, exists := spans[key]; exists {
			return nil, invalid
		}
		for _, canonical := range []string{"serverBaseUrl", "apiKey", "secret", "peerMeshDevice"} {
			if strings.EqualFold(key, canonical) && key != canonical {
				return nil, invalid
			}
		}
		if !skip() || p >= len(data) || data[p] != ':' {
			return nil, invalid
		}
		p++
		if !skip() || p >= len(data) {
			return nil, invalid
		}
		start := p
		if data[p] == '"' {
			if !quoted() {
				return nil, invalid
			}
		} else if data[p] == '{' || data[p] == '[' {
			stack := []byte{}
			for p < len(data) {
				if !skip() || p >= len(data) {
					return nil, invalid
				}
				c := data[p]
				if c == '"' {
					if !quoted() {
						return nil, invalid
					}
					continue
				}
				p++
				if c == '{' || c == '[' {
					stack = append(stack, c)
				}
				if c == '}' || c == ']' {
					if len(stack) == 0 || (c == '}' && stack[len(stack)-1] != '{') || (c == ']' && stack[len(stack)-1] != '[') {
						return nil, invalid
					}
					stack = stack[:len(stack)-1]
				}
				if len(stack) == 0 {
					break
				}
			}
			if len(stack) != 0 {
				return nil, invalid
			}
		} else {
			for p < len(data) && !strings.ContainsRune(" \t\r\n,}/", rune(data[p])) {
				p++
			}
		}
		if p == start {
			return nil, invalid
		}
		spans[key] = uiSpan{start, p}
		if !skip() || p >= len(data) {
			return nil, invalid
		}
		if data[p] == ',' {
			p++
			continue
		}
		if data[p] != '}' {
			return nil, invalid
		}
	}
}

func uiPatchConfig(data []byte, changes map[string]string) ([]byte, error) {
	spans, err := uiConfigSpans(data)
	if err != nil {
		return nil, err
	}
	type edit struct {
		span  uiSpan
		value []byte
	}
	var edits []edit
	var additions []string
	keys := make([]string, 0, len(changes))
	for key := range changes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := strings.TrimSpace(changes[key])
		switch key {
		case "serverBaseUrl":
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return nil, errors.New("服务地址必须是无凭据、查询串和片段的 HTTP/HTTPS 地址")
			}
		case "apiKey", "secret":
			if value == "" {
				continue
			}
		case "peerMeshDevice":
			if value != "noop" && value != "auto" {
				return nil, errors.New("页面仅支持 noop 或 auto；其他模式请在外部配置")
			}
		default:
			return nil, errors.New("请求包含不支持编辑的字段")
		}
		encoded, _ := json.Marshal(value)
		if span, ok := spans[key]; ok {
			edits = append(edits, edit{span, encoded})
		} else {
			k, _ := json.Marshal(key)
			additions = append(additions, string(k)+": "+string(encoded))
		}
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].span.start > edits[j].span.start })
	out := append([]byte(nil), data...)
	for _, e := range edits {
		out = append(append(append([]byte(nil), out[:e.span.start]...), e.value...), out[e.span.end:]...)
	}
	if len(additions) > 0 {
		// A leading JSONC comment can itself contain a brace.
		at := uiObjectStart(out) + 1
		insert := "\n  " + strings.Join(additions, ",\n  ")
		if len(spans) > 0 {
			insert += ","
		}
		insert += "\n"
		out = append(append(append([]byte(nil), out[:at]...), []byte(insert)...), out[at:]...)
	}
	return out, nil
}
func uiObjectStart(data []byte) int {
	for p := 0; p < len(data); {
		if p+1 < len(data) && data[p] == '/' && data[p+1] == '/' {
			for p < len(data) && data[p] != '\n' {
				p++
			}
			continue
		}
		if p+1 < len(data) && data[p] == '/' && data[p+1] == '*' {
			p += bytes.Index(data[p+2:], []byte("*/")) + 4
			continue
		}
		if data[p] == '{' {
			return p
		}
		p++
	}
	return -1
}

func uiPrepareConfig(path string, edit uiConfigEdit) ([]byte, client.Config, []string, error) {
	data, revision, err := uiReadConfig(path)
	if err != nil {
		return nil, client.Config{}, nil, err
	}
	if revision != edit.Revision {
		return nil, client.Config{}, nil, errUIConflict
	}
	data, err = uiPatchConfig(data, edit.Changes)
	if err != nil {
		return nil, client.Config{}, nil, err
	}
	warnings := []string{}
	config, err := client.ParseConfigWithDiagnostics(data, func(s string) { warnings = append(warnings, s) })
	if err != nil {
		return nil, client.Config{}, nil, errors.New("配置校验失败：检查服务地址、凭据/密钥引用、网卡和 TLS 设置；可在终端运行 config validate 获取诊断")
	}
	return data, config, warnings, nil
}

func uiWriteConfig(path, revision string, data []byte) error {
	_, current, err := uiReadConfig(path)
	if err != nil {
		return err
	}
	if current != revision {
		return errUIConflict
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0200 == 0 {
		return errors.New("配置文件为只读，未保存")
	}
	// A private staging directory gives Windows files an owner-only inherited ACL.
	dir, err := os.MkdirTemp(filepath.Dir(path), ".specus-ui-save-")
	if err != nil {
		return errors.New("无法创建配置临时文件，请检查目录权限")
	}
	defer os.Remove(dir)
	if err = checkPrivate(dir, true); err != nil {
		return errors.New("无法保护配置文件权限，未保存")
	}
	tmp := filepath.Join(dir, "config.jsonc")
	defer os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("无法创建配置文件")
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("配置写入失败，原文件未修改")
	}
	if err = checkPrivate(tmp, true); err != nil {
		return errors.New("无法保护配置文件的所有者和权限，未保存")
	}
	_, current, err = uiReadConfig(path)
	if err != nil {
		return err
	}
	if current != revision {
		return errUIConflict
	}
	if err = os.Rename(tmp, path); err != nil {
		return errors.New("无法原子替换配置，请检查文件权限或占用")
	}
	return nil
}
