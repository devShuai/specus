package connectivity

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	// MaxBodyBytes bounds the request body; the only field is a path of at most 256 bytes.
	MaxBodyBytes = 4096
	maxPathBytes = 256
)

// parseRequestBody accepts an empty body, {} or {"path": "<path>"} and returns the probe path
// ("/" by default). Anything else -- another JSON type, an unknown key, a path that is not a string
// or breaks the rules of section 3.1 -- is invalid.
func parseRequestBody(body []byte) (string, bool) {
	if len(body) > MaxBodyBytes {
		return "", false
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "/", true
	}
	if trimmed[0] != '{' {
		return "", false
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return "", false
	}
	if decoder.More() {
		return "", false
	}
	path := "/"
	for key, raw := range fields {
		if key != "path" {
			return "", false
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || raw[0] != '"' {
			return "", false
		}
		if err := json.Unmarshal(raw, &path); err != nil {
			return "", false
		}
	}
	if !ValidProbePath(path) {
		return "", false
	}
	return path, true
}

// ValidProbePath applies section 3.1: 1..256 bytes, starts with "/" but not "//", only RFC 3986
// pchar and "/" (with well-formed %XX), and no "." or ".." segment, also when the dot is encoded.
func ValidProbePath(path string) bool {
	if len(path) < 1 || len(path) > maxPathBytes || path[0] != '/' || strings.HasPrefix(path, "//") {
		return false
	}
	for index := 0; index < len(path); index++ {
		character := path[index]
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/", character) >= 0:
		case character == '%':
			if index+2 >= len(path) || !isHex(path[index+1]) || !isHex(path[index+2]) {
				return false
			}
			index += 2
		default:
			return false
		}
	}
	for _, segment := range strings.Split(path, "/") {
		decoded := strings.ReplaceAll(strings.ReplaceAll(segment, "%2e", "."), "%2E", ".")
		if decoded == "." || decoded == ".." {
			return false
		}
	}
	return true
}

func isHex(character byte) bool {
	return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
		(character >= 'A' && character <= 'F')
}
