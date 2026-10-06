package directhttp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errOffline = errors.New("客户端不在线")
	errTimeout = errors.New("HTTP 转发请求超时")
	// errForwardFailed is the fixed public body for a stream RST before the response is
	// committed (http-route.md §1). It must stay distinct from errOffline.
	errForwardFailed = errors.New("HTTP 转发请求失败")
)

// maxLoggedReasonRunes bounds how much of a peer-supplied RST reason reaches one log field.
const maxLoggedReasonRunes = 256

// StreamResetError is the terminal error of an HTTP stream the client reset. Reason is the
// client's free-text RST metadata and may carry the target URL, internal hosts or the raw
// query, so Error() deliberately omits it: only logSafeReason(Reason) may reach a log.
type StreamResetError struct {
	Code   uint32
	Reason string
}

func (e *StreamResetError) Error() string { return "HTTP stream reset by client" }

func statusForError(err error) int {
	switch {
	case errors.Is(err, errOffline):
		// 与 Java HttpSpecusController 一致：客户端不在线返回 502 Bad Gateway。
		return http.StatusBadGateway
	case errors.Is(err, errTimeout):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

// logSafeReason keeps at most maxLoggedReasonRunes runes of a peer-supplied reason and escapes
// control and line-separator characters (and invalid UTF-8) so the text cannot forge log lines.
func logSafeReason(reason string) string {
	var safe strings.Builder
	runes := 0
	for index := 0; index < len(reason); {
		if runes == maxLoggedReasonRunes {
			safe.WriteString("...(truncated)")
			break
		}
		r, size := utf8.DecodeRuneInString(reason[index:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&safe, "\\x%02x", reason[index])
		case r == '\\':
			safe.WriteString(`\\`)
		case r == '\n':
			safe.WriteString(`\n`)
		case r == '\r':
			safe.WriteString(`\r`)
		case r == '\t':
			safe.WriteString(`\t`)
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&safe, "\\u%04x", r)
		default:
			safe.WriteRune(r)
		}
		index += size
		runes++
	}
	return safe.String()
}
