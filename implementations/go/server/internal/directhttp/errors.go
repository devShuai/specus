package directhttp

import (
	"errors"
	"net/http"
)

var (
	errOffline = errors.New("客户端不在线")
	errTimeout = errors.New("HTTP 转发请求超时")
)

func statusForError(err error) int {
	switch {
	case errors.Is(err, errOffline):
		// 与 Java HttpTunnelController 一致：客户端不在线返回 502 Bad Gateway。
		return http.StatusBadGateway
	case errors.Is(err, errTimeout):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}
