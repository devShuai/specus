package directhttp

import (
	"errors"
	"net/http"
)

var (
	errOffline = errors.New("客户端不在线")
	errForward = errors.New("HTTP 转发请求失败")
	errTimeout = errors.New("HTTP 转发请求超时")
)

func statusForError(err error) int {
	switch {
	case errors.Is(err, errOffline):
		return http.StatusServiceUnavailable
	case errors.Is(err, errTimeout):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}
