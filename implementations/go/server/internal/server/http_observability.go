package server

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"
)

func (a *App) observeManagementHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		response := &observedResponseWriter{ResponseWriter: w}
		panicked := false
		defer func() {
			if recovered := recover(); recovered != nil {
				panicked = true
				if !response.wroteHeader && !response.hijacked {
					http.Error(response, "internal server error", http.StatusInternalServerError)
				}
				a.logger.Error("management HTTP panic",
					"method", r.Method,
					"pattern", safeRequestPattern(r),
					"panic", fmt.Sprint(recovered),
					"stack", string(debug.Stack()))
			}

			status := response.statusCode()
			level := slog.LevelInfo
			if status >= http.StatusInternalServerError || panicked {
				level = slog.LevelError
			} else if status >= http.StatusBadRequest {
				level = slog.LevelWarn
			}
			a.logger.Log(r.Context(), level, "management HTTP request",
				"method", r.Method,
				"pattern", safeRequestPattern(r),
				"status", status,
				"bytes", response.bytesWritten,
				"durationMs", time.Since(startedAt).Milliseconds(),
				"panic", panicked)
		}()

		next.ServeHTTP(response, r)
	})
}

func safeRequestPattern(r *http.Request) string {
	if pattern := strings.TrimSpace(r.Pattern); pattern != "" {
		return pattern
	}
	return "unmatched"
}

type observedResponseWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int64
	wroteHeader  bool
	hijacked     bool
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *observedResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(payload)
	w.bytesWritten += int64(written)
	return written, err
}

func (w *observedResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *observedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	connection, buffer, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err == nil {
		w.hijacked = true
		if !w.wroteHeader {
			w.status = http.StatusSwitchingProtocols
			w.wroteHeader = true
		}
	}
	return connection, buffer, err
}

func (w *observedResponseWriter) ReadFrom(reader io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if target, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		written, err := target.ReadFrom(reader)
		w.bytesWritten += written
		return written, err
	}
	return io.Copy(writerOnly{Writer: w}, reader)
}

func (w *observedResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

type writerOnly struct {
	io.Writer
}
