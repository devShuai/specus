package directhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
)

// SetHTTPShares attaches the temporary HTTP share service that authorizes /http-share/ requests.
func (s *Service) SetHTTPShares(shares *httpshare.Service) { s.shares = shares }

// IsSharePath reports whether a request belongs to the share entry. The raw path decides: the
// entry must see dot segments and escapes exactly as the visitor sent them, before any mux
// cleans the path.
func IsSharePath(r *http.Request) bool {
	path := r.URL.EscapedPath()
	return path == "/http-share" || strings.HasPrefix(path, httpshare.SharePathRoot)
}

// ServeShare handles ANY /http-share/{shareId}/** (protocol/spec/temporary-http-share.md §6). It
// never falls back to "no record means public": only a share proven by its cookie, whose route,
// client and creator still allow it, reaches the device.
func (s *Service) ServeShare(w http.ResponseWriter, r *http.Request) {
	if s.shares == nil {
		writeShareRefusal(w, httpshare.Decision{Status: http.StatusNotFound, Code: httpshare.CodeNotFound})
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	upgrade := isWebSocketUpgrade(r)
	var (
		connMu sync.Mutex
		wsConn *websocket.Conn
	)
	cut := func() {
		connMu.Lock()
		conn := wsConn
		connMu.Unlock()
		if conn != nil {
			// The share ended: a WebSocket closes with 1008 (policy violation).
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "share ended"),
				time.Now().Add(wsCloseSendTimeout))
		}
		cancel()
	}
	decision := s.shares.Authorize(ctx, httpshare.VisitorRequest{
		Path: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery, Method: r.Method, Upgrade: upgrade,
		Cookies: r.Header.Values("Cookie"), Cut: cut,
	})
	if decision.Grant == nil {
		writeShareRefusal(w, decision)
		return
	}
	grant := decision.Grant
	defer grant.Lease.Release()
	shareID := grant.Share.ShareID
	target := forwardTarget{clientName: grant.ClientName, route: grant.RouteName, relativePath: grant.RelativePath,
		pathRewrite: grant.PathRewrite, rewritePrefix: strings.TrimSuffix(httpshare.SharePath(shareID), "/"),
		shareID: shareID, cookie: grant.ForwardedCookie, hasCookie: grant.HasCookie}
	r = r.WithContext(ctx)
	if upgrade {
		s.serveWebSocketWith(w, r, target, func(conn *websocket.Conn) {
			connMu.Lock()
			wsConn = conn
			connMu.Unlock()
		})
		return
	}
	s.forward(w, r, target)
	if grant.Lease.WasCut() {
		// The share ended mid-response: abort the connection so the visitor never mistakes a
		// truncated body for a complete one. The device already got RST from the stream.
		panic(http.ErrAbortHandler)
	}
}

func writeShareRefusal(w http.ResponseWriter, decision httpshare.Decision) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	if decision.Status == http.StatusPermanentRedirect {
		header.Set("Location", decision.Location)
		w.WriteHeader(decision.Status)
		return
	}
	if decision.Allow != "" {
		header.Set("Allow", decision.Allow)
	}
	if decision.RetryAfter > 0 {
		header.Set("Retry-After", strconv.FormatInt(decision.RetryAfter, 10))
	}
	if decision.ClearCookie != "" {
		header.Add("Set-Cookie", decision.ClearCookie)
	}
	header.Set("Content-Type", "application/json")
	w.WriteHeader(decision.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": decision.Code})
}
