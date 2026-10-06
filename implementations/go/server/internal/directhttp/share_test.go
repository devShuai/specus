package directhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
	"github.com/devShuai/specus/implementations/go/server/internal/httpshare/sharetest"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// shareFixture is a real store seeded with the vector world, the real share service and the real
// share entry, with a fake client data channel that records what reaches the device.
type shareFixture struct {
	db      *store.DB
	shares  *httpshare.Service
	service *Service
	server  *httptest.Server

	mu        sync.Mutex
	opened    []map[string]any
	newStream func() Stream
}

func newShareFixture(t *testing.T, input sharetest.CaseInput, world sharetest.World, now time.Time) *shareFixture {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "share.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sharetest.Seed(t, db, world, input.WorldChanges, input.Shares, auth.HashToken)
	shares := httpshare.NewService(db, httpshare.BuiltInAdmin{Username: "root", TenantID: "t1"}, nil)
	shares.SetClock(func() time.Time { return now })
	fixture := &shareFixture{db: db, shares: shares}
	fixture.newStream = func() Stream {
		stream := newFakeStream()
		stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/plain"}}
		stream.responses = []fakeResponse{{data: []byte("ok")}, {end: true}}
		return stream
	}
	fixture.service = NewService(onlineRegistry(sharetest.ClientName(7)),
		func(_ string, metadata map[string]any) (Stream, error) {
			fixture.mu.Lock()
			fixture.opened = append(fixture.opened, metadata)
			fixture.mu.Unlock()
			return fixture.newStream(), nil
		},
		func(_ string, metadata map[string]any, _ *websocket.Conn) (*WebSocketSpecus, error) {
			fixture.mu.Lock()
			fixture.opened = append(fixture.opened, metadata)
			fixture.mu.Unlock()
			return nil, errors.New("recorded")
		},
		5*time.Second, 1024, 1024, nil, nil, nil, store.TrafficDetailOptions{})
	fixture.service.SetHTTPShares(shares)
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.service.ServeShare))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *shareFixture) lastOpened() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.opened) == 0 {
		return nil
	}
	return f.opened[len(f.opened)-1]
}

// waitOpened gives the server time to reach the device: it answers a WebSocket handshake before it
// opens the stream, so the client can see the 101 first.
func (f *shareFixture) waitOpened(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for f.lastOpened() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

func headerValues(metadata map[string]any, name string) []string {
	var values []string
	for _, header := range metadataStrings(metadata, "headers") {
		key, value, _ := strings.Cut(header, ":")
		if strings.EqualFold(strings.TrimSpace(key), name) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

type shareResponse struct {
	status int
	header http.Header
	code   string
}

func (f *shareFixture) do(t *testing.T, method, path, rawQuery string, cookies []string, upgrade bool,
	extra http.Header) shareResponse {
	t.Helper()
	target := f.server.URL + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	if upgrade && method == http.MethodGet {
		dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
		header := http.Header{}
		for _, cookie := range cookies {
			header.Add("Cookie", cookie)
		}
		conn, response, err := dialer.Dial("ws"+strings.TrimPrefix(target, "http"), header)
		if err == nil {
			f.waitOpened(5 * time.Second)
			_ = conn.Close()
			return shareResponse{status: http.StatusSwitchingProtocols, header: response.Header}
		}
		if response == nil {
			t.Fatalf("websocket dial: %v", err)
		}
		defer response.Body.Close()
		var body struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(response.Body).Decode(&body)
		return shareResponse{status: response.StatusCode, header: response.Header, code: body.Code}
	}
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header["Cookie"] = append([]string(nil), cookies...)
	for name, values := range extra {
		request.Header[name] = values
	}
	if upgrade {
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(data, &body)
	return shareResponse{status: response.StatusCode, header: response.Header, code: body.Code}
}

// TestShareVectorAccess replays the access section through the real share entry.
func TestShareVectorAccess(t *testing.T) {
	vector := sharetest.Load(t)
	for _, c := range vector.Access {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			input := c.Input
			expect := sharetest.ParseExpect(t, c.Expect)
			now := sharetest.Now(t, input.Now)
			fixture := newShareFixture(t, input, vector.World, now)
			request := input.Request
			shareID := strings.SplitN(strings.TrimPrefix(request.Path, httpshare.SharePathRoot), "/", 2)[0]
			switch input.Admission {
			case "share-busy":
				for range httpshare.MaxConcurrentPerShare {
					if _, ok := fixture.shares.Streams().Acquire(shareID, now.Add(time.Hour), nil); !ok {
						t.Fatal("could not fill the stream registry")
					}
				}
			case "rate-limited":
				for range httpshare.ShareBurst {
					fixture.shares.ShareLimiter().Take(shareID, now.UnixMilli())
				}
			}
			if !input.IsReadable() {
				_ = fixture.db.Close()
			}
			var extra http.Header
			if request.Authorization != "" {
				extra = http.Header{"Authorization": {request.Authorization}}
			}
			response := fixture.do(t, request.Method, request.Path, request.RawQuery, request.Cookies, request.Upgrade, extra)
			opened := fixture.lastOpened()

			if expect.Forward != nil {
				if opened == nil {
					t.Fatalf("not forwarded: %d %s", response.status, response.code)
				}
				if opened["route"] != expect.Forward.Route || opened["relativePath"] != expect.Forward.RelativePath ||
					opened["rawQuery"] != expect.Forward.RawQuery {
					t.Errorf("forwarded %v %v %v, want %+v", opened["route"], opened["relativePath"], opened["rawQuery"],
						*expect.Forward)
				}
				if source := opened["source"]; source == "http" && opened["method"] != expect.Forward.Method {
					t.Errorf("method %v, want %s", opened["method"], expect.Forward.Method)
				}
				cookies := headerValues(opened, "Cookie")
				switch {
				case expect.Forward.Cookie == nil && len(cookies) != 0:
					t.Errorf("Cookie forwarded: %q", cookies)
				case expect.Forward.Cookie != nil && (len(cookies) != 1 || cookies[0] != *expect.Forward.Cookie):
					t.Errorf("Cookie %q, want %q", cookies, *expect.Forward.Cookie)
				}
				encoded, _ := json.Marshal(opened)
				if strings.Contains(string(encoded), "hs1.") {
					t.Errorf("the token reached the device: %s", encoded)
				}
				return
			}
			if opened != nil {
				t.Fatalf("refused request was forwarded: %v", opened)
			}
			if response.status != expect.Status() || response.code != expect.Code {
				t.Fatalf("got %d %s, want %d %s", response.status, response.code, expect.Status(), expect.Code)
			}
			if response.header.Get("Cache-Control") != "no-store" {
				t.Errorf("Cache-Control %q", response.header.Get("Cache-Control"))
			}
			if expect.Location != "" && response.header.Get("Location") != expect.Location {
				t.Errorf("Location %q, want %q", response.header.Get("Location"), expect.Location)
			}
			if expect.Allow != "" && response.header.Get("Allow") != expect.Allow {
				t.Errorf("Allow %q, want %q", response.header.Get("Allow"), expect.Allow)
			}
			if expect.RetryAfterSeconds != nil && response.header.Get("Retry-After") != fmt.Sprint(*expect.RetryAfterSeconds) {
				t.Errorf("Retry-After %q, want %d", response.header.Get("Retry-After"), *expect.RetryAfterSeconds)
			}
			setCookies := response.header.Values("Set-Cookie")
			if expect.SetCookie == nil {
				if len(setCookies) != 0 {
					t.Errorf("unexpected Set-Cookie %q", setCookies)
				}
			} else if len(setCookies) != 1 || !sharetest.SameJSON(sharetest.CookieView(setCookies[0]), expect.SetCookie) {
				t.Errorf("Set-Cookie %q, want %s", setCookies, expect.SetCookie)
			}
			if !input.IsReadable() {
				return
			}
			if expect.Revoke != nil {
				state := sharetest.ShareState(t, fixture.db, shareID)
				if state.RevokedAt == nil || state.RevokedBy != nil || state.RevokeReason == nil ||
					*state.RevokeReason != expect.Revoke.Reason {
					t.Errorf("share state %+v, want revoked for %s by the system", state, expect.Revoke.Reason)
				}
			}
			sharetest.SameAudit(t, c.Name, sharetest.AuditEntries(t, fixture.db, "t1"), expect.Audit, nil)
		})
	}
}

// fixtureWithShare seeds the vector world with one active share of route 42 and returns the
// fixture and the share's cookie.
func fixtureWithShare(t *testing.T, access, prefix string) (*shareFixture, string, string) {
	t.Helper()
	vector := sharetest.Load(t)
	shareID, token, err := httpshare.NewToken(sharetest.NewFixedRandom(t, vector.NewShare.ShareIDBytesHex,
		vector.NewShare.SecretBytesHex))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	row := sharetest.ShareRow{ShareID: shareID, TenantID: "t1", RouteID: 42, TokenSHA256: httpshare.TokenHash(token),
		Access: access, PathPrefix: prefix, CreatedBy: "alice",
		CreatedAt: now.Add(-time.Minute).Format("2006-01-02T15:04:05Z"),
		ExpiresAt: now.Add(time.Hour).Format("2006-01-02T15:04:05Z")}
	fixture := newShareFixture(t, sharetest.CaseInput{Shares: []sharetest.ShareRow{row}}, vector.World, now)
	fixture.shares.SetClock(time.Now)
	return fixture, shareID, httpshare.CookieName + "=" + token
}

func TestShareForwardsAuthorizationAndRewritesResponseHeaders(t *testing.T) {
	fixture, shareID, cookie := fixtureWithShare(t, httpshare.AccessFull, "/")
	fixture.newStream = func() Stream {
		stream := newFakeStream()
		stream.head = map[string]any{"statusCode": 200, "headers": []string{
			"Content-Type:text/plain", "Set-Cookie:sid=1; Path=/; Domain=example.com; HttpOnly",
			"Set-Cookie:__Host-x=1; Path=/; Secure", "Set-Cookie:" + httpshare.CookieName + "=evil; Path=/",
			"Clear-Site-Data:\"cookies\"", "Cache-Control:no-store", "Expires:0"}}
		stream.responses = []fakeResponse{{data: []byte("ok")}, {end: true}}
		return stream
	}
	response := fixture.do(t, http.MethodPost, "/http-share/"+shareID+"/api", "", []string{"a=1; " + cookie, "b=2"}, false,
		http.Header{"Authorization": {"Bearer upstream-token"}})
	if response.status != http.StatusOK {
		t.Fatalf("status %d %s", response.status, response.code)
	}
	opened := fixture.lastOpened()
	if got := headerValues(opened, "Authorization"); len(got) != 1 || got[0] != "Bearer upstream-token" {
		t.Errorf("Authorization %q, want it relayed unchanged", got)
	}
	if got := headerValues(opened, "Cookie"); len(got) != 1 || got[0] != "a=1; b=2" {
		t.Errorf("Cookie %q", got)
	}
	if got := response.header.Values("Set-Cookie"); len(got) != 1 ||
		got[0] != "sid=1; Path=/http-share/"+shareID+"/; HttpOnly" {
		t.Errorf("Set-Cookie %q", got)
	}
	if response.header.Get("Clear-Site-Data") != "" || response.header.Get("Expires") != "" ||
		response.header.Get("Cache-Control") != "private, no-store" {
		t.Errorf("headers %v", response.header)
	}
	if response.header.Get("Content-Security-Policy") != "" || response.header.Get("X-Frame-Options") != "" {
		t.Errorf("portal headers on a share response: %v", response.header)
	}
}

func TestSharePathRewriteUsesTheSharePrefix(t *testing.T) {
	fixture, shareID, cookie := fixtureWithShare(t, httpshare.AccessRead, "/")
	if _, err := fixture.db.ExecStatement(context.Background(),
		`UPDATE http_route_mapping SET path_rewrite_enabled = 1 WHERE id = 42`); err != nil {
		t.Fatal(err)
	}
	fixture.newStream = func() Stream {
		stream := newFakeStream()
		stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/html"}}
		stream.responses = []fakeResponse{{data: []byte(`<a href="/docs/a">a</a>`)}, {end: true}}
		return stream
	}
	request, _ := http.NewRequest(http.MethodGet, fixture.server.URL+"/http-share/"+shareID+"/", nil)
	request.Header.Set("Cookie", cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), `href="/http-share/`+shareID+`/docs/a"`) || strings.Contains(string(body), "/http/") {
		t.Fatalf("rewritten body %s", body)
	}
}

// streamingStream answers with a head and one chunk, then blocks until the request is cut.
type streamingStream struct {
	*fakeStream
	sent   bool
	resets chan string
}

func (s *streamingStream) ReadResponse(ctx context.Context) ([]byte, map[string]any, bool, error) {
	if !s.sent {
		s.sent = true
		return []byte("first chunk\n"), nil, false, nil
	}
	<-ctx.Done()
	return nil, nil, false, ctx.Err()
}

func (s *streamingStream) Reset(_ uint32, reason string) {
	select {
	case s.resets <- reason:
	default:
	}
}

func startStreaming(t *testing.T, fixture *shareFixture, shareID, cookie string) (*http.Response, chan string) {
	t.Helper()
	resets := make(chan string, 4)
	fixture.newStream = func() Stream {
		stream := &streamingStream{fakeStream: newFakeStream(), resets: resets}
		stream.head = map[string]any{"statusCode": 200, "headers": []string{"Content-Type:text/event-stream"}}
		return stream
	}
	request, _ := http.NewRequest(http.MethodGet, fixture.server.URL+"/http-share/"+shareID+"/events", nil)
	request.Header.Set("Cookie", cookie)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("first chunk\n"))
	if _, err := io.ReadFull(response.Body, buffer); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	if fixture.shares.Streams().Count(shareID) != 1 {
		t.Fatalf("in-flight streams = %d", fixture.shares.Streams().Count(shareID))
	}
	return response, resets
}

func awaitCut(t *testing.T, response *http.Response, resets chan string, within time.Duration) time.Duration {
	t.Helper()
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(response.Body)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the cut response ended like a complete one")
		}
	case <-time.After(within):
		t.Fatalf("in-flight response not cut within %s", within)
	}
	select {
	case <-resets:
	case <-time.After(time.Second):
		t.Fatal("the device stream was not reset")
	}
	return time.Since(started)
}

func TestShareRevokeOnThisInstanceCutsInFlightStreamAtOnce(t *testing.T) {
	fixture, shareID, cookie := fixtureWithShare(t, httpshare.AccessRead, "/")
	response, resets := startStreaming(t, fixture, shareID, cookie)
	defer response.Body.Close()
	result := fixture.shares.Revoke(context.Background(), httpshare.Caller{Username: "alice"}, "42", shareID, nil)
	if result.Status != http.StatusOK {
		t.Fatalf("revoke %d %s", result.Status, result.Code)
	}
	awaitCut(t, response, resets, time.Second)
	after := fixture.do(t, http.MethodGet, "/http-share/"+shareID+"/", "", []string{cookie}, false, nil)
	if after.status != http.StatusGone || after.code != httpshare.CodeRevoked ||
		!strings.Contains(after.header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("after revoke: %d %s %v", after.status, after.code, after.header)
	}
}

func TestShareRevokedElsewhereCutsInFlightStreamWithinFiveSeconds(t *testing.T) {
	fixture, shareID, cookie := fixtureWithShare(t, httpshare.AccessRead, "/")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fixture.shares.RunStreamWatch(ctx)
	response, resets := startStreaming(t, fixture, shareID, cookie)
	defer response.Body.Close()
	// Another instance revokes the share: only the database changes here.
	if _, err := fixture.db.ExecStatement(context.Background(), `UPDATE http_share SET revoked_at = ?,
		revoked_by = 'alice', revoke_reason = 'revoked-by-user' WHERE share_id = ?`, time.Now().Unix(), shareID); err != nil {
		t.Fatal(err)
	}
	elapsed := awaitCut(t, response, resets, 5*time.Second)
	t.Logf("cut after %s", elapsed)
}

func TestShareExpiryCutsInFlightStreamWithinASecond(t *testing.T) {
	fixture, shareID, cookie := fixtureWithShare(t, httpshare.AccessRead, "/")
	expiresAt := time.Now().Add(1500 * time.Millisecond).Truncate(time.Second).Add(time.Second)
	if _, err := fixture.db.ExecStatement(context.Background(), `UPDATE http_share SET expires_at = ? WHERE share_id = ?`,
		expiresAt.Unix(), shareID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fixture.shares.RunStreamWatch(ctx)
	response, resets := startStreaming(t, fixture, shareID, cookie)
	defer response.Body.Close()
	awaitCut(t, response, resets, time.Until(expiresAt)+1500*time.Millisecond)
	if late := time.Since(expiresAt); late > 1100*time.Millisecond || late < 0 {
		t.Errorf("cut %s after expiry", late)
	}
}
