package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// shareDevice is a fake client data channel: it answers every HTTP OPEN with what it received,
// except /stream, which sends one chunk and then waits for the server to reset the stream.
type shareDevice struct {
	mu     sync.Mutex
	opens  []map[string]any
	resets chan uint32
}

func runShareDevice(t *testing.T, dataConn net.Conn, dataReader *bufio.Reader) *shareDevice {
	t.Helper()
	device := &shareDevice{resets: make(chan uint32, 8)}
	go func() {
		for {
			packet, err := readProtocolPacket(dataReader)
			if err != nil {
				return
			}
			message, ok := packet.(protocol.NatMessage)
			if !ok {
				continue
			}
			if message.Type == protocol.NatRST {
				device.resets <- message.StreamID
				continue
			}
			if message.Type != protocol.NatOpen || fmt.Sprint(message.Metadata["source"]) != "http" {
				continue
			}
			device.mu.Lock()
			device.opens = append(device.opens, message.Metadata)
			device.mu.Unlock()
			_ = protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatOpen, StreamID: message.StreamID,
				Metadata: map[string]any{"source": "http", "phase": "response", "statusCode": 200,
					"headers": []string{"Content-Type:text/plain", "Set-Cookie:session=1; Path=/; Domain=example.com",
						"Cache-Control:public, max-age=600"}}})
			body := []byte("hello from the device\n")
			if message.Metadata["relativePath"] == "/stream" {
				body = []byte("first chunk\n")
			}
			_ = protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatData, StreamID: message.StreamID, Data: body})
			if message.Metadata["relativePath"] != "/stream" {
				_ = protocol.WritePacket(dataConn, protocol.NatMessage{Type: protocol.NatFin, StreamID: message.StreamID})
			}
		}
	}()
	return device
}

func (d *shareDevice) last() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.opens) == 0 {
		return nil
	}
	return d.opens[len(d.opens)-1]
}

func deviceHeaders(metadata map[string]any, name string) []string {
	var values []string
	items, _ := metadata["headers"].([]any)
	for _, item := range items {
		key, value, _ := strings.Cut(fmt.Sprint(item), ":")
		if strings.EqualFold(strings.TrimSpace(key), name) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

func shareGet(t *testing.T, url, cookie string, header http.Header) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	client := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return response
}

func decodeCode(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(response.Body).Decode(&body)
	return body.Code
}

// TestHTTPShareEndToEnd drives a share through the whole server: the admin API creates it, the
// public exchange sets the cookie, a request reaches the client's data channel without the token,
// an in-flight stream is cut by the revocation, and a route change ends a second share.
func TestHTTPShareEndToEnd(t *testing.T) {
	app, port := startTestApp(t)
	_, ts := newHTTPTestServer(t, app)
	token := adminToken(t, ts)
	demo := findClient(t, listClients(t, ts, token), DemoClientName)

	resp := authRequest(t, ts, http.MethodPost, "/api/admin/clients/"+itoa(demo.ID)+"/http-routes", token,
		`{"route":"web","targetBaseUrl":"http://127.0.0.1:8080","enabled":true,`+
			`"authEnabled":true,"authUsername":"route-user","authPassword":"route-password"}`)
	var route struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&route)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create route %d", resp.StatusCode)
	}
	routePath := "/api/admin/http-routes/" + itoa(route.ID)

	createShare := func() (string, string) {
		t.Helper()
		resp := authRequest(t, ts, http.MethodPost, routePath+"/shares", token, `{"expiresInSeconds":600}`)
		defer resp.Body.Close()
		var created struct {
			Share    httpshare.ShareView `json:"share"`
			Token    string              `json:"token"`
			LinkPath string              `json:"linkPath"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&created)
		if resp.StatusCode != http.StatusCreated || created.LinkPath != "/#/http-share/"+created.Token ||
			resp.Header.Get("Cache-Control") != "private, no-store" {
			t.Fatalf("create share %d %+v", resp.StatusCode, created)
		}
		return created.Share.ShareID, created.Token
	}
	shareID, shareToken := createShare()

	// The landing page exchanges the token for the cookie.
	exchange, err := http.Post(ts.URL+"/api/public/http-shares/exchange", "application/json",
		strings.NewReader(`{"token":"`+shareToken+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var exchanged struct {
		Location string `json:"location"`
	}
	_ = json.NewDecoder(exchange.Body).Decode(&exchanged)
	exchange.Body.Close()
	cookieFor := func(maxAge string) string {
		return httpshare.CookieName + "=" + shareToken + "; Path=/http-share/" + shareID + "/; Max-Age=" + maxAge +
			"; HttpOnly; Secure; SameSite=Strict"
	}
	setCookie := exchange.Header.Get("Set-Cookie")
	if exchange.StatusCode != http.StatusOK || exchanged.Location != "/http-share/"+shareID+"/" ||
		setCookie != cookieFor("600") && setCookie != cookieFor("599") ||
		exchange.Header.Get("Cache-Control") != "no-store" ||
		exchange.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("exchange %d %q %v", exchange.StatusCode, exchanged.Location, exchange.Header)
	}
	cookie := "theme=dark; " + httpshare.CookieName + "=" + shareToken

	controlConn, dataConn, dataReader := loginHTTPTestChannels(t, app, port)
	defer controlConn.Close()
	defer dataConn.Close()
	device := runShareDevice(t, dataConn, dataReader)

	response := shareGet(t, ts.URL+"/http-share/"+shareID+"/hello?x=%2F1", cookie,
		http.Header{"Authorization": {"Bearer upstream"}})
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "hello from the device\n" {
		t.Fatalf("share GET %d %q", response.StatusCode, body)
	}
	opened := device.last()
	if opened["route"] != "web" || opened["relativePath"] != "/hello" || opened["rawQuery"] != "x=%2F1" {
		t.Fatalf("device saw %v", opened)
	}
	if got := deviceHeaders(opened, "Cookie"); len(got) != 1 || got[0] != "theme=dark" {
		t.Fatalf("device Cookie %q", got)
	}
	if got := deviceHeaders(opened, "Authorization"); len(got) != 1 || got[0] != "Bearer upstream" {
		t.Fatalf("device Authorization %q", got)
	}
	if encoded, _ := json.Marshal(opened); strings.Contains(string(encoded), shareToken) {
		t.Fatalf("the token reached the device: %s", encoded)
	}
	if response.Header.Get("Set-Cookie") != "session=1; Path=/http-share/"+shareID+"/" ||
		response.Header.Get("Cache-Control") != "private, no-cache" ||
		response.Header.Get("Content-Security-Policy") != "" || response.Header.Get("X-Frame-Options") != "" {
		t.Fatalf("share response headers %v", response.Header)
	}

	// The entry sees the raw path: a dot segment is refused, not resolved by the mux.
	dotted := shareGet(t, ts.URL+"/http-share/"+shareID+"/a/../b", cookie, nil)
	if dotted.StatusCode != http.StatusOK {
		// The whole-route share has no path rules of its own; the request goes to the device raw.
		t.Fatalf("whole-route share dotted path %d", dotted.StatusCode)
	}
	dotted.Body.Close()
	if device.last()["relativePath"] != "/a/../b" {
		t.Fatalf("dotted path forwarded as %v", device.last()["relativePath"])
	}
	redirect := shareGet(t, ts.URL+"/http-share/"+shareID+"?q=1", "", nil)
	redirect.Body.Close()
	if redirect.StatusCode != http.StatusPermanentRedirect || redirect.Header.Get("Location") != "/http-share/"+shareID+"/?q=1" {
		t.Fatalf("missing slash %d %q", redirect.StatusCode, redirect.Header.Get("Location"))
	}

	// An in-flight response is cut the moment the share is revoked on this instance.
	stream := shareGet(t, ts.URL+"/http-share/"+shareID+"/stream", cookie, nil)
	chunk := make([]byte, len("first chunk\n"))
	if _, err := io.ReadFull(stream.Body, chunk); err != nil {
		t.Fatalf("first chunk: %v", err)
	}
	revoke := authRequest(t, ts, http.MethodPost, routePath+"/shares/"+shareID+"/revoke", token, "")
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("revoke %d", revoke.StatusCode)
	}
	cut := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(stream.Body)
		cut <- err
	}()
	select {
	case err := <-cut:
		if err == nil {
			t.Fatal("the revoked stream ended like a complete response")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the revoked stream was not cut")
	}
	select {
	case <-device.resets:
	case <-time.After(5 * time.Second):
		t.Fatal("the device never got RST for the cut stream")
	}
	stream.Body.Close()
	gone := shareGet(t, ts.URL+"/http-share/"+shareID+"/hello", cookie, nil)
	if gone.StatusCode != http.StatusGone || !strings.Contains(gone.Header.Get("Set-Cookie"), "Max-Age=0") ||
		decodeCode(t, gone) != httpshare.CodeRevoked {
		t.Fatalf("after revoke %d %v", gone.StatusCode, gone.Header)
	}

	// Disabling the route ends a second share through the route hook; enabling it again does
	// not bring the share back.
	secondID, secondToken := createShare()
	secondCookie := httpshare.CookieName + "=" + secondToken
	disable := authRequest(t, ts, http.MethodPut, routePath, token,
		`{"route":"web","targetBaseUrl":"http://127.0.0.1:8080","enabled":false}`)
	disable.Body.Close()
	enable := authRequest(t, ts, http.MethodPut, routePath, token,
		`{"route":"web","targetBaseUrl":"http://127.0.0.1:8080","enabled":true}`)
	enable.Body.Close()
	if disable.StatusCode != http.StatusOK || enable.StatusCode != http.StatusOK {
		t.Fatalf("route update %d %d", disable.StatusCode, enable.StatusCode)
	}
	ended := shareGet(t, ts.URL+"/http-share/"+secondID+"/", secondCookie, nil)
	if ended.StatusCode != http.StatusGone || decodeCode(t, ended) != httpshare.CodeRevoked {
		t.Fatalf("share after route disabled %d", ended.StatusCode)
	}
	audit := authRequest(t, ts, http.MethodGet, routePath+"/access-audit", token, "")
	var page struct {
		Entries []httpshare.AuditView `json:"entries"`
	}
	_ = json.NewDecoder(audit.Body).Decode(&page)
	audit.Body.Close()
	var actions []string
	for _, entry := range page.Entries {
		actions = append(actions, entry.Action+":"+string(entry.Detail))
	}
	want := []string{
		`route.exposure-changed:{"from":"disabled","to":"protected"}`,
		`share.revoked:{"reason":"route-disabled"}`,
		`route.exposure-changed:{"from":"protected","to":"disabled"}`,
		`share.created:`, `share.revoked:{"reason":"revoked-by-user"}`, `share.created:`, `route.created:{"exposure":"protected"}`,
	}
	if len(actions) != len(want) {
		t.Fatalf("audit %q", actions)
	}
	for i := range want {
		if !strings.HasPrefix(actions[i], want[i]) {
			t.Fatalf("audit %q, want %q", actions, want)
		}
	}
}
