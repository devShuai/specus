package connectivity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Replays protocol/test-vectors/service-connectivity-check-v1.json through the real Checker: a fake
// route source, a fake device that answers each probe as the case scripts it, and a fake monotonic
// clock that the device moves to the scripted atMs. Status and body must match field by field.

type vectorAnswer struct {
	Kind    string `json:"kind"`
	Status  int    `json:"status"`
	Failure string `json:"failure"`
	Cause   string `json:"cause"`
	AtMs    int64  `json:"atMs"`
}

type vectorCase struct {
	Name  string `json:"name"`
	Input struct {
		Authenticated  *bool  `json:"authenticated"`
		RequestValid   *bool  `json:"requestValid"`
		ConfigReadable *bool  `json:"configReadable"`
		RouteVisible   *bool  `json:"routeVisible"`
		Admission      string `json:"admission"`
		Route          *struct {
			Enabled     bool `json:"enabled"`
			TargetValid bool `json:"targetValid"`
		} `json:"route"`
		Device *struct {
			Enabled            bool `json:"enabled"`
			ControlOnline      bool `json:"controlOnline"`
			DataOnline         bool `json:"dataOnline"`
			HTTPRouteCapabilty *int `json:"httpRouteCapability"`
		} `json:"device"`
		Answers []vectorAnswer `json:"answers"`
	} `json:"input"`
	Expect struct {
		HTTPStatus        int             `json:"httpStatus"`
		Code              string          `json:"code"`
		RetryAfterSeconds int             `json:"retryAfterSeconds"`
		Body              json.RawMessage `json:"body"`
	} `json:"expect"`
}

type rateEvent struct {
	AtMs              int64  `json:"atMs"`
	Username          string `json:"username"`
	RouteID           int64  `json:"routeId"`
	Admitted          bool   `json:"admitted"`
	HTTPStatus        int    `json:"httpStatus"`
	Code              string `json:"code"`
	LimitedBy         string `json:"limitedBy"`
	RetryAfterSeconds int    `json:"retryAfterSeconds"`
}

type checkVector struct {
	CheckBudgetMs int64        `json:"checkBudgetMs"`
	Cases         []vectorCase `json:"cases"`
	Rate          struct {
		PerRoute struct {
			IntervalMs int64 `json:"intervalMs"`
			Burst      int64 `json:"burst"`
		} `json:"perRoute"`
		PerUser struct {
			IntervalMs int64 `json:"intervalMs"`
			Burst      int64 `json:"burst"`
		} `json:"perUser"`
		MaxConcurrentPerRoute  int         `json:"maxConcurrentPerRoute"`
		MaxConcurrentPerServer int         `json:"maxConcurrentPerServer"`
		Events                 []rateEvent `json:"events"`
	} `json:"rate"`
}

func loadCheckVector(t *testing.T) checkVector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "service-connectivity-check-v1.json"))
		if err == nil {
			var vector checkVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatal(err)
			}
			return vector
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("protocol/test-vectors/service-connectivity-check-v1.json not found")
		}
		dir = parent
	}
}

type fakeClock struct{ now int64 }

func (c *fakeClock) NowMs() int64 { return c.now }

type fakeDevice struct {
	clock      *fakeClock
	control    bool
	data       bool
	capability int
	answers    []vectorAnswer
	opened     []map[string]any
	abandoned  int
}

func (d *fakeDevice) Presence(string) (bool, bool) { return d.control, d.data }

func (d *fakeDevice) Open(_ string, metadata map[string]any) (Probe, error) {
	d.opened = append(d.opened, metadata)
	answer := d.answers[0]
	d.answers = d.answers[1:]
	if answer.Kind == "open-failed" {
		d.clock.now = answer.AtMs
		if answer.Cause == "stream-limit" {
			return nil, ErrStreamLimit
		}
		return nil, errors.New("write failed")
	}
	return &fakeProbe{device: d, answer: answer}, nil
}

type fakeProbe struct {
	device *fakeDevice
	answer vectorAnswer
}

func (p *fakeProbe) Capability() int { return p.device.capability }

func (p *fakeProbe) Await(context.Context) (int, error) {
	switch p.answer.Kind {
	case "response":
		p.device.clock.now = p.answer.AtMs
		return p.answer.Status, nil
	case "rst":
		p.device.clock.now = p.answer.AtMs
		return 0, &ResetError{Failure: p.answer.Failure}
	case "link-lost":
		p.device.clock.now = p.answer.AtMs
		return 0, ErrLinkLost
	case "none":
		p.device.clock.now = BudgetMs
		return 0, context.DeadlineExceeded
	}
	panic("unknown answer kind " + p.answer.Kind)
}

func (p *fakeProbe) Abandon() { p.device.abandoned++ }

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func TestConnectivityCheckVector(t *testing.T) {
	vector := loadCheckVector(t)
	if vector.CheckBudgetMs != BudgetMs {
		t.Fatalf("budget %d, vector %d", BudgetMs, vector.CheckBudgetMs)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, testCase := range vector.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			var logs bytes.Buffer
			clock := &fakeClock{}
			device := &fakeDevice{clock: clock, control: true, data: true, answers: testCase.Input.Answers}
			route := &Route{ID: 42, TenantID: "default", ClientName: "device-a", Name: "app",
				TargetBaseURL: "http://127.0.0.1:8080/base", Enabled: true, ClientEnabled: true}
			if r := testCase.Input.Route; r != nil {
				route.Enabled = r.Enabled
				if !r.TargetValid {
					route.TargetBaseURL = "ftp://127.0.0.1/"
				}
			}
			if d := testCase.Input.Device; d != nil {
				route.ClientEnabled = d.Enabled
				device.control, device.data = d.ControlOnline, d.DataOnline
				if d.HTTPRouteCapabilty != nil {
					device.capability = *d.HTTPRouteCapabilty
				}
			}
			checker := newChecker(device, clock, slog.New(slog.NewTextHandler(&logs, nil)))
			request := Request{Principal: &Principal{TenantID: "default", Username: "alice"}, RouteID: "42"}
			if !boolOr(testCase.Input.Authenticated, true) {
				request.Principal = nil
			}
			if !boolOr(testCase.Input.RequestValid, true) {
				request.Body = []byte(`{"path":"/../admin"}`)
			}
			source := func(context.Context, int64) (*Route, error) {
				if !boolOr(testCase.Input.ConfigReadable, true) {
					return nil, errors.New("database unavailable")
				}
				if !boolOr(testCase.Input.RouteVisible, true) {
					return nil, ErrRouteNotFound
				}
				return route, nil
			}
			switch testCase.Input.Admission {
			case "route-in-progress":
				release, refused := checker.admission.admit("default", "admin", route.ID, 0)
				if refused != nil {
					t.Fatalf("occupying the route slot: %+v", refused)
				}
				defer release()
			case "server-busy":
				for id := int64(1); id <= int64(vector.Rate.MaxConcurrentPerServer); id++ {
					release, refused := checker.admission.admit("other", "user-"+itoa(id), 1000+id, 0)
					if refused != nil {
						t.Fatalf("occupying slot %d: %+v", id, refused)
					}
					defer release()
				}
			}

			response := checker.Handle(context.Background(), request, source)
			if response.Status != testCase.Expect.HTTPStatus {
				t.Fatalf("status %d, want %d (body %+v)", response.Status, testCase.Expect.HTTPStatus, response.Body)
			}
			if response.Status != 200 {
				if testCase.Expect.Code != "" {
					refusal, ok := response.Body.(RefusalBody)
					if !ok || refusal.Code != testCase.Expect.Code {
						t.Fatalf("refusal body %+v, want code %s", response.Body, testCase.Expect.Code)
					}
				}
				// The vector pins Retry-After where it states one; every 429 and 503 carries one.
				wantRetry := testCase.Expect.RetryAfterSeconds
				if wantRetry == 0 && (response.Status == 429 || response.Status == 503) {
					wantRetry = 1
				}
				if response.RetryAfterSeconds != wantRetry {
					t.Fatalf("Retry-After %d, want %d", response.RetryAfterSeconds, wantRetry)
				}
				if len(device.opened) != 0 {
					t.Fatal("a refused check reached the device")
				}
				return
			}

			encoded, err := json.Marshal(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if got["routeId"] != float64(42) {
				t.Fatalf("routeId = %v", got["routeId"])
			}
			checkedAt, _ := got["checkedAt"].(string)
			if parsed, err := time.Parse(time.RFC3339, checkedAt); err != nil || !strings.HasSuffix(checkedAt, "Z") ||
				parsed.Nanosecond() != 0 {
				t.Fatalf("checkedAt %q is not UTC RFC 3339 in seconds", checkedAt)
			}
			delete(got, "routeId")
			delete(got, "checkedAt")
			var want map[string]any
			if err := json.Unmarshal(testCase.Expect.Body, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("body mismatch\n got: %s\nwant: %s", encoded, testCase.Expect.Body)
			}
			// Each request sent is exactly one probe, opened with the fixed metadata and always ended.
			requests, _ := got["requests"].([]any)
			if len(device.opened) != len(requests) {
				t.Fatalf("opened %d probes for requests %v", len(device.opened), requests)
			}
			for index, metadata := range device.opened {
				if metadata["method"] != requests[index] || metadata["relativePath"] != "/" ||
					metadata["rawQuery"] != "" || metadata["route"] != "app" ||
					!reflect.DeepEqual(metadata["headers"], []string{"Accept:*/*", "User-Agent:" + UserAgent}) {
					t.Fatalf("probe metadata %#v", metadata)
				}
				if _, ok := metadata["contentLength"]; ok {
					t.Fatalf("probe declares a body: %#v", metadata)
				}
			}
			opened := 0
			for _, answer := range testCase.Input.Answers[:len(requests)] {
				if answer.Kind != "open-failed" {
					opened++
				}
			}
			if device.abandoned != opened {
				t.Fatalf("abandoned %d of %d probe streams", device.abandoned, opened)
			}
			line := logs.String()
			if !strings.Contains(line, "[connectivity-check] tenant=default user=alice route=42 outcome=") ||
				strings.Contains(line, "127.0.0.1") {
				t.Fatalf("log line %q", line)
			}
		})
	}
}

func TestConnectivityRateVector(t *testing.T) {
	vector := loadCheckVector(t)
	if vector.Rate.PerRoute.IntervalMs != routeIntervalMs || vector.Rate.PerRoute.Burst != routeBurst ||
		vector.Rate.PerUser.IntervalMs != userIntervalMs || vector.Rate.PerUser.Burst != userBurst ||
		vector.Rate.MaxConcurrentPerRoute != 1 || vector.Rate.MaxConcurrentPerServer != maxConcurrentPerServer {
		t.Fatalf("rate parameters differ from the vector: %+v", vector.Rate)
	}
	limits := newAdmission()
	for index, event := range vector.Rate.Events {
		refused := limits.rate("default", event.Username, event.RouteID, event.AtMs)
		if event.Admitted != (refused == nil) {
			t.Fatalf("event %d %+v: refused %+v", index, event, refused)
		}
		if refused != nil && (refused.status != event.HTTPStatus || refused.code != event.Code ||
			refused.limitedBy != event.LimitedBy || refused.retryAfterSeconds != event.RetryAfterSeconds) {
			t.Fatalf("event %d %+v: refused %+v", index, event, refused)
		}
	}
}

// The same events through Handle: a refused check answers 429 with Retry-After, consumes nothing
// and never reaches the device; one log line per caller and minute.
func TestConnectivityRateEventsThroughHandle(t *testing.T) {
	vector := loadCheckVector(t)
	clock := &fakeClock{}
	device := &fakeDevice{clock: clock}
	var logs bytes.Buffer
	checker := newChecker(device, clock, slog.New(slog.NewTextHandler(&logs, nil)))
	for index, event := range vector.Rate.Events {
		clock.now = event.AtMs
		route := &Route{ID: event.RouteID, TenantID: "default", ClientName: "device", Name: "app",
			TargetBaseURL: "http://127.0.0.1/", Enabled: true, ClientEnabled: true}
		response := checker.Handle(context.Background(), Request{
			Principal: &Principal{TenantID: "default", Username: event.Username},
			RouteID:   itoa(event.RouteID),
		}, func(context.Context, int64) (*Route, error) { return route, nil })
		if event.Admitted {
			if response.Status != 200 {
				t.Fatalf("event %d: status %d", index, response.Status)
			}
			continue
		}
		if response.Status != event.HTTPStatus || response.RetryAfterSeconds != event.RetryAfterSeconds ||
			response.Body.(RefusalBody).Code != event.Code {
			t.Fatalf("event %d: %+v", index, response)
		}
	}
	refusals := strings.Count(logs.String(), "refused code=CHECK_RATE_LIMITED")
	// alice is refused at 1, 9999, 10008 and 40000, all within a minute of the first, so one line;
	// admin is refused once at 10000.
	if refusals != 2 {
		t.Fatalf("logged %d rate refusals:\n%s", refusals, logs.String())
	}
}

func itoa(value int64) string { return strconv.FormatInt(value, 10) }

func TestConnectivityRequestBody(t *testing.T) {
	valid := map[string]string{
		"":                             "/",
		"  ":                           "/",
		"{}":                           "/",
		`{"path":"/healthz"}`:          "/healthz",
		`{"path":"/"}`:                 "/",
		`{"path":"/a//b"}`:             "/a//b",
		`{"path":"/v1/%E4%B8%AD"}`:     "/v1/%E4%B8%AD",
		`{"path":"/a.b/..c/~x"}`:       "/a.b/..c/~x",
		`{"path":"/a:b@c!$&'()*+,;="}`: "/a:b@c!$&'()*+,;=",
	}
	for body, want := range valid {
		if got, ok := parseRequestBody([]byte(body)); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", body, got, ok, want)
		}
	}
	invalid := []string{
		"null", "[]", `"x"`, "1", "{", `{"path":null}`, `{"path":1}`, `{"other":"/"}`,
		`{"path":"/","x":1}`, `{} {}`, `{"path":""}`, `{"path":"healthz"}`, `{"path":"//evil.example/"}`,
		`{"path":"/a?b"}`, `{"path":"/a#b"}`, `{"path":"/a\\b"}`, `{"path":"/a b"}`, `{"path":"/a\tb"}`,
		`{"path":"/."}`, `{"path":"/a/../b"}`, `{"path":"/%2e%2E/x"}`, `{"path":"/a/%2e"}`,
		`{"path":"/%zz"}`, `{"path":"/%4"}`, `{"path":"/` + strings.Repeat("a", 256) + `"}`,
		`{"path":"/ä"}`,
	}
	for _, body := range invalid {
		if got, ok := parseRequestBody([]byte(body)); ok {
			t.Errorf("%q accepted as %q", body, got)
		}
	}
	if _, ok := parseRequestBody(bytes.Repeat([]byte(" "), MaxBodyBytes+1)); ok {
		t.Error("an oversized body was accepted")
	}
	if _, ok := parseRequestBody([]byte(`{"path":"/` + strings.Repeat("a", 255) + `"}`)); !ok {
		t.Error("a 256-byte path was refused")
	}
}

func TestValidTargetBaseURL(t *testing.T) {
	for _, value := range []string{"http://127.0.0.1:8080", "https://example.com/base/", "HTTP://host"} {
		if !ValidTargetBaseURL(value) {
			t.Errorf("%q refused", value)
		}
	}
	for _, value := range []string{"", "ftp://host/", "http://", "/relative", "http:///path", "host:80"} {
		if ValidTargetBaseURL(value) {
			t.Errorf("%q accepted", value)
		}
	}
}

// A slow probe holds the route slot: a second check of the same route is refused while it runs.
func TestConnectivityOneCheckPerRoute(t *testing.T) {
	clock := &fakeClock{}
	block := make(chan struct{})
	device := &blockingDevice{release: block, waiting: make(chan struct{})}
	checker := newChecker(device, clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
	route := &Route{ID: 7, TenantID: "default", ClientName: "device", Name: "app",
		TargetBaseURL: "http://127.0.0.1/", Enabled: true, ClientEnabled: true}
	source := func(context.Context, int64) (*Route, error) { return route, nil }
	done := make(chan Response, 1)
	go func() {
		done <- checker.Handle(context.Background(), Request{
			Principal: &Principal{TenantID: "default", Username: "alice"}, RouteID: "7"}, source)
	}()
	<-device.waiting
	second := checker.Handle(context.Background(), Request{
		Principal: &Principal{TenantID: "default", Username: "admin"}, RouteID: "7"}, source)
	if second.Status != 429 || second.Body.(RefusalBody).Code != "CHECK_IN_PROGRESS" || second.RetryAfterSeconds != 1 {
		t.Fatalf("second check: %+v", second)
	}
	close(block)
	if first := <-done; first.Status != 200 {
		t.Fatalf("first check: %+v", first)
	}
}

type blockingDevice struct {
	release chan struct{}
	waiting chan struct{}
}

func (d *blockingDevice) Presence(string) (bool, bool) { return true, true }

func (d *blockingDevice) Open(string, map[string]any) (Probe, error) { return d, nil }

func (d *blockingDevice) Capability() int { return 1 }

func (d *blockingDevice) Await(ctx context.Context) (int, error) {
	close(d.waiting)
	<-d.release
	return 204, nil
}

func (d *blockingDevice) Abandon() {}
