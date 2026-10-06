// Package connectivity runs the service connectivity check of one HTTP route: the four stages
// configured, device online, target reachable and access succeeded, decided in that order by a
// bounded HEAD (and at most one GET) sent through the device's data connection.
//
// The contract is protocol/spec/service-connectivity-check.md; the shared vector
// protocol/test-vectors/service-connectivity-check-v1.json pins every outcome, and
// tools/protocol/generate_service_connectivity_vectors.py holds the reference state machine this
// file follows.
package connectivity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// BudgetMs bounds one check from the start of request handling, HEAD and GET together.
	BudgetMs = 10_000
	// UserAgent lets the target's access log recognise the probe.
	UserAgent = "specus-connectivity-check/1"
	// probeResetCode is the RST value the server sends to end a probe stream; clients do not read it.
	probeResetCode   = 1
	probeResetReason = "connectivity check finished"
)

// Stage names, in their fixed order.
const (
	StageConfigured      = "configured"
	StageDeviceOnline    = "device-online"
	StageTargetReachable = "target-reachable"
	StageAccess          = "access-succeeded"
)

var stageOrder = [...]string{StageConfigured, StageDeviceOnline, StageTargetReachable, StageAccess}

const (
	resultPassed     = "passed"
	resultFailed     = "failed"
	resultUnverified = "unverified"
	resultSkipped    = "skipped"
)

// rstFailures maps a trusted RST metadata.failure to the stage and code it decides (section 6.2).
var rstFailures = map[string][2]string{
	"route-not-loaded": {StageDeviceOnline, "DEVICE_ROUTE_NOT_LOADED"},
	"target-invalid":   {StageTargetReachable, "TARGET_ADDRESS_INVALID"},
	"connect-refused":  {StageTargetReachable, "TARGET_CONNECT_REFUSED"},
	"connect-timeout":  {StageTargetReachable, "TARGET_CONNECT_TIMEOUT"},
	"dns-failed":       {StageTargetReachable, "TARGET_DNS_FAILED"},
	"tls-failed":       {StageTargetReachable, "TARGET_TLS_FAILED"},
	"unreachable":      {StageTargetReachable, "TARGET_UNREACHABLE"},
	"protocol-error":   {StageTargetReachable, "TARGET_PROTOCOL_ERROR"},
}

// Clock is a monotonic millisecond clock; tests inject one to replay the vector's timings.
type Clock interface {
	NowMs() int64
}

type monotonicClock struct{ origin time.Time }

func (c monotonicClock) NowMs() int64 { return time.Since(c.origin).Milliseconds() }

// Route is what the check needs to know about one route the caller may see.
type Route struct {
	ID            int64
	TenantID      string
	ClientName    string
	Name          string
	TargetBaseURL string
	Enabled       bool
	ClientEnabled bool
}

// ErrRouteNotFound is returned by a RouteSource for a route that is absent or not visible to the
// caller; both answer the same 404 so route ids cannot be enumerated across tenants.
var ErrRouteNotFound = errors.New("route not found")

// RouteSource loads one route on behalf of the authenticated caller. Any error other than
// ErrRouteNotFound means the records could not be read (503, never "not configured").
type RouteSource func(ctx context.Context, routeID int64) (*Route, error)

// ErrStreamLimit is returned by Device.Open when the data connection already carries as many
// streams as the server allows; the probe shares that cap with public requests.
var ErrStreamLimit = errors.New("data connection stream limit reached")

// ErrLinkLost is returned by Probe.Await when the data connection closed or was replaced before the
// device answered.
var ErrLinkLost = errors.New("data connection lost")

// ResetError is a device RST before the response head. Failure is metadata.failure, "" if absent.
type ResetError struct{ Failure string }

func (e *ResetError) Error() string { return "probe reset by device" }

// Device reaches clients through this process's connections.
type Device interface {
	// Presence reports whether the client has an authenticated control session and a bound data
	// connection right now. No reconnect grace: the check reports the present state.
	Presence(clientName string) (control, data bool)
	// Open hands one probe request to the device: OPEN with metadata, then the request FIN.
	// ErrStreamLimit when the stream cap is reached; any other error means the link is gone.
	Open(clientName string, metadata map[string]any) (Probe, error)
}

// Probe is one probe request in flight.
type Probe interface {
	// Capability is clientHttpRouteCapabilities.version of the session the probe runs on.
	Capability() int
	// Await returns the relayed response status, a *ResetError, ErrLinkLost, or ctx.Err().
	Await(ctx context.Context) (int, error)
	// Abandon ends the stream: RST unless it already ended both ways. The body is never read.
	Abandon()
}

// Principal is the authenticated management caller; nil means no valid session.
type Principal struct {
	TenantID string
	Username string
}

// Request is one connectivity check call as the HTTP layer received it.
type Request struct {
	Principal *Principal
	RouteID   string
	// Body holds at most maxBodyBytes+1 bytes of the request body.
	Body []byte
}

// Response is what the HTTP layer writes: status, JSON body and, for 429/503, Retry-After.
type Response struct {
	Status            int
	Body              any
	RetryAfterSeconds int
}

// RefusalBody is the body of every non-200 answer.
type RefusalBody struct {
	Code string `json:"code"`
}

// StageResult is one of the four stages; a skipped stage has neither code nor atMs.
type StageResult struct {
	Stage  string `json:"stage"`
	Result string `json:"result"`
	Code   string `json:"code,omitempty"`
	AtMs   *int64 `json:"atMs,omitempty"`
}

// Result is the 200 body.
type Result struct {
	SchemaVersion int           `json:"schemaVersion"`
	Kind          string        `json:"kind"`
	RouteID       int64         `json:"routeId"`
	CheckedAt     string        `json:"checkedAt"`
	Outcome       string        `json:"outcome"`
	StoppedAt     *string       `json:"stoppedAt"`
	Code          string        `json:"code"`
	TotalMs       int64         `json:"totalMs"`
	Requests      []string      `json:"requests"`
	Stages        []StageResult `json:"stages"`
	StatusClass   string        `json:"statusClass,omitempty"`
}

// Checker runs connectivity checks. One instance serves the whole process: it owns the
// concurrency slots and the rate limiter.
type Checker struct {
	device    Device
	clock     Clock
	wall      func() time.Time
	admission *admission
	logger    *slog.Logger
	requestID func() string
}

// NewChecker builds the process-wide checker.
func NewChecker(device Device, logger *slog.Logger) *Checker {
	clock := monotonicClock{origin: time.Now()}
	return newChecker(device, clock, logger)
}

func newChecker(device Device, clock Clock, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Checker{
		device: device, clock: clock, wall: time.Now, admission: newAdmission(),
		logger: logger, requestID: randomRequestID,
	}
}

// Handle answers one check request in the order of section 3.2: 401, 400, 503 (records unreadable),
// 404, 429 (route in progress), 503 (process busy), 429 (rate), then the check itself (200).
func (c *Checker) Handle(ctx context.Context, request Request, routes RouteSource) Response {
	start := c.clock.NowMs()
	checkedAt := c.wall().UTC().Truncate(time.Second).Format(time.RFC3339)
	if request.Principal == nil {
		// The management layer answers this with its usual unauthenticated response.
		return Response{Status: 401}
	}
	path, ok := parseRequestBody(request.Body)
	if !ok {
		return refusal(400, "CHECK_REQUEST_INVALID", 0)
	}
	routeID, err := strconv.ParseInt(request.RouteID, 10, 64)
	if err != nil || routeID <= 0 {
		return refusal(404, "CHECK_TARGET_NOT_FOUND", 0)
	}
	route, err := routes(ctx, routeID)
	if errors.Is(err, ErrRouteNotFound) || (err == nil && route == nil) {
		return refusal(404, "CHECK_TARGET_NOT_FOUND", 0)
	}
	if err != nil {
		return refusal(503, "CHECK_UNAVAILABLE", 1)
	}

	tenant, user := request.Principal.TenantID, request.Principal.Username
	release, refused := c.admission.admit(tenant, user, route.ID, c.clock.NowMs())
	if refused != nil {
		if refused.code == "CHECK_RATE_LIMITED" && c.admission.shouldLogRefusal(tenant, user, c.clock.NowMs()) {
			c.logger.Info(fmt.Sprintf("[connectivity-check] tenant=%s user=%s route=%d refused code=%s retryAfter=%d",
				tenant, user, route.ID, refused.code, refused.retryAfterSeconds))
		}
		return refusal(refused.status, refused.code, refused.retryAfterSeconds)
	}
	defer release()

	result := c.run(ctx, start, route, path)
	result.RouteID = route.ID
	result.CheckedAt = checkedAt
	stage := "-"
	if result.StoppedAt != nil {
		stage = *result.StoppedAt
	}
	c.logger.Info(fmt.Sprintf("[connectivity-check] tenant=%s user=%s route=%d outcome=%s stage=%s code=%s totalMs=%d",
		tenant, user, route.ID, result.Outcome, stage, result.Code, result.TotalMs))
	return Response{Status: 200, Body: result}
}

func refusal(status int, code string, retryAfterSeconds int) Response {
	return Response{Status: status, Body: RefusalBody{Code: code}, RetryAfterSeconds: retryAfterSeconds}
}

// stages accumulates decisions in order; the first stage that did not pass ends the check.
type stages struct {
	decided  []StageResult
	requests []string
	class    string
}

func (s *stages) decide(stage, result, code string, atMs int64) {
	at := atMs
	s.decided = append(s.decided, StageResult{Stage: stage, Result: result, Code: code, AtMs: &at})
}

func (s *stages) finish() Result {
	all := make([]StageResult, 0, len(stageOrder))
	all = append(all, s.decided...)
	for _, stage := range stageOrder[len(s.decided):] {
		all = append(all, StageResult{Stage: stage, Result: resultSkipped})
	}
	last := s.decided[len(s.decided)-1]
	outcome := map[string]string{resultPassed: "succeeded", resultFailed: "failed",
		resultUnverified: "unverified"}[last.Result]
	var stoppedAt *string
	if outcome != "succeeded" {
		stage := last.Stage
		stoppedAt = &stage
	}
	requests := s.requests
	if requests == nil {
		requests = []string{}
	}
	return Result{
		SchemaVersion: 1, Kind: "http-route", Outcome: outcome, StoppedAt: stoppedAt, Code: last.Code,
		TotalMs: *last.AtMs, Requests: requests, Stages: all, StatusClass: s.class,
	}
}

// answer is what the device did with one probe request.
type answer struct {
	kind       string // response, rst, link-lost, open-failed, none
	status     int
	failure    string
	trusted    bool
	streamFull bool
	atMs       int64
}

func (c *Checker) run(ctx context.Context, start int64, route *Route, path string) Result {
	s := &stages{}
	// Stage 1: the server's own records.
	switch {
	case !route.Enabled:
		s.decide(StageConfigured, resultFailed, "ROUTE_DISABLED", 0)
		return s.finish()
	case !route.ClientEnabled:
		s.decide(StageConfigured, resultFailed, "CLIENT_DISABLED", 0)
		return s.finish()
	case !ValidTargetBaseURL(route.TargetBaseURL):
		s.decide(StageConfigured, resultFailed, "ROUTE_TARGET_INVALID", 0)
		return s.finish()
	}
	s.decide(StageConfigured, resultPassed, "CONFIGURED", 0)

	// Stage 2 preconditions: a control session and its data connection, as they are now.
	control, data := c.device.Presence(route.ClientName)
	if !control {
		s.decide(StageDeviceOnline, resultFailed, "DEVICE_OFFLINE", 0)
		return s.finish()
	}
	if !data {
		s.decide(StageDeviceOnline, resultFailed, "DEVICE_DATA_CHANNEL_DOWN", 0)
		return s.finish()
	}

	head := c.exchange(ctx, s, start, route, "HEAD", path)
	switch head.kind {
	case "open-failed":
		code := "DEVICE_LINK_LOST"
		if head.streamFull {
			code = "DEVICE_BUSY"
		}
		s.decide(StageDeviceOnline, resultFailed, code, head.atMs)
		return s.finish()
	case "none":
		s.decide(StageDeviceOnline, resultPassed, "DEVICE_ONLINE", BudgetMs)
		s.decide(StageTargetReachable, resultFailed, "TARGET_TIMEOUT", BudgetMs)
		return s.finish()
	case "link-lost":
		s.decide(StageDeviceOnline, resultFailed, "DEVICE_LINK_LOST", head.atMs)
		return s.finish()
	case "rst":
		if mapped, known := rstFailures[head.failure]; head.trusted && known {
			if mapped[0] == StageDeviceOnline {
				s.decide(StageDeviceOnline, resultFailed, mapped[1], head.atMs)
				return s.finish()
			}
			s.decide(StageDeviceOnline, resultPassed, "DEVICE_ONLINE", head.atMs)
			s.decide(StageTargetReachable, resultFailed, mapped[1], head.atMs)
			return s.finish()
		}
		// An older client, no classification, or one this server does not know: the device
		// answered, but nothing says whether the target was reached. Never guess from the reason.
		s.decide(StageDeviceOnline, resultPassed, "DEVICE_ONLINE", head.atMs)
		s.decide(StageTargetReachable, resultUnverified, "TARGET_UNVERIFIED", head.atMs)
		return s.finish()
	}

	s.decide(StageDeviceOnline, resultPassed, "DEVICE_ONLINE", head.atMs)
	if head.status < 200 || head.status > 599 {
		// Not a final answer the target could have meant; clients never relay one.
		s.decide(StageTargetReachable, resultFailed, "TARGET_PROTOCOL_ERROR", head.atMs)
		return s.finish()
	}
	s.decide(StageTargetReachable, resultPassed, "TARGET_ANSWERED", head.atMs)
	if head.status != 405 && head.status != 501 {
		result, code := accessCode(head.status)
		s.decide(StageAccess, result, code, head.atMs)
		s.class = statusClass(head.status)
		return s.finish()
	}

	// HEAD refused by method: one GET within what is left of the same budget.
	get := c.exchange(ctx, s, start, route, "GET", path)
	if get.kind == "response" && get.status >= 200 && get.status <= 599 {
		result, code := accessCode(get.status)
		s.decide(StageAccess, result, code, get.atMs)
		s.class = statusClass(get.status)
		return s.finish()
	}
	at := get.atMs
	if get.kind == "none" {
		at = BudgetMs
	}
	s.decide(StageAccess, resultFailed, "ACCESS_NO_ANSWER", at)
	return s.finish()
}

// exchange sends one probe request and waits for the device's first answer within the budget.
func (c *Checker) exchange(ctx context.Context, s *stages, start int64, route *Route, method, path string) answer {
	s.requests = append(s.requests, method)
	probe, err := c.device.Open(route.ClientName, probeMetadata(c.requestID(), method, route.Name, path))
	if err != nil {
		return answer{kind: "open-failed", streamFull: errors.Is(err, ErrStreamLimit), atMs: c.elapsed(start)}
	}
	defer probe.Abandon()
	remaining := start + BudgetMs - c.clock.NowMs()
	if remaining <= 0 {
		return answer{kind: "none", atMs: BudgetMs}
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(remaining)*time.Millisecond)
	defer cancel()
	status, err := probe.Await(waitCtx)
	at := c.elapsed(start)
	var reset *ResetError
	switch {
	case err == nil:
		if at >= BudgetMs {
			return answer{kind: "none", atMs: BudgetMs}
		}
		return answer{kind: "response", status: status, atMs: at}
	case errors.As(err, &reset):
		if at >= BudgetMs {
			return answer{kind: "none", atMs: BudgetMs}
		}
		return answer{kind: "rst", failure: reset.Failure, trusted: probe.Capability() >= 1, atMs: at}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// Budget spent, or the admin caller went away: nobody reads a later answer.
		return answer{kind: "none", atMs: BudgetMs}
	default:
		if at >= BudgetMs {
			return answer{kind: "none", atMs: BudgetMs}
		}
		return answer{kind: "link-lost", atMs: at}
	}
}

func (c *Checker) elapsed(start int64) int64 {
	elapsed := c.clock.NowMs() - start
	if elapsed < 0 {
		return 0
	}
	if elapsed > BudgetMs {
		return BudgetMs
	}
	return elapsed
}

func probeMetadata(requestID, method, route, path string) map[string]any {
	return map[string]any{
		"source": "http", "phase": "request", "requestId": requestID, "method": method,
		"route": route, "relativePath": path, "rawQuery": "",
		"headers": []string{"Accept:*/*", "User-Agent:" + UserAgent},
	}
}

func accessCode(status int) (string, string) {
	switch {
	case status >= 200 && status <= 399:
		return resultPassed, "ACCESS_OK"
	case status == 401 || status == 403 || status == 407:
		// The target wants its own credentials; the check never sends any.
		return resultUnverified, "ACCESS_AUTH_REQUIRED"
	case status == 404 || status == 410:
		return resultFailed, "ACCESS_NOT_FOUND"
	case status >= 400 && status <= 499:
		return resultFailed, "ACCESS_CLIENT_ERROR"
	default:
		return resultFailed, "ACCESS_SERVER_ERROR"
	}
}

func statusClass(status int) string { return strconv.Itoa(status/100) + "xx" }

// ValidTargetBaseURL is the configured stage's defensive check of a stored targetBaseUrl: an
// absolute http or https URL with a host.
func ValidTargetBaseURL(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return (scheme == "http" || scheme == "https") && parsed.Host != "" && parsed.Hostname() != ""
}

func randomRequestID() string {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buffer[:])
}
