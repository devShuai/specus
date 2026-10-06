package httpshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	roleAdmin        = "ADMIN"
	maxExchangeBytes = 4096
	maxCreateBytes   = 4096
)

// BuiltInAdmin describes the configured administrator that is not a row of the user table. While
// the server accepts it as a principal it counts as an enabled admin of its tenant, so its shares
// do not lapse for want of a creator.
type BuiltInAdmin struct {
	Username string
	TenantID string
	Enabled  func() bool
}

// Caller is the authenticated identity of a management request.
type Caller struct {
	Username string
	TenantID string
}

type principal struct {
	username string
	tenantID string
	admin    bool
}

// Result is a management or exchange answer: a status, an error code or a body, and headers.
type Result struct {
	Status  int
	Code    string
	Body    any
	Headers http.Header
}

// ShareView is the share object of the management API.
type ShareView struct {
	ShareID      string  `json:"shareId"`
	RouteID      int64   `json:"routeId"`
	Label        *string `json:"label"`
	Access       string  `json:"access"`
	PathPrefix   string  `json:"pathPrefix"`
	SharePath    string  `json:"sharePath"`
	CreatedAt    string  `json:"createdAt"`
	CreatedBy    string  `json:"createdBy"`
	ExpiresAt    string  `json:"expiresAt"`
	Status       string  `json:"status"`
	RevokedAt    *string `json:"revokedAt"`
	RevokedBy    *string `json:"revokedBy"`
	RevokeReason *string `json:"revokeReason"`
}

// AuditView is one audit entry of the management API.
type AuditView struct {
	AuditID int64           `json:"auditId"`
	At      string          `json:"at"`
	Actor   *string         `json:"actor"`
	Action  string          `json:"action"`
	RouteID int64           `json:"routeId"`
	ShareID *string         `json:"shareId"`
	Detail  json.RawMessage `json:"detail"`
}

// Service decides everything about temporary HTTP shares. Authorization is never cached: every
// decision reads the share, its route, client and creator from the database.
type Service struct {
	db       *store.DB
	builtIn  BuiltInAdmin
	logger   *slog.Logger
	mu       sync.RWMutex
	now      func() time.Time
	random   io.Reader
	exchange *Limiter
	perShare *Limiter
	streams  *Streams
}

// NewService builds the share service over db.
func NewService(db *store.DB, builtIn BuiltInAdmin, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{db: db, builtIn: builtIn, logger: logger, now: time.Now, random: rand.Reader,
		exchange: NewLimiter(ExchangeIntervalMs, ExchangeBurst), perShare: NewLimiter(ShareIntervalMs, ShareBurst),
		streams: NewStreams(MaxConcurrentPerShare)}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// SetRandom replaces the token random source (tests). Production uses crypto/rand.
func (s *Service) SetRandom(random io.Reader) {
	s.mu.Lock()
	s.random = random
	s.mu.Unlock()
}

// Now is the service clock.
func (s *Service) Now() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now()
}

// ExchangeLimiter is the per-source-address limiter of the exchange endpoint.
func (s *Service) ExchangeLimiter() *Limiter { return s.exchange }

// ShareLimiter is the per-share limiter of visitor requests.
func (s *Service) ShareLimiter() *Limiter { return s.perShare }

// Streams is this instance's registry of in-flight share streams.
func (s *Service) Streams() *Streams { return s.streams }

// CutStreams aborts this instance's in-flight streams of shares that just ended.
func (s *Service) CutStreams(shareIDs []string) {
	for _, id := range shareIDs {
		s.streams.Cut(id)
	}
}

func (s *Service) principalFor(user *store.ManagementUser, username string) *principal {
	if user != nil {
		if !user.Enabled {
			return nil
		}
		return &principal{username: user.Username, tenantID: normalizeTenant(user.TenantID),
			admin: strings.EqualFold(user.Role, roleAdmin)}
	}
	if s.builtIn.Username != "" && strings.EqualFold(username, s.builtIn.Username) &&
		(s.builtIn.Enabled == nil || s.builtIn.Enabled()) {
		return &principal{username: s.builtIn.Username, tenantID: normalizeTenant(s.builtIn.TenantID), admin: true}
	}
	return nil
}

func normalizeTenant(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "default"
	}
	return value
}

func (p *principal) canManage(route *store.HTTPRouteMapping, client *store.ClientAccount) bool {
	if p == nil || route == nil || p.tenantID != normalizeTenant(route.TenantID) {
		return false
	}
	return p.admin || client != nil && client.OwnerUsername == p.username
}

// LapseReason returns why a share that is neither revoked nor expired can no longer be honoured,
// or "" when it still can. The first matching condition names the revocation.
func (s *Service) LapseReason(snapshot store.HTTPShareSnapshot) string {
	route := snapshot.Route
	if route == nil || normalizeTenant(route.TenantID) != normalizeTenant(snapshot.Share.TenantID) {
		return ReasonRouteDeleted
	}
	if snapshot.Client == nil {
		return ReasonClientDeleted
	}
	if !snapshot.Client.Enabled {
		return ReasonClientDisabled
	}
	switch Exposure(route.Enabled, route.AuthEnabled) {
	case ExposureDisabled:
		return ReasonRouteDisabled
	case ExposurePublic:
		return ReasonRouteMadePublic
	}
	if !s.principalFor(snapshot.Creator, snapshot.Share.CreatedBy).canManage(route, snapshot.Client) {
		return ReasonCreatorLostAccess
	}
	return ""
}

func statusOf(share store.HTTPShare, now int64) string {
	if share.RevokedAt != nil {
		return StatusRevoked
	}
	if now >= share.ExpiresAt {
		return StatusExpired
	}
	return StatusActive
}

// View renders a share for the management API.
func View(share store.HTTPShare, now int64) ShareView {
	view := ShareView{ShareID: share.ShareID, RouteID: share.RouteID, Label: share.Label, Access: share.Access,
		PathPrefix: share.PathPrefix, SharePath: SharePath(share.ShareID), CreatedAt: FormatInstant(share.CreatedAt),
		CreatedBy: share.CreatedBy, ExpiresAt: FormatInstant(share.ExpiresAt), Status: statusOf(share, now),
		RevokedBy: share.RevokedBy, RevokeReason: share.RevokeReason}
	if share.RevokedAt != nil {
		revokedAt := FormatInstant(*share.RevokedAt)
		view.RevokedAt = &revokedAt
	}
	return view
}

func failure(status int, code string) Result { return Result{Status: status, Code: code} }

// ---- management -------------------------------------------------------------------------------

type createFields struct {
	expiresIn  int64
	access     string
	pathPrefix string
	label      *string
}

func parseCreateBody(body []byte) (createFields, bool) {
	fields := createFields{access: AccessRead, pathPrefix: "/"}
	var raw map[string]json.RawMessage
	if len(body) > maxCreateBytes || json.Unmarshal(body, &raw) != nil || raw == nil {
		return fields, false
	}
	for key := range raw {
		switch key {
		case "expiresInSeconds", "access", "pathPrefix", "label":
		default:
			return fields, false
		}
	}
	seconds, present := raw["expiresInSeconds"]
	if !present {
		return fields, false
	}
	text := strings.TrimSpace(string(seconds))
	if strings.ContainsAny(text, ".eE\"") {
		return fields, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < MinExpiresInSeconds || value > MaxExpiresInSeconds {
		return fields, false
	}
	fields.expiresIn = value
	if access, present := raw["access"]; present {
		var text string
		if json.Unmarshal(access, &text) != nil || (text != AccessRead && text != AccessFull) {
			return fields, false
		}
		fields.access = text
	}
	if prefix, present := raw["pathPrefix"]; present {
		var text string
		if json.Unmarshal(prefix, &text) != nil || bytes.Equal(bytes.TrimSpace(prefix), []byte("null")) {
			return fields, false
		}
		canonical, ok := CanonicalPrefix(text)
		if !ok {
			return fields, false
		}
		fields.pathPrefix = canonical
	}
	if label, present := raw["label"]; present && !bytes.Equal(bytes.TrimSpace(label), []byte("null")) {
		var text string
		if json.Unmarshal(label, &text) != nil {
			return fields, false
		}
		text = strings.Trim(text, " ")
		for _, ch := range text {
			if ch < 0x20 || ch == 0x7F {
				return fields, false
			}
		}
		if utf8.RuneCountInString(text) > LabelMaxCodePoints {
			return fields, false
		}
		if text != "" {
			fields.label = &text
		}
	}
	return fields, true
}

type routeAccess struct {
	caller *principal
	route  *store.HTTPRouteMapping
	client *store.ClientAccount
}

// manageable re-reads the caller, the route and its client and decides whether the caller may
// manage the route right now. A route that is missing, of another tenant or not the caller's is
// the same 404.
func (s *Service) manageable(ctx context.Context, caller Caller, routeIDText string) (routeAccess, *Result) {
	var access routeAccess
	user, err := s.db.FindManagementUserByUsername(ctx, caller.Username)
	if err != nil {
		result := failure(http.StatusServiceUnavailable, CodeUnavailable)
		return access, &result
	}
	access.caller = s.principalFor(user, caller.Username)
	routeID, err := strconv.ParseInt(routeIDText, 10, 64)
	if err != nil {
		result := failure(http.StatusNotFound, CodeRouteNotFound)
		return access, &result
	}
	route, err := s.db.GetHTTPRouteByID(ctx, routeID)
	if err != nil {
		result := failure(http.StatusServiceUnavailable, CodeUnavailable)
		return access, &result
	}
	if route != nil {
		client, err := s.db.GetClient(ctx, route.ClientID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			result := failure(http.StatusServiceUnavailable, CodeUnavailable)
			return access, &result
		}
		access.client = client
	}
	access.route = route
	if !access.caller.canManage(route, access.client) {
		result := failure(http.StatusNotFound, CodeRouteNotFound)
		return access, &result
	}
	return access, nil
}

// Create issues a new share for a route (spec §4.1).
func (s *Service) Create(ctx context.Context, caller Caller, routeIDText string, body []byte) Result {
	fields, ok := parseCreateBody(body)
	if !ok {
		return failure(http.StatusBadRequest, CodeRequestInvalid)
	}
	access, refusal := s.manageable(ctx, caller, routeIDText)
	if refusal != nil {
		return *refusal
	}
	route := access.route
	switch {
	case !route.Enabled:
		return failure(http.StatusConflict, CodeRouteDisabled)
	case access.client == nil || !access.client.Enabled:
		return failure(http.StatusConflict, CodeClientDisabled)
	case !route.AuthEnabled:
		return failure(http.StatusConflict, CodeRoutePublic)
	}
	now := s.Now().Unix()
	for attempt := 0; ; attempt++ {
		s.mu.RLock()
		random := s.random
		s.mu.RUnlock()
		shareID, token, err := NewToken(random)
		if err != nil {
			s.logger.Error("share token generation failed", "err", err)
			return failure(http.StatusServiceUnavailable, CodeUnavailable)
		}
		share := store.HTTPShare{ShareID: shareID, TenantID: normalizeTenant(route.TenantID), RouteID: route.ID,
			TokenSHA256: TokenHash(token), Access: fields.access, PathPrefix: fields.pathPrefix, Label: fields.label,
			CreatedBy: access.caller.username, CreatedAt: now, ExpiresAt: now + fields.expiresIn}
		audit := store.HTTPAccessAuditEntry{TenantID: share.TenantID, At: now, Actor: &share.CreatedBy,
			Action: ActionShareCreated, RouteID: route.ID, ShareID: &share.ShareID,
			Detail: store.AuditDetail("access", share.Access, "pathPrefix", share.PathPrefix,
				"expiresAt", FormatInstant(share.ExpiresAt))}
		err = s.db.InsertHTTPShare(ctx, share, MaxActiveSharesPerRoute, now, audit)
		switch {
		case err == nil:
			return Result{Status: http.StatusCreated, Body: map[string]any{
				"share": View(share, now), "token": token, "linkPath": LinkPath(token)}}
		case errors.Is(err, store.ErrShareLimitReached):
			return failure(http.StatusConflict, CodeLimitReached)
		case errors.Is(err, store.ErrShareIDTaken) && attempt < 3:
			continue
		default:
			s.logger.Error("share creation failed", "err", err)
			return failure(http.StatusServiceUnavailable, CodeUnavailable)
		}
	}
}

// settle revokes a share that is still within its lifetime but has lapsed, so a management view
// never shows as active a share nobody can use. It returns the share as it now stands.
func (s *Service) settle(ctx context.Context, share store.HTTPShare, now int64) (store.HTTPShare, error) {
	if !share.Active(now) {
		return share, nil
	}
	snapshot, err := s.db.SnapshotHTTPShare(ctx, share)
	if err != nil {
		return share, err
	}
	reason := s.LapseReason(snapshot)
	if reason == "" {
		return share, nil
	}
	if _, err := s.db.RevokeHTTPShare(ctx, share, now, nil, reason); err != nil {
		return share, err
	}
	s.streams.Cut(share.ShareID)
	current, err := s.db.GetHTTPShare(ctx, share.ShareID)
	if err != nil || current == nil {
		return share, err
	}
	return *current, nil
}

// List returns every stored share of a route, newest first (spec §4.2).
func (s *Service) List(ctx context.Context, caller Caller, routeIDText string) Result {
	access, refusal := s.manageable(ctx, caller, routeIDText)
	if refusal != nil {
		return *refusal
	}
	shares, err := s.db.ListHTTPSharesByRoute(ctx, access.route.ID)
	if err != nil {
		return failure(http.StatusServiceUnavailable, CodeUnavailable)
	}
	now := s.Now().Unix()
	views := make([]ShareView, 0, len(shares))
	for _, share := range shares {
		settled, err := s.settle(ctx, share, now)
		if err != nil {
			return failure(http.StatusServiceUnavailable, CodeUnavailable)
		}
		views = append(views, View(settled, now))
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"shares": views}}
}

func (s *Service) routeShare(ctx context.Context, caller Caller, routeIDText, shareID string) (routeAccess,
	*store.HTTPShare, *Result) {
	access, refusal := s.manageable(ctx, caller, routeIDText)
	if refusal != nil {
		return access, nil, refusal
	}
	share, err := s.db.GetHTTPShare(ctx, shareID)
	if err != nil {
		result := failure(http.StatusServiceUnavailable, CodeUnavailable)
		return access, nil, &result
	}
	if share == nil || share.RouteID != access.route.ID {
		result := failure(http.StatusNotFound, CodeNotFound)
		return access, nil, &result
	}
	return access, share, nil
}

// Get returns one share of a route.
func (s *Service) Get(ctx context.Context, caller Caller, routeIDText, shareID string) Result {
	_, share, refusal := s.routeShare(ctx, caller, routeIDText, shareID)
	if refusal != nil {
		return *refusal
	}
	now := s.Now().Unix()
	settled, err := s.settle(ctx, *share, now)
	if err != nil {
		return failure(http.StatusServiceUnavailable, CodeUnavailable)
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"share": View(settled, now)}}
}

// Revoke ends a share (spec §4.3). It is idempotent: an ended share is returned unchanged.
func (s *Service) Revoke(ctx context.Context, caller Caller, routeIDText, shareID string, body []byte) Result {
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
		var raw map[string]json.RawMessage
		if json.Unmarshal(trimmed, &raw) != nil || raw == nil || len(raw) > 0 {
			return failure(http.StatusBadRequest, CodeRequestInvalid)
		}
	}
	access, share, refusal := s.routeShare(ctx, caller, routeIDText, shareID)
	if refusal != nil {
		return *refusal
	}
	now := s.Now().Unix()
	if share.Active(now) {
		actor := access.caller.username
		if _, err := s.db.RevokeHTTPShare(ctx, *share, now, &actor, ReasonRevokedByUser); err != nil {
			return failure(http.StatusServiceUnavailable, CodeUnavailable)
		}
		s.streams.Cut(share.ShareID)
		current, err := s.db.GetHTTPShare(ctx, share.ShareID)
		if err != nil || current == nil {
			return failure(http.StatusServiceUnavailable, CodeUnavailable)
		}
		share = current
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"share": View(*share, now)}}
}

// AuditQuery is the paging of an audit read.
type AuditQuery struct {
	RouteID string
	Limit   string
	Before  string
}

func parseAuditPaging(query AuditQuery) (int, *int64, bool) {
	limit := 50
	if query.Limit != "" {
		value, err := strconv.Atoi(query.Limit)
		if err != nil || value < 1 || value > 200 {
			return 0, nil, false
		}
		limit = value
	}
	var before *int64
	if query.Before != "" {
		value, err := strconv.ParseInt(query.Before, 10, 64)
		if err != nil {
			return 0, nil, false
		}
		before = &value
	}
	return limit, before, true
}

func (s *Service) auditPage(ctx context.Context, tenantID string, routeID *int64, limit int, before *int64) Result {
	entries, err := s.db.ListHTTPAccessAudit(ctx, tenantID, routeID, before, limit+1)
	if err != nil {
		return failure(http.StatusServiceUnavailable, CodeUnavailable)
	}
	var nextBefore *int64
	if len(entries) > limit {
		entries = entries[:limit]
		last := entries[len(entries)-1].ID
		nextBefore = &last
	}
	views := make([]AuditView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, AuditView{AuditID: entry.ID, At: FormatInstant(entry.At), Actor: entry.Actor,
			Action: entry.Action, RouteID: entry.RouteID, ShareID: entry.ShareID, Detail: json.RawMessage(entry.Detail)})
	}
	return Result{Status: http.StatusOK, Body: map[string]any{"entries": views, "nextBefore": nextBefore}}
}

// RouteAudit pages the audit of one route for whoever may manage it.
func (s *Service) RouteAudit(ctx context.Context, caller Caller, routeIDText string, query AuditQuery) Result {
	limit, before, ok := parseAuditPaging(query)
	if !ok {
		return failure(http.StatusBadRequest, CodeRequestInvalid)
	}
	access, refusal := s.manageable(ctx, caller, routeIDText)
	if refusal != nil {
		return *refusal
	}
	return s.auditPage(ctx, access.caller.tenantID, &access.route.ID, limit, before)
}

// TenantAudit pages the tenant's audit, including deleted routes, for tenant admins only.
func (s *Service) TenantAudit(ctx context.Context, caller Caller, query AuditQuery) Result {
	limit, before, ok := parseAuditPaging(query)
	if !ok {
		return failure(http.StatusBadRequest, CodeRequestInvalid)
	}
	var routeID *int64
	if query.RouteID != "" {
		value, err := strconv.ParseInt(query.RouteID, 10, 64)
		if err != nil {
			return failure(http.StatusBadRequest, CodeRequestInvalid)
		}
		routeID = &value
	}
	user, err := s.db.FindManagementUserByUsername(ctx, caller.Username)
	if err != nil {
		return failure(http.StatusServiceUnavailable, CodeUnavailable)
	}
	p := s.principalFor(user, caller.Username)
	if p == nil || !p.admin {
		return failure(http.StatusForbidden, CodeForbidden)
	}
	return s.auditPage(ctx, p.tenantID, routeID, limit, before)
}

// ---- exchange -----------------------------------------------------------------------------------

// Exchange trades the token from the link fragment for the share cookie (spec §5.2).
func (s *Service) Exchange(ctx context.Context, contentType string, body []byte, source string) Result {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	if mediaType != "application/json" {
		return failure(http.StatusUnsupportedMediaType, CodeRequestInvalid)
	}
	var raw map[string]json.RawMessage
	if len(body) > maxExchangeBytes || json.Unmarshal(body, &raw) != nil || raw == nil || len(raw) != 1 {
		return failure(http.StatusBadRequest, CodeRequestInvalid)
	}
	tokenRaw, present := raw["token"]
	var token string
	if !present || json.Unmarshal(tokenRaw, &token) != nil || bytes.Equal(bytes.TrimSpace(tokenRaw), []byte("null")) {
		return failure(http.StatusBadRequest, CodeRequestInvalid)
	}
	current := s.Now()
	if allowed, wait := s.exchange.Take(source, current.UnixMilli()); !allowed {
		result := failure(http.StatusTooManyRequests, CodeRateLimited)
		result.Headers = http.Header{"Retry-After": {strconv.FormatInt(RetryAfterSeconds(wait), 10)}}
		return result
	}
	shareID, ok := ParseToken(token)
	if !ok {
		return failure(http.StatusNotFound, CodeNotFound)
	}
	snapshot, err := s.db.LoadHTTPShareSnapshot(ctx, shareID)
	if err != nil {
		return failure(http.StatusServiceUnavailable, CodeUnavailable)
	}
	if snapshot == nil || !hashMatches(snapshot.Share.TokenSHA256, token) {
		return failure(http.StatusNotFound, CodeNotFound)
	}
	now := current.Unix()
	if ended := s.ended(ctx, *snapshot, now); ended != "" {
		return failure(http.StatusGone, ended)
	}
	share := snapshot.Share
	maxAge := (share.ExpiresAt*1000 - current.UnixMilli() + 999) / 1000
	return Result{Status: http.StatusOK,
		Body: map[string]any{"shareId": share.ShareID, "location": SharePathRoot + share.ShareID + share.PathPrefix,
			"expiresAt": FormatInstant(share.ExpiresAt), "access": share.Access, "pathPrefix": share.PathPrefix},
		Headers: http.Header{"Set-Cookie": {SetCookieHeader(share.ShareID, token, maxAge)},
			"Referrer-Policy": {"no-referrer"}}}
}

func hashMatches(stored, token string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(stored)), []byte(TokenHash(token))) == 1
}

// ended returns the code for a share whose holder proved the token but which has ended, or "".
// A share that lapsed is revoked on the spot, so it never comes back when its route is enabled
// again; a failed revocation still ends this request.
func (s *Service) ended(ctx context.Context, snapshot store.HTTPShareSnapshot, now int64) string {
	switch statusOf(snapshot.Share, now) {
	case StatusRevoked:
		return CodeRevoked
	case StatusExpired:
		return CodeExpired
	}
	reason := s.LapseReason(snapshot)
	if reason == "" {
		return ""
	}
	if _, err := s.db.RevokeHTTPShare(ctx, snapshot.Share, now, nil, reason); err != nil {
		s.logger.Warn("read-time share revocation failed", "share", snapshot.Share.ShareID, "err", err)
	}
	s.streams.Cut(snapshot.Share.ShareID)
	return CodeRevoked
}

// ---- visitor requests ---------------------------------------------------------------------------

// VisitorRequest is what the share entry knows about a request before reading its body.
type VisitorRequest struct {
	// Path is the raw (still percent-encoded) request path, starting with /http-share/.
	Path     string
	RawQuery string
	Method   string
	Upgrade  bool
	Cookies  []string
	// Cut aborts the request once it has been admitted and its share ends.
	Cut func()
}

// Grant is an admitted share request: where to forward it and the lease of its stream.
type Grant struct {
	Share           store.HTTPShare
	ClientName      string
	RouteName       string
	PathRewrite     bool
	RelativePath    string
	ForwardedCookie string
	HasCookie       bool
	Lease           *Lease
}

// Decision answers a visitor request: a refusal (Status != 0) or a Grant.
type Decision struct {
	Status      int
	Code        string
	Location    string
	Allow       string
	RetryAfter  int64
	ClearCookie string
	Grant       *Grant
}

// Authorize decides a request under /http-share/ (spec §6.1 steps 1-11). Every refusal is decided
// before the request body is read, a NAT stream is opened or a WebSocket is accepted.
func (s *Service) Authorize(ctx context.Context, request VisitorRequest) Decision {
	rest := strings.TrimPrefix(request.Path, SharePathRoot)
	shareID, tail, slash := strings.Cut(rest, "/")
	if !ValidShareID(shareID) {
		return Decision{Status: http.StatusNotFound, Code: CodeNotFound}
	}
	if !slash {
		location := SharePath(shareID)
		if request.RawQuery != "" {
			location += "?" + request.RawQuery
		}
		return Decision{Status: http.StatusPermanentRedirect, Location: location}
	}
	relativePath := "/" + tail
	snapshot, err := s.db.LoadHTTPShareSnapshot(ctx, shareID)
	if err != nil {
		return Decision{Status: http.StatusServiceUnavailable, Code: CodeUnavailable}
	}
	if snapshot == nil {
		return Decision{Status: http.StatusNotFound, Code: CodeNotFound}
	}
	proved := false
	for _, candidate := range CredentialCandidates(request.Cookies, shareID) {
		if hashMatches(snapshot.Share.TokenSHA256, candidate) {
			proved = true
		}
	}
	if !proved {
		return Decision{Status: http.StatusNotFound, Code: CodeNotFound}
	}
	current := s.Now()
	if code := s.ended(ctx, *snapshot, current.Unix()); code != "" {
		return Decision{Status: http.StatusGone, Code: code, ClearCookie: ClearCookieHeader(shareID)}
	}
	share := snapshot.Share
	if share.Access == AccessRead {
		if !IsReadMethod(request.Method) {
			return Decision{Status: http.StatusMethodNotAllowed, Code: CodeMethodNotAllowed, Allow: "GET, HEAD"}
		}
		if request.Upgrade {
			return Decision{Status: http.StatusForbidden, Code: CodeScopeDenied}
		}
	}
	if !PathInScope(share.PathPrefix, relativePath) {
		return Decision{Status: http.StatusForbidden, Code: CodeScopeDenied}
	}
	lease, ok := s.streams.Acquire(shareID, time.Unix(share.ExpiresAt, 0), request.Cut)
	if !ok {
		return Decision{Status: http.StatusTooManyRequests, Code: CodeBusy, RetryAfter: 1}
	}
	if allowed, wait := s.perShare.Take(shareID, current.UnixMilli()); !allowed {
		lease.Release()
		return Decision{Status: http.StatusTooManyRequests, Code: CodeRateLimited, RetryAfter: RetryAfterSeconds(wait)}
	}
	cookie, hasCookie := ForwardedCookie(request.Cookies)
	return Decision{Grant: &Grant{Share: share, ClientName: snapshot.Client.ClientName, RouteName: snapshot.Route.Route,
		PathRewrite: snapshot.Route.PathRewriteEnabled, RelativePath: relativePath, ForwardedCookie: cookie,
		HasCookie: hasCookie, Lease: lease}}
}

// ---- background work ----------------------------------------------------------------------------

// Sweep runs one expiry and lapse sweep (spec §7.5).
func (s *Service) Sweep(ctx context.Context) error {
	revoked, err := s.db.SweepHTTPShares(ctx, s.Now().Unix(), ShareRetentionDays*86_400,
		AuditRetentionDays*86_400, s.LapseReason)
	s.CutStreams(revoked)
	return err
}

// RunSweeper sweeps at start and then every SweepInterval until ctx ends.
func (s *Service) RunSweeper(ctx context.Context) {
	ticker := time.NewTicker(SweepInterval)
	defer ticker.Stop()
	for {
		if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("http share sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RecheckStreams re-reads every share with in-flight streams on this instance and cuts the
// streams of those that ended, wherever that happened.
func (s *Service) RecheckStreams(ctx context.Context) {
	now := s.Now().Unix()
	for _, shareID := range s.streams.Shares() {
		snapshot, err := s.db.LoadHTTPShareSnapshot(ctx, shareID)
		if err != nil {
			continue
		}
		if snapshot == nil || s.ended(ctx, *snapshot, now) != "" {
			s.streams.Cut(shareID)
		}
	}
}

// RunStreamWatch cuts in-flight streams at their share's expiry (within a second) and rechecks
// the shares with in-flight streams every StreamRecheckInterval.
func (s *Service) RunStreamWatch(ctx context.Context) {
	ticker := time.NewTicker(StreamExpiryTick)
	defer ticker.Stop()
	lastRecheck := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.streams.CutExpired(s.Now())
		if time.Since(lastRecheck) >= StreamRecheckInterval {
			lastRecheck = time.Now()
			s.RecheckStreams(ctx)
		}
	}
}
