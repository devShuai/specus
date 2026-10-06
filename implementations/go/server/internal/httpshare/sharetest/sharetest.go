// Package sharetest loads protocol/test-vectors/temporary-http-share-v1.json and seeds its fixture
// world into a real store, so the share vectors can drive the server's own handlers. It is
// imported by tests only.
package sharetest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// RoutePassword is the Basic password of every protected fixture route.
const RoutePassword = "route-password"

// Vector is the decoded vector file.
type Vector struct {
	Constants map[string]any  `json:"constants"`
	Codes     map[string][]string `json:"codes"`
	World     World           `json:"world"`
	NewShare  struct {
		ShareIDBytesHex string `json:"shareIdBytesHex"`
		SecretBytesHex  string `json:"secretBytesHex"`
		ShareID         string `json:"shareId"`
		Token           string `json:"token"`
	} `json:"newShare"`
	Token struct {
		Examples []struct {
			ShareIDBytesHex string `json:"shareIdBytesHex"`
			SecretBytesHex  string `json:"secretBytesHex"`
			ShareID         string `json:"shareId"`
			Token           string `json:"token"`
			TokenSHA256     string `json:"tokenSha256"`
			SharePath       string `json:"sharePath"`
			LinkPath        string `json:"linkPath"`
		} `json:"examples"`
		Parse []struct {
			Input   *string `json:"input"`
			ShareID *string `json:"shareId"`
		} `json:"parse"`
	} `json:"token"`
	PathPrefix []struct {
		Input     json.RawMessage `json:"input"`
		Canonical *string         `json:"canonical"`
	} `json:"pathPrefix"`
	Create   []Case `json:"create"`
	Exchange []Case `json:"exchange"`
	Access   []Case `json:"access"`
	Headers  struct {
		RequestCookie []struct {
			CookieHeaders   []string `json:"cookieHeaders"`
			ForwardedCookie *string  `json:"forwardedCookie"`
		} `json:"requestCookie"`
		Response []struct {
			Name     string   `json:"name"`
			ShareID  string   `json:"shareId"`
			Status   int      `json:"status"`
			Upstream []string `json:"upstream"`
			Relayed  []string `json:"relayed"`
		} `json:"response"`
	} `json:"headers"`
	Lifecycle []LifecycleCase `json:"lifecycle"`
	Rate      struct {
		Exchange RateSection `json:"exchange"`
		Share    RateSection `json:"share"`
	} `json:"rate"`
}

// World is the shared fixture: users, clients and routes.
type World struct {
	Users   map[string]User   `json:"users"`
	Clients map[string]Client `json:"clients"`
	Routes  map[string]Route  `json:"routes"`
}

type User struct {
	Username string `json:"username"`
	TenantID string `json:"tenantId"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
}

type Client struct {
	ClientID int64  `json:"clientId"`
	TenantID string `json:"tenantId"`
	Owner    string `json:"owner"`
	Enabled  bool   `json:"enabled"`
}

type Route struct {
	RouteID     int64  `json:"routeId"`
	TenantID    string `json:"tenantId"`
	ClientID    int64  `json:"clientId"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	AuthEnabled bool   `json:"authEnabled"`
}

// ShareRow is a stored share as the vector writes it.
type ShareRow struct {
	ShareID      string  `json:"shareId"`
	TenantID     string  `json:"tenantId"`
	RouteID      int64   `json:"routeId"`
	TokenSHA256  string  `json:"tokenSha256"`
	Access       string  `json:"access"`
	PathPrefix   string  `json:"pathPrefix"`
	Label        *string `json:"label"`
	CreatedBy    string  `json:"createdBy"`
	CreatedAt    string  `json:"createdAt"`
	ExpiresAt    string  `json:"expiresAt"`
	RevokedAt    *string `json:"revokedAt"`
	RevokedBy    *string `json:"revokedBy"`
	RevokeReason *string `json:"revokeReason"`
}

// WorldChange is one change a case applies to the fixture world.
type WorldChange struct {
	Table   string          `json:"table"`
	Key     json.RawMessage `json:"key"`
	Deleted bool            `json:"deleted"`
	Set     map[string]any  `json:"set"`
}

// Case is a create, exchange or access case.
type Case struct {
	Name   string          `json:"name"`
	Input  CaseInput       `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

type CaseInput struct {
	Now           string          `json:"now"`
	Authenticated *bool           `json:"authenticated"`
	Readable      *bool           `json:"readable"`
	Caller        *string         `json:"caller"`
	RouteID       int64           `json:"routeId"`
	Body          json.RawMessage `json:"body"`
	ContentType   *string         `json:"contentType"`
	RateLimitedMs int64           `json:"rateLimitedMs"`
	Admission     string          `json:"admission"`
	Shares        []ShareRow      `json:"shares"`
	WorldChanges  []WorldChange   `json:"worldChanges"`
	Request       *struct {
		Method        string   `json:"method"`
		Path          string   `json:"path"`
		Cookies       []string `json:"cookies"`
		RawQuery      string   `json:"rawQuery"`
		Upgrade       bool     `json:"upgrade"`
		Authorization string   `json:"authorization"`
	} `json:"request"`
}

// IsReadable reports whether the case's store can be read.
func (c CaseInput) IsReadable() bool { return c.Readable == nil || *c.Readable }

// Audit is an expected audit entry.
type Audit struct {
	Action  string          `json:"action"`
	At      string          `json:"at"`
	Actor   *string         `json:"actor"`
	RouteID int64           `json:"routeId"`
	ShareID *string         `json:"shareId"`
	Detail  json.RawMessage `json:"detail"`
}

// LifecycleCase replays management events.
type LifecycleCase struct {
	Name  string `json:"name"`
	Input struct {
		Shares []ShareRow       `json:"shares"`
		Events []map[string]any `json:"events"`
	} `json:"input"`
	Expect struct {
		Audit  []Audit `json:"audit"`
		Shares map[string]struct {
			Status       string  `json:"status"`
			RevokeReason *string `json:"revokeReason"`
			RevokedBy    *string `json:"revokedBy"`
		} `json:"shares"`
		Responses []struct {
			HTTPStatus int    `json:"httpStatus"`
			Status     string `json:"status"`
			Code       string `json:"code"`
		} `json:"responses"`
	} `json:"expect"`
}

type RateSection struct {
	IntervalMs int64 `json:"intervalMs"`
	Burst      int   `json:"burst"`
	Events     []struct {
		AtMs              int64  `json:"atMs"`
		Key               string `json:"key"`
		Requests          int    `json:"requests"`
		Admitted          int    `json:"admitted"`
		RetryAfterSeconds *int64 `json:"retryAfterSeconds"`
	} `json:"events"`
}

// Load reads the vector from protocol/test-vectors, searching upwards from the working directory.
func Load(t testing.TB) Vector {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 10; depth++ {
		candidate := filepath.Join(dir, "protocol", "test-vectors", "temporary-http-share-v1.json")
		if data, err := os.ReadFile(candidate); err == nil {
			var vector Vector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			return vector
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("temporary-http-share-v1.json not found")
	return Vector{}
}

// Instant parses a vector timestamp.
func Instant(t testing.TB, text string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		t.Fatalf("bad instant %q: %v", text, err)
	}
	return parsed
}

// Now is the case's "now", defaulting to the vector's fixed instant.
func Now(t testing.TB, text string) time.Time {
	if text == "" {
		text = "2026-10-06T08:00:00Z"
	}
	return Instant(t, text)
}

// FixedRandom yields the hex-encoded bytes in order, then fails.
type FixedRandom struct{ data []byte }

// NewFixedRandom builds a random source from hex strings.
func NewFixedRandom(t testing.TB, hexParts ...string) *FixedRandom {
	t.Helper()
	var data []byte
	for _, part := range hexParts {
		raw, err := hex.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, raw...)
	}
	return &FixedRandom{data: data}
}

func (r *FixedRandom) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, fmt.Errorf("fixed random exhausted")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// ClientName is the fixture name of a client.
func ClientName(id int64) string { return "client-" + strconv.FormatInt(id, 10) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Seed writes the world, the case's world changes and its shares into db.
func Seed(t testing.TB, db *store.DB, world World, changes []WorldChange, shares []ShareRow, hashPassword func(string) string) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, key := range sortedKeys(world.Users) {
		user := world.Users[key]
		if err := db.InsertManagementUser(ctx, store.ManagementUser{Username: user.Username, TenantID: user.TenantID,
			PasswordHash: "unused", Role: user.Role, Enabled: user.Enabled, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range sortedKeys(world.Clients) {
		client := world.Clients[key]
		if err := db.InsertClient(ctx, store.ClientAccount{ID: client.ClientID, TenantID: client.TenantID,
			OwnerUsername: client.Owner, ClientName: ClientName(client.ClientID), PasswordHash: "unused",
			Enabled: client.Enabled, ConnectionRateLimitPerMinute: 60, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range sortedKeys(world.Routes) {
		InsertRoute(t, db, world.Routes[key], hashPassword)
	}
	for _, change := range changes {
		Apply(t, db, change)
	}
	for _, share := range shares {
		InsertShare(t, db, share)
	}
}

// InsertRoute stores one fixture route.
func InsertRoute(t testing.TB, db *store.DB, route Route, hashPassword func(string) string) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mapping := store.HTTPRouteMapping{ID: route.RouteID, TenantID: route.TenantID, ClientID: route.ClientID,
		ClientName: ClientName(route.ClientID), Route: route.Name, TargetBaseURL: "http://127.0.0.1:8080",
		Enabled: route.Enabled, AuthEnabled: route.AuthEnabled, CreatedAt: now, UpdatedAt: now}
	if route.AuthEnabled {
		mapping.AuthUsername = "route-user"
		mapping.AuthPasswordHash = hashPassword(RoutePassword)
	}
	if err := db.InsertHTTPRoute(context.Background(), mapping); err != nil {
		t.Fatal(err)
	}
}

func boolInt(value any) int {
	if value == true {
		return 1
	}
	return 0
}

// Apply makes one world change directly in the database, bypassing every hook.
func Apply(t testing.TB, db *store.DB, change WorldChange) {
	t.Helper()
	ctx := context.Background()
	var key any
	var text string
	if err := json.Unmarshal(change.Key, &text); err == nil {
		key = text
	} else {
		var number int64
		if err := json.Unmarshal(change.Key, &number); err != nil {
			t.Fatalf("bad world change key %s", change.Key)
		}
		key = number
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecStatement(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	table := map[string]string{"users": "specus_management_user", "clients": "specus_client_account",
		"routes": "http_route_mapping"}[change.Table]
	column := map[string]string{"users": "username", "clients": "id", "routes": "id"}[change.Table]
	if change.Deleted {
		exec(`DELETE FROM `+table+` WHERE `+column+` = ?`, key)
		return
	}
	for field, value := range change.Set {
		switch field {
		case "enabled":
			exec(`UPDATE `+table+` SET enabled = ? WHERE `+column+` = ?`, boolInt(value), key)
		case "authEnabled":
			exec(`UPDATE `+table+` SET auth_enabled = ? WHERE `+column+` = ?`, boolInt(value), key)
		case "role":
			exec(`UPDATE `+table+` SET role = ? WHERE `+column+` = ?`, value, key)
		default:
			t.Fatalf("unsupported world change field %s", field)
		}
	}
}

// InsertShare stores a share row exactly as the vector gives it.
func InsertShare(t testing.TB, db *store.DB, row ShareRow) {
	t.Helper()
	var revokedAt any
	if row.RevokedAt != nil {
		revokedAt = Instant(t, *row.RevokedAt).Unix()
	}
	if _, err := db.ExecStatement(context.Background(), `INSERT INTO http_share (share_id, tenant_id, route_id,
		token_sha256, access, path_prefix, label, created_by, created_at, expires_at, revoked_at, revoked_by,
		revoke_reason, expiry_recorded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		row.ShareID, row.TenantID, row.RouteID, row.TokenSHA256, row.Access, row.PathPrefix, row.Label,
		row.CreatedBy, Instant(t, row.CreatedAt).Unix(), Instant(t, row.ExpiresAt).Unix(), revokedAt,
		row.RevokedBy, row.RevokeReason); err != nil {
		t.Fatal(err)
	}
}

// AuditEntries returns every audit entry of a tenant in write order.
func AuditEntries(t testing.TB, db *store.DB, tenantID string) []Audit {
	t.Helper()
	entries, err := db.ListHTTPAccessAudit(context.Background(), tenantID, nil, nil, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]Audit, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		out = append(out, Audit{Action: entry.Action, At: time.Unix(entry.At, 0).UTC().Format("2006-01-02T15:04:05Z"),
			Actor: entry.Actor, RouteID: entry.RouteID, ShareID: entry.ShareID, Detail: json.RawMessage(entry.Detail)})
	}
	return out
}

// SameAudit compares audit entries field by field; detail objects are compared as JSON values.
func SameAudit(t testing.TB, label string, got, want []Audit, routeIDs map[int64]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d audit entries, want %d\n got %s\nwant %s", label, len(got), len(want), dump(got), dump(want))
		return
	}
	for i := range want {
		wantRoute := want[i].RouteID
		if mapped, ok := routeIDs[wantRoute]; ok {
			wantRoute = mapped
		}
		if got[i].Action != want[i].Action || got[i].At != want[i].At || deref(got[i].Actor) != deref(want[i].Actor) ||
			(got[i].Actor == nil) != (want[i].Actor == nil) || got[i].RouteID != wantRoute ||
			deref(got[i].ShareID) != deref(want[i].ShareID) || (got[i].ShareID == nil) != (want[i].ShareID == nil) ||
			!SameJSON(got[i].Detail, want[i].Detail) {
			t.Errorf("%s: audit[%d]\n got %s\nwant %s", label, i, dump(got[i]), dump(want[i]))
		}
	}
}

// SameJSON compares two JSON documents as values.
func SameJSON(left, right json.RawMessage) bool {
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// Expect is the expectation of a create, exchange or access case.
type Expect struct {
	HTTPStatus        json.RawMessage `json:"httpStatus"`
	Code              string          `json:"code"`
	Location          string          `json:"location"`
	Allow             string          `json:"allow"`
	RetryAfterSeconds *int64          `json:"retryAfterSeconds"`
	Body              json.RawMessage `json:"body"`
	SetCookie         json.RawMessage `json:"setCookie"`
	Revoke            *struct {
		Reason    string  `json:"reason"`
		RevokedBy *string `json:"revokedBy"`
	} `json:"revoke"`
	Audit   []Audit `json:"audit"`
	Forward *struct {
		Route        string  `json:"route"`
		Method       string  `json:"method"`
		RelativePath string  `json:"relativePath"`
		RawQuery     string  `json:"rawQuery"`
		Cookie       *string `json:"cookie"`
	} `json:"forward"`
}

// ParseExpect decodes a case expectation.
func ParseExpect(t testing.TB, raw json.RawMessage) Expect {
	t.Helper()
	var expect Expect
	if err := json.Unmarshal(raw, &expect); err != nil {
		t.Fatal(err)
	}
	return expect
}

// Status is the numeric status, or 0 for "forwarded".
func (e Expect) Status() int {
	var status int
	if json.Unmarshal(e.HTTPStatus, &status) != nil {
		return 0
	}
	return status
}

// CookieView turns a Set-Cookie header into the vector's structured cookie.
func CookieView(header string) json.RawMessage {
	parts := strings.Split(header, ";")
	name, value, _ := strings.Cut(strings.TrimSpace(parts[0]), "=")
	view := map[string]any{"name": name, "value": value, "path": nil, "maxAge": nil, "httpOnly": false,
		"secure": false, "sameSite": nil, "domain": nil}
	for _, part := range parts[1:] {
		key, attribute, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(key) {
		case "path":
			view["path"] = attribute
		case "max-age":
			age, _ := strconv.ParseInt(attribute, 10, 64)
			view["maxAge"] = age
		case "httponly":
			view["httpOnly"] = true
		case "secure":
			view["secure"] = true
		case "samesite":
			view["sameSite"] = attribute
		case "domain":
			view["domain"] = attribute
		default:
			view[key] = attribute
		}
	}
	data, _ := json.Marshal(view)
	return data
}

// ShareState reads the revocation columns of a stored share.
func ShareState(t testing.TB, db *store.DB, shareID string) store.HTTPShare {
	t.Helper()
	share, err := db.GetHTTPShare(context.Background(), shareID)
	if err != nil || share == nil {
		t.Fatalf("share %s: %v", shareID, err)
	}
	return *share
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func dump(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}
