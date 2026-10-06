package httpshare_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
	"github.com/devShuai/specus/implementations/go/server/internal/httpshare/sharetest"
)

// Binds the pure parts of the share implementation to protocol/test-vectors/temporary-http-share-v1.json:
// constants, token construction and parsing, prefix canonicalisation, header rewriting and the
// two GCRA limiters. The create, exchange, access and lifecycle sections run through the real
// handlers in the management and directhttp packages.

func TestShareVectorConstants(t *testing.T) {
	vector := sharetest.Load(t)
	want := map[string]any{
		"tokenVersion": httpshare.TokenVersion, "shareIdBytes": httpshare.ShareIDBytes,
		"secretBytes": httpshare.SecretBytes, "tokenPattern": httpshare.TokenPattern,
		"cookieName": httpshare.CookieName, "maxCookieCandidates": httpshare.MaxCookieCandidates,
		"sharePathRoot": httpshare.SharePathRoot, "linkRoot": httpshare.LinkRoot,
		"minExpiresInSeconds": httpshare.MinExpiresInSeconds, "maxExpiresInSeconds": httpshare.MaxExpiresInSeconds,
		"maxActiveSharesPerRoute": httpshare.MaxActiveSharesPerRoute,
		"labelMaxCodePoints":      httpshare.LabelMaxCodePoints, "pathPrefixMaxBytes": httpshare.PathPrefixMaxBytes,
		"readMethods": httpshare.ReadMethods, "maxConcurrentPerShare": httpshare.MaxConcurrentPerShare,
		"sweepIntervalMaxSeconds":   60,
		"streamRecheckMaxSeconds":   5,
		"shareRetentionDays":        httpshare.ShareRetentionDays,
		"auditRetentionDays":        httpshare.AuditRetentionDays,
		"revokeReasons": []string{httpshare.ReasonRevokedByUser, httpshare.ReasonRouteDisabled,
			httpshare.ReasonRouteMadePublic, httpshare.ReasonRouteDeleted, httpshare.ReasonClientDisabled,
			httpshare.ReasonClientDeleted, httpshare.ReasonCreatorLostAccess},
		"auditActions": []string{httpshare.ActionShareCreated, httpshare.ActionShareRevoked,
			httpshare.ActionShareExpired, httpshare.ActionRouteCreated, httpshare.ActionRouteExposure,
			httpshare.ActionRouteCredentials, httpshare.ActionRouteDeleted},
	}
	for key, value := range want {
		got, _ := json.Marshal(vector.Constants[key])
		expected, _ := json.Marshal(value)
		if string(got) != string(expected) {
			t.Errorf("constant %s = %s, implementation %s", key, got, expected)
		}
	}
	if len(vector.Constants) != len(want) {
		t.Errorf("vector has %d constants, compared %d", len(vector.Constants), len(want))
	}
	if httpshare.SweepInterval.Seconds() > 60 || httpshare.StreamRecheckInterval.Seconds() > 5 {
		t.Errorf("sweep %s / recheck %s exceed the contract", httpshare.SweepInterval, httpshare.StreamRecheckInterval)
	}
	if vector.Rate.Exchange.IntervalMs != httpshare.ExchangeIntervalMs || vector.Rate.Exchange.Burst != httpshare.ExchangeBurst ||
		vector.Rate.Share.IntervalMs != httpshare.ShareIntervalMs || vector.Rate.Share.Burst != httpshare.ShareBurst {
		t.Errorf("rate constants differ: %+v %+v", vector.Rate.Exchange, vector.Rate.Share)
	}
}

func TestShareVectorTokens(t *testing.T) {
	vector := sharetest.Load(t)
	for _, example := range vector.Token.Examples {
		shareID, token, err := httpshare.NewToken(sharetest.NewFixedRandom(t, example.ShareIDBytesHex, example.SecretBytesHex))
		if err != nil {
			t.Fatal(err)
		}
		if shareID != example.ShareID || token != example.Token || httpshare.TokenHash(token) != example.TokenSHA256 ||
			httpshare.SharePath(shareID) != example.SharePath || httpshare.LinkPath(token) != example.LinkPath {
			t.Errorf("token example %s: got %s %s", example.ShareID, shareID, token)
		}
	}
	for i, parse := range vector.Token.Parse {
		input := ""
		if parse.Input != nil {
			input = *parse.Input
		}
		id, ok := httpshare.ParseToken(input)
		switch {
		case parse.ShareID == nil && ok:
			t.Errorf("parse[%d] %q accepted as %s", i, input, id)
		case parse.ShareID != nil && (!ok || id != *parse.ShareID):
			t.Errorf("parse[%d] %q = %s/%t, want %s", i, input, id, ok, *parse.ShareID)
		}
	}
	t.Logf("token: %d examples, %d parse cases", len(vector.Token.Examples), len(vector.Token.Parse))
}

func TestShareVectorPathPrefix(t *testing.T) {
	vector := sharetest.Load(t)
	for _, c := range vector.PathPrefix {
		var input string
		isString := json.Unmarshal(c.Input, &input) == nil
		got, ok := "", false
		if isString {
			got, ok = httpshare.CanonicalPrefix(input)
		}
		if c.Canonical == nil {
			if ok {
				t.Errorf("prefix %s accepted as %q", c.Input, got)
			}
			continue
		}
		if !ok || got != *c.Canonical {
			t.Errorf("prefix %s = %q/%t, want %q", c.Input, got, ok, *c.Canonical)
		}
	}
	t.Logf("pathPrefix: %d cases", len(vector.PathPrefix))
}

func TestShareVectorHeaders(t *testing.T) {
	vector := sharetest.Load(t)
	for i, c := range vector.Headers.RequestCookie {
		got, ok := httpshare.ForwardedCookie(c.CookieHeaders)
		if c.ForwardedCookie == nil && ok || c.ForwardedCookie != nil && (!ok || got != *c.ForwardedCookie) {
			t.Errorf("requestCookie[%d] %q = %q/%t, want %v", i, c.CookieHeaders, got, ok, c.ForwardedCookie)
		}
	}
	for _, c := range vector.Headers.Response {
		got := httpshare.ResponseHeaders(c.Status, c.Upstream, c.ShareID)
		if !reflect.DeepEqual(got, c.Relayed) {
			t.Errorf("response %s:\n got %q\nwant %q", c.Name, got, c.Relayed)
		}
	}
	t.Logf("headers: %d request cookie cases, %d response cases", len(vector.Headers.RequestCookie),
		len(vector.Headers.Response))
}

func TestShareVectorRateLimits(t *testing.T) {
	vector := sharetest.Load(t)
	for name, section := range map[string]sharetest.RateSection{"exchange": vector.Rate.Exchange, "share": vector.Rate.Share} {
		limiter := httpshare.NewLimiter(section.IntervalMs, section.Burst)
		for i, event := range section.Events {
			admitted := 0
			var retry *int64
			for range event.Requests {
				ok, wait := limiter.Take(event.Key, event.AtMs)
				if ok {
					admitted++
				} else if retry == nil {
					value := httpshare.RetryAfterSeconds(wait)
					retry = &value
				}
			}
			if admitted != event.Admitted || fmt.Sprint(deref(retry)) != fmt.Sprint(deref(event.RetryAfterSeconds)) ||
				(retry == nil) != (event.RetryAfterSeconds == nil) {
				t.Errorf("%s event %d: admitted %d retry %v, want %d %v", name, i, admitted, deref(retry), event.Admitted,
					deref(event.RetryAfterSeconds))
			}
		}
	}
}

func deref(value *int64) int64 {
	if value == nil {
		return -1
	}
	return *value
}

func TestLimiterRefusesNewKeysWhenFullOfActiveEntries(t *testing.T) {
	limiter := httpshare.NewLimiter(1000, 1)
	for i := range httpshare.DefaultMaxLimiterKeys {
		if ok, _ := limiter.Take(fmt.Sprint("k", i), 0); !ok {
			t.Fatalf("key %d refused", i)
		}
	}
	if ok, _ := limiter.Take("new", 0); ok {
		t.Fatal("a new key was admitted while every entry still limits someone")
	}
	if ok, _ := limiter.Take("new", 1000); !ok {
		t.Fatal("expired entries were not evicted for a new key")
	}
}
