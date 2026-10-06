// Package httpshare implements temporary HTTP shares: a revocable, expiring grant for one
// protected HTTP route, reached under /http-share/{shareId}/ with an HttpOnly cookie that holds the
// share token. See protocol/spec/temporary-http-share.md.
package httpshare

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	TokenVersion            = "hs1"
	ShareIDBytes            = 12
	SecretBytes             = 32
	CookieName              = "__Secure-specus_http_share"
	MaxCookieCandidates     = 4
	SharePathRoot           = "/http-share/"
	LinkRoot                = "/#/http-share/"
	MinExpiresInSeconds     = 300
	MaxExpiresInSeconds     = 604_800
	MaxActiveSharesPerRoute = 20
	LabelMaxCodePoints      = 60
	PathPrefixMaxBytes      = 256
	MaxConcurrentPerShare   = 64
	ExchangeIntervalMs      = 6_000
	ExchangeBurst           = 10
	ShareIntervalMs         = 50
	ShareBurst              = 200
	ShareRetentionDays      = 30
	AuditRetentionDays      = 180
	SweepInterval           = 30 * time.Second
	StreamRecheckInterval   = 2 * time.Second
	StreamExpiryTick        = time.Second

	AccessRead = "read"
	AccessFull = "full"

	StatusActive  = "active"
	StatusRevoked = "revoked"
	StatusExpired = "expired"

	ReasonRevokedByUser     = "revoked-by-user"
	ReasonRouteDisabled     = "route-disabled"
	ReasonRouteMadePublic   = "route-made-public"
	ReasonRouteDeleted      = "route-deleted"
	ReasonClientDisabled    = "client-disabled"
	ReasonClientDeleted     = "client-deleted"
	ReasonCreatorLostAccess = "creator-lost-access"

	ActionShareCreated     = "share.created"
	ActionShareRevoked     = "share.revoked"
	ActionShareExpired     = "share.expired"
	ActionRouteCreated     = "route.created"
	ActionRouteExposure    = "route.exposure-changed"
	ActionRouteCredentials = "route.credentials-changed"
	ActionRouteDeleted     = "route.deleted"

	CodeRequestInvalid   = "SHARE_REQUEST_INVALID"
	CodeUnavailable      = "SHARE_UNAVAILABLE"
	CodeRouteNotFound    = "SHARE_ROUTE_NOT_FOUND"
	CodeRouteDisabled    = "SHARE_ROUTE_DISABLED"
	CodeClientDisabled   = "SHARE_CLIENT_DISABLED"
	CodeRoutePublic      = "SHARE_ROUTE_PUBLIC"
	CodeLimitReached     = "SHARE_LIMIT_REACHED"
	CodeNotFound         = "SHARE_NOT_FOUND"
	CodeRevoked          = "SHARE_REVOKED"
	CodeExpired          = "SHARE_EXPIRED"
	CodeRateLimited      = "SHARE_RATE_LIMITED"
	CodeMethodNotAllowed = "SHARE_METHOD_NOT_ALLOWED"
	CodeScopeDenied      = "SHARE_SCOPE_DENIED"
	CodeBusy             = "SHARE_BUSY"
	CodeForbidden        = "SHARE_FORBIDDEN"

	ExposureDisabled  = "disabled"
	ExposureProtected = "protected"
	ExposurePublic    = "public"
)

// ReadMethods are the only methods a read-only share forwards.
var ReadMethods = []string{"GET", "HEAD"}

var (
	tokenPattern   = regexp.MustCompile(`^hs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})$`)
	shareIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`)
)

// TokenPattern is the documented full-match pattern of a share token.
const TokenPattern = `hs1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})`

// NewToken draws a share id and a secret from random (the CSPRNG in production) and returns the
// share id and the whole token.
func NewToken(random io.Reader) (shareID, token string, err error) {
	raw := make([]byte, ShareIDBytes+SecretBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", "", err
	}
	shareID = base64.RawURLEncoding.EncodeToString(raw[:ShareIDBytes])
	secret := base64.RawURLEncoding.EncodeToString(raw[ShareIDBytes:])
	return shareID, TokenVersion + "." + shareID + "." + secret, nil
}

// ParseToken returns the share id embedded in a well-formed token. The whole string must match:
// no trimming, so a trailing newline or a space is a malformed token.
func ParseToken(text string) (string, bool) {
	if strings.ContainsAny(text, "\r\n") {
		return "", false
	}
	match := tokenPattern.FindStringSubmatch(text)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// ValidShareID reports whether value is a well-formed share id.
func ValidShareID(value string) bool {
	return shareIDPattern.MatchString(value) && !strings.ContainsAny(value, "\r\n")
}

// TokenHash is the stored form of a token: lowercase hex SHA-256 of its UTF-8 bytes.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// SharePath is the visitor entry of a share.
func SharePath(shareID string) string { return SharePathRoot + shareID + "/" }

// LinkPath is the landing-page path that carries the token in the URL fragment.
func LinkPath(token string) string { return LinkRoot + token }

// Exposure is how a route is reachable: disabled, protected by Basic, or public.
func Exposure(enabled, authEnabled bool) string {
	if !enabled {
		return ExposureDisabled
	}
	if authEnabled {
		return ExposureProtected
	}
	return ExposurePublic
}

// FormatInstant renders an epoch second as the API timestamp.
func FormatInstant(epochSeconds int64) string {
	return time.Unix(epochSeconds, 0).UTC().Format("2006-01-02T15:04:05Z")
}

// ---- paths ------------------------------------------------------------------------------------

const unreservedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// pathChars is RFC 3986 pchar without ";" plus "/": a servlet container treats ";" as the start of
// path parameters, so "/docs/..;/admin" would leave the prefix after the container normalised it.
const pathChars = unreservedChars + "!$&'()*+,=:@/"

func isHex(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F'
}

func hexValue(ch byte) byte {
	switch {
	case ch >= '0' && ch <= '9':
		return ch - '0'
	case ch >= 'a' && ch <= 'f':
		return ch - 'a' + 10
	default:
		return ch - 'A' + 10
	}
}

// NormalizePath applies RFC 3986 syntax normalisation to an already percent-encoded path: escapes
// of unreserved characters are decoded and every other escape gets upper-case hex. It fails for a
// path that is not plain ASCII pchar/"/"/escapes or that has a malformed escape. The result only
// decides the scope; the request is forwarded with its original raw path.
func NormalizePath(raw string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '%' {
			if i+2 >= len(raw) {
				return "", false
			}
			if !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", false
			}
			decoded := hexValue(raw[i+1])<<4 | hexValue(raw[i+2])
			if strings.IndexByte(unreservedChars, decoded) >= 0 {
				out.WriteByte(decoded)
			} else {
				out.WriteByte('%')
				out.WriteString(strings.ToUpper(raw[i+1 : i+3]))
			}
			i += 2
			continue
		}
		if ch >= 0x80 || strings.IndexByte(pathChars, ch) < 0 {
			return "", false
		}
		out.WriteByte(ch)
	}
	return out.String(), true
}

// unsafeForPrefix reports a normalized path that could step outside a prefix once the target
// decodes it: a dot segment, or an escaped slash, backslash or control character.
func unsafeForPrefix(normalized string) bool {
	for i := 0; i+2 < len(normalized); i++ {
		if normalized[i] != '%' {
			continue
		}
		escape := normalized[i+1 : i+3]
		switch escape {
		case "2F", "5C", "7F":
			return true
		}
		if escape[0] == '0' || escape[0] == '1' {
			return true
		}
	}
	segments := strings.Split(normalized, "/")
	for _, segment := range segments[1:] {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// CanonicalPrefix returns the stored form of a pathPrefix, or false when it must be rejected.
func CanonicalPrefix(value string) (string, bool) {
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") {
		return "", false
	}
	normalized, ok := NormalizePath(value)
	if !ok || unsafeForPrefix(normalized) {
		return "", false
	}
	inner := strings.TrimPrefix(normalized, "/")
	inner = strings.TrimSuffix(inner, "/")
	if inner != "" {
		for _, segment := range strings.Split(inner, "/") {
			if segment == "" {
				return "", false
			}
		}
	}
	canonical := normalized
	if !strings.HasSuffix(canonical, "/") {
		canonical += "/"
	}
	if len(canonical) > PathPrefixMaxBytes {
		return "", false
	}
	return canonical, true
}

// PathInScope reports whether a raw relative path is covered by a canonical prefix. The prefix
// "/" covers the whole route with no rule beyond the route's own.
func PathInScope(prefix, relativePath string) bool {
	if prefix == "/" {
		return true
	}
	normalized, ok := NormalizePath(relativePath)
	if !ok || unsafeForPrefix(normalized) {
		return false
	}
	return normalized == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(normalized, prefix)
}

// ---- cookies and headers ----------------------------------------------------------------------

func cookiePairs(headers []string) []string {
	var pairs []string
	for _, header := range headers {
		for _, part := range strings.Split(header, ";") {
			part = strings.Trim(part, " \t")
			if part != "" {
				pairs = append(pairs, part)
			}
		}
	}
	return pairs
}

func pairName(pair string) string {
	name, _, _ := strings.Cut(pair, "=")
	return strings.Trim(name, " \t")
}

func pairValue(pair string) string {
	_, value, found := strings.Cut(pair, "=")
	if !found {
		return ""
	}
	return strings.Trim(value, " \t")
}

// CredentialCandidates returns the values of the share cookie that name this share, in order, at
// most MaxCookieCandidates. A page on the same origin can plant a second cookie of the same name
// with a longer Path; the browser sends it first, so a few values are tried, not only the first.
func CredentialCandidates(cookieHeaders []string, shareID string) []string {
	var out []string
	for _, pair := range cookiePairs(cookieHeaders) {
		if pairName(pair) != CookieName {
			continue
		}
		value := pairValue(pair)
		if id, ok := ParseToken(value); ok && id == shareID {
			out = append(out, value)
			if len(out) == MaxCookieCandidates {
				break
			}
		}
	}
	return out
}

// ForwardedCookie is the single Cookie header sent to the device: every pair except the share
// cookie, in order. It is empty (and ok false) when nothing is left.
func ForwardedCookie(cookieHeaders []string) (string, bool) {
	var kept []string
	for _, pair := range cookiePairs(cookieHeaders) {
		if pairName(pair) != CookieName {
			kept = append(kept, pair)
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, "; "), true
}

var cacheHeaders = map[string]struct{}{
	"cache-control": {}, "cdn-cache-control": {}, "surrogate-control": {}, "expires": {}, "pragma": {},
}

// ScopeSetCookie confines an upstream Set-Cookie value to the share path, or returns false when it
// is dropped. Every route and share lives on one origin: a cookie set with Path=/ or a Domain by
// the target of share A would otherwise reach every other route and share the visitor opens.
func ScopeSetCookie(value, shareID string) (string, bool) {
	parts := strings.Split(value, ";")
	name := pairName(parts[0])
	if name == CookieName || strings.HasPrefix(strings.ToLower(name), "__host-") {
		return "", false
	}
	out := []string{strings.Trim(parts[0], " \t")}
	for _, part := range parts[1:] {
		attribute := strings.Trim(part, " \t")
		if attribute == "" {
			continue
		}
		key := strings.ToLower(pairName(attribute))
		if key == "domain" {
			continue
		}
		if key == "path" {
			path := pairValue(attribute)
			if strings.HasPrefix(path, "/") {
				attribute = "Path=" + SharePathRoot + shareID + path
			}
		}
		out = append(out, attribute)
	}
	return strings.Join(out, "; "), true
}

// ResponseHeaders rewrites the headers relayed to a share visitor after the route's own response
// rules: Set-Cookie is confined to the share path, Clear-Site-Data is dropped because it would wipe
// the whole origin, and cache headers are replaced so no shared cache keeps a copy and the browser
// revalidates every reuse. A 101 keeps its other headers.
func ResponseHeaders(status int, headers []string, shareID string) []string {
	noStore := false
	out := make([]string, 0, len(headers)+1)
	for _, header := range headers {
		name, value, _ := strings.Cut(header, ":")
		lowered := strings.ToLower(strings.TrimSpace(name))
		switch {
		case lowered == "clear-site-data":
			continue
		case lowered == "set-cookie":
			if scoped, ok := ScopeSetCookie(strings.Trim(value, " \t"), shareID); ok {
				out = append(out, strings.TrimSpace(name)+":"+scoped)
			}
			continue
		}
		if status != 101 {
			if _, cache := cacheHeaders[lowered]; cache {
				if lowered == "cache-control" {
					for _, directive := range strings.Split(value, ",") {
						key, _, _ := strings.Cut(strings.TrimSpace(directive), "=")
						if strings.EqualFold(strings.TrimSpace(key), "no-store") {
							noStore = true
						}
					}
				}
				continue
			}
		}
		out = append(out, header)
	}
	if status != 101 {
		if noStore {
			out = append(out, "Cache-Control:private, no-store")
		} else {
			out = append(out, "Cache-Control:private, no-cache")
		}
	}
	return out
}

// SetCookieHeader is the exchange's cookie: the token, scoped to the share path, living exactly as
// long as the share.
func SetCookieHeader(shareID, token string, maxAge int64) string {
	return CookieName + "=" + token + "; Path=" + SharePath(shareID) + "; Max-Age=" +
		strconv.FormatInt(maxAge, 10) + "; HttpOnly; Secure; SameSite=Strict"
}

// ClearCookieHeader makes the browser stop presenting the cookie of an ended share.
func ClearCookieHeader(shareID string) string {
	return CookieName + "=; Path=" + SharePath(shareID) + "; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
}

// IsReadMethod reports whether a read-only share forwards method.
func IsReadMethod(method string) bool {
	return method == "GET" || method == "HEAD"
}
