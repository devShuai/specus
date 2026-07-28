package transfer

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

const (
	ossV4Algorithm       = "OSS4-HMAC-SHA256"
	ossV4Terminator      = "aliyun_v4_request"
	ossUnsignedPayload   = "UNSIGNED-PAYLOAD"
	maxPresignTTLSeconds = int64(7 * 24 * 60 * 60)
)

type ObjectStat struct {
	Exists        bool
	ContentLength int64
}

type PresignedURL struct {
	URL       string
	Headers   map[string]string
	ExpiresAt time.Time
}

type ObjectStorage struct {
	cfg               config.ObjectStorageConfig
	client            *http.Client
	now               func() time.Time
	callbackKeysMu    sync.RWMutex
	callbackKeysByURL map[string]*rsa.PublicKey
}

func NewObjectStorage(cfg config.ObjectStorageConfig) *ObjectStorage {
	return &ObjectStorage{cfg: cfg, client: &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, now: time.Now, callbackKeysByURL: make(map[string]*rsa.PublicKey)}
}

func (s *ObjectStorage) Enabled() bool {
	return s != nil && strings.EqualFold(strings.TrimSpace(s.cfg.Provider), "aliyun-oss") &&
		strings.TrimSpace(s.cfg.Endpoint) != "" && strings.TrimSpace(s.cfg.Bucket) != "" &&
		strings.TrimSpace(s.cfg.AccessKeyID) != "" && strings.TrimSpace(s.cfg.AccessKeySecret) != ""
}

func (s *ObjectStorage) PresignUpload(objectKey, contentType string, ttl time.Duration) (PresignedURL, error) {
	if !s.Enabled() {
		return PresignedURL{}, errors.New("object storage is not configured")
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return PresignedURL{}, err
	}
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return s.presign(http.MethodPut, objectKey, contentType, ttl, "")
}

// PresignDownload accepts an optional one-time grant id that is signed into the
// OSS URL for audit correlation without exposing the bearer grant token.
func (s *ObjectStorage) PresignDownload(objectKey string, ttl time.Duration, grantID ...string) (PresignedURL, error) {
	if !s.Enabled() {
		return PresignedURL{}, errors.New("object storage is not configured")
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return PresignedURL{}, err
	}
	marker := ""
	if len(grantID) > 0 {
		marker = strings.TrimSpace(grantID[0])
	}
	return s.presign(http.MethodGet, objectKey, "", ttl, marker)
}

func (s *ObjectStorage) VerifyUploadCallback(ctx context.Context, requestTarget string, body []byte,
	authorization, encodedPublicKeyURL string) bool {
	if !s.Enabled() || strings.TrimSpace(s.cfg.UploadCallbackURL) == "" || requestTarget == "" ||
		len(body) > 64*1024 || strings.TrimSpace(authorization) == "" ||
		strings.TrimSpace(encodedPublicKeyURL) == "" {
		return false
	}
	publicKey, err := s.callbackPublicKey(ctx, encodedPublicKeyURL)
	if err != nil {
		return false
	}
	signatureValue := strings.TrimSpace(authorization)
	if len(signatureValue) >= 4 && strings.EqualFold(signatureValue[:4], "OSS ") {
		signatureValue = strings.TrimSpace(signatureValue[4:])
	}
	signature, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		return false
	}
	verifiedValue, err := callbackStringToVerify(requestTarget, body)
	if err != nil {
		return false
	}
	digest := md5.Sum([]byte(verifiedValue))
	return rsa.VerifyPKCS1v15(publicKey, crypto.MD5, digest[:], signature) == nil
}

func (s *ObjectStorage) Stat(ctx context.Context, objectKey string) (ObjectStat, error) {
	if !s.Enabled() {
		return ObjectStat{}, errors.New("object storage is not configured")
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return ObjectStat{}, err
	}
	req, err := s.authorizedRequest(ctx, http.MethodHead, objectKey)
	if err != nil {
		return ObjectStat{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return ObjectStat{}, fmt.Errorf("failed to stat object: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ObjectStat{}, fmt.Errorf("failed to stat object: HTTP %d", resp.StatusCode)
	}
	length := int64(-1)
	if raw := resp.Header.Get("Content-Length"); raw != "" {
		if parsed, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil {
			length = parsed
		}
	}
	return ObjectStat{Exists: true, ContentLength: length}, nil
}

func (s *ObjectStorage) Delete(ctx context.Context, objectKey string) error {
	if !s.Enabled() {
		return nil
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return err
	}
	req, err := s.authorizedRequest(ctx, http.MethodDelete, objectKey)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete object: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("failed to delete object: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *ObjectStorage) presign(method, objectKey, contentType string, ttl time.Duration,
	grantID string) (PresignedURL, error) {
	now := s.now().UTC()
	ttlSeconds := normalizePresignTTL(ttl)
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	region, err := s.resolvedRegion()
	if err != nil {
		return PresignedURL{}, err
	}
	date := now.Format("20060102")
	timestamp := now.Format("20060102T150405Z")
	scope := date + "/" + region + "/oss/" + ossV4Terminator
	query := map[string]string{
		"x-oss-additional-headers": "host",
		"x-oss-credential":         strings.TrimSpace(s.cfg.AccessKeyID) + "/" + scope,
		"x-oss-date":               timestamp,
		"x-oss-expires":            strconv.FormatInt(ttlSeconds, 10),
		"x-oss-signature-version":  ossV4Algorithm,
	}
	if grantID != "" {
		query["x-st-grant"] = grantID
	}
	headers := map[string]string{"host": s.objectHost()}
	responseHeaders := map[string]string{}
	if contentType != "" {
		headers["content-type"] = contentType
		responseHeaders["Content-Type"] = contentType
	}
	if method == http.MethodPut {
		callback, callbackErr := s.uploadCallbackHeader()
		if callbackErr != nil {
			return PresignedURL{}, callbackErr
		}
		if callback != "" {
			headers["x-oss-callback"] = callback
			responseHeaders["x-oss-callback"] = callback
		}
	}
	canonical := s.canonicalRequest(method, objectKey, query, headers, "host", ossUnsignedPayload)
	query["x-oss-signature"] = s.signature(now, canonical, region)
	return PresignedURL{
		URL:       s.objectURL(objectKey) + "?" + canonicalQuery(query),
		Headers:   responseHeaders,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *ObjectStorage) authorizedRequest(ctx context.Context, method, objectKey string) (*http.Request, error) {
	now := s.now().UTC()
	region, err := s.resolvedRegion()
	if err != nil {
		return nil, err
	}
	date := now.Format("20060102")
	timestamp := now.Format("20060102T150405Z")
	headers := map[string]string{
		"host":                 s.objectHost(),
		"x-oss-content-sha256": ossUnsignedPayload,
		"x-oss-date":           timestamp,
	}
	canonical := s.canonicalRequest(method, objectKey, nil, headers, "host", ossUnsignedPayload)
	authorization := ossV4Algorithm + " Credential=" + strings.TrimSpace(s.cfg.AccessKeyID) + "/" +
		date + "/" + region + "/oss/" + ossV4Terminator +
		", AdditionalHeaders=host, Signature=" + s.signature(now, canonical, region)
	req, err := http.NewRequestWithContext(ctx, method, s.objectURL(objectKey), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-oss-content-sha256", ossUnsignedPayload)
	req.Header.Set("x-oss-date", timestamp)
	req.Header.Set("Authorization", authorization)
	return req, nil
}

func (s *ObjectStorage) canonicalRequest(method, objectKey string, query, headers map[string]string,
	additionalHeaders, payloadHash string) string {
	return strings.ToUpper(method) + "\n" + s.canonicalResource(objectKey) + "\n" +
		canonicalQuery(query) + "\n" + canonicalHeaders(headers) + "\n" +
		additionalHeaders + "\n" + payloadHash
}

func (s *ObjectStorage) signature(now time.Time, canonicalRequest, region string) string {
	date := now.UTC().Format("20060102")
	scope := date + "/" + region + "/oss/" + ossV4Terminator
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := ossV4Algorithm + "\n" + now.UTC().Format("20060102T150405Z") + "\n" +
		scope + "\n" + hex.EncodeToString(requestHash[:])
	dateKey := hmacSHA256([]byte("aliyun_v4"+s.cfg.AccessKeySecret), date)
	regionKey := hmacSHA256(dateKey, region)
	serviceKey := hmacSHA256(regionKey, "oss")
	signingKey := hmacSHA256(serviceKey, ossV4Terminator)
	return hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func canonicalHeaders(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	var result strings.Builder
	for _, key := range keys {
		result.WriteString(key)
		result.WriteByte(':')
		result.WriteString(strings.TrimSpace(headers[key]))
		result.WriteByte('\n')
	}
	return result.String()
}

func canonicalQuery(query map[string]string) string {
	type pair struct{ key, value string }
	pairs := make([]pair, 0, len(query))
	for key, value := range query {
		pairs = append(pairs, pair{key: uriEncode(key, true), value: uriEncode(value, true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	var result strings.Builder
	for index, entry := range pairs {
		if index > 0 {
			result.WriteByte('&')
		}
		result.WriteString(entry.key)
		result.WriteByte('=')
		result.WriteString(entry.value)
	}
	return result.String()
}

func normalizePresignTTL(ttl time.Duration) int64 {
	seconds := int64(ttl / time.Second)
	if seconds < 1 {
		return 1
	}
	if seconds > maxPresignTTLSeconds {
		return maxPresignTTLSeconds
	}
	return seconds
}

func (s *ObjectStorage) uploadCallbackHeader() (string, error) {
	value := strings.TrimSpace(s.cfg.UploadCallbackURL)
	if value == "" {
		return "", nil
	}
	callbackURL, err := url.Parse(value)
	if err != nil || callbackURL.Hostname() == "" || callbackURL.User != nil || callbackURL.Fragment != "" ||
		(callbackURL.Scheme != "http" && callbackURL.Scheme != "https") {
		return "", errors.New("object storage upload callback URL is invalid")
	}
	callback := map[string]any{
		"callbackUrl": callbackURL.String(),
		"callbackBody": "{\"bucket\":${bucket},\"object\":${object},\"size\":${size}," +
			"\"mimeType\":${mimeType},\"etag\":${etag}}",
		"callbackBodyType": "application/json",
	}
	if callbackURL.Scheme == "https" {
		callback["callbackSNI"] = true
	}
	encoded, err := json.Marshal(callback)
	if err != nil {
		return "", fmt.Errorf("failed to serialize object storage upload callback: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func (s *ObjectStorage) callbackPublicKey(ctx context.Context, encodedURL string) (*rsa.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedURL))
	if err != nil {
		return nil, err
	}
	publicKeyURL, err := url.Parse(strings.TrimSpace(string(decoded)))
	if err != nil || !strings.EqualFold(publicKeyURL.Hostname(), "gosspublic.alicdn.com") ||
		(publicKeyURL.Scheme != "http" && publicKeyURL.Scheme != "https") || publicKeyURL.User != nil ||
		publicKeyURL.Fragment != "" || publicKeyURL.RawQuery != "" || publicKeyURL.Port() != "" ||
		!strings.HasPrefix(publicKeyURL.EscapedPath(), "/callback_pub_key") {
		return nil, errors.New("OSS callback public key URL is invalid")
	}
	publicKeyURL.Scheme = "https"
	cacheKey := publicKeyURL.String()
	s.callbackKeysMu.RLock()
	cached := s.callbackKeysByURL[cacheKey]
	s.callbackKeysMu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	loadCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(loadCtx, http.MethodGet, cacheKey, nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to load OSS callback public key: HTTP %d", response.StatusCode)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(pemBytes) > 64*1024 {
		return nil, errors.New("invalid OSS callback public key response")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid OSS callback public key PEM")
	}
	var parsed any
	if block.Type == "RSA PUBLIC KEY" {
		parsed, err = x509.ParsePKCS1PublicKey(block.Bytes)
	} else {
		parsed, err = x509.ParsePKIXPublicKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("OSS callback public key is not RSA")
	}
	s.callbackKeysMu.Lock()
	if existing := s.callbackKeysByURL[cacheKey]; existing != nil {
		key = existing
	} else {
		s.callbackKeysByURL[cacheKey] = key
	}
	s.callbackKeysMu.Unlock()
	return key, nil
}

func callbackStringToVerify(requestTarget string, body []byte) (string, error) {
	path, query, found := strings.Cut(requestTarget, "?")
	decodedPath, err := url.PathUnescape(path)
	if err != nil {
		return "", err
	}
	if found {
		decodedPath += "?" + query
	}
	return decodedPath + "\n" + string(body), nil
}

func (s *ObjectStorage) resolvedRegion() (string, error) {
	if region := strings.TrimSpace(s.cfg.Region); region != "" {
		return region, nil
	}
	parsed, err := s.endpointURL()
	if err != nil {
		return "", err
	}
	host := strings.ToLower(parsed.Hostname())
	if strings.HasPrefix(host, "oss-") {
		candidate := strings.TrimPrefix(strings.SplitN(host, ".", 2)[0], "oss-")
		candidate = strings.TrimSuffix(candidate, "-internal")
		if candidate != "" && candidate != "accelerate" {
			return candidate, nil
		}
	}
	return "", errors.New("object storage region is required for OSS V4 signing")
}

func (s *ObjectStorage) validateObjectKey(objectKey string) error {
	value := strings.TrimSpace(objectKey)
	prefix := strings.Trim(strings.TrimSpace(s.cfg.ObjectPrefix), "/")
	if value == "" {
		return errors.New("objectKey cannot be blank")
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, `\`) || strings.Contains(value, "..") ||
		strings.Contains(value, "//") || strings.IndexFunc(value, func(r rune) bool { return r < 32 }) >= 0 {
		return errors.New("objectKey is invalid")
	}
	if prefix != "" && !strings.HasPrefix(value, prefix+"/") {
		return errors.New("objectKey is outside the configured prefix")
	}
	return nil
}

func (s *ObjectStorage) endpointURL() (*url.URL, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(s.cfg.Endpoint), "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("object storage endpoint is invalid")
	}
	return parsed, nil
}

func (s *ObjectStorage) objectHost() string {
	parsed, _ := s.endpointURL()
	host := parsed.Hostname()
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	return strings.TrimSpace(s.cfg.Bucket) + "." + host
}

func (s *ObjectStorage) objectURL(objectKey string) string {
	parsed, _ := s.endpointURL()
	return parsed.Scheme + "://" + s.objectHost() + "/" + uriEncode(objectKey, false)
}

func (s *ObjectStorage) canonicalResource(objectKey string) string {
	return uriEncode("/"+strings.TrimSpace(s.cfg.Bucket)+"/"+objectKey, false)
}

func uriEncode(value string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded strings.Builder
	for _, current := range []byte(value) {
		unreserved := current >= 'A' && current <= 'Z' || current >= 'a' && current <= 'z' ||
			current >= '0' && current <= '9' || current == '-' || current == '_' || current == '.' || current == '~'
		if unreserved || !encodeSlash && current == '/' {
			encoded.WriteByte(current)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexDigits[current>>4])
		encoded.WriteByte(hexDigits[current&0x0f])
	}
	return encoded.String()
}
