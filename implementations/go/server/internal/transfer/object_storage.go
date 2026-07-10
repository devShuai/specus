package transfer

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
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
	cfg    config.ObjectStorageConfig
	client *http.Client
}

func NewObjectStorage(cfg config.ObjectStorageConfig) *ObjectStorage {
	return &ObjectStorage{cfg: cfg, client: &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
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
	expiresAt := time.Now().Add(ttl)
	expires := expiresAt.Unix()
	signature := s.signature("PUT", contentType, expires, objectKey)
	return PresignedURL{
		URL:       s.signedURL(objectKey, expires, signature),
		Headers:   map[string]string{"Content-Type": contentType},
		ExpiresAt: expiresAt,
	}, nil
}

func (s *ObjectStorage) PresignDownload(objectKey string, ttl time.Duration) (PresignedURL, error) {
	if !s.Enabled() {
		return PresignedURL{}, errors.New("object storage is not configured")
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return PresignedURL{}, err
	}
	expiresAt := time.Now().Add(ttl)
	expires := expiresAt.Unix()
	return PresignedURL{
		URL:     s.signedURL(objectKey, expires, s.signature("GET", "", expires, objectKey)),
		Headers: map[string]string{}, ExpiresAt: expiresAt,
	}, nil
}

func (s *ObjectStorage) Stat(ctx context.Context, objectKey string) (ObjectStat, error) {
	if !s.Enabled() {
		return ObjectStat{}, errors.New("object storage is not configured")
	}
	if err := s.validateObjectKey(objectKey); err != nil {
		return ObjectStat{}, err
	}
	now := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := "HEAD\n\n\n" + now + "\n" + s.canonicalResource(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.objectURL(objectKey), nil)
	if err != nil {
		return ObjectStat{}, err
	}
	req.Header.Set("Date", now)
	req.Header.Set("Authorization", "OSS "+strings.TrimSpace(s.cfg.AccessKeyID)+":"+s.hmacSHA1(stringToSign))
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
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
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
	now := time.Now().UTC().Format(http.TimeFormat)
	stringToSign := "DELETE\n\n\n" + now + "\n" + s.canonicalResource(objectKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.objectURL(objectKey), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Date", now)
	req.Header.Set("Authorization", "OSS "+strings.TrimSpace(s.cfg.AccessKeyID)+":"+s.hmacSHA1(stringToSign))
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

func (s *ObjectStorage) signature(method, contentType string, expires int64, objectKey string) string {
	value := strings.ToUpper(method) + "\n\n" + contentType + "\n" + strconv.FormatInt(expires, 10) + "\n" + s.canonicalResource(objectKey)
	return s.hmacSHA1(value)
}

func (s *ObjectStorage) hmacSHA1(value string) string {
	mac := hmac.New(sha1.New, []byte(s.cfg.AccessKeySecret))
	_, _ = mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (s *ObjectStorage) signedURL(objectKey string, expires int64, signature string) string {
	query := url.Values{}
	query.Set("OSSAccessKeyId", strings.TrimSpace(s.cfg.AccessKeyID))
	query.Set("Expires", strconv.FormatInt(expires, 10))
	query.Set("Signature", signature)
	return s.objectURL(objectKey) + "?" + strings.ReplaceAll(query.Encode(), "+", "%20")
}

func (s *ObjectStorage) objectURL(objectKey string) string {
	endpoint := strings.TrimRight(strings.TrimSpace(s.cfg.Endpoint), "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}
	parsed, _ := url.Parse(endpoint)
	host := parsed.Hostname()
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	segments := strings.Split(objectKey, "/")
	for index := range segments {
		segments[index] = url.PathEscape(segments[index])
	}
	return parsed.Scheme + "://" + strings.TrimSpace(s.cfg.Bucket) + "." + host + "/" + strings.Join(segments, "/")
}

func (s *ObjectStorage) canonicalResource(objectKey string) string {
	return "/" + strings.TrimSpace(s.cfg.Bucket) + "/" + objectKey
}
