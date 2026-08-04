package media

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

const (
	awsAlgorithm  = "AWS4-HMAC-SHA256"
	awsTerminator = "aws4_request"
	awsService    = "s3"
)

type MultipartUpload struct {
	ObjectKey string
	UploadID  string
}

type CompletedPart struct {
	PartNumber int
	ETag       string
}

// Storage is the capture service's RustFS/S3 contract. Keeping it narrow makes the capture
// and playback paths testable without a real object store.
type Storage interface {
	Ready() bool
	BeginMultipart(context.Context, string, string, string) (MultipartUpload, error)
	UploadPart(context.Context, MultipartUpload, int, []byte) (CompletedPart, error)
	CompleteMultipart(context.Context, MultipartUpload, []CompletedPart) (string, error)
	AbortMultipart(context.Context, MultipartUpload) error
	Open(context.Context, string, int64, int64) (io.ReadCloser, error)
	ReadAll(context.Context, string, int64) ([]byte, error)
	Delete(context.Context, string) error
}

// RustFSStorage implements the AWS S3 REST protocol directly. RustFS is S3 compatible and
// this avoids coupling the server to a large SDK solely for multipart capture/playback.
type RustFSStorage struct {
	cfg    config.MediaCaptureConfig
	client *http.Client
	now    func() time.Time
	ready  atomic.Bool
}

func NewRustFSStorage(cfg config.MediaCaptureConfig) *RustFSStorage {
	return &RustFSStorage{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
}

// Initialize verifies the private bucket. Incomplete/disabled configuration is a safe no-op;
// an explicitly enabled but unreachable or unauthorized bucket is a startup error.
func (s *RustFSStorage) Initialize(ctx context.Context) error {
	if s == nil || !s.cfg.Ready() {
		return nil
	}
	response, err := s.do(ctx, http.MethodHead, "", nil, nil, nil)
	if err != nil {
		return fmt.Errorf("verify RustFS bucket: %w", err)
	}
	status := response.StatusCode
	response.Body.Close()
	if status == http.StatusNotFound && s.cfg.CreateBucketIfMissing {
		response, err = s.do(ctx, http.MethodPut, "", nil, nil, nil)
		if err != nil {
			return fmt.Errorf("create RustFS bucket: %w", err)
		}
		status = response.StatusCode
		response.Body.Close()
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("verify RustFS bucket: HTTP %d", status)
	}
	s.ready.Store(true)
	return nil
}

func (s *RustFSStorage) Ready() bool { return s != nil && s.ready.Load() }

func (s *RustFSStorage) BeginMultipart(ctx context.Context, objectKey, contentType,
	contentEncoding string) (MultipartUpload, error) {
	if !s.Ready() {
		return MultipartUpload{}, errors.New("RustFS media storage is disabled")
	}
	headers := make(http.Header)
	if value := strings.TrimSpace(contentType); value != "" {
		headers.Set("Content-Type", value)
	}
	if value := strings.TrimSpace(contentEncoding); value != "" {
		headers.Set("Content-Encoding", value)
	}
	response, err := s.do(ctx, http.MethodPost, objectKey, url.Values{"uploads": {""}}, headers, nil)
	if err != nil {
		return MultipartUpload{}, err
	}
	defer response.Body.Close()
	if err := requireS3Success(response); err != nil {
		return MultipartUpload{}, err
	}
	var result struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&result); err != nil {
		return MultipartUpload{}, fmt.Errorf("decode multipart response: %w", err)
	}
	if strings.TrimSpace(result.UploadID) == "" {
		return MultipartUpload{}, errors.New("RustFS returned an empty multipart upload id")
	}
	return MultipartUpload{ObjectKey: objectKey, UploadID: result.UploadID}, nil
}

func (s *RustFSStorage) UploadPart(ctx context.Context, upload MultipartUpload,
	partNumber int, data []byte) (CompletedPart, error) {
	if !s.Ready() {
		return CompletedPart{}, errors.New("RustFS media storage is disabled")
	}
	query := url.Values{
		"partNumber": {strconv.Itoa(partNumber)},
		"uploadId":   {upload.UploadID},
	}
	response, err := s.do(ctx, http.MethodPut, upload.ObjectKey, query, nil, data)
	if err != nil {
		return CompletedPart{}, err
	}
	defer response.Body.Close()
	if err := requireS3Success(response); err != nil {
		return CompletedPart{}, err
	}
	etag := strings.TrimSpace(response.Header.Get("ETag"))
	if etag == "" {
		return CompletedPart{}, errors.New("RustFS upload-part response did not contain an ETag")
	}
	return CompletedPart{PartNumber: partNumber, ETag: etag}, nil
}

func (s *RustFSStorage) CompleteMultipart(ctx context.Context, upload MultipartUpload,
	parts []CompletedPart) (string, error) {
	if !s.Ready() {
		return "", errors.New("RustFS media storage is disabled")
	}
	sorted := append([]CompletedPart(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PartNumber < sorted[j].PartNumber })
	type xmlPart struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	}
	payload := struct {
		XMLName xml.Name  `xml:"CompleteMultipartUpload"`
		Parts   []xmlPart `xml:"Part"`
	}{Parts: make([]xmlPart, 0, len(sorted))}
	for _, part := range sorted {
		payload.Parts = append(payload.Parts, xmlPart{PartNumber: part.PartNumber, ETag: part.ETag})
	}
	body, err := xml.Marshal(payload)
	if err != nil {
		return "", err
	}
	response, err := s.do(ctx, http.MethodPost, upload.ObjectKey,
		url.Values{"uploadId": {upload.UploadID}}, http.Header{"Content-Type": {"application/xml"}}, body)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if err := requireS3Success(response); err != nil {
		return "", err
	}
	var result struct {
		XMLName xml.Name
		ETag    string `xml:"ETag"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if err := xml.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode complete-multipart response: %w", err)
	}
	if strings.EqualFold(result.XMLName.Local, "Error") || strings.TrimSpace(result.Code) != "" {
		return "", fmt.Errorf("RustFS complete multipart failed: %s: %s",
			strings.TrimSpace(result.Code), strings.TrimSpace(result.Message))
	}
	if strings.TrimSpace(result.ETag) == "" {
		result.ETag = response.Header.Get("ETag")
	}
	if strings.TrimSpace(result.ETag) == "" {
		return "", errors.New("RustFS complete-multipart response did not contain an ETag")
	}
	return strings.TrimSpace(result.ETag), nil
}

func (s *RustFSStorage) AbortMultipart(ctx context.Context, upload MultipartUpload) error {
	if !s.Ready() || strings.TrimSpace(upload.UploadID) == "" {
		return nil
	}
	response, err := s.do(ctx, http.MethodDelete, upload.ObjectKey,
		url.Values{"uploadId": {upload.UploadID}}, nil, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return requireS3Success(response)
}

func (s *RustFSStorage) Open(ctx context.Context, objectKey string, start, end int64) (io.ReadCloser, error) {
	if !s.Ready() {
		return nil, errors.New("RustFS media storage is disabled")
	}
	headers := make(http.Header)
	rangeRequested := start >= 0 && end >= start
	if rangeRequested {
		headers.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	}
	response, err := s.do(ctx, http.MethodGet, objectKey, nil, headers, nil)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		err := s3ResponseError(response)
		response.Body.Close()
		return nil, err
	}
	if rangeRequested && response.StatusCode != http.StatusPartialContent {
		response.Body.Close()
		return nil, fmt.Errorf("RustFS ignored requested byte range %d-%d (status %d)", start, end, response.StatusCode)
	}
	return response.Body, nil
}

func (s *RustFSStorage) ReadAll(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("media object read limit must be positive")
	}
	input, err := s.Open(ctx, objectKey, -1, -1)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	data, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("media object exceeds %d-byte manifest limit", maxBytes)
	}
	return data, nil
}

func (s *RustFSStorage) Delete(ctx context.Context, objectKey string) error {
	if !s.Ready() {
		return nil
	}
	response, err := s.do(ctx, http.MethodDelete, objectKey, nil, nil, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil
	}
	return requireS3Success(response)
}

func (s *RustFSStorage) do(ctx context.Context, method, objectKey string, query url.Values,
	headers http.Header, body []byte) (*http.Response, error) {
	requestURL, err := s.requestURL(objectKey, query)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	s.sign(request, body)
	return s.client.Do(request)
}

func (s *RustFSStorage) requestURL(objectKey string, query url.Values) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(s.cfg.Endpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, errors.New("invalid RustFS endpoint")
	}
	endpoint.Fragment = ""
	endpoint.RawQuery = ""
	bucket := strings.TrimSpace(s.cfg.Bucket)
	segments := make([]string, 0, 2)
	if s.cfg.PathStyle {
		segments = append(segments, bucket)
	} else {
		endpoint.Host = bucket + "." + endpoint.Host
	}
	if key := strings.Trim(objectKey, "/"); key != "" {
		segments = append(segments, strings.Split(key, "/")...)
	}
	path := strings.TrimRight(endpoint.Path, "/")
	rawPath := strings.TrimRight(endpoint.EscapedPath(), "/")
	for _, segment := range segments {
		path += "/" + segment
		rawPath += "/" + awsURIEncode(segment)
	}
	if path == "" {
		path = "/"
		rawPath = "/"
	}
	endpoint.Path = path
	endpoint.RawPath = rawPath
	endpoint.RawQuery = canonicalAWSQuery(query)
	return endpoint, nil
}

func (s *RustFSStorage) sign(request *http.Request, body []byte) {
	now := s.now().UTC()
	region := strings.TrimSpace(s.cfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	payloadHashBytes := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(payloadHashBytes[:])
	timestamp := now.Format("20060102T150405Z")
	request.Header.Set("x-amz-date", timestamp)
	request.Header.Set("x-amz-content-sha256", payloadHash)
	host := request.URL.Host
	canonicalHeaders := "host:" + strings.TrimSpace(host) + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + timestamp + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := request.Method + "\n" + request.URL.EscapedPath() + "\n" +
		request.URL.RawQuery + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
	date := now.Format("20060102")
	scope := date + "/" + region + "/" + awsService + "/" + awsTerminator
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := awsAlgorithm + "\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	dateKey := awsHMAC([]byte("AWS4"+s.cfg.AccessKeySecret), date)
	regionKey := awsHMAC(dateKey, region)
	serviceKey := awsHMAC(regionKey, awsService)
	signingKey := awsHMAC(serviceKey, awsTerminator)
	signature := hex.EncodeToString(awsHMAC(signingKey, stringToSign))
	request.Header.Set("Authorization", awsAlgorithm+" Credential="+strings.TrimSpace(s.cfg.AccessKeyID)+"/"+
		scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func awsHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func canonicalAWSQuery(values url.Values) string {
	type pair struct{ key, value string }
	pairs := make([]pair, 0)
	for key, entries := range values {
		if len(entries) == 0 {
			entries = []string{""}
		}
		for _, value := range entries {
			pairs = append(pairs, pair{awsURIEncode(key), awsURIEncode(value)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	var result strings.Builder
	for index, item := range pairs {
		if index > 0 {
			result.WriteByte('&')
		}
		result.WriteString(item.key)
		result.WriteByte('=')
		result.WriteString(item.value)
	}
	return result.String()
}

func awsURIEncode(value string) string {
	var result strings.Builder
	for _, b := range []byte(value) {
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
			b == '-' || b == '_' || b == '.' || b == '~' {
			result.WriteByte(b)
		} else {
			result.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return result.String()
}

func requireS3Success(response *http.Response) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	return s3ResponseError(response)
}

func s3ResponseError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	message := strings.TrimSpace(string(body))
	if message == "" {
		return fmt.Errorf("RustFS request failed: HTTP %d", response.StatusCode)
	}
	return fmt.Errorf("RustFS request failed: HTTP %d: %s", response.StatusCode, message)
}
