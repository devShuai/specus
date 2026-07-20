package transfer

import (
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
)

func TestObjectStorageHeadAndDeleteTreatEveryStatusBelow400AsSuccessWithoutRedirect(t *testing.T) {
	storage := newObjectStorageHTTPTestTarget()
	for _, method := range []string{http.MethodHead, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			storage.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != method {
					t.Fatalf("method = %s, want %s", request.Method, method)
				}
				return objectStorageResponse(request, http.StatusTemporaryRedirect, map[string]string{
					"Location":       "https://redirected.invalid/object",
					"Content-Length": "17",
				}), nil
			})

			if method == http.MethodHead {
				stat, err := storage.Stat(context.Background(), "prefix/object.txt")
				if err != nil {
					t.Fatalf("HEAD 307: %v", err)
				}
				if !stat.Exists || stat.ContentLength != 17 {
					t.Fatalf("HEAD 307 stat = %+v", stat)
				}
			} else if err := storage.Delete(context.Background(), "prefix/object.txt"); err != nil {
				t.Fatalf("DELETE 307: %v", err)
			}
			if calls != 1 {
				t.Fatalf("redirect was followed: round trips = %d, want 1", calls)
			}
		})
	}
}

func TestObjectStorageHeadAndDeleteRejectEveryStatusAtLeast400(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		status int
	}{
		{name: "head-400", method: http.MethodHead, status: http.StatusBadRequest},
		{name: "head-404", method: http.MethodHead, status: http.StatusNotFound},
		{name: "delete-400", method: http.MethodDelete, status: http.StatusBadRequest},
		{name: "delete-404", method: http.MethodDelete, status: http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			storage := newObjectStorageHTTPTestTarget()
			storage.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				return objectStorageResponse(request, test.status, nil), nil
			})
			if test.method == http.MethodHead {
				if _, err := storage.Stat(context.Background(), "prefix/object.txt"); err == nil {
					t.Fatalf("HEAD %d succeeded", test.status)
				}
			} else if err := storage.Delete(context.Background(), "prefix/object.txt"); err == nil {
				t.Fatalf("DELETE %d succeeded", test.status)
			}
		})
	}
}

func newObjectStorageHTTPTestTarget() *ObjectStorage {
	return NewObjectStorage(config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "https://oss.example.test", Region: "cn-hangzhou", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
	})
}

func TestPresignedDownloadUsesOSSv4AndSignsGrantMarker(t *testing.T) {
	storage := NewObjectStorage(config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
		Bucket: "examplebucket", AccessKeyID: "test-access-key",
		AccessKeySecret: "test-secret-key", ObjectPrefix: "prefix",
	})
	storage.now = func() time.Time {
		return time.Date(2024, 12, 3, 3, 44, 20, 0, time.UTC)
	}

	result, err := storage.PresignDownload("prefix/example.txt", 600*time.Second, "grant-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"x-oss-signature-version=OSS4-HMAC-SHA256",
		"x-oss-credential=test-access-key%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request",
		"x-oss-date=20241203T034420Z",
		"x-oss-expires=600",
		"x-st-grant=grant-123",
		"x-oss-signature=c2fae9c2ac1a8e6ec5d0ef73e0ac015f40deaf92c3ec5626139a7cacb71225ac",
	} {
		if !strings.Contains(result.URL, expected) {
			t.Fatalf("presigned URL missing %q: %s", expected, result.URL)
		}
	}
	if strings.Contains(result.URL, "OSSAccessKeyId=") || strings.Contains(result.URL, "&Signature=") {
		t.Fatalf("presigned URL still uses OSS v1: %s", result.URL)
	}
}

func TestPresignedUploadIncludesSignedOssCallbackHeader(t *testing.T) {
	storage := NewObjectStorage(config.ObjectStorageConfig{
		Provider: "aliyun-oss", Endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
		Bucket: "examplebucket", AccessKeyID: "test-access-key", AccessKeySecret: "test-secret-key",
		ObjectPrefix: "prefix", UploadCallbackURL: "https://tunnel.example/api/public/transfer/oss-callback",
	})
	result, err := storage.PresignUpload("prefix/example.txt", "text/plain", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encoded := result.Headers["x-oss-callback"]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var callback map[string]any
	if err := json.Unmarshal(decoded, &callback); err != nil {
		t.Fatal(err)
	}
	if callback["callbackUrl"] != "https://tunnel.example/api/public/transfer/oss-callback" ||
		callback["callbackBodyType"] != "application/json" || callback["callbackSNI"] != true {
		t.Fatalf("unexpected callback header: %s", decoded)
	}
	if !strings.Contains(callback["callbackBody"].(string), "${object}") {
		t.Fatalf("callback body does not include OSS object: %s", decoded)
	}
}

func signCallbackForTest(t *testing.T, storage *ObjectStorage, requestTarget string,
	body []byte) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	storage.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Host != "gosspublic.alicdn.com" {
			t.Fatalf("unexpected callback public key request: %s %s", request.Method, request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(string(publicPEM))), Request: request}, nil
	})
	value, err := callbackStringToVerify(requestTarget, body)
	if err != nil {
		t.Fatal(err)
	}
	digest := md5.Sum([]byte(value))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKeyURL := base64.StdEncoding.EncodeToString(
		[]byte("http://gosspublic.alicdn.com/callback_pub_key_v1.pem"))
	return base64.StdEncoding.EncodeToString(signature), publicKeyURL
}

func objectStorageResponse(request *http.Request, status int, headers map[string]string) *http.Response {
	header := make(http.Header)
	for name, value := range headers {
		header.Set(name, value)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}
}
