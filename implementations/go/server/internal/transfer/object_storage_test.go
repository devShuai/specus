package transfer

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

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
		Provider: "aliyun-oss", Endpoint: "https://oss.example.test", Bucket: "private",
		AccessKeyID: "key", AccessKeySecret: "secret", ObjectPrefix: "prefix",
	})
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
