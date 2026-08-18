package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

func TestHostedClientPackagesUploadCatalogVersionCheckDownloadAndDelete(t *testing.T) {
	dataDirectory := t.TempDir()
	cfg := config.Default()
	cfg.DataDirectory = dataDirectory
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)

	firstBody := []byte("go-client-v1.1.0")
	first := uploadClientPackage(t, ts, admin, firstBody, map[string]string{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "1.1.0",
		"displayName": "specus-client-go-1.1.0-linux-x64", "isLatest": "true",
		"changelogUrl": "https://example.com/releases/v1.1.0", "minSupportedVersion": "1.0.0",
	})
	if !first.Hosted || first.PackageID == nil || *first.PackageID != first.ID || !first.IsLatest {
		t.Fatalf("unexpected hosted package response: %+v", first)
	}
	wantHash := sha256.Sum256(firstBody)
	if first.SHA256 != hex.EncodeToString(wantHash[:]) || first.FileSize != int64(len(firstBody)) {
		t.Fatalf("server-computed package metadata mismatch: %+v", first)
	}
	if first.DownloadURL != "/api/public/client-packages/"+strconv.FormatInt(first.ID, 10)+"/download" {
		t.Fatalf("downloadUrl = %q", first.DownloadURL)
	}

	response, err := http.Get(ts.URL + first.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || !bytes.Equal(downloaded, firstBody) {
		t.Fatalf("download status=%d body=%q err=%v", response.StatusCode, downloaded, readErr)
	}
	request, _ := http.NewRequest(http.MethodHead, ts.URL+first.DownloadURL, nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength != int64(len(firstBody)) {
		t.Fatalf("HEAD status=%d length=%d", response.StatusCode, response.ContentLength)
	}

	check := getClientVersionCheck(t, ts.URL, "go", "linux", "x64", "1.0.0")
	if !check.UpdateAvailable || check.Mandatory || check.LatestVersion != "1.1.0" ||
		check.PackageID == nil || *check.PackageID != first.ID || check.SHA256 != first.SHA256 {
		t.Fatalf("unexpected version check: %+v", check)
	}
	check = getClientVersionCheck(t, ts.URL, "go", "linux", "x64", "0.9.0")
	if !check.UpdateAvailable || !check.Mandatory {
		t.Fatalf("old unsupported version should be mandatory: %+v", check)
	}

	second := uploadClientPackage(t, ts, admin, []byte("go-client-v1.2.0"), map[string]string{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "1.2.0",
		"displayName": "specus-client-go-1.2.0-linux-x64", "isLatest": "true",
	})
	all := listClientPackages(t, ts.URL, admin)
	latestByID := map[int64]bool{}
	for _, item := range all {
		latestByID[item.ID] = item.IsLatest
	}
	if latestByID[first.ID] || !latestByID[second.ID] {
		t.Fatalf("latest flags were not switched atomically: %#v", latestByID)
	}

	response = authRequest(t, ts, http.MethodPost,
		"/api/admin/client-downloads/"+strconv.FormatInt(first.ID, 10)+"/latest", admin, "")
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set latest status = %d", response.StatusCode)
	}
	check = getClientVersionCheck(t, ts.URL, "go", "linux", "x64", "1.0.0")
	if check.LatestVersion != "1.1.0" || check.PackageID == nil || *check.PackageID != first.ID {
		t.Fatalf("explicit latest was not selected: %+v", check)
	}

	duplicate := uploadClientPackageResponse(t, ts, admin, []byte("duplicate"), map[string]string{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "1.1.0",
		"displayName": "duplicate",
	})
	duplicate.Body.Close()
	if duplicate.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate target version status = %d, want 409", duplicate.StatusCode)
	}

	response = authRequest(t, ts, http.MethodDelete,
		"/api/admin/client-downloads/"+strconv.FormatInt(first.ID, 10), admin, "")
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete hosted package status = %d", response.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(dataDirectory, "packages", strconv.FormatInt(first.ID, 10))); !os.IsNotExist(err) {
		t.Fatalf("hosted package file remained after delete: %v", err)
	}
}

func TestHostedClientPackagesSupportAndroidUniversalAPK(t *testing.T) {
	cfg := config.Default()
	cfg.DataDirectory = t.TempDir()
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)
	item := uploadClientPackage(t, ts, admin, []byte("unsigned-apk"), map[string]string{
		"implementation": "android", "platform": "android", "arch": "any", "version": "2.0.0",
		"displayName": "specus-client-android-2.0.0.apk", "isLatest": "true",
	})
	check := getClientVersionCheck(t, ts.URL, "android", "android", "any", "1.0.0")
	if !check.UpdateAvailable || check.LatestVersion != "2.0.0" ||
		check.PackageID == nil || *check.PackageID != item.ID {
		t.Fatalf("Android universal package was not selected: %+v", check)
	}
}

type clientPackageViewForTest struct {
	ID          int64  `json:"id"`
	Version     string `json:"version"`
	DownloadURL string `json:"downloadUrl"`
	SHA256      string `json:"sha256"`
	FileSize    int64  `json:"fileSize"`
	IsLatest    bool   `json:"isLatest"`
	Hosted      bool   `json:"hosted"`
	PackageID   *int64 `json:"packageId"`
}

type clientVersionCheckForTest struct {
	UpdateAvailable bool    `json:"updateAvailable"`
	Mandatory       bool    `json:"mandatory"`
	LatestVersion   string  `json:"latestVersion"`
	PackageID       *int64  `json:"packageId"`
	DownloadURL     string  `json:"downloadUrl"`
	SHA256          string  `json:"sha256"`
	FileSize        int64   `json:"fileSize"`
	ChangelogURL    *string `json:"changelogUrl"`
}

func uploadClientPackage(t *testing.T, ts *httptest.Server, token string,
	content []byte, fields map[string]string) clientPackageViewForTest {
	t.Helper()
	response := uploadClientPackageResponse(t, ts, token, content, fields)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("upload status=%d body=%s", response.StatusCode, body)
	}
	var view clientPackageViewForTest
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	return view
}

func uploadClientPackageResponse(t *testing.T, ts *httptest.Server, token string,
	content []byte, fields map[string]string) *http.Response {
	t.Helper()
	return uploadClientPackageResponseToURL(t, ts.URL, token, content, fields)
}

func uploadClientPackageResponseToURL(t *testing.T, baseURL, token string,
	content []byte, fields map[string]string) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "package.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/admin/client-packages", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func listClientPackages(t *testing.T, tsURL string, token string) []clientPackageViewForTest {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, tsURL+"/api/admin/client-downloads", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var views []clientPackageViewForTest
	if err := json.NewDecoder(response.Body).Decode(&views); err != nil {
		t.Fatal(err)
	}
	return views
}

func getClientVersionCheck(t *testing.T, tsURL, implementation, platform, arch, current string) clientVersionCheckForTest {
	t.Helper()
	query := url.Values{
		"implementation": {implementation}, "platform": {platform}, "arch": {arch}, "current": {current},
	}
	response, err := http.Get(tsURL + "/api/public/client-version-check?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("version check status=%d body=%s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var view clientVersionCheckForTest
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	return view
}
