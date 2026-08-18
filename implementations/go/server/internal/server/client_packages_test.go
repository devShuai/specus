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
	request, _ = http.NewRequest(http.MethodGet, ts.URL+first.DownloadURL, nil)
	request.Header.Set("Range", "bytes=3-7")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	ranged, rangeErr := io.ReadAll(response.Body)
	response.Body.Close()
	if rangeErr != nil || response.StatusCode != http.StatusPartialContent ||
		!bytes.Equal(ranged, firstBody[3:8]) {
		t.Fatalf("range status=%d body=%q err=%v", response.StatusCode, ranged, rangeErr)
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
	public := listPublicClientPackages(t, ts.URL)
	visibleTargetVersions := make([]clientPackageViewForTest, 0)
	for _, item := range public {
		if item.ID == first.ID || item.ID == second.ID {
			visibleTargetVersions = append(visibleTargetVersions, item)
		}
	}
	if len(visibleTargetVersions) != 1 || visibleTargetVersions[0].ID != second.ID {
		t.Fatalf("public catalog exposed historical target versions: %+v", visibleTargetVersions)
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
	check = getClientVersionCheck(t, ts.URL, "go", "linux", "x64", "1.0.0")
	if check.UpdateAvailable || check.LatestVersion != "" || check.PackageID != nil {
		t.Fatalf("deleting explicit latest published an unmarked historical version: %+v", check)
	}
}

func TestHostedClientPackagesSupportAndroidUniversalAPK(t *testing.T) {
	cfg := config.Default()
	cfg.DataDirectory = t.TempDir()
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)
	item := uploadClientPackage(t, ts, admin, []byte("unsigned-apk"), map[string]string{
		"implementation": "android", "platform": "android", "arch": "any", "version": "2.0.0",
		"displayName": "specus-client-android-2.0.0", "isLatest": "true",
	})
	check := getClientVersionCheck(t, ts.URL, "android", "android", "any", "1.0.0")
	if !check.UpdateAvailable || check.LatestVersion != "2.0.0" ||
		check.PackageID == nil || *check.PackageID != item.ID {
		t.Fatalf("Android universal package was not selected: %+v", check)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request, _ := http.NewRequest(method, ts.URL+item.DownloadURL, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK ||
			!strings.Contains(response.Header.Get("Content-Disposition"), "specus-client-android-2.0.0.apk") ||
			response.Header.Get("Cache-Control") != "no-store" ||
			response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s Android download headers/status: status=%d headers=%v", method, response.StatusCode, response.Header)
		}
	}
	for name, fields := range map[string]map[string]string{
		"android implementation on desktop": {
			"implementation": "android", "platform": "linux", "arch": "any",
		},
		"android platform with Go implementation": {
			"implementation": "go", "platform": "android", "arch": "any",
		},
		"android package with concrete architecture": {
			"implementation": "android", "platform": "android", "arch": "arm64",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fields["version"] = "2.0.1"
			fields["displayName"] = "invalid-android-coordinate"
			response := uploadClientPackageResponse(t, ts, admin, []byte("invalid-apk"), fields)
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("invalid Android upload status=%d body=%s", response.StatusCode, body)
			}
		})
	}
}

func TestExternalClientPackageCatalogVersionCheckAndValidation(t *testing.T) {
	cfg := config.Default()
	cfg.DataDirectory = t.TempDir()
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)
	sha := strings.Repeat("a", 64)
	valid := map[string]any{
		"implementation": "go", "platform": "macos", "arch": "arm64", "version": "1.4.0",
		"displayName": "Go macOS arm64", "downloadUrl": "https://github.com/devShuai/specus/releases/download/v1.4.0/specus-client-darwin-arm64.tar.gz",
		"sha256": sha, "fileSize": 42, "enabled": true, "isLatest": true,
	}
	body, _ := json.Marshal(valid)
	response := authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin, string(body))
	if response.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("create external package status=%d body=%s", response.StatusCode, responseBody)
	}
	var created clientPackageViewForTest
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if created.Hosted || created.PackageID != nil || created.SHA256 != sha || created.FileSize != 42 {
		t.Fatalf("external package response = %+v", created)
	}
	check := getClientVersionCheck(t, ts.URL, "go", "macos", "arm64", "1.0.0")
	if !check.UpdateAvailable || check.LatestVersion != "1.4.0" || check.PackageID != nil ||
		check.DownloadURL != valid["downloadUrl"] || check.SHA256 != sha || check.FileSize != 42 {
		t.Fatalf("external package version check = %+v", check)
	}

	for name, mutate := range map[string]func(map[string]any){
		"insecure scheme": func(request map[string]any) { request["downloadUrl"] = "http://example.test/client.zip" },
		"userinfo":        func(request map[string]any) { request["downloadUrl"] = "https://user@example.test/client.zip" },
		"query":           func(request map[string]any) { request["downloadUrl"] = "https://example.test/client.zip?token=x" },
		"fragment":        func(request map[string]any) { request["downloadUrl"] = "https://example.test/client.zip#part" },
		"missing hash":    func(request map[string]any) { delete(request, "sha256") },
		"invalid hash":    func(request map[string]any) { request["sha256"] = "bad" },
		"zero size":       func(request map[string]any) { request["fileSize"] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			request := make(map[string]any, len(valid))
			for key, value := range valid {
				request[key] = value
			}
			request["platform"] = "linux"
			mutate(request)
			encoded, _ := json.Marshal(request)
			response := authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin, string(encoded))
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				responseBody, _ := io.ReadAll(response.Body)
				t.Fatalf("invalid external package status=%d body=%s", response.StatusCode, responseBody)
			}
		})
	}
}

func TestClientPackageDisabledLatestInvariantAndPublicLegacySuppression(t *testing.T) {
	cfg := config.Default()
	cfg.DataDirectory = t.TempDir()
	_, ts := newAPIServerWithConfig(t, cfg)
	admin := adminToken(t, ts)

	invalidUpload := uploadClientPackageResponse(t, ts, admin, []byte("invalid"), map[string]string{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "1.0.0",
		"displayName": "invalid", "enabled": "false", "isLatest": "true",
	})
	invalidUpload.Body.Close()
	if invalidUpload.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled latest upload status = %d", invalidUpload.StatusCode)
	}

	invalidCreateBody, _ := json.Marshal(map[string]any{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "1.0.0",
		"displayName": "invalid external", "downloadUrl": "https://example.com/invalid",
		"enabled": false, "isLatest": true,
	})
	response := authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin, string(invalidCreateBody))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled latest JSON create status = %d", response.StatusCode)
	}

	legacyBody, _ := json.Marshal(map[string]any{
		"implementation": "go", "platform": "linux", "arch": "x64",
		"displayName": "legacy", "downloadUrl": "https://example.com/legacy", "enabled": true,
	})
	response = authRequest(t, ts, http.MethodPost, "/api/admin/client-downloads", admin, string(legacyBody))
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("create legacy status=%d body=%s", response.StatusCode, body)
	}
	var legacy clientPackageViewForTest
	if err := json.NewDecoder(response.Body).Decode(&legacy); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	publicResponse, err := http.Get(ts.URL + "/api/public/client-downloads")
	if err != nil {
		t.Fatal(err)
	}
	var publicLegacy []map[string]any
	if err := json.NewDecoder(publicResponse.Body).Decode(&publicLegacy); err != nil {
		publicResponse.Body.Close()
		t.Fatal(err)
	}
	publicResponse.Body.Close()
	var legacyJSON map[string]any
	for _, item := range publicLegacy {
		if item["id"] == float64(legacy.ID) {
			legacyJSON = item
			break
		}
	}
	if legacyJSON == nil || legacyJSON["version"] != nil || legacyJSON["sha256"] != nil ||
		legacyJSON["fileSize"] != float64(0) || legacyJSON["isLatest"] != false ||
		legacyJSON["hosted"] != false || legacyJSON["packageId"] != nil {
		t.Fatalf("legacy compatibility JSON = %#v", legacyJSON)
	}

	disabled := uploadClientPackage(t, ts, admin, []byte("disabled-version"), map[string]string{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "2.0.0",
		"displayName": "disabled", "enabled": "false", "isLatest": "false",
	})
	response = authRequest(t, ts, http.MethodPost,
		"/api/admin/client-downloads/"+strconv.FormatInt(disabled.ID, 10)+"/latest", admin, "")
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("mark disabled package latest status = %d", response.StatusCode)
	}

	invalidUpdateBody, _ := json.Marshal(map[string]any{
		"implementation": "go", "platform": "linux", "arch": "x64", "version": "2.0.0",
		"displayName": "disabled", "downloadUrl": disabled.DownloadURL,
		"enabled": false, "isLatest": true,
	})
	response = authRequest(t, ts, http.MethodPut,
		"/api/admin/client-downloads/"+strconv.FormatInt(disabled.ID, 10), admin, string(invalidUpdateBody))
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled latest update status = %d", response.StatusCode)
	}

	for _, item := range listPublicClientPackages(t, ts.URL) {
		if item.ID == legacy.ID || item.ID == disabled.ID {
			t.Fatalf("public catalog exposed legacy/disabled versioned target: %+v", item)
		}
	}
}

func TestClientVersionCheckNoCandidateReturnsStableNullFields(t *testing.T) {
	cfg := config.Default()
	cfg.DataDirectory = t.TempDir()
	_, ts := newAPIServerWithConfig(t, cfg)
	query := url.Values{
		"implementation": {"android"}, "platform": {"android"}, "arch": {"any"}, "current": {"1.0.0"},
	}
	response, err := http.Get(ts.URL + "/api/public/client-version-check?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["updateAvailable"] != false || body["mandatory"] != false || body["fileSize"] != float64(0) {
		t.Fatalf("unexpected no-candidate flags: %#v", body)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("version check cache policy = %q, want no-store", response.Header.Get("Cache-Control"))
	}
	for _, field := range []string{"latestVersion", "packageId", "downloadUrl", "sha256", "changelogUrl"} {
		value, exists := body[field]
		if !exists || value != nil {
			t.Fatalf("no-candidate field %s = %#v (exists=%t), want null", field, value, exists)
		}
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

func listPublicClientPackages(t *testing.T, tsURL string) []clientPackageViewForTest {
	t.Helper()
	response, err := http.Get(tsURL + "/api/public/client-downloads")
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
