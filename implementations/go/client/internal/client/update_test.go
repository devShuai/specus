package client

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestUpdaterDownloadsVerifiesAndAtomicallyReplacesExecutable(t *testing.T) {
	oldBinary := []byte("old-client-binary")
	newBinary := []byte("new-client-binary")
	hash := sha256.Sum256(newBinary)
	var checkQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/public/client-version-check":
			checkQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(UpdateInfo{
				UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(42),
				DownloadURL: "/api/public/client-packages/42/download",
				SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(newBinary)),
			})
		case "/api/public/client-packages/42/download":
			_, _ = w.Write(newBinary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executable := filepath.Join(t.TempDir(), updateExecutableName())
	if err := os.WriteFile(executable, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	updater := testUpdater(server, executable, true)
	result, err := updater.CheckAndApply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Checked || !result.Installed || result.LatestVersion != "1.1.0" ||
		result.BackupPath != executable+".bak" {
		t.Fatalf("unexpected update result: %+v", result)
	}
	current, _ := os.ReadFile(executable)
	backup, _ := os.ReadFile(executable + ".bak")
	if !bytes.Equal(current, newBinary) || !bytes.Equal(backup, oldBinary) {
		t.Fatalf("replacement current=%q backup=%q", current, backup)
	}
	if _, err := os.Stat(executable + ".new"); !os.IsNotExist(err) {
		t.Fatalf("candidate file was not cleaned up: %v", err)
	}
	if !strings.Contains(checkQuery, "implementation=go") ||
		!strings.Contains(checkQuery, "current=1.0.0") {
		t.Fatalf("version check query = %q", checkQuery)
	}
	platform, arch := updateTarget(runtime.GOOS, runtime.GOARCH)
	if !strings.Contains(checkQuery, "platform="+platform) || !strings.Contains(checkQuery, "arch="+arch) {
		t.Fatalf("version check target missing from %q", checkQuery)
	}
}

func TestUpdaterChecksumFailureLeavesCurrentExecutableUntouched(t *testing.T) {
	oldBinary := []byte("old-client")
	packageBody := []byte("tampered-client")
	wrongHash := sha256.Sum256([]byte("expected-client"))
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(7),
		DownloadURL: "/package", SHA256: hex.EncodeToString(wrongHash[:]), FileSize: int64(len(packageBody)),
	}, packageBody)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	if err := os.WriteFile(executable, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	updater := testUpdater(server, executable, true)
	if _, err := updater.CheckAndApply(context.Background()); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("checksum mismatch error = %v", err)
	}
	current, _ := os.ReadFile(executable)
	if !bytes.Equal(current, oldBinary) {
		t.Fatalf("current executable changed after checksum failure: %q", current)
	}
	if _, err := os.Stat(executable + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup should not exist after pre-replacement failure: %v", err)
	}
}

func TestUpdaterRequiresConfirmationAndBlocksDeclinedMandatoryUpdate(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, Mandatory: true, LatestVersion: "2.0.0", PackageID: int64Pointer(9),
		DownloadURL: "/package", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
	}, body)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := testUpdater(server, executable, false)
	updater.confirm = func(UpdateInfo) bool { return false }
	result, err := updater.CheckAndApply(context.Background())
	if !errors.Is(err, ErrMandatoryUpdateDeclined) || result.Installed || !result.Mandatory {
		t.Fatalf("declined mandatory result=%+v err=%v", result, err)
	}
	current, _ := os.ReadFile(executable)
	if string(current) != "old" {
		t.Fatalf("declined update changed executable: %q", current)
	}
}

func TestPrepareUpdateExecutableExtractsReleaseZIPAndTarGzip(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, updateExecutableName())
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	expectedName := updateExecutableName()
	newBinary := []byte("archive-client-binary")

	zipPath := filepath.Join(directory, "client.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(zipFile)
	entry, _ := zipWriter.Create("release/" + expectedName)
	_, _ = entry.Write(newBinary)
	_ = zipWriter.Close()
	_ = zipFile.Close()
	zipCandidate := executable + ".zip.new"
	if err := prepareUpdateExecutable(zipPath, zipCandidate, executable); err != nil {
		t.Fatalf("extract ZIP: %v", err)
	}
	assertFileBytes(t, zipCandidate, newBinary)

	tarPath := filepath.Join(directory, "client.tar.gz")
	tarFile, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(tarFile)
	tarWriter := tar.NewWriter(gzipWriter)
	_ = tarWriter.WriteHeader(&tar.Header{Name: "release/" + expectedName, Mode: 0o755, Size: int64(len(newBinary)), Typeflag: tar.TypeReg})
	_, _ = tarWriter.Write(newBinary)
	_ = tarWriter.Close()
	_ = gzipWriter.Close()
	_ = tarFile.Close()
	tarCandidate := executable + ".tar.new"
	if err := prepareUpdateExecutable(tarPath, tarCandidate, executable); err != nil {
		t.Fatalf("extract tar.gz: %v", err)
	}
	assertFileBytes(t, tarCandidate, newBinary)
}

func TestAtomicReplacementRollsBackWhenCandidateMoveFails(t *testing.T) {
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	old := []byte("still-current")
	if err := os.WriteFile(executable, old, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceExecutableAtomically(executable, executable+".missing"); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
	assertFileBytes(t, executable, old)
	if _, err := os.Stat(executable + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("rollback left backup instead of restoring current: %v", err)
	}
}

func TestUpdaterRejectsInsecureOrCrossOriginPackageURL(t *testing.T) {
	updater := NewUpdater(Config{ServerBaseURL: "http://example.com"}, "1.0.0", true, log.New(io.Discard, "", 0))
	if _, _, err := updater.secureDownloadURL("/package"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure origin error = %v", err)
	}
	updater.config.ServerBaseURL = "https://specus.example.com"
	if _, _, err := updater.secureDownloadURL("https://evil.example.com/package"); err == nil {
		t.Fatal("cross-origin package URL accepted")
	}
}

func TestUpdateMonitorChecksAfterConfiguredInterval(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(11),
		DownloadURL: "/package", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
	}, body)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := testUpdater(server, executable, true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := updater.Monitor(ctx, 10*time.Millisecond)
	if err != nil || !result.Installed {
		t.Fatalf("monitor result=%+v err=%v", result, err)
	}
}

func testUpdater(server *httptest.Server, executable string, auto bool) *Updater {
	updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", auto, log.New(io.Discard, "", 0))
	updater.httpClient = server.Client()
	updater.allowHTTP = true
	updater.output = io.Discard
	updater.executablePath = func() (string, error) { return executable, nil }
	return updater
}

func updateTestServer(t *testing.T, info UpdateInfo, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/public/client-version-check" {
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		if r.URL.Path == "/package" {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
}

func updateExecutableName() string {
	if runtime.GOOS == "windows" {
		return "specus-client.exe"
	}
	return "specus-client"
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func int64Pointer(value int64) *int64 { return &value }
