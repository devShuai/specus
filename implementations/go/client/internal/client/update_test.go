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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
		!strings.HasPrefix(filepath.Base(result.BackupPath), ".specus-update-backup-") {
		t.Fatalf("unexpected update result: %+v", result)
	}
	current, _ := os.ReadFile(executable)
	backup, _ := os.ReadFile(result.BackupPath)
	if !bytes.Equal(current, newBinary) || !bytes.Equal(backup, oldBinary) {
		t.Fatalf("replacement current=%q backup=%q", current, backup)
	}
	assertNoUpdateTemporaryFiles(t, filepath.Dir(executable), ".specus-update-candidate-", ".specus-update-download-")
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
		DownloadURL: "/api/public/client-packages/7/download", SHA256: hex.EncodeToString(wrongHash[:]), FileSize: int64(len(packageBody)),
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
	assertNoUpdateTemporaryFiles(t, filepath.Dir(executable), ".specus-update-backup-", ".specus-update-candidate-", ".specus-update-download-")
}

func TestUpdaterPackageDownloadHasTotalTimeoutAfterHeaders(t *testing.T) {
	body := []byte("x")
	hash := sha256.Sum256(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/public/client-version-check":
			_ = json.NewEncoder(w).Encode(UpdateInfo{
				UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(71),
				DownloadURL: "/api/public/client-packages/71/download",
				SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
			})
		case "/api/public/client-packages/71/download":
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	updater := testUpdater(server, executable, true)
	updater.httpClient.Timeout = 50 * time.Millisecond
	started := time.Now()
	if _, err := updater.CheckAndApply(context.Background()); err == nil {
		t.Fatal("stalled package response did not time out")
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled package response exceeded the bounded test timeout")
	}
	assertFileBytes(t, executable, []byte("old"))
	assertNoUpdateTemporaryFiles(t, filepath.Dir(executable), ".specus-update-download-", ".specus-update-candidate-")
}

func TestUpdaterStagesWindowsReplacementAndLaunchesHelper(t *testing.T) {
	oldBinary := []byte("old-client")
	newBinary := []byte("new-client")
	hash := sha256.Sum256(newBinary)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(8),
		DownloadURL: "/api/public/client-packages/8/download", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(newBinary)),
	}, newBinary)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, oldBinary, 0o755)
	updater := testUpdater(server, executable, true)
	updater.deferReplacement = true
	var launchedExecutable, launchedCandidate, launchedHash string
	updater.launchDeferred = func(path, candidatePath, candidateHash string) error {
		launchedExecutable, launchedCandidate, launchedHash = path, candidatePath, candidateHash
		return nil
	}
	result, err := updater.CheckAndApply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Installed || !result.RestartScheduled || launchedExecutable != executable {
		t.Fatalf("deferred result=%+v launched=%q", result, launchedExecutable)
	}
	candidate, err := os.ReadFile(launchedCandidate)
	if err != nil || !bytes.Equal(candidate, newBinary) {
		t.Fatalf("staged candidate=%q err=%v", candidate, err)
	}
	wantCandidateHash := sha256.Sum256(newBinary)
	if launchedHash != hex.EncodeToString(wantCandidateHash[:]) {
		t.Fatalf("helper candidate hash=%q", launchedHash)
	}
	_ = os.Remove(launchedCandidate)
	assertFileBytes(t, executable, oldBinary)
}

func TestUpdaterRequiresConfirmationButDeclinedMandatoryUpdateDoesNotBlockStartup(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, Mandatory: true, LatestVersion: "2.0.0", PackageID: int64Pointer(9),
		DownloadURL: "/api/public/client-packages/9/download", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
	}, body)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := testUpdater(server, executable, false)
	updater.confirm = func(UpdateInfo) bool { return false }
	result, err := updater.CheckAndApply(context.Background())
	if err != nil || result.Installed || !result.Mandatory || !result.Checked {
		t.Fatalf("declined mandatory result=%+v err=%v", result, err)
	}
	current, _ := os.ReadFile(executable)
	if string(current) != "old" {
		t.Fatalf("declined update changed executable: %q", current)
	}
	updater.confirm = nil
	updater.input = strings.NewReader("")
	result, err = updater.CheckAndApply(context.Background())
	if err != nil || result.Installed || !result.Mandatory {
		t.Fatalf("non-interactive mandatory result=%+v err=%v", result, err)
	}
}

func TestUpdateMonitorContinuesAfterDeclinedMandatoryUpdate(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, Mandatory: true, LatestVersion: "2.0.0", PackageID: int64Pointer(10),
		DownloadURL: "/api/public/client-packages/10/download", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
	}, body)
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := testUpdater(server, executable, false)
	updater.confirm = func(UpdateInfo) bool { return false }
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	result, err := updater.Monitor(ctx, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || result.Installed {
		t.Fatalf("monitor stopped on declined mandatory update: result=%+v err=%v", result, err)
	}
	assertFileBytes(t, executable, []byte("old"))
}

func TestUpdaterRejectsIncompleteOrOversizedVersionMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/client-version-check" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"updateAvailable":true,"latestVersion":"1.1.0",`+
			`"downloadUrl":"/package","sha256":"`+strings.Repeat("0", 64)+`","fileSize":1}`)
	}))
	updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = server.Client()
	updater.allowHTTP = true
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "downloadUrl") {
		t.Fatalf("incomplete metadata error = %v", err)
	}
	server.Close()

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat(" ", updateMetadataMaxBytes+1))
	}))
	defer oversized.Close()
	updater.config.ServerBaseURL = oversized.URL
	updater.httpClient = oversized.Client()
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func TestUpdaterRejectsCrossOriginVersionCheckRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdateInfo{UpdateAvailable: false})
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/catalog", http.StatusFound)
	}))
	defer source.Close()
	updater := NewUpdater(Config{ServerBaseURL: source.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = source.Client()
	updater.allowHTTP = true
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "configured server origin") {
		t.Fatalf("cross-origin metadata redirect error = %v", err)
	}
}

func TestUpdaterRejectsHTTPVersionCatalogEvenForHTTPSExternalPackage(t *testing.T) {
	hash := sha256.Sum256([]byte("external-package"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdateInfo{
			UpdateAvailable: true, LatestVersion: "1.1.0",
			DownloadURL: "https://releases.example.test/specus-client.tar.gz",
			SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len("external-package")),
		})
	}))
	defer server.Close()
	updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = server.Client()
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTPS serverBaseUrl") {
		t.Fatalf("HTTP version catalog error = %v", err)
	}
}

func TestUpdaterAllowsExternalHTTPSChangelogAndRejectsInsecureMetadataURL(t *testing.T) {
	hash := sha256.Sum256([]byte("x"))
	changelog := "https://github.com/devShuai/specus/releases/tag/v1.1.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdateInfo{
			UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(72),
			DownloadURL: "/api/public/client-packages/72/download",
			SHA256:      hex.EncodeToString(hash[:]), FileSize: 1, ChangelogURL: &changelog,
		})
	}))
	defer server.Close()
	updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = server.Client()
	updater.allowHTTP = true
	info, err := updater.check(context.Background())
	if err != nil || info.ChangelogURL == nil || *info.ChangelogURL != changelog {
		t.Fatalf("external HTTPS changelog result=%+v err=%v", info, err)
	}
	insecure := "http://evil.example/releases/1.1.0"
	changelog = insecure
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "changelogUrl") {
		t.Fatalf("insecure changelog URL error = %v", err)
	}
}

func TestPrintUpdateStripsTerminalControlSequences(t *testing.T) {
	var output bytes.Buffer
	updater := NewUpdater(Config{}, "1.0.0", false, log.New(io.Discard, "", 0))
	updater.output = &output
	changelog := "https://example.test/release\x1b]8;;https://evil.test\x07link\x1b]8;;\x07\r\nforged\u2028line"
	updater.printUpdate(UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0\x1b[2J\u009b31mred\u009b0m", FileSize: 1,
		ChangelogURL: &changelog,
	})
	text := output.String()
	if strings.ContainsAny(text, "\x1b\r\u2028\u2029") || strings.Contains(text, "[2J") || strings.Contains(text, "31m") {
		t.Fatalf("terminal control sequence survived sanitization: %q", text)
	}
	if strings.Count(text, "\n") != 2 {
		t.Fatalf("server metadata injected extra terminal lines: %q", text)
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

func TestUpdateArchiveBudgetCountsAllEntriesAndExpandedBytes(t *testing.T) {
	budget := updateArchiveBudget{}
	for index := 0; index < updateArchiveMaxEntries; index++ {
		if err := budget.add(0); err != nil {
			t.Fatalf("entry %d unexpectedly rejected: %v", index, err)
		}
	}
	if err := budget.add(0); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("archive entry overflow error = %v", err)
	}
	budget = updateArchiveBudget{}
	if err := budget.add(updateArchiveMaxBytes - 1); err != nil {
		t.Fatal(err)
	}
	if err := budget.add(2); err == nil || !strings.Contains(err.Error(), "expanded size") {
		t.Fatalf("archive expanded-size overflow error = %v", err)
	}
}

func TestUpdateArchiveExtractionEnforcesNonTargetEntryBudgets(t *testing.T) {
	t.Run("ZIP entry count", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "many-entries.zip")
		archiveFile, err := os.Create(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(archiveFile)
		for index := 0; index <= updateArchiveMaxEntries; index++ {
			if _, err := writer.CreateHeader(&zip.FileHeader{Name: "docs/" + strconv.Itoa(index)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := archiveFile.Close(); err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(filepath.Dir(archivePath), "candidate")
		if err := extractZIPExecutable(archivePath, candidate, updateExecutableName(), false); err == nil ||
			!strings.Contains(err.Error(), "entry limit") {
			t.Fatalf("ZIP entry budget error = %v", err)
		}
	})

	t.Run("tar expanded bytes", func(t *testing.T) {
		archivePath := filepath.Join(t.TempDir(), "expanded.tar.gz")
		archiveFile, err := os.Create(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		gzipWriter := gzip.NewWriter(archiveFile)
		tarWriter := tar.NewWriter(gzipWriter)
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: "docs/not-the-client", Mode: 0o600, Typeflag: tar.TypeReg,
			Size: int64(updateArchiveMaxBytes) + 1,
		}); err != nil {
			t.Fatal(err)
		}
		// Close reports the intentionally missing huge payload. The valid header is enough to prove
		// the scanner accounts for a non-target entry before it attempts extraction.
		_ = tarWriter.Close()
		if err := gzipWriter.Close(); err != nil {
			t.Fatal(err)
		}
		if err := archiveFile.Close(); err != nil {
			t.Fatal(err)
		}
		candidate := filepath.Join(filepath.Dir(archivePath), "candidate")
		if err := extractTarGzipExecutable(archivePath, candidate, updateExecutableName(), false); err == nil ||
			!strings.Contains(err.Error(), "expanded size") {
			t.Fatalf("tar expanded-byte budget error = %v", err)
		}
	})
}

func TestUpdaterPreservesPreoccupiedLegacySiblingPaths(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, updateExecutableName())
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	legacyPaths := []string{
		executable + ".download", executable + ".new", executable + ".bak",
		executable + ".failed", executable + ".update-helper.exe",
	}
	for _, path := range legacyPaths {
		if err := os.WriteFile(path, []byte("user-owned"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newBinary := []byte("new")
	hash := sha256.Sum256(newBinary)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(73),
		DownloadURL: "/api/public/client-packages/73/download",
		SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(newBinary)),
	}, newBinary)
	defer server.Close()
	updater := testUpdater(server, executable, true)
	if _, err := updater.CheckAndApply(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range legacyPaths {
		assertFileBytes(t, path, []byte("user-owned"))
	}
}

func TestReplacementFailsClosedOnPreoccupiedBackupPath(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, updateExecutableName())
	candidate := filepath.Join(directory, "candidate")
	backup := filepath.Join(directory, ".specus-update-backup-user")
	if err := os.WriteFile(executable, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("user-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutablePlatform(executable, candidate, backup); err == nil {
		t.Fatal("preoccupied backup path was overwritten")
	}
	assertFileBytes(t, executable, []byte("old"))
	assertFileBytes(t, candidate, []byte("new"))
	assertFileBytes(t, backup, []byte("user-owned"))
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
	assertNoUpdateTemporaryFiles(t, filepath.Dir(executable), ".specus-update-backup-")
}

func TestRollbackInstalledUpdateRestoresBackupAndConstrainsPath(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, updateExecutableName())
	candidate := filepath.Join(directory, "candidate")
	if err := os.WriteFile(executable, []byte("working-old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte("broken-new"), 0o755); err != nil {
		t.Fatal(err)
	}
	backup, err := replaceExecutableAtomically(executable, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := RollbackInstalledUpdate(executable, filepath.Join(directory, "unrelated")); err == nil {
		t.Fatal("rollback accepted an unrelated backup path")
	}
	assertFileBytes(t, executable, []byte("broken-new"))
	if err := RollbackInstalledUpdate(executable, backup); err != nil {
		t.Fatal(err)
	}
	assertFileBytes(t, executable, []byte("working-old"))
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup was not consumed by rollback: %v", err)
	}
}

func TestWindowsDeferredUpdateWaitsForRealImageLockThenReplaces(t *testing.T) {
	if os.Getenv("SPECUS_UPDATE_LOCK_CHILD") == "1" {
		ready := os.Getenv("SPECUS_UPDATE_LOCK_READY")
		_ = os.WriteFile(ready, []byte("ready"), 0o600)
		time.Sleep(400 * time.Millisecond)
		os.Exit(0)
	}
	if runtime.GOOS != "windows" {
		t.Skip("Windows image locking semantics")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "locked-client.exe")
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFileForUpdateTest(t, source, target)
	ready := filepath.Join(directory, "ready")
	command := exec.Command(target, "-test.run=TestWindowsDeferredUpdateWaitsForRealImageLockThenReplaces")
	command.Env = append(os.Environ(), "SPECUS_UPDATE_LOCK_CHILD=1", "SPECUS_UPDATE_LOCK_READY="+ready)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatal("locked image child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	newBinary := []byte("replacement-after-image-unlock")
	candidateFile, err := os.CreateTemp(directory, ".specus-update-candidate-*")
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := candidateFile.Name()
	if _, err := candidateFile.Write(newBinary); err != nil {
		t.Fatal(err)
	}
	if err := candidateFile.Close(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(newBinary)
	started := time.Now()
	if err := applyDeferredUpdate(target, candidatePath, command.Process.Pid, hex.EncodeToString(hash[:]), nil); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 250*time.Millisecond {
		t.Fatal("deferred update did not wait for the running Windows image to exit")
	}
	assertFileBytes(t, target, newBinary)
	assertFileBytes(t, target, newBinary)
}

func TestDeferredUpdateFailureCleansCandidateAndRestartsRolledBackClient(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows deferred update lifecycle")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "specus-client.exe")
	if err := os.WriteFile(target, []byte("working-old"), 0o700); err != nil {
		t.Fatal(err)
	}
	startExitedProcess := func() int {
		command := exec.Command("cmd.exe", "/c", "exit", "0")
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		pid := command.Process.Pid
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
		return pid
	}
	newCandidate := func(content []byte) string {
		file, err := os.CreateTemp(directory, ".specus-update-candidate-*")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return file.Name()
	}

	t.Run("wait timeout", func(t *testing.T) {
		candidate := newCandidate([]byte("new"))
		hash := sha256.Sum256([]byte("new"))
		if err := applyDeferredUpdateWithTimeout(target, candidate, os.Getpid(), hex.EncodeToString(hash[:]),
			10*time.Millisecond, nil); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("wait timeout error = %v", err)
		}
		if _, err := os.Stat(candidate); !os.IsNotExist(err) {
			t.Fatalf("wait failure left candidate: %v", err)
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		candidate := newCandidate([]byte("tampered"))
		wrongHash := sha256.Sum256([]byte("expected"))
		var restartModes []bool
		err := applyDeferredUpdateWithTimeout(target, candidate, startExitedProcess(), hex.EncodeToString(wrongHash[:]),
			time.Second, func(skip bool) error {
				restartModes = append(restartModes, skip)
				return nil
			})
		if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
			t.Fatalf("hash mismatch error = %v", err)
		}
		if len(restartModes) != 1 || !restartModes[0] {
			t.Fatalf("previous client restart modes = %v", restartModes)
		}
		if _, err := os.Stat(candidate); !os.IsNotExist(err) {
			t.Fatalf("hash failure left candidate: %v", err)
		}
	})

	t.Run("new image restart failure", func(t *testing.T) {
		newBinary := []byte("verified-new")
		candidate := newCandidate(newBinary)
		hash := sha256.Sum256(newBinary)
		var restartModes []bool
		err := applyDeferredUpdateWithTimeout(target, candidate, startExitedProcess(), hex.EncodeToString(hash[:]),
			time.Second, func(skip bool) error {
				restartModes = append(restartModes, skip)
				if !skip {
					return errors.New("new image failed to start")
				}
				return nil
			})
		if err == nil || !strings.Contains(err.Error(), "rolled back and restarted") {
			t.Fatalf("restart failure result = %v", err)
		}
		if len(restartModes) != 2 || restartModes[0] || !restartModes[1] {
			t.Fatalf("restart modes = %v", restartModes)
		}
		assertFileBytes(t, target, []byte("working-old"))
	})
}

func TestOwnedHelperCleanupPreservesUnmarkedFiles(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, updateExecutableName())
	candidate, err := os.CreateTemp(directory, ".specus-update-candidate-*")
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := candidate.Name()
	_ = candidate.Close()
	helper := filepath.Join(directory, ".specus-update-helper-owned.exe")
	if err := os.WriteFile(helper, []byte("helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeUpdateHelperOwnership(helper, updateHelperOwnership{
		Magic: updateHelperOwnerMagic, TargetPath: target, CandidatePath: candidatePath,
		CandidateHash: strings.Repeat("0", 64), CreatedAtUnix: time.Now().Add(-staleUpdateHelperTTL).Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedUpdateHelper(helper, target, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{helper, helper + ".owner", candidatePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("owned helper artifact remained at %s: %v", path, err)
		}
	}
	unmarked := filepath.Join(directory, ".specus-update-helper-user.exe")
	if err := os.WriteFile(unmarked, []byte("user-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedUpdateHelper(unmarked, target, false); err == nil {
		t.Fatal("unmarked helper file was accepted as updater-owned")
	}
	assertFileBytes(t, unmarked, []byte("user-owned"))
}

func TestRollbackRestartFlagIsInsertedBeforeArgumentSeparator(t *testing.T) {
	arguments := []string{"specus-client", "--config=config.jsonc", "--", "payload"}
	got := RestartArgumentsWithUpdateCheckDisabled(arguments)
	want := []string{"specus-client", "--config=config.jsonc", "--no-update-check", "--", "payload"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("rollback restart arguments = %#v, want %#v", got, want)
	}
	again := RestartArgumentsWithUpdateCheckDisabled(got)
	if len(again) != len(got) {
		t.Fatalf("rollback restart flag was duplicated: %#v", again)
	}
}

func TestUpdaterRejectsInsecureOrCrossOriginPackageURL(t *testing.T) {
	updater := NewUpdater(Config{ServerBaseURL: "http://example.com"}, "1.0.0", true, log.New(io.Discard, "", 0))
	packageID := int64(42)
	if _, _, err := updater.secureDownloadURL("/api/public/client-packages/42/download", &packageID); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure origin error = %v", err)
	}
	updater.config.ServerBaseURL = "https://specus.example.com"
	if _, _, err := updater.secureDownloadURL("https://evil.example.com/api/public/client-packages/42/download", &packageID); err == nil {
		t.Fatal("cross-origin package URL accepted")
	}
	valid := "/api/public/client-packages/42/download"
	if _, _, err := updater.secureDownloadURL(valid, &packageID); err != nil {
		t.Fatalf("valid hosted package URL rejected: %v", err)
	}
	invalid := []string{
		"/api/public/client-packages/41/download",
		valid + "?token=secret",
		valid + "#fragment",
		"https://user@specus.example.com" + valid,
		"/api/public/client-packages/%34%32/download",
	}
	for _, value := range invalid {
		if _, _, err := updater.secureDownloadURL(value, &packageID); err == nil {
			t.Errorf("unsafe package URL accepted: %q", value)
		}
	}
	updater.config.ServerBaseURL = "https://user@specus.example.com"
	if _, _, err := updater.secureDownloadURL(valid, &packageID); err == nil {
		t.Fatal("serverBaseUrl containing userinfo accepted")
	}
}

func TestUpdaterAcceptsStrictExternalPackageURLWithoutPackageID(t *testing.T) {
	updater := NewUpdater(Config{ServerBaseURL: "https://specus.example.com"}, "1.0.0", true, log.New(io.Discard, "", 0))
	valid := "https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client.tar.gz"
	resolved, origin, err := updater.secureDownloadURL(valid, nil)
	if err != nil || resolved.String() != valid || origin != nil {
		t.Fatalf("valid external package URL resolved=%v origin=%v err=%v", resolved, origin, err)
	}
	for _, value := range []string{
		"/releases/client.tar.gz",
		"http://example.test/client.tar.gz",
		"https://user@example.test/client.tar.gz",
		"https://example.test/client.tar.gz?signature=x",
		"https://example.test/client.tar.gz#fragment",
	} {
		if _, _, err := updater.secureDownloadURL(value, nil); err == nil {
			t.Errorf("unsafe initial external package URL accepted: %q", value)
		}
	}
}

func TestUpdaterDownloadsExternalPackageAcrossHTTPSRedirectWithSignedQuery(t *testing.T) {
	oldBinary := []byte("old-client")
	newBinary := []byte("external-release-client")
	hash := sha256.Sum256(newBinary)
	asset := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/asset" || r.URL.Query().Get("signature") != "signed" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(newBinary)
	}))
	defer asset.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, asset.URL+"/asset?signature=signed", http.StatusFound)
	}))
	defer redirect.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/client-version-check" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(UpdateInfo{
			UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: nil,
			DownloadURL: redirect.URL + "/release",
			SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(newBinary)),
		})
	}))
	defer source.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	if err := os.WriteFile(executable, oldBinary, 0o755); err != nil {
		t.Fatal(err)
	}
	updater := NewUpdater(Config{ServerBaseURL: source.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = source.Client()
	updater.output = io.Discard
	updater.executablePath = func() (string, error) { return executable, nil }
	updater.deferReplacement = false
	result, err := updater.CheckAndApply(context.Background())
	if err != nil || !result.Installed {
		t.Fatalf("external redirected update result=%+v err=%v", result, err)
	}
	assertFileBytes(t, executable, newBinary)
}

func TestUpdaterRejectsExternalPackageRedirectDowngrade(t *testing.T) {
	body := []byte("external-release-client")
	hash := sha256.Sum256(body)
	insecureAsset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer insecureAsset.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecureAsset.URL+"/asset?signature=signed", http.StatusFound)
	}))
	defer redirect.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdateInfo{
			UpdateAvailable: true, LatestVersion: "1.1.0",
			DownloadURL: redirect.URL + "/release",
			SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
		})
	}))
	defer source.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := NewUpdater(Config{ServerBaseURL: source.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = source.Client()
	updater.output = io.Discard
	updater.executablePath = func() (string, error) { return executable, nil }
	updater.deferReplacement = false
	if _, err := updater.CheckAndApply(context.Background()); err == nil || !strings.Contains(err.Error(), "absolute HTTPS") {
		t.Fatalf("external redirect downgrade error = %v", err)
	}
	assertFileBytes(t, executable, []byte("old"))
}

func TestUpdaterExternalPackageAllowsAtMostFiveHTTPSRedirects(t *testing.T) {
	for _, test := range []struct {
		name      string
		hops      int
		wantError bool
	}{
		{name: "five", hops: 5},
		{name: "six", hops: 6, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte("redirected-external-client")
			hash := sha256.Sum256(body)
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/public/client-version-check" {
					_ = json.NewEncoder(w).Encode(UpdateInfo{
						UpdateAvailable: true, LatestVersion: "1.1.0",
						DownloadURL: server.URL + "/download/0",
						SHA256:      hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
					})
					return
				}
				step, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/download/"))
				if err != nil || step < 0 || step > test.hops {
					http.NotFound(w, r)
					return
				}
				if step < test.hops {
					next := strconv.Itoa(step + 1)
					http.Redirect(w, r, server.URL+"/download/"+next+"?signature="+next, http.StatusFound)
					return
				}
				_, _ = w.Write(body)
			}))
			defer server.Close()
			executable := filepath.Join(t.TempDir(), updateExecutableName())
			_ = os.WriteFile(executable, []byte("old"), 0o755)
			updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
			updater.httpClient = server.Client()
			updater.output = io.Discard
			updater.executablePath = func() (string, error) { return executable, nil }
			updater.deferReplacement = false
			result, err := updater.CheckAndApply(context.Background())
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "too many package download redirects") {
					t.Fatalf("redirect limit result=%+v err=%v", result, err)
				}
				assertFileBytes(t, executable, []byte("old"))
				return
			}
			if err != nil || !result.Installed {
				t.Fatalf("five redirects result=%+v err=%v", result, err)
			}
			assertFileBytes(t, executable, body)
		})
	}
}

func TestUpdaterRejectsVersionMetadataDownloadURLNotBoundToPackage(t *testing.T) {
	hash := sha256.Sum256([]byte("x"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdateInfo{
			UpdateAvailable: true,
			LatestVersion:   "1.1.0",
			PackageID:       int64Pointer(42),
			DownloadURL:     "/api/public/client-packages/43/download",
			SHA256:          hex.EncodeToString(hash[:]),
			FileSize:        1,
		})
	}))
	defer server.Close()
	updater := NewUpdater(Config{ServerBaseURL: server.URL}, "1.0.0", true, log.New(io.Discard, "", 0))
	updater.httpClient = server.Client()
	updater.allowHTTP = true
	if _, err := updater.check(context.Background()); err == nil || !strings.Contains(err.Error(), "hosted package route") {
		t.Fatalf("mismatched package route metadata error = %v", err)
	}
}

func TestUpdaterRejectsPackageRedirectAwayFromExactHostedRoute(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	info := UpdateInfo{
		UpdateAvailable: true,
		LatestVersion:   "1.1.0",
		PackageID:       int64Pointer(42),
		DownloadURL:     "/api/public/client-packages/42/download",
		SHA256:          hex.EncodeToString(hash[:]),
		FileSize:        int64(len(body)),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/public/client-version-check":
			_ = json.NewEncoder(w).Encode(info)
		case info.DownloadURL:
			http.Redirect(w, r, "/arbitrary-same-origin-endpoint", http.StatusFound)
		case "/arbitrary-same-origin-endpoint":
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	executable := filepath.Join(t.TempDir(), updateExecutableName())
	_ = os.WriteFile(executable, []byte("old"), 0o755)
	updater := testUpdater(server, executable, true)
	if _, err := updater.CheckAndApply(context.Background()); err == nil || !strings.Contains(err.Error(), "exact hosted package route") {
		t.Fatalf("same-origin off-route redirect error = %v", err)
	}
	assertFileBytes(t, executable, []byte("old"))
}

func TestValidUpdateVersionMatchesStrictSemVerWithoutIntegerOverflow(t *testing.T) {
	valid := []string{
		"1.2.3",
		"v1.2.3-alpha.1+build.01",
		"999999999999999999999.0.0",
	}
	for _, value := range valid {
		if !validUpdateVersion(value) {
			t.Errorf("validUpdateVersion(%q) = false", value)
		}
	}
	invalid := []string{"1.2", "1.2.03", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3+bad!"}
	for _, value := range invalid {
		if validUpdateVersion(value) {
			t.Errorf("validUpdateVersion(%q) = true", value)
		}
	}
}

func TestUpdateMonitorChecksAfterConfiguredInterval(t *testing.T) {
	body := []byte("new-client")
	hash := sha256.Sum256(body)
	server := updateTestServer(t, UpdateInfo{
		UpdateAvailable: true, LatestVersion: "1.1.0", PackageID: int64Pointer(11),
		DownloadURL: "/api/public/client-packages/11/download", SHA256: hex.EncodeToString(hash[:]), FileSize: int64(len(body)),
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
	updater.deferReplacement = false
	return updater
}

func copyFileForUpdateTest(t *testing.T, sourcePath, targetPath string) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func updateTestServer(t *testing.T, info UpdateInfo, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/public/client-version-check" {
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		if r.URL.Path == info.DownloadURL {
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

func assertNoUpdateTemporaryFiles(t *testing.T, directory string, prefixes ...string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		for _, prefix := range prefixes {
			if strings.HasPrefix(entry.Name(), prefix) {
				t.Errorf("unexpected updater-owned temporary file remained: %s", entry.Name())
			}
		}
	}
}

func int64Pointer(value int64) *int64 { return &value }
