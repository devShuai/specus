package client

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DefaultUpdateCheckInterval  = time.Duration(DefaultUpdateCheckIntervalHours) * time.Hour
	UpdateHelperFlagName        = "apply-update-helper"
	UpdateParentPIDFlagName     = "update-parent-pid"
	UpdateCandidateHashFlagName = "update-candidate-sha256"
	DisableUpdateCheckFlagName  = "no-update-check"
	updateMetadataMaxBytes      = 64 * 1024
	updatePackageMaxBytes       = int64(1024 * 1024 * 1024)
	updateBinaryMaxBytes        = int64(256 * 1024 * 1024)
	updateArchiveMaxEntries     = 20_000
	updateArchiveMaxBytes       = uint64(4 * 1024 * 1024 * 1024)
	updateMetadataTimeout       = 30 * time.Second
	updateDownloadTimeout       = 10 * time.Minute
	updateBackupOwnerMagic      = "specus-client-update-backup-v1\n"
	updateHelperOwnerMagic      = "specus-client-update-helper-v1"
	updateHelperCleanupEnv      = "SPECUS_UPDATE_HELPER_CLEANUP"
)

type UpdateInfo struct {
	UpdateAvailable bool    `json:"updateAvailable"`
	Mandatory       bool    `json:"mandatory"`
	LatestVersion   string  `json:"latestVersion"`
	PackageID       *int64  `json:"packageId"`
	DownloadURL     string  `json:"downloadUrl"`
	SHA256          string  `json:"sha256"`
	FileSize        int64   `json:"fileSize"`
	ChangelogURL    *string `json:"changelogUrl"`
}

type UpdateResult struct {
	Checked          bool
	Installed        bool
	Mandatory        bool
	PreviousVersion  string
	LatestVersion    string
	ExecutablePath   string
	BackupPath       string
	RestartScheduled bool
}

// Updater checks the server connected by this client. HTTP and filesystem seams are kept on the
// value so tests can exercise the full download/verification/replacement flow without replacing
// process globals.
type Updater struct {
	config           Config
	currentVersion   string
	autoUpdate       bool
	logger           *log.Logger
	httpClient       *http.Client
	input            io.Reader
	output           io.Writer
	executablePath   func() (string, error)
	confirm          func(UpdateInfo) bool
	allowHTTP        bool
	deferReplacement bool
	launchDeferred   func(executable, candidatePath, candidateHash string) error
}

func NewUpdater(config Config, currentVersion string, autoUpdate bool, logger *log.Logger) *Updater {
	if logger == nil {
		logger = log.Default()
	}
	return &Updater{
		config:           config,
		currentVersion:   strings.TrimPrefix(strings.TrimSpace(currentVersion), "v"),
		autoUpdate:       autoUpdate,
		logger:           logger,
		httpClient:       &http.Client{},
		input:            os.Stdin,
		output:           os.Stdout,
		executablePath:   os.Executable,
		deferReplacement: runtime.GOOS == "windows",
	}
}

// CheckAndApply performs one catalog lookup and, after confirmation, installs the selected package.
func (updater *Updater) CheckAndApply(ctx context.Context) (UpdateResult, error) {
	if updater == nil {
		return UpdateResult{}, nil
	}
	result := UpdateResult{PreviousVersion: updater.currentVersion}
	if !updater.config.UpdatesEnabled() || !validUpdateVersion(updater.currentVersion) {
		return result, nil
	}
	info, err := updater.check(ctx)
	result.Checked = true
	if err != nil {
		return result, err
	}
	result.Mandatory = info.Mandatory
	result.LatestVersion = info.LatestVersion
	if !info.UpdateAvailable {
		return result, nil
	}
	updater.printUpdate(info)
	if !updater.autoUpdate && !updater.confirmUpdate(info) {
		// mandatory is a strong compatibility warning, not a remote kill switch. Declining or
		// deferring an update must never prevent the tunnel from starting or staying connected.
		return result, nil
	}
	executable, err := updater.executablePath()
	if err != nil {
		return result, fmt.Errorf("resolve current executable: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return result, fmt.Errorf("resolve absolute executable path: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	backup, restartScheduled, err := updater.downloadAndReplace(ctx, info, executable)
	if err != nil {
		return result, err
	}
	result.Installed = true
	result.ExecutablePath = executable
	result.BackupPath = backup
	result.RestartScheduled = restartScheduled
	return result, nil
}

// Monitor waits one full interval before each subsequent check. Call CheckAndApply once at startup,
// then run Monitor alongside the client connection loop to provide the documented 24-hour cadence.
func (updater *Updater) Monitor(ctx context.Context, interval time.Duration) (UpdateResult, error) {
	if interval <= 0 {
		interval = DefaultUpdateCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return UpdateResult{}, ctx.Err()
		case <-ticker.C:
			result, err := updater.CheckAndApply(ctx)
			if err != nil {
				updater.logger.Printf("client update check failed: %v", err)
				continue
			}
			if result.Installed {
				return result, nil
			}
		}
	}
}

func (updater *Updater) check(ctx context.Context) (UpdateInfo, error) {
	platform, arch := updateTarget(runtime.GOOS, runtime.GOARCH)
	origin, err := url.Parse(strings.TrimSpace(updater.config.ServerBaseURL))
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil {
		return UpdateInfo{}, errors.New("serverBaseUrl is invalid for client update checks")
	}
	if !updater.allowHTTP && !strings.EqualFold(origin.Scheme, "https") {
		return UpdateInfo{}, errors.New("automatic client update requires an HTTPS serverBaseUrl")
	}
	if updater.allowHTTP && !strings.EqualFold(origin.Scheme, "http") &&
		!strings.EqualFold(origin.Scheme, "https") {
		return UpdateInfo{}, errors.New("serverBaseUrl is invalid for client update checks")
	}
	endpoint, err := url.Parse(strings.TrimRight(updater.config.ServerBaseURL, "/") +
		"/api/public/client-version-check")
	if err != nil {
		return UpdateInfo{}, fmt.Errorf("build client version endpoint: %w", err)
	}
	query := endpoint.Query()
	query.Set("implementation", "go")
	query.Set("platform", platform)
	query.Set("arch", arch)
	query.Set("current", updater.currentVersion)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return UpdateInfo{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "specus-client-go/"+updater.currentVersion)
	client := *updater.httpClient
	client.Timeout = boundedHTTPTimeout(client.Timeout, updateMetadataTimeout)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many client version check redirects")
		}
		if !updater.sameConfiguredOrigin(request.URL, origin) {
			return errors.New("client version check redirect left the configured server origin")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return UpdateInfo{}, fmt.Errorf("query client version catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return UpdateInfo{}, fmt.Errorf("query client version catalog HTTP %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, updateMetadataMaxBytes+1))
	if err != nil {
		return UpdateInfo{}, fmt.Errorf("read client version catalog: %w", err)
	}
	if len(body) > updateMetadataMaxBytes {
		return UpdateInfo{}, errors.New("client version catalog exceeds the response size limit")
	}
	var info UpdateInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return UpdateInfo{}, fmt.Errorf("decode client version catalog: %w", err)
	}
	if !info.UpdateAvailable {
		return info, nil
	}
	if !validUpdateVersion(info.LatestVersion) {
		return UpdateInfo{}, errors.New("version catalog returned an invalid latestVersion")
	}
	if info.PackageID != nil && *info.PackageID <= 0 {
		return UpdateInfo{}, errors.New("version catalog returned an invalid packageId")
	}
	if info.FileSize < 1 || info.FileSize > updatePackageMaxBytes {
		return UpdateInfo{}, errors.New("version catalog returned an invalid fileSize")
	}
	if len(info.SHA256) != sha256.Size*2 {
		return UpdateInfo{}, errors.New("version catalog returned an invalid sha256")
	}
	if _, err := hex.DecodeString(info.SHA256); err != nil {
		return UpdateInfo{}, errors.New("version catalog returned an invalid sha256")
	}
	if strings.TrimSpace(info.DownloadURL) == "" {
		return UpdateInfo{}, errors.New("version catalog returned an empty downloadUrl")
	}
	if _, _, err := updater.secureDownloadURL(info.DownloadURL, info.PackageID); err != nil {
		return UpdateInfo{}, fmt.Errorf("version catalog returned an invalid downloadUrl: %w", err)
	}
	if info.ChangelogURL != nil && strings.TrimSpace(*info.ChangelogURL) != "" {
		changelogURL, err := updater.secureMetadataURL(*info.ChangelogURL, origin)
		if err != nil {
			return UpdateInfo{}, fmt.Errorf("version catalog returned an invalid changelogUrl: %w", err)
		}
		info.ChangelogURL = &changelogURL
	}
	return info, nil
}

func (updater *Updater) printUpdate(info UpdateInfo) {
	if updater.output == nil {
		return
	}
	label := "发现新版本"
	if info.Mandatory {
		label = "当前版本已低于最低支持版本，必须升级"
	}
	_, _ = fmt.Fprintf(updater.output, "%s：%s -> %s（%s）\n", label,
		sanitizeTerminalText(updater.currentVersion), sanitizeTerminalText(info.LatestVersion), formatUpdateSize(info.FileSize))
	if info.ChangelogURL != nil && strings.TrimSpace(*info.ChangelogURL) != "" {
		_, _ = fmt.Fprintf(updater.output, "更新说明：%s\n", sanitizeTerminalText(*info.ChangelogURL))
	}
}

func boundedHTTPTimeout(current, maximum time.Duration) time.Duration {
	if current <= 0 || current > maximum {
		return maximum
	}
	return current
}

func sanitizeTerminalText(value string) string {
	var result strings.Builder
	spacePending := false
	for index := 0; index < len(value); {
		char := value[index]
		if char == 0x1b {
			index = skipANSISequence(value, index)
			spacePending = result.Len() > 0
			continue
		}
		if char < 0x20 || char == 0x7f || (char >= 0x80 && char <= 0x9f) {
			index++
			spacePending = result.Len() > 0
			continue
		}
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			index++
			spacePending = result.Len() > 0
			continue
		}
		index += size
		if r == '\u009b' {
			index = skipCSISequence(value, index)
			spacePending = result.Len() > 0
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\u2028' || r == '\u2029' {
			spacePending = result.Len() > 0
			continue
		}
		if spacePending && r != ' ' {
			result.WriteByte(' ')
		}
		spacePending = false
		result.WriteRune(r)
	}
	return strings.TrimSpace(result.String())
}

func skipCSISequence(value string, index int) int {
	for index < len(value) {
		char := value[index]
		index++
		if char >= 0x40 && char <= 0x7e {
			break
		}
	}
	return index
}

func skipANSISequence(value string, index int) int {
	index++
	if index >= len(value) {
		return index
	}
	switch value[index] {
	case '[':
		index++
		for index < len(value) {
			char := value[index]
			index++
			if char >= 0x40 && char <= 0x7e {
				break
			}
		}
		return index
	case ']', 'P', 'X', '^', '_':
		index++
		for index < len(value) {
			if value[index] == 0x07 {
				return index + 1
			}
			if value[index] == 0x1b && index+1 < len(value) && value[index+1] == '\\' {
				return index + 2
			}
			index++
		}
		return index
	default:
		return index + 1
	}
}

func (updater *Updater) confirmUpdate(info UpdateInfo) bool {
	if updater.confirm != nil {
		return updater.confirm(info)
	}
	if updater.input == nil || updater.output == nil || !readerIsInteractive(updater.input) {
		updater.logger.Printf("client update %s is available; restart with --auto-update or confirm in an interactive terminal",
			info.LatestVersion)
		return false
	}
	_, _ = fmt.Fprint(updater.output, "现在下载并安装？[y/N] ")
	line, err := bufio.NewReader(updater.input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		updater.logger.Printf("read update confirmation failed: %v", err)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes", "是":
		return true
	default:
		return false
	}
}

func readerIsInteractive(reader io.Reader) bool {
	file, ok := reader.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (updater *Updater) downloadAndReplace(ctx context.Context, info UpdateInfo, executable string) (string, bool, error) {
	downloadURL, origin, err := updater.secureDownloadURL(info.DownloadURL, info.PackageID)
	if err != nil {
		return "", false, err
	}
	download, err := os.CreateTemp(filepath.Dir(executable), ".specus-update-download-*")
	if err != nil {
		return "", false, fmt.Errorf("create update download: %w", err)
	}
	downloadPath := download.Name()
	defer os.Remove(downloadPath)
	candidate, err := os.CreateTemp(filepath.Dir(executable), ".specus-update-candidate-*")
	if err != nil {
		_ = download.Close()
		return "", false, fmt.Errorf("reserve update candidate: %w", err)
	}
	candidatePath := candidate.Name()
	if err := candidate.Close(); err != nil {
		_ = download.Close()
		_ = os.Remove(candidatePath)
		return "", false, fmt.Errorf("close reserved update candidate: %w", err)
	}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			_ = os.Remove(candidatePath)
		}
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		_ = download.Close()
		return "", false, err
	}
	request.Header.Set("User-Agent", "specus-client-go/"+updater.currentVersion)
	client := *updater.httpClient
	client.Timeout = boundedHTTPTimeout(client.Timeout, updateDownloadTimeout)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("too many package download redirects")
		}
		if origin != nil {
			if info.PackageID == nil || !updater.sameSecureOrigin(request.URL, origin) ||
				!exactHostedPackageURL(request.URL, *info.PackageID) {
				return errors.New("package redirect left the exact hosted package route")
			}
			return nil
		}
		if !isSecureExternalPackageURL(request.URL, false) {
			return errors.New("external package redirect must remain on an absolute HTTPS URL without userinfo")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		_ = download.Close()
		return "", false, fmt.Errorf("download client update: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		_ = download.Close()
		return "", false, fmt.Errorf("download client update HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(download, hash), io.LimitReader(response.Body, info.FileSize+1))
	closeBodyErr := response.Body.Close()
	syncErr := download.Sync()
	closeErr := download.Close()
	if copyErr != nil {
		return "", false, fmt.Errorf("download client update body: %w", copyErr)
	}
	if closeBodyErr != nil {
		return "", false, fmt.Errorf("close client update response: %w", closeBodyErr)
	}
	if syncErr != nil {
		return "", false, fmt.Errorf("sync client update download: %w", syncErr)
	}
	if closeErr != nil {
		return "", false, fmt.Errorf("close client update download: %w", closeErr)
	}
	if size != info.FileSize {
		return "", false, fmt.Errorf("client update size mismatch: got %d, want %d", size, info.FileSize)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualHash, info.SHA256) {
		return "", false, errors.New("client update SHA-256 mismatch")
	}
	if err := prepareOwnedUpdateExecutable(downloadPath, candidatePath, executable); err != nil {
		return "", false, err
	}
	if updater.deferReplacement {
		candidateHash, err := sha256File(candidatePath)
		if err != nil {
			return "", false, fmt.Errorf("hash candidate client executable: %w", err)
		}
		launch := updater.launchDeferred
		if launch == nil {
			launch = scheduleWindowsUpdateHelper
		}
		if err := launch(executable, candidatePath, candidateHash); err != nil {
			return "", false, err
		}
		keepCandidate = true
		return "", true, nil
	}
	backup, err := replaceExecutableAtomically(executable, candidatePath)
	return backup, false, err
}

func (updater *Updater) secureDownloadURL(value string, packageID *int64) (*url.URL, *url.URL, error) {
	origin, err := url.Parse(strings.TrimSpace(updater.config.ServerBaseURL))
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil {
		return nil, nil, errors.New("serverBaseUrl is invalid for client update")
	}
	if !updater.allowHTTP && !strings.EqualFold(origin.Scheme, "https") {
		return nil, nil, errors.New("automatic client update requires an HTTPS serverBaseUrl")
	}
	if updater.allowHTTP && !strings.EqualFold(origin.Scheme, "http") &&
		!strings.EqualFold(origin.Scheme, "https") {
		return nil, nil, errors.New("serverBaseUrl is invalid for client update")
	}
	reference, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, nil, fmt.Errorf("parse package downloadUrl: %w", err)
	}
	if packageID == nil {
		if !isSecureExternalPackageURL(reference, true) {
			return nil, nil, errors.New("external package downloadUrl must be an absolute HTTPS URL without userinfo, query or fragment")
		}
		return reference, nil, nil
	}
	if *packageID <= 0 {
		return nil, nil, errors.New("packageId is invalid for client update")
	}
	resolved := origin.ResolveReference(reference)
	if !updater.sameSecureOrigin(resolved, origin) {
		return nil, nil, errors.New("package downloadUrl must stay on the configured server origin over HTTPS")
	}
	if !exactHostedPackageURL(resolved, *packageID) {
		return nil, nil, errors.New("package downloadUrl must exactly match the hosted package route")
	}
	return resolved, origin, nil
}

func isSecureExternalPackageURL(candidate *url.URL, initial bool) bool {
	if candidate == nil || !candidate.IsAbs() || !strings.EqualFold(candidate.Scheme, "https") ||
		candidate.Host == "" || candidate.User != nil {
		return false
	}
	if initial && (candidate.RawQuery != "" || candidate.ForceQuery ||
		candidate.Fragment != "" || candidate.RawFragment != "") {
		return false
	}
	return true
}

func (updater *Updater) secureMetadataURL(value string, origin *url.URL) (string, error) {
	reference, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("parse metadata URL: %w", err)
	}
	resolved := origin.ResolveReference(reference)
	if resolved.User != nil || resolved.Host == "" || resolved.Scheme == "" {
		return "", errors.New("metadata URL is invalid")
	}
	if !strings.EqualFold(resolved.Scheme, "https") &&
		!(updater.allowHTTP && strings.EqualFold(resolved.Scheme, "http") &&
			updater.sameConfiguredOrigin(resolved, origin)) {
		return "", errors.New("metadata URL must use HTTPS")
	}
	return resolved.String(), nil
}

func exactHostedPackageURL(candidate *url.URL, packageID int64) bool {
	if candidate == nil || candidate.User != nil || packageID <= 0 {
		return false
	}
	expectedPath := fmt.Sprintf("/api/public/client-packages/%d/download", packageID)
	return candidate.Path == expectedPath && candidate.EscapedPath() == expectedPath &&
		candidate.RawQuery == "" && !candidate.ForceQuery &&
		candidate.Fragment == "" && candidate.RawFragment == ""
}

func (updater *Updater) sameSecureOrigin(candidate, origin *url.URL) bool {
	if !updater.sameConfiguredOrigin(candidate, origin) {
		return false
	}
	if updater.allowHTTP {
		return strings.EqualFold(candidate.Scheme, origin.Scheme) &&
			(strings.EqualFold(candidate.Scheme, "http") || strings.EqualFold(candidate.Scheme, "https"))
	}
	return strings.EqualFold(candidate.Scheme, "https") && strings.EqualFold(origin.Scheme, "https")
}

func (updater *Updater) sameConfiguredOrigin(candidate, origin *url.URL) bool {
	return candidate != nil && origin != nil &&
		candidate.User == nil && origin.User == nil &&
		strings.EqualFold(candidate.Scheme, origin.Scheme) &&
		strings.EqualFold(candidate.Host, origin.Host)
}

func prepareUpdateExecutable(packagePath, candidatePath, executable string) error {
	return prepareUpdateExecutableWithOwnership(packagePath, candidatePath, executable, false)
}

func prepareOwnedUpdateExecutable(packagePath, candidatePath, executable string) error {
	return prepareUpdateExecutableWithOwnership(packagePath, candidatePath, executable, true)
}

func prepareUpdateExecutableWithOwnership(packagePath, candidatePath, executable string, candidateReserved bool) error {
	current, err := os.Stat(executable)
	if err != nil {
		return fmt.Errorf("stat current executable: %w", err)
	}
	if !current.Mode().IsRegular() {
		return errors.New("current executable is not a regular file")
	}
	packageFile, err := os.Open(packagePath)
	if err != nil {
		return err
	}
	magic := make([]byte, 4)
	read, readErr := io.ReadFull(packageFile, magic)
	_ = packageFile.Close()
	if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return fmt.Errorf("inspect client update package: %w", readErr)
	}
	magic = magic[:read]
	expectedName := "specus-client"
	if runtime.GOOS == "windows" || strings.EqualFold(filepath.Ext(executable), ".exe") {
		expectedName += ".exe"
	}
	switch {
	case len(magic) >= 4 && string(magic[:4]) == "PK\x03\x04":
		err = extractZIPExecutable(packagePath, candidatePath, expectedName, candidateReserved)
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		err = extractTarGzipExecutable(packagePath, candidatePath, expectedName, candidateReserved)
	default:
		err = copyBoundedExecutable(packagePath, candidatePath, candidateReserved)
	}
	if err != nil {
		return err
	}
	mode := current.Mode().Perm()
	if mode&0o111 == 0 && runtime.GOOS != "windows" {
		mode |= 0o700
	}
	if err := os.Chmod(candidatePath, mode); err != nil {
		return fmt.Errorf("set update executable permissions: %w", err)
	}
	return nil
}

func extractZIPExecutable(packagePath, candidatePath, expectedName string, candidateReserved bool) error {
	archive, err := zip.OpenReader(packagePath)
	if err != nil {
		return fmt.Errorf("open ZIP client update: %w", err)
	}
	defer archive.Close()
	budget := updateArchiveBudget{}
	var selected *zip.File
	for _, entry := range archive.File {
		if err := budget.add(entry.UncompressedSize64); err != nil {
			return fmt.Errorf("scan ZIP client update: %w", err)
		}
		base := filepath.Base(filepath.FromSlash(entry.Name))
		if base != expectedName || entry.FileInfo().IsDir() {
			continue
		}
		if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
			return errors.New("ZIP client executable is not a regular file")
		}
		if selected != nil {
			return errors.New("ZIP client update contains duplicate executables")
		}
		if entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > uint64(updateBinaryMaxBytes) {
			return errors.New("ZIP client executable exceeds the extraction limit")
		}
		selected = entry
	}
	if selected == nil {
		return fmt.Errorf("ZIP client update does not contain %s", expectedName)
	}
	reader, err := selected.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	return writeBoundedCandidate(candidatePath, reader, candidateReserved)
}

func extractTarGzipExecutable(packagePath, candidatePath, expectedName string, candidateReserved bool) error {
	file, err := os.Open(packagePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open tar.gz client update: %w", err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	budget := updateArchiveBudget{}
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar.gz client update: %w", err)
		}
		if header.Size < 0 {
			return errors.New("tar.gz client update contains a negative entry size")
		}
		if err := budget.add(uint64(header.Size)); err != nil {
			return fmt.Errorf("scan tar.gz client update: %w", err)
		}
		if filepath.Base(filepath.FromSlash(header.Name)) != expectedName {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return errors.New("tar.gz client executable is not a regular file")
		}
		if found {
			return errors.New("tar.gz client update contains duplicate executables")
		}
		if header.Size < 1 || header.Size > updateBinaryMaxBytes {
			return errors.New("tar.gz client executable exceeds the extraction limit")
		}
		if err := writeBoundedCandidate(candidatePath, reader, candidateReserved); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("tar.gz client update does not contain %s", expectedName)
	}
	return nil
}

func copyBoundedExecutable(sourcePath, candidatePath string, candidateReserved bool) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	return writeBoundedCandidate(candidatePath, source, candidateReserved)
}

type updateArchiveBudget struct {
	entries int
	bytes   uint64
}

func (budget *updateArchiveBudget) add(size uint64) error {
	budget.entries++
	if budget.entries > updateArchiveMaxEntries {
		return errors.New("client update archive exceeds the entry limit")
	}
	if size > updateArchiveMaxBytes-budget.bytes {
		return errors.New("client update archive exceeds the expanded size limit")
	}
	budget.bytes += size
	return nil
}

func writeBoundedCandidate(candidatePath string, source io.Reader, candidateReserved bool) error {
	flags := os.O_WRONLY
	if candidateReserved {
		info, err := os.Lstat(candidatePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return errors.New("reserved candidate executable is not an empty regular file")
		}
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(candidatePath, flags, 0o700)
	if err != nil {
		return fmt.Errorf("create candidate executable: %w", err)
	}
	size, copyErr := io.Copy(file, io.LimitReader(source, updateBinaryMaxBytes+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(candidatePath)
		return copyErr
	}
	if size < 1 || size > updateBinaryMaxBytes {
		_ = os.Remove(candidatePath)
		return errors.New("client executable exceeds the extraction limit")
	}
	if syncErr != nil {
		_ = os.Remove(candidatePath)
		return syncErr
	}
	if closeErr != nil {
		_ = os.Remove(candidatePath)
		return closeErr
	}
	return nil
}

func replaceExecutableAtomically(executable, candidate string) (string, error) {
	backup, ownerPath, err := createUpdateBackupOwnership(executable)
	if err != nil {
		return "", err
	}
	if err := replaceExecutablePlatform(executable, candidate, backup); err != nil {
		_ = os.Remove(ownerPath)
		return "", err
	}
	return backup, nil
}

// RollbackInstalledUpdate restores the backup created by replaceExecutableAtomically when the
// freshly installed image cannot be started. The backup path is constrained to the executable's
// own sibling so callers cannot turn the recovery operation into an arbitrary file move.
func RollbackInstalledUpdate(executable, backup string) error {
	executable, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	backup, err = filepath.Abs(backup)
	if err != nil {
		return err
	}
	ownerPath := backup + ".owner"
	if !samePath(filepath.Dir(backup), filepath.Dir(executable)) ||
		!strings.HasPrefix(filepath.Base(backup), ".specus-update-backup-") {
		return errors.New("client update backup path is invalid")
	}
	ownerInfo, err := os.Lstat(ownerPath)
	if err != nil || !ownerInfo.Mode().IsRegular() || ownerInfo.Size() < 1 || ownerInfo.Size() > 512 {
		return errors.New("client update backup ownership marker is invalid")
	}
	owner, err := os.ReadFile(ownerPath)
	if err != nil || string(owner) != updateBackupOwnerMagic+filepath.Base(executable)+"\n" {
		return errors.New("client update backup ownership marker is invalid")
	}
	backupInfo, err := os.Lstat(backup)
	if err != nil {
		return fmt.Errorf("stat client update backup: %w", err)
	}
	if !backupInfo.Mode().IsRegular() {
		return errors.New("client update backup is not a regular file")
	}
	if err := rollbackExecutablePlatform(executable, backup); err != nil {
		return err
	}
	if err := os.Remove(ownerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove client update backup ownership marker: %w", err)
	}
	return nil
}

func createUpdateBackupOwnership(executable string) (string, string, error) {
	executable, err := filepath.Abs(executable)
	if err != nil {
		return "", "", err
	}
	owner, err := os.CreateTemp(filepath.Dir(executable), ".specus-update-backup-*.owner")
	if err != nil {
		return "", "", fmt.Errorf("create client update backup ownership marker: %w", err)
	}
	ownerPath := owner.Name()
	backup := strings.TrimSuffix(ownerPath, ".owner")
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		_ = owner.Close()
		_ = os.Remove(ownerPath)
		if err == nil {
			err = errors.New("reserved client update backup path already exists")
		}
		return "", "", err
	}
	payload := updateBackupOwnerMagic + filepath.Base(executable) + "\n"
	if _, err := io.WriteString(owner, payload); err != nil {
		_ = owner.Close()
		_ = os.Remove(ownerPath)
		return "", "", fmt.Errorf("write client update backup ownership marker: %w", err)
	}
	if err := owner.Sync(); err != nil {
		_ = owner.Close()
		_ = os.Remove(ownerPath)
		return "", "", fmt.Errorf("sync client update backup ownership marker: %w", err)
	}
	if err := owner.Close(); err != nil {
		_ = os.Remove(ownerPath)
		return "", "", fmt.Errorf("close client update backup ownership marker: %w", err)
	}
	return backup, ownerPath, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > updateBinaryMaxBytes {
		return "", errors.New("client executable is not a bounded regular file")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, updateBinaryMaxBytes+1))
	if err != nil {
		return "", err
	}
	if written != info.Size() {
		return "", errors.New("client executable changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type updateHelperOwnership struct {
	Magic         string `json:"magic"`
	TargetPath    string `json:"targetPath"`
	CandidatePath string `json:"candidatePath"`
	CandidateHash string `json:"candidateHash"`
	CreatedAtUnix int64  `json:"createdAtUnix"`
}

const staleUpdateHelperTTL = 24 * time.Hour

func scheduleWindowsUpdateHelper(executable, candidatePath, candidateHash string) error {
	if runtime.GOOS != "windows" {
		return errors.New("deferred update helper is only available on Windows")
	}
	executable, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	candidatePath, err = filepath.Abs(candidatePath)
	if err != nil {
		return err
	}
	if err := validateOwnedUpdateCandidate(executable, candidatePath); err != nil {
		return err
	}
	helper, err := os.CreateTemp(filepath.Dir(executable), ".specus-update-helper-*.exe")
	if err != nil {
		return fmt.Errorf("create Windows update helper: %w", err)
	}
	helperPath := helper.Name()
	if err := copyUpdateHelper(executable, helper); err != nil {
		_ = helper.Close()
		_ = os.Remove(helperPath)
		return err
	}
	if err := helper.Close(); err != nil {
		_ = os.Remove(helperPath)
		return fmt.Errorf("close Windows update helper: %w", err)
	}
	ownership := updateHelperOwnership{
		Magic: updateHelperOwnerMagic, TargetPath: executable, CandidatePath: candidatePath,
		CandidateHash: strings.ToLower(candidateHash), CreatedAtUnix: time.Now().Unix(),
	}
	if err := writeUpdateHelperOwnership(helperPath, ownership); err != nil {
		_ = os.Remove(helperPath)
		return err
	}
	arguments := []string{
		helperPath,
		"--" + UpdateHelperFlagName,
		"--" + UpdateParentPIDFlagName + "=" + strconv.Itoa(os.Getpid()),
		"--" + UpdateCandidateHashFlagName + "=" + candidateHash,
		"--",
	}
	arguments = append(arguments, os.Args[1:]...)
	workingDirectory, _ := os.Getwd()
	process, err := os.StartProcess(helperPath, arguments, &os.ProcAttr{
		Dir: workingDirectory, Env: os.Environ(), Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		_ = os.Remove(helperPath + ".owner")
		_ = os.Remove(helperPath)
		return fmt.Errorf("start Windows update helper: %w", err)
	}
	if err := process.Release(); err != nil {
		return fmt.Errorf("release Windows update helper process: %w", err)
	}
	return nil
}

func copyUpdateHelper(sourcePath string, target *os.File) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open current executable for update helper: %w", err)
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > updateBinaryMaxBytes {
		return errors.New("current executable is not a bounded regular file")
	}
	written, copyErr := io.Copy(target, io.LimitReader(source, updateBinaryMaxBytes+1))
	syncErr := target.Sync()
	if copyErr != nil || syncErr != nil || written != info.Size() {
		return fmt.Errorf("write Windows update helper: copy=%v sync=%v bytes=%d/%d",
			copyErr, syncErr, written, info.Size())
	}
	if err := target.Chmod(0o700); err != nil {
		return fmt.Errorf("make Windows update helper executable: %w", err)
	}
	return nil
}

func writeUpdateHelperOwnership(helperPath string, ownership updateHelperOwnership) error {
	owner, err := os.OpenFile(helperPath+".owner", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create update helper ownership marker: %w", err)
	}
	encodeErr := json.NewEncoder(owner).Encode(ownership)
	syncErr := owner.Sync()
	closeErr := owner.Close()
	if encodeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(helperPath + ".owner")
		return fmt.Errorf("write update helper ownership marker: encode=%v sync=%v close=%v",
			encodeErr, syncErr, closeErr)
	}
	return nil
}

func readUpdateHelperOwnership(helperPath string) (updateHelperOwnership, error) {
	ownerPath := helperPath + ".owner"
	info, err := os.Lstat(ownerPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 8192 {
		return updateHelperOwnership{}, errors.New("update helper ownership marker is invalid")
	}
	file, err := os.Open(ownerPath)
	if err != nil {
		return updateHelperOwnership{}, errors.New("update helper ownership marker is invalid")
	}
	defer file.Close()
	var ownership updateHelperOwnership
	decoder := json.NewDecoder(io.LimitReader(file, 8193))
	if err := decoder.Decode(&ownership); err != nil || ownership.Magic != updateHelperOwnerMagic {
		return updateHelperOwnership{}, errors.New("update helper ownership marker is invalid")
	}
	return ownership, nil
}

// RunDeferredUpdateHelper runs inside the private helper copy on Windows. All writable paths are
// derived from the helper's own location, so hidden command-line flags cannot be abused to replace
// an arbitrary privileged file. The helper waits for the image lock owner, verifies the extracted
// candidate again, installs with rollback, and only then restarts the normal client arguments.
func RunDeferredUpdateHelper(parentPID int, candidateHash string, restartArguments []string) error {
	if runtime.GOOS != "windows" {
		return errors.New("the deferred update helper is only supported on Windows")
	}
	helperPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve update helper executable: %w", err)
	}
	helperPath, err = filepath.Abs(helperPath)
	if err != nil {
		return err
	}
	if parentPID <= 0 || parentPID == os.Getpid() {
		return errors.New("invalid update parent pid")
	}
	ownership, err := validateUpdateHelperOwnership(helperPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(ownership.CandidateHash, candidateHash) {
		_ = os.Remove(ownership.CandidatePath)
		return errors.New("deferred update candidate SHA-256 mismatch")
	}
	return applyDeferredUpdate(ownership.TargetPath, ownership.CandidatePath, parentPID, candidateHash, func(skipUpdate bool) error {
		arguments := append([]string{ownership.TargetPath}, restartArguments...)
		if skipUpdate {
			arguments = RestartArgumentsWithUpdateCheckDisabled(arguments)
		}
		workingDirectory, _ := os.Getwd()
		environment := append(os.Environ(), updateHelperCleanupEnv+"="+helperPath)
		process, err := os.StartProcess(ownership.TargetPath, arguments, &os.ProcAttr{
			Dir: workingDirectory, Env: environment, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		})
		if err != nil {
			return err
		}
		return process.Release()
	})
}

func applyDeferredUpdate(targetPath, candidatePath string, parentPID int, candidateHash string,
	restart func(skipUpdate bool) error) error {
	return applyDeferredUpdateWithTimeout(targetPath, candidatePath, parentPID, candidateHash, 2*time.Minute, restart)
}

func applyDeferredUpdateWithTimeout(targetPath, candidatePath string, parentPID int, candidateHash string,
	waitTimeout time.Duration, restart func(skipUpdate bool) error) (returnErr error) {
	if err := validateOwnedUpdateCandidate(targetPath, candidatePath); err != nil {
		return err
	}
	candidateConsumed := false
	parentExited := false
	recoveryHandled := false
	defer func() {
		if !candidateConsumed {
			_ = os.Remove(candidatePath)
		}
		if returnErr != nil && parentExited && !recoveryHandled && restart != nil {
			if recoveryErr := restart(true); recoveryErr != nil {
				returnErr = fmt.Errorf("%w (restarting previous client failed: %v)", returnErr, recoveryErr)
			}
		}
	}()
	if len(candidateHash) != sha256.Size*2 {
		return errors.New("deferred update candidate SHA-256 mismatch")
	}
	if _, err := hex.DecodeString(candidateHash); err != nil {
		return errors.New("deferred update candidate SHA-256 mismatch")
	}
	if err := waitForProcessExit(parentPID, waitTimeout); err != nil {
		return err
	}
	parentExited = true
	// Hash after the parent has exited, immediately before the rename, to avoid accepting a
	// candidate that changed while the helper was waiting for the Windows image lock.
	actualHash, err := sha256File(candidatePath)
	if err != nil {
		return fmt.Errorf("verify deferred update candidate: %w", err)
	}
	if !strings.EqualFold(actualHash, candidateHash) {
		return errors.New("deferred update candidate SHA-256 mismatch")
	}
	backupPath, err := replaceExecutableAtomically(targetPath, candidatePath)
	if err != nil {
		return err
	}
	candidateConsumed = true
	if restart != nil {
		err = restart(false)
	}
	if err != nil {
		recoveryHandled = true
		if rollbackErr := RollbackInstalledUpdate(targetPath, backupPath); rollbackErr != nil {
			return fmt.Errorf("restart updated client: %w (rollback failed: %v)", err, rollbackErr)
		}
		if restart != nil {
			if recoveryErr := restart(true); recoveryErr != nil {
				return fmt.Errorf("restart updated client: %w (rolled back; restarting previous client failed: %v)", err, recoveryErr)
			}
		}
		return fmt.Errorf("restart updated client: %w (rolled back and restarted previous client)", err)
	}
	return nil
}

func validateOwnedUpdateCandidate(targetPath, candidatePath string) error {
	targetPath, targetErr := filepath.Abs(targetPath)
	candidatePath, candidateErr := filepath.Abs(candidatePath)
	if targetErr != nil || candidateErr != nil || filepath.Dir(targetPath) != filepath.Dir(candidatePath) ||
		!strings.HasPrefix(filepath.Base(candidatePath), ".specus-update-candidate-") {
		return errors.New("deferred update candidate path is invalid")
	}
	return nil
}

func validateUpdateHelperOwnership(helperPath string) (updateHelperOwnership, error) {
	helperPath, err := filepath.Abs(helperPath)
	if err != nil || !strings.HasPrefix(filepath.Base(helperPath), ".specus-update-helper-") ||
		!strings.HasSuffix(strings.ToLower(helperPath), ".exe") {
		return updateHelperOwnership{}, errors.New("update helper executable path is invalid")
	}
	ownership, err := readUpdateHelperOwnership(helperPath)
	if err != nil {
		return updateHelperOwnership{}, err
	}
	ownership.TargetPath, err = filepath.Abs(ownership.TargetPath)
	if err != nil {
		return updateHelperOwnership{}, errors.New("update helper target path is invalid")
	}
	ownership.CandidatePath, err = filepath.Abs(ownership.CandidatePath)
	if err != nil || filepath.Dir(helperPath) != filepath.Dir(ownership.TargetPath) ||
		filepath.Dir(helperPath) != filepath.Dir(ownership.CandidatePath) {
		return updateHelperOwnership{}, errors.New("update helper owned paths are invalid")
	}
	if err := validateOwnedUpdateCandidate(ownership.TargetPath, ownership.CandidatePath); err != nil {
		return updateHelperOwnership{}, err
	}
	return ownership, nil
}

// RestartArgumentsWithUpdateCheckDisabled inserts the one-shot safety flag before a possible "--"
// separator so flag.Parse cannot mistake it for a positional argument during rollback recovery.
func RestartArgumentsWithUpdateCheckDisabled(arguments []string) []string {
	flag := "--" + DisableUpdateCheckFlagName
	separator := len(arguments)
	for index, argument := range arguments {
		if argument == flag || strings.HasPrefix(argument, flag+"=") {
			return arguments
		}
		if argument == "--" && separator == len(arguments) {
			separator = index
		}
	}
	result := make([]string, 0, len(arguments)+1)
	result = append(result, arguments[:separator]...)
	result = append(result, flag)
	result = append(result, arguments[separator:]...)
	return result
}

func waitForProcessExit(pid int, timeout time.Duration) error {
	return waitForProcessExitPlatform(pid, timeout)
}

// CleanupStaleUpdateHelper removes only helpers carrying a valid ownership marker for this
// executable. The explicit helper from the restart environment is retried until Windows releases
// its image; older owned crash remnants are collected only after a conservative TTL.
func CleanupStaleUpdateHelper(logger *log.Logger) {
	if runtime.GOOS != "windows" {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return
	}
	if helperPath := strings.TrimSpace(os.Getenv(updateHelperCleanupEnv)); helperPath != "" {
		for attempt := 0; attempt < 20; attempt++ {
			if err := removeOwnedUpdateHelper(helperPath, executable, false); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		_ = os.Unsetenv(updateHelperCleanupEnv)
	}
	entries, err := os.ReadDir(filepath.Dir(executable))
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".specus-update-helper-") ||
			!strings.HasSuffix(strings.ToLower(name), ".exe") {
			continue
		}
		helperPath := filepath.Join(filepath.Dir(executable), name)
		if err := removeOwnedUpdateHelper(helperPath, executable, true); err != nil &&
			!errors.Is(err, os.ErrNotExist) && logger != nil {
			logger.Printf("stale Windows update helper could not be removed: %s", sanitizeTerminalText(helperPath))
		}
	}
}

func removeOwnedUpdateHelper(helperPath, executable string, requireExpired bool) error {
	helperPath, err := filepath.Abs(helperPath)
	if err != nil {
		return err
	}
	ownership, err := validateUpdateHelperOwnership(helperPath)
	if err != nil || !samePath(ownership.TargetPath, executable) {
		return errors.New("update helper ownership does not match this executable")
	}
	if requireExpired && time.Since(time.Unix(ownership.CreatedAtUnix, 0)) < staleUpdateHelperTTL {
		return nil
	}
	_ = os.Remove(ownership.CandidatePath)
	if err := os.Remove(helperPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Remove(helperPath + ".owner")
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func updateTarget(goos, goarch string) (string, string) {
	platform := goos
	if platform == "darwin" {
		platform = "macos"
	}
	arch := goarch
	if arch == "amd64" {
		arch = "x64"
	}
	return platform, arch
}

func validUpdateVersion(value string) bool {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "v")
	if trimmed == "" || len(trimmed) > 32 {
		return false
	}
	if index := strings.IndexByte(trimmed, '+'); index >= 0 {
		if !validUpdateIdentifiers(trimmed[index+1:], false) {
			return false
		}
		trimmed = trimmed[:index]
	}
	if index := strings.IndexByte(trimmed, '-'); index >= 0 {
		if !validUpdateIdentifiers(trimmed[index+1:], true) {
			return false
		}
		trimmed = trimmed[:index]
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func validUpdateIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, char := range identifier {
			if (char < '0' || char > '9') && (char < 'A' || char > 'Z') &&
				(char < 'a' || char > 'z') && char != '-' {
				return false
			}
			if char < '0' || char > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func formatUpdateSize(size int64) string {
	if size >= 1024*1024*1024 {
		return fmt.Sprintf("%.1f GiB", float64(size)/float64(1024*1024*1024))
	}
	if size >= 1024*1024 {
		return fmt.Sprintf("%.1f MiB", float64(size)/float64(1024*1024))
	}
	if size >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(size)/1024)
	}
	return strconv.FormatInt(size, 10) + " B"
}
