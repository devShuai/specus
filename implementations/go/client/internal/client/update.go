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
)

const (
	DefaultUpdateCheckInterval = 24 * time.Hour
	updateMetadataMaxBytes     = 64 * 1024
	updatePackageMaxBytes      = int64(1024 * 1024 * 1024)
	updateBinaryMaxBytes       = int64(256 * 1024 * 1024)
)

var ErrMandatoryUpdateDeclined = errors.New("mandatory client update was declined")

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
	Checked         bool
	Installed       bool
	Mandatory       bool
	PreviousVersion string
	LatestVersion   string
	ExecutablePath  string
	BackupPath      string
}

// Updater checks the server connected by this client. HTTP and filesystem seams are kept on the
// value so tests can exercise the full download/verification/replacement flow without replacing
// process globals.
type Updater struct {
	config         Config
	currentVersion string
	autoUpdate     bool
	logger         *log.Logger
	httpClient     *http.Client
	input          io.Reader
	output         io.Writer
	executablePath func() (string, error)
	confirm        func(UpdateInfo) bool
	allowHTTP      bool
}

func NewUpdater(config Config, currentVersion string, autoUpdate bool, logger *log.Logger) *Updater {
	if logger == nil {
		logger = log.Default()
	}
	return &Updater{
		config:         config,
		currentVersion: strings.TrimPrefix(strings.TrimSpace(currentVersion), "v"),
		autoUpdate:     autoUpdate,
		logger:         logger,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		input:          os.Stdin,
		output:         os.Stdout,
		executablePath: os.Executable,
	}
}

// CheckAndApply performs one catalog lookup and, after confirmation, installs the selected package.
func (updater *Updater) CheckAndApply(ctx context.Context) (UpdateResult, error) {
	result := UpdateResult{PreviousVersion: updater.currentVersion}
	if updater == nil || !updater.config.UpdatesEnabled() || !validUpdateVersion(updater.currentVersion) {
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
		if info.Mandatory {
			return result, ErrMandatoryUpdateDeclined
		}
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
	backup, err := updater.downloadAndReplace(ctx, info, executable)
	if err != nil {
		return result, err
	}
	result.Installed = true
	result.ExecutablePath = executable
	result.BackupPath = backup
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
				if errors.Is(err, ErrMandatoryUpdateDeclined) {
					return result, err
				}
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
	response, err := updater.httpClient.Do(request)
	if err != nil {
		return UpdateInfo{}, fmt.Errorf("query client version catalog: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return UpdateInfo{}, fmt.Errorf("query client version catalog HTTP %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, updateMetadataMaxBytes+1))
	var info UpdateInfo
	if err := decoder.Decode(&info); err != nil {
		return UpdateInfo{}, fmt.Errorf("decode client version catalog: %w", err)
	}
	if !info.UpdateAvailable {
		return info, nil
	}
	if !validUpdateVersion(info.LatestVersion) {
		return UpdateInfo{}, errors.New("version catalog returned an invalid latestVersion")
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
		updater.currentVersion, info.LatestVersion, formatUpdateSize(info.FileSize))
	if info.ChangelogURL != nil && strings.TrimSpace(*info.ChangelogURL) != "" {
		_, _ = fmt.Fprintf(updater.output, "更新说明：%s\n", strings.TrimSpace(*info.ChangelogURL))
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

func (updater *Updater) downloadAndReplace(ctx context.Context, info UpdateInfo, executable string) (string, error) {
	downloadURL, origin, err := updater.secureDownloadURL(info.DownloadURL)
	if err != nil {
		return "", err
	}
	downloadPath := executable + ".download"
	candidatePath := executable + ".new"
	_ = os.Remove(downloadPath)
	_ = os.Remove(candidatePath)
	defer os.Remove(downloadPath)
	defer os.Remove(candidatePath)

	download, err := os.OpenFile(downloadPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create update download: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		_ = download.Close()
		return "", err
	}
	request.Header.Set("User-Agent", "specus-client-go/"+updater.currentVersion)
	client := *updater.httpClient
	client.Timeout = 0
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many package download redirects")
		}
		if !updater.sameSecureOrigin(request.URL, origin) {
			return errors.New("package redirect left the configured server origin or downgraded HTTPS")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		_ = download.Close()
		return "", fmt.Errorf("download client update: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		_ = download.Close()
		return "", fmt.Errorf("download client update HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(download, hash), io.LimitReader(response.Body, info.FileSize+1))
	closeBodyErr := response.Body.Close()
	syncErr := download.Sync()
	closeErr := download.Close()
	if copyErr != nil {
		return "", fmt.Errorf("download client update body: %w", copyErr)
	}
	if closeBodyErr != nil {
		return "", fmt.Errorf("close client update response: %w", closeBodyErr)
	}
	if syncErr != nil {
		return "", fmt.Errorf("sync client update download: %w", syncErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close client update download: %w", closeErr)
	}
	if size != info.FileSize {
		return "", fmt.Errorf("client update size mismatch: got %d, want %d", size, info.FileSize)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualHash, info.SHA256) {
		return "", errors.New("client update SHA-256 mismatch")
	}
	if err := prepareUpdateExecutable(downloadPath, candidatePath, executable); err != nil {
		return "", err
	}
	return replaceExecutableAtomically(executable, candidatePath)
}

func (updater *Updater) secureDownloadURL(value string) (*url.URL, *url.URL, error) {
	origin, err := url.Parse(strings.TrimSpace(updater.config.ServerBaseURL))
	if err != nil || origin.Scheme == "" || origin.Host == "" {
		return nil, nil, errors.New("serverBaseUrl is invalid for client update")
	}
	if !updater.allowHTTP && !strings.EqualFold(origin.Scheme, "https") {
		return nil, nil, errors.New("automatic client update requires an HTTPS serverBaseUrl")
	}
	reference, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, nil, fmt.Errorf("parse package downloadUrl: %w", err)
	}
	resolved := origin.ResolveReference(reference)
	if !updater.sameSecureOrigin(resolved, origin) {
		return nil, nil, errors.New("package downloadUrl must stay on the configured server origin over HTTPS")
	}
	return resolved, origin, nil
}

func (updater *Updater) sameSecureOrigin(candidate, origin *url.URL) bool {
	if candidate == nil || origin == nil || !strings.EqualFold(candidate.Host, origin.Host) {
		return false
	}
	if updater.allowHTTP {
		return strings.EqualFold(candidate.Scheme, origin.Scheme) &&
			(strings.EqualFold(candidate.Scheme, "http") || strings.EqualFold(candidate.Scheme, "https"))
	}
	return strings.EqualFold(candidate.Scheme, "https") && strings.EqualFold(origin.Scheme, "https")
}

func prepareUpdateExecutable(packagePath, candidatePath, executable string) error {
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
		err = extractZIPExecutable(packagePath, candidatePath, expectedName)
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		err = extractTarGzipExecutable(packagePath, candidatePath, expectedName)
	default:
		err = copyBoundedExecutable(packagePath, candidatePath)
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

func extractZIPExecutable(packagePath, candidatePath, expectedName string) error {
	archive, err := zip.OpenReader(packagePath)
	if err != nil {
		return fmt.Errorf("open ZIP client update: %w", err)
	}
	defer archive.Close()
	var selected *zip.File
	for _, entry := range archive.File {
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
	return writeBoundedCandidate(candidatePath, reader)
}

func extractTarGzipExecutable(packagePath, candidatePath, expectedName string) error {
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
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar.gz client update: %w", err)
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
		if err := writeBoundedCandidate(candidatePath, reader); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("tar.gz client update does not contain %s", expectedName)
	}
	return nil
}

func copyBoundedExecutable(sourcePath, candidatePath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	return writeBoundedCandidate(candidatePath, source)
}

func writeBoundedCandidate(candidatePath string, source io.Reader) error {
	file, err := os.OpenFile(candidatePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
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
	backup := executable + ".bak"
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove previous client backup: %w", err)
	}
	if err := os.Rename(executable, backup); err != nil {
		return "", fmt.Errorf("backup current client executable: %w", err)
	}
	if err := os.Rename(candidate, executable); err != nil {
		rollbackErr := os.Rename(backup, executable)
		if rollbackErr != nil {
			return "", fmt.Errorf("install client update: %w (rollback failed: %v)", err, rollbackErr)
		}
		return "", fmt.Errorf("install client update: %w (rolled back)", err)
	}
	return backup, nil
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
		if !validUpdateIdentifiers(trimmed[index+1:]) {
			return false
		}
		trimmed = trimmed[:index]
	}
	if index := strings.IndexByte(trimmed, '-'); index >= 0 {
		if !validUpdateIdentifiers(trimmed[index+1:]) {
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
		if _, err := strconv.ParseUint(part, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func validUpdateIdentifiers(value string) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		for _, char := range identifier {
			if (char < '0' || char > '9') && (char < 'A' || char > 'Z') &&
				(char < 'a' || char > 'z') && char != '-' {
				return false
			}
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
