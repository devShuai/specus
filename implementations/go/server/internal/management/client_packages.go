package management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	maxClientPackageUploadBytes = int64(1024 * 1024 * 1024)
	publicDownloadWindowLength  = time.Minute
	publicDownloadRequests      = 240
	maxPublicDownloadSources    = 100_000
)

type publicDownloadWindow struct {
	started time.Time
	count   int
}

// publicDownloadRateLimiter is deliberately bounded. When the source table is full, an unseen
// source is denied rather than allowing an attacker to grow server memory without limit.
type publicDownloadRateLimiter struct {
	mu        sync.Mutex
	windows   map[string]publicDownloadWindow
	lastPurge time.Time
	now       func() time.Time
}

func newPublicDownloadRateLimiter() *publicDownloadRateLimiter {
	return &publicDownloadRateLimiter{windows: make(map[string]publicDownloadWindow), now: time.Now}
}

func (limiter *publicDownloadRateLimiter) allow(source string) (bool, time.Duration) {
	if limiter == nil {
		return true, 0
	}
	now := limiter.now()
	key := strings.TrimSpace(source)
	if key == "" {
		key = security.UnknownClientAddress
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.lastPurge.IsZero() || now.Sub(limiter.lastPurge) >= publicDownloadWindowLength {
		for existingKey, window := range limiter.windows {
			if now.Sub(window.started) >= publicDownloadWindowLength {
				delete(limiter.windows, existingKey)
			}
		}
		limiter.lastPurge = now
	}
	window, exists := limiter.windows[key]
	if !exists {
		if len(limiter.windows) >= maxPublicDownloadSources {
			return false, publicDownloadWindowLength
		}
		window = publicDownloadWindow{started: now}
	}
	if now.Sub(window.started) >= publicDownloadWindowLength {
		window = publicDownloadWindow{started: now}
	}
	window.count++
	limiter.windows[key] = window
	if window.count <= publicDownloadRequests {
		return true, 0
	}
	retryAfter := publicDownloadWindowLength - now.Sub(window.started)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	return false, retryAfter
}

func (a *API) allowPublicDownloadRequest(w http.ResponseWriter, r *http.Request) bool {
	source := security.UnknownClientAddress
	if a.addressResolver != nil {
		source = a.addressResolver.Resolve(r)
	}
	allowed, retryAfter := a.downloadLimiter.allow(source)
	if allowed {
		return true
	}
	w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
	writeError(w, http.StatusTooManyRequests, "下载请求过于频繁,请稍后再试")
	return false
}

func (a *API) handlePublicClientVersionCheck(w http.ResponseWriter, r *http.Request) {
	if !a.allowPublicDownloadRequest(w, r) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	implementation, err := requireDownloadEnum(r.URL.Query().Get("implementation"),
		allowedDownloadImplementations, "implementation is unsupported")
	if err != nil {
		a.fail(w, err)
		return
	}
	platform, err := requireDownloadEnum(r.URL.Query().Get("platform"),
		allowedDownloadPlatforms, "platform is unsupported")
	if err != nil {
		a.fail(w, err)
		return
	}
	arch, err := requireDownloadEnum(r.URL.Query().Get("arch"),
		allowedDownloadArchitectures, "arch is unsupported")
	if err != nil {
		a.fail(w, err)
		return
	}
	current, err := normalizeSemanticVersion(r.URL.Query().Get("current"))
	if err != nil {
		a.fail(w, validation("current must be a semantic version"))
		return
	}
	links, err := a.db.ListClientDownloadLinks(r.Context(), true)
	if err != nil {
		a.fail(w, err)
		return
	}
	latest := selectLatestClientDownload(links, implementation, platform, arch)
	if latest == nil {
		writeJSON(w, http.StatusOK, ClientVersionCheckView{})
		return
	}
	if latest.Version == nil {
		writeJSON(w, http.StatusOK, ClientVersionCheckView{})
		return
	}
	latestVersion, err := parseSemanticVersion(*latest.Version)
	if err != nil {
		a.logger.Error("latest client package has invalid version", "id", latest.ID, "version", *latest.Version)
		writeJSON(w, http.StatusOK, ClientVersionCheckView{})
		return
	}
	updateAvailable := compareSemanticVersions(latestVersion, current) > 0
	mandatory := false
	if updateAvailable && latest.MinSupportedVersion != nil {
		if minimum, parseErr := parseSemanticVersion(*latest.MinSupportedVersion); parseErr == nil {
			mandatory = compareSemanticVersions(current, minimum) < 0
		}
	}
	view := ClientVersionCheckView{
		UpdateAvailable: updateAvailable,
		Mandatory:       mandatory,
		FileSize:        latest.FileSize,
		ChangelogURL:    latest.ChangelogURL,
	}
	view.LatestVersion = latest.Version
	view.DownloadURL = &latest.DownloadURL
	view.SHA256 = &latest.SHA256
	if isHostedClientPackage(*latest) {
		id := latest.ID
		view.PackageID = &id
	}
	writeJSON(w, http.StatusOK, view)
}

func selectLatestClientDownload(links []store.ClientDownloadLink,
	implementation, platform, arch string) *store.ClientDownloadLink {
	bestRank := -1
	var best *store.ClientDownloadLink
	for index := range links {
		candidate := &links[index]
		if !candidate.Enabled || !candidate.IsLatest || !isInstallableClientDistribution(*candidate) ||
			candidate.Implementation != implementation {
			continue
		}
		platformRank := matchDownloadTarget(candidate.Platform, platform)
		archRank := matchDownloadTarget(candidate.Arch, arch)
		if platformRank < 0 || archRank < 0 {
			continue
		}
		if candidate.Version == nil {
			continue
		}
		parsed, err := parseSemanticVersion(*candidate.Version)
		if err != nil {
			continue
		}
		rank := platformRank*2 + archRank
		if best == nil || rank > bestRank {
			best, bestRank = candidate, rank
			continue
		}
		if rank == bestRank {
			currentBest, err := parseSemanticVersion(*best.Version)
			if err != nil || compareSemanticVersions(parsed, currentBest) > 0 {
				best = candidate
			}
		}
	}
	return best
}

// publicClientDownloadLinks keeps the legacy external-link response compatible while preventing a
// versioned target from exposing every historical package to download-page recommendation logic.
// Once a target has real catalog versions, only its enabled explicit latest entry is public.
func publicClientDownloadLinks(links []store.ClientDownloadLink) []store.ClientDownloadLink {
	versionedTargets := make(map[string]bool)
	for _, link := range links {
		if !isLegacyClientDownload(link) {
			versionedTargets[clientDownloadTargetKey(link)] = true
		}
	}
	result := make([]store.ClientDownloadLink, 0, len(links))
	for _, link := range links {
		if !link.Enabled {
			continue
		}
		if versionedTargets[clientDownloadTargetKey(link)] {
			if link.IsLatest {
				result = append(result, link)
			}
			continue
		}
		// Old rows had neither version nor latest. Keep returning them until an administrator
		// publishes the first versioned entry for the target.
		if isLegacyClientDownload(link) {
			result = append(result, link)
		}
	}
	return result
}

func isLegacyClientDownload(link store.ClientDownloadLink) bool {
	return link.Version == nil
}

func clientDownloadTargetKey(link store.ClientDownloadLink) string {
	return strings.ToLower(strings.TrimSpace(link.Implementation)) + "\x00" +
		strings.ToLower(strings.TrimSpace(link.Platform)) + "\x00" +
		strings.ToLower(strings.TrimSpace(link.Arch))
}

func matchDownloadTarget(candidate, requested string) int {
	if candidate == requested {
		return 1
	}
	if candidate == "any" {
		return 0
	}
	return -1
}

func (a *API) handlePublicClientPackageDownload(w http.ResponseWriter, r *http.Request) {
	if !a.allowPublicDownloadRequest(w, r) {
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	link, err := a.db.GetClientDownloadLink(r.Context(), id)
	if err != nil || link == nil || !link.Enabled || !isHostedClientPackage(*link) {
		if err == nil {
			err = store.ErrNotFound
		}
		a.fail(w, err)
		return
	}
	path, err := a.clientPackagePath(id)
	if err != nil {
		a.fail(w, err)
		return
	}
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		a.fail(w, store.ErrNotFound)
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	if !pathInfo.Mode().IsRegular() {
		a.fail(w, fmt.Errorf("hosted client package %d is not a regular file", id))
		return
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		a.fail(w, store.ErrNotFound)
		return
	}
	if err != nil {
		a.fail(w, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		a.fail(w, err)
		return
	}
	// SameFile closes the Lstat/Open race and prevents a local symlink swap from turning the
	// public download route into a reader for another server-owned file.
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) || info.Size() != link.FileSize {
		a.fail(w, fmt.Errorf("hosted client package %d metadata does not match file", id))
		return
	}
	downloadName := clientPackageDownloadName(*link)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": downloadName}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", `"sha256-`+link.SHA256+`"`)
	http.ServeContent(w, r, downloadName, link.UpdatedAt, file)
}

func clientPackageDownloadName(link store.ClientDownloadLink) string {
	name := strings.TrimSpace(link.DisplayName)
	if separator := strings.LastIndexAny(name, `/\`); separator >= 0 {
		name = name[separator+1:]
	}
	name = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return '-'
		}
		return char
	}, name)
	name = strings.Trim(name, ". ")
	if name == "" {
		name = "specus-client-package-" + strconv.FormatInt(link.ID, 10)
	}
	if link.Implementation == "android" && link.Platform == "android" && link.Arch == "any" &&
		!strings.HasSuffix(strings.ToLower(name), ".apk") {
		name += ".apk"
	}
	return name
}

func (a *API) handleUploadClientPackage(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以上传客户端包"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxClientPackageUploadBytes+1024*1024)
	if err := r.ParseMultipartForm(1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "multipart 请求无效或文件过大")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	displayName := strings.TrimSpace(r.FormValue("displayName"))
	if displayName == "" && header != nil {
		displayName = filepath.Base(strings.TrimSpace(header.Filename))
	}
	displayOrder, err := optionalFormInt(r.FormValue("displayOrder"))
	if err != nil {
		a.fail(w, validation("displayOrder must be an integer"))
		return
	}
	enabled, err := optionalFormBool(r.FormValue("enabled"))
	if err != nil {
		a.fail(w, validation("enabled must be true or false"))
		return
	}
	isLatest, err := optionalFormBool(r.FormValue("isLatest"))
	if err != nil {
		a.fail(w, validation("isLatest must be true or false"))
		return
	}
	id := auth.NewClientID()
	now := time.Now()
	link := store.ClientDownloadLink{ID: id, Enabled: true, CreatedAt: now, UpdatedAt: now}
	req := clientDownloadLinkMutation{
		Implementation:      r.FormValue("implementation"),
		Platform:            r.FormValue("platform"),
		Arch:                r.FormValue("arch"),
		Version:             r.FormValue("version"),
		DisplayName:         displayName,
		DownloadURL:         clientPackageDownloadURL(id),
		Description:         r.FormValue("description"),
		ChangelogURL:        r.FormValue("changelogUrl"),
		MinSupportedVersion: r.FormValue("minSupportedVersion"),
		DisplayOrder:        displayOrder,
		Enabled:             enabled,
		IsLatest:            isLatest,
	}
	if err := applyClientDownloadLinkMutation(&link, req); err != nil {
		a.fail(w, err)
		return
	}
	// Uploaded packages require a real release version; NULL is reserved for compatibility rows
	// and old external-link CRUD clients.
	if link.Version == nil {
		a.fail(w, validation("version is required"))
		return
	}
	directory, err := a.ensureClientPackageDirectory()
	if err != nil {
		a.fail(w, err)
		return
	}
	temporary, err := os.CreateTemp(directory, ".client-package-upload-*")
	if err != nil {
		a.fail(w, err)
		return
	}
	temporaryPath := temporary.Name()
	committedPath := ""
	defer func() {
		_ = temporary.Close()
		if temporaryPath != "" {
			_ = os.Remove(temporaryPath)
		}
		if committedPath != "" {
			_ = os.Remove(committedPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		a.fail(w, err)
		return
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(file, maxClientPackageUploadBytes+1))
	if err != nil {
		a.fail(w, err)
		return
	}
	if size < 1 || size > maxClientPackageUploadBytes {
		a.fail(w, validation("file must contain 1 byte to 1 GiB"))
		return
	}
	if err := temporary.Sync(); err != nil {
		a.fail(w, err)
		return
	}
	if err := temporary.Close(); err != nil {
		a.fail(w, err)
		return
	}
	finalPath, err := a.clientPackagePath(id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if _, err := os.Lstat(finalPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			err = errors.New("generated client package id already exists")
		}
		a.fail(w, err)
		return
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		a.fail(w, err)
		return
	}
	temporaryPath = ""
	committedPath = finalPath
	link.SHA256 = hex.EncodeToString(hash.Sum(nil))
	link.FileSize = size
	if err := a.db.InsertClientDownloadLink(r.Context(), link); err != nil {
		a.failClientDownloadMutation(w, err)
		return
	}
	committedPath = ""
	writeJSON(w, http.StatusCreated, clientDownloadLinkView(link))
}

func (a *API) handleSetLatestClientDownload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if !principal.Admin {
		a.fail(w, forbidden("仅管理员可以维护客户端包"))
		return
	}
	id, err := pathInt(r, "id")
	if err != nil {
		a.fail(w, err)
		return
	}
	link, err := a.db.GetClientDownloadLink(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !link.Enabled {
		a.fail(w, validation("disabled package cannot be latest"))
		return
	}
	if link.Version == nil {
		a.fail(w, validation("package version is not semantic"))
		return
	}
	if _, err := parseSemanticVersion(*link.Version); err != nil {
		a.fail(w, validation("package version is not semantic"))
		return
	}
	if !isInstallableClientDistribution(*link) {
		a.fail(w, validation("latest package requires a trusted HTTPS URL, SHA-256 and fileSize"))
		return
	}
	updated, err := a.db.SetClientDownloadLinkLatest(r.Context(), id, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrClientDownloadDisabled) {
			a.fail(w, conflict("package was disabled or changed; refresh and retry"))
			return
		}
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, clientDownloadLinkView(*updated))
}

func (a *API) failClientDownloadMutation(w http.ResponseWriter, err error) {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique") || strings.Contains(message, "duplicate") {
		a.fail(w, conflict("同一实现、平台、架构和版本已存在"))
		return
	}
	a.fail(w, err)
}

func optionalFormInt(value string) (*int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func optionalFormBool(value string) (*bool, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(trimmed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func (a *API) ensureClientPackageDirectory() (string, error) {
	return a.validatedClientPackageDirectory(true)
}

func (a *API) validatedClientPackageDirectory(create bool) (string, error) {
	directory := strings.TrimSpace(a.packageDirectory)
	if directory == "" {
		return "", unavailable("client package directory is not configured")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(absolute, 0o750); err != nil {
			return "", fmt.Errorf("create client package directory: %w", err)
		}
		info, err = os.Lstat(absolute)
	}
	if errors.Is(err, os.ErrNotExist) {
		return "", unavailable("client package directory does not exist")
	}
	if err != nil {
		return "", fmt.Errorf("inspect client package directory: %w", err)
	}
	if !info.IsDir() || clientPackageDirectoryIsReparsePoint(info) {
		return "", unavailable("client package directory must be a physical directory")
	}
	return absolute, nil
}

func (a *API) clientPackagePath(id int64) (string, error) {
	if id <= 0 {
		return "", validation("invalid client package id")
	}
	absolute, err := a.validatedClientPackageDirectory(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(absolute, strconv.FormatInt(id, 10)), nil
}

func clientPackageDownloadURL(id int64) string {
	return "/api/public/client-packages/" + strconv.FormatInt(id, 10) + "/download"
}

func isHostedClientPackage(link store.ClientDownloadLink) bool {
	return isManagedClientPackageURL(link) && hasAuthoritativeClientPackageMetadata(link)
}

func isManagedClientPackageURL(link store.ClientDownloadLink) bool {
	return link.ID > 0 && link.DownloadURL == clientPackageDownloadURL(link.ID)
}

func hasAuthoritativeClientPackageMetadata(link store.ClientDownloadLink) bool {
	if len(link.SHA256) != sha256.Size*2 || link.FileSize <= 0 ||
		link.FileSize > maxClientPackageUploadBytes {
		return false
	}
	_, err := hex.DecodeString(link.SHA256)
	return err == nil
}

func normalizeClientDownloadSHA256(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", nil
	}
	if len(normalized) != sha256.Size*2 {
		return "", validation("sha256 must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", validation("sha256 must contain exactly 64 hexadecimal characters")
	}
	return normalized, nil
}

func isExternalClientPackageURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && parsed.IsAbs() && strings.EqualFold(parsed.Scheme, "https") &&
		parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func isInstallableClientDistribution(link store.ClientDownloadLink) bool {
	if !hasAuthoritativeClientPackageMetadata(link) {
		return false
	}
	return isManagedClientPackageURL(link) || isExternalClientPackageURL(link.DownloadURL)
}

// stageClientPackageDeletion moves a hosted file out of its public numeric path before the DB row
// is deleted. A DB failure restores it; a successful deletion unlinks the staged file.
func (a *API) stageClientPackageDeletion(link store.ClientDownloadLink) (commit func(), rollback func(), err error) {
	if !isHostedClientPackage(link) {
		return func() {}, func() {}, nil
	}
	path, err := a.clientPackagePath(link.ID)
	if err != nil {
		return nil, nil, err
	}
	staged := path + ".deleting-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(path, staged); errors.Is(err, os.ErrNotExist) {
		return func() {}, func() {}, nil
	} else if err != nil {
		return nil, nil, err
	}
	return func() { _ = os.Remove(staged) }, func() { _ = os.Rename(staged, path) }, nil
}

type semanticVersion struct {
	major, minor, patch string
	prerelease          []string
}

func normalizeSemanticVersion(value string) (semanticVersion, error) {
	return parseSemanticVersion(value)
}

func parseSemanticVersion(value string) (semanticVersion, error) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "v")
	if trimmed == "" || len(trimmed) > 32 {
		return semanticVersion{}, errors.New("semantic version is empty or too long")
	}
	withoutBuild := trimmed
	if index := strings.IndexByte(withoutBuild, '+'); index >= 0 {
		if index == len(withoutBuild)-1 || !validSemanticIdentifiers(withoutBuild[index+1:], false) {
			return semanticVersion{}, errors.New("invalid semantic version build metadata")
		}
		withoutBuild = withoutBuild[:index]
	}
	core := withoutBuild
	var prerelease []string
	if index := strings.IndexByte(core, '-'); index >= 0 {
		if index == len(core)-1 || !validSemanticIdentifiers(core[index+1:], true) {
			return semanticVersion{}, errors.New("invalid semantic version prerelease")
		}
		prerelease = strings.Split(core[index+1:], ".")
		core = core[:index]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semanticVersion{}, errors.New("semantic version must contain major.minor.patch")
	}
	for _, part := range parts {
		if !validSemanticNumber(part) {
			return semanticVersion{}, errors.New("invalid semantic version number")
		}
	}
	return semanticVersion{major: parts[0], minor: parts[1], patch: parts[2], prerelease: prerelease}, nil
}

func validSemanticIdentifiers(value string, rejectNumericLeadingZero bool) bool {
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

func validSemanticNumber(value string) bool {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func compareSemanticVersions(left, right semanticVersion) int {
	for _, pair := range [][2]string{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if compared := compareSemanticNumbers(pair[0], pair[1]); compared != 0 {
			return compared
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) == 0 {
		return 0
	}
	if len(left.prerelease) == 0 {
		return 1
	}
	if len(right.prerelease) == 0 {
		return -1
	}
	for index := 0; index < len(left.prerelease) && index < len(right.prerelease); index++ {
		leftID, rightID := left.prerelease[index], right.prerelease[index]
		leftNumeric, rightNumeric := allDigits(leftID), allDigits(rightID)
		switch {
		case leftNumeric && rightNumeric:
			if compared := compareSemanticNumbers(leftID, rightID); compared != 0 {
				return compared
			}
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		default:
			if leftID < rightID {
				return -1
			}
			if leftID > rightID {
				return 1
			}
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}

func compareSemanticNumbers(left, right string) int {
	left = strings.TrimLeft(left, "0")
	right = strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
