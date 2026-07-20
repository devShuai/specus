package management

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/transfer"
)

func (a *API) handlePublicAttachmentPresignUpload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	var request transfer.PresignUploadRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	if err := a.attachments.CheckPresignIP(attachmentClientIP(r)); err != nil {
		a.failAttachment(w, err)
		return
	}
	response, err := a.attachments.CreatePublicUpload(r.Context(), principal.TenantID,
		principal.Username, request)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handlePublicAttachmentComplete(w http.ResponseWriter, r *http.Request) {
	principal, authenticated := principalFromContext(r)
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, ok := attachmentID(w, r)
	if !ok {
		return
	}
	var request transfer.CompleteAttachmentRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	response, err := a.attachments.CompletePublic(r.Context(), id, request.RoomToken,
		principal.TenantID, principal.Username)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handlePublicAttachmentPresignDownload(w http.ResponseWriter, r *http.Request) {
	principal, authenticated := principalFromContext(r)
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, ok := attachmentID(w, r)
	if !ok {
		return
	}
	var request transfer.PresignDownloadRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	response, err := a.attachments.CreatePublicDownload(r.Context(), id, request.RoomToken,
		principal.TenantID, principal.Username)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handleAdminAttachmentPresignUpload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	var request transfer.PresignUploadRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return
	}
	if request.TargetClientID == nil {
		writeError(w, http.StatusBadRequest, "targetClientId is required")
		return
	}
	if _, err := a.requireClientAccess(r.Context(), principal, *request.TargetClientID); err != nil {
		a.fail(w, err)
		return
	}
	response, err := a.attachments.CreateAdminUpload(r.Context(), principal.TenantID,
		principal.Username, *request.TargetClientID, request)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handleAdminAttachmentComplete(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, valid := attachmentID(w, r)
	if !valid {
		return
	}
	if !a.canAccessAdminAttachment(w, r, principal, id) {
		return
	}
	response, err := a.attachments.CompleteAdmin(r.Context(), id, principal.TenantID,
		principal.Username)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handleAdminAttachmentPresignDownload(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	id, valid := attachmentID(w, r)
	if !valid {
		return
	}
	if !a.canAccessAdminAttachment(w, r, principal, id) {
		return
	}
	response, err := a.attachments.CreateAdminDownload(r.Context(), id, principal.TenantID,
		principal.Username)
	if err != nil {
		a.failAttachment(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *API) canAccessAdminAttachment(w http.ResponseWriter, r *http.Request,
	principal managementPrincipal, id int64) bool {
	item, err := a.attachments.GetAdminAttachment(r.Context(), id, principal.TenantID)
	if err != nil || item == nil {
		a.failAttachment(w, attachmentLookupError(id, err))
		return false
	}
	if item.TargetClientID == nil {
		writeError(w, http.StatusBadRequest, "target client is not accessible")
		return false
	}
	if _, err := a.requireClientAccess(r.Context(), principal, *item.TargetClientID); err != nil {
		a.fail(w, err)
		return false
	}
	return true
}

func (a *API) failAttachment(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, transfer.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, transfer.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, transfer.ErrInternal):
		writeError(w, http.StatusInternalServerError, "服务器内部错误")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func attachmentID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("attachmentId"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "attachmentId 无效")
		return 0, false
	}
	return id, true
}

func attachmentLookupError(id int64, err error) error {
	if err != nil {
		return err
	}
	return errors.New("attachment not found: " + strconv.FormatInt(id, 10))
}

func attachmentClientIP(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Real-IP")); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); value != "" {
		parts := strings.Split(value, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
