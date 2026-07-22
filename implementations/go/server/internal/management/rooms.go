package management

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/transfer"
)

// Public-transfer room endpoints, aligned with the Java PublicTransferRoomResource (S-3).
// All nine routes are unauthenticated; the room credential travels in the request body.

func (a *API) handleRoomListAccessTokens(w http.ResponseWriter, r *http.Request) {
	var credential transfer.RoomCredential
	if !decodeRoomRequest(w, r, &credential) {
		return
	}
	views, err := a.rooms.ListAccessTokens(r.Context(), credential)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleRoomCreateAccessToken(w http.ResponseWriter, r *http.Request) {
	var request transfer.CreateAccessTokenRequest
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	created, err := a.rooms.CreateAccessToken(r.Context(), request)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, created)
}

func (a *API) handleRoomRevokeAccessToken(w http.ResponseWriter, r *http.Request) {
	accessID, err := pathInt(r, "accessId")
	if err != nil {
		writeError(w, http.StatusBadRequest, "accessId 无效")
		return
	}
	var credential transfer.RoomCredential
	if !decodeRoomRequest(w, r, &credential) {
		return
	}
	view, err := a.rooms.RevokeAccessToken(r.Context(), accessID, credential)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (a *API) handleRoomCreatePairingCode(w http.ResponseWriter, r *http.Request) {
	var request transfer.CreatePairingCodeRequest
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	response, err := a.rooms.CreatePairingCode(r.Context(), request)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handleRoomRedeemPairingCode(w http.ResponseWriter, r *http.Request) {
	var request transfer.RedeemPairingCodeRequest
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	if err := a.rooms.CheckPairingCodeRedeem(r.Context(), attachmentClientIP(r)); err != nil {
		a.failRoom(w, err)
		return
	}
	response, err := a.rooms.RedeemPairingCode(r.Context(), request)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}

func (a *API) handleRoomListVersions(w http.ResponseWriter, r *http.Request) {
	var credential transfer.RoomCredential
	if !decodeRoomRequest(w, r, &credential) {
		return
	}
	views, err := a.rooms.ListVersions(r.Context(), credential)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleRoomCreateVersion(w http.ResponseWriter, r *http.Request) {
	var request transfer.CreateDiagramVersionRequest
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	view, err := a.rooms.CreateVersion(r.Context(), request)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (a *API) handleRoomGetVersion(w http.ResponseWriter, r *http.Request) {
	versionID, err := pathInt(r, "versionId")
	if err != nil {
		writeError(w, http.StatusBadRequest, "versionId 无效")
		return
	}
	var credential transfer.RoomCredential
	if !decodeRoomRequest(w, r, &credential) {
		return
	}
	detail, err := a.rooms.GetVersion(r.Context(), versionID, credential)
	if err != nil {
		a.failRoom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (a *API) handleRoomDeleteVersion(w http.ResponseWriter, r *http.Request) {
	versionID, err := pathInt(r, "versionId")
	if err != nil {
		writeError(w, http.StatusBadRequest, "versionId 无效")
		return
	}
	var credential transfer.RoomCredential
	if !decodeRoomRequest(w, r, &credential) {
		return
	}
	if err := a.rooms.DeleteVersion(r.Context(), versionID, credential); err != nil {
		a.failRoom(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeRoomRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return false
	}
	return true
}

// failRoom maps the transfer package error categories to the Java status codes
// (GlobalExceptionHandler + ResponseStatusException).
func (a *API) failRoom(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, transfer.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, transfer.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, transfer.ErrForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, transfer.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, transfer.ErrInternal):
		writeError(w, http.StatusInternalServerError, "服务器内部错误")
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
