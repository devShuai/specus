package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// User diagram document endpoints, aligned with the Java UserDiagramDocumentResource (S-3).
// Visibility is scoped to the authenticated tenant + owner username.

const (
	maxDiagramDocumentsPerUser = 100
	maxDiagramSnapshotBytes    = 3 * 1024 * 1024
	// diagramISOLayout matches store.formatTime so stored and rendered timestamps agree.
	diagramISOLayout = "2006-01-02T15:04:05.0000000Z"
)

type diagramDocumentMutation struct {
	Name     string `json:"name"`
	Update   string `json:"update"`
	Revision *int64 `json:"revision"`
}

type diagramDocumentView struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
	Revision  int64  `json:"revision"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type diagramDocumentDetail struct {
	Document diagramDocumentView `json:"document"`
	Update   string              `json:"update"`
}

func (a *API) handleListDiagrams(w http.ResponseWriter, r *http.Request) {
	tenantID, username, ok := diagramOwner(w, r)
	if !ok {
		return
	}
	documents, err := a.db.ListUserDiagramDocumentSummaries(r.Context(), tenantID, username)
	if err != nil {
		a.fail(w, err)
		return
	}
	views := make([]diagramDocumentView, 0, len(documents))
	for _, document := range documents {
		views = append(views, diagramView(document))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) handleGetDiagram(w http.ResponseWriter, r *http.Request) {
	document, ok := a.requireOwnedDiagram(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, diagramDocumentDetail{
		Document: diagramView(*document),
		Update:   base64.StdEncoding.EncodeToString(document.SnapshotData),
	})
}

func (a *API) handleCreateDiagram(w http.ResponseWriter, r *http.Request) {
	tenantID, username, ok := diagramOwner(w, r)
	if !ok {
		return
	}
	var request diagramDocumentMutation
	if !decodeDiagramRequest(w, r, &request) {
		return
	}
	count, err := a.db.CountUserDiagramDocuments(r.Context(), tenantID, username)
	if err != nil {
		a.fail(w, err)
		return
	}
	if count >= maxDiagramDocumentsPerUser {
		a.fail(w, conflict("云端流程图数量已达到 100 个上限"))
		return
	}
	snapshot, err := decodeDiagramSnapshot(request.Update)
	if err != nil {
		a.fail(w, err)
		return
	}
	name, err := diagramRequireText(request.Name, "name", 120)
	if err != nil {
		a.fail(w, err)
		return
	}
	id, err := a.newDiagramDocumentID(r.Context())
	if err != nil {
		a.fail(w, err)
		return
	}
	now := time.Now().UTC()
	document := store.UserDiagramDocument{
		ID: id, TenantID: tenantID, OwnerUsername: username, Name: name,
		SnapshotData: snapshot, SizeBytes: int64(len(snapshot)),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.db.InsertUserDiagramDocument(r.Context(), document); err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, diagramView(document))
}

func (a *API) handleUpdateDiagram(w http.ResponseWriter, r *http.Request) {
	document, ok := a.requireOwnedDiagram(w, r)
	if !ok {
		return
	}
	var request diagramDocumentMutation
	if !decodeDiagramRequest(w, r, &request) {
		return
	}
	if request.Revision == nil || *request.Revision != document.Revision {
		a.fail(w, conflict("云端文件已被其他会话更新，请重新打开后再保存"))
		return
	}
	snapshot, err := decodeDiagramSnapshot(request.Update)
	if err != nil {
		a.fail(w, err)
		return
	}
	name, err := diagramRequireText(request.Name, "name", 120)
	if err != nil {
		a.fail(w, err)
		return
	}
	document.Name = name
	document.SnapshotData = snapshot
	document.SizeBytes = int64(len(snapshot))
	document.UpdatedAt = time.Now().UTC()
	updated, err := a.db.UpdateUserDiagramDocument(r.Context(), *document, document.Revision)
	if err != nil {
		a.fail(w, err)
		return
	}
	if !updated {
		a.fail(w, conflict("云端文件已被其他会话更新，请重新打开后再保存"))
		return
	}
	document.Revision++
	writeJSON(w, http.StatusOK, diagramView(*document))
}

func (a *API) handleDeleteDiagram(w http.ResponseWriter, r *http.Request) {
	document, ok := a.requireOwnedDiagram(w, r)
	if !ok {
		return
	}
	if err := a.db.DeleteUserDiagramDocument(r.Context(), document.ID,
		document.TenantID, document.OwnerUsername); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) requireOwnedDiagram(w http.ResponseWriter, r *http.Request) (*store.UserDiagramDocument, bool) {
	tenantID, username, ok := diagramOwner(w, r)
	if !ok {
		return nil, false
	}
	id, err := pathInt(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "id 无效")
		return nil, false
	}
	document, err := a.db.GetUserDiagramDocument(r.Context(), id, tenantID, username)
	if err != nil {
		a.fail(w, err)
		return nil, false
	}
	if document == nil {
		writeError(w, http.StatusNotFound, "云端流程图不存在")
		return nil, false
	}
	return document, true
}

// diagramOwner mirrors the Java UserDiagramDocumentService.owner(): tenant + username are
// mandatory and length-checked.
func diagramOwner(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "需要登录后才能访问云端流程图")
		return "", "", false
	}
	tenantID, err := diagramRequireText(principal.TenantID, "tenantId", 80)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	username, err := diagramRequireText(principal.Username, "username", 160)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", "", false
	}
	return tenantID, username, true
}

func (a *API) newDiagramDocumentID(ctx context.Context) (int64, error) {
	for attempt := 0; attempt < 8; attempt++ {
		id := auth.NewClientID()
		exists, err := a.db.UserDiagramDocumentExists(ctx, id)
		if err != nil {
			return 0, err
		}
		if !exists {
			return id, nil
		}
	}
	return 0, conflict("无法生成云端流程图 ID")
}

func decodeDiagramSnapshot(encoded string) ([]byte, error) {
	if strings.TrimSpace(encoded) == "" || len(encoded) > 4*1024*1024+16 {
		return nil, validation("流程图数据无效或超过限制")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, validation("流程图数据不是有效的 Base64")
	}
	if len(decoded) == 0 || len(decoded) > maxDiagramSnapshotBytes {
		return nil, validation("流程图数据无效或超过 3 MB")
	}
	return decoded, nil
}

func diagramRequireText(value, field string, maxLength int) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", validation(field + " 不能为空")
	}
	if len(utf16.Encode([]rune(normalized))) > maxLength {
		return "", validation("字段长度不能超过 " + strconv.Itoa(maxLength))
	}
	if strings.ContainsAny(normalized, "\r\n") {
		return "", validation("字段不能包含换行")
	}
	return normalized, nil
}

func diagramView(document store.UserDiagramDocument) diagramDocumentView {
	return diagramDocumentView{
		ID: document.ID, Name: document.Name, SizeBytes: document.SizeBytes,
		Revision:  document.Revision,
		CreatedAt: document.CreatedAt.UTC().Format(diagramISOLayout),
		UpdatedAt: document.UpdatedAt.UTC().Format(diagramISOLayout),
	}
}

func decodeDiagramRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024)
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "请求体无效")
		return false
	}
	return true
}
