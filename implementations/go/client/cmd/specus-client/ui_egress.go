package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// The local page's egress editor. It makes the changes the egress commands make, through egressPlan,
// and writes them the same way; what differs is that the page confirms takeover in a dialog of its
// own before it asks, and that every change carries the revision the page was showing, so an edit
// made against a file that changed since is refused rather than applied to something else.
//
// The Java and .NET management pages serve the same routes with the same answers.

type uiEgressChange struct {
	Revision       string `json:"revision"`
	Op             string `json:"op"`
	Match          string `json:"match"`
	Action         string `json:"action"`
	EgressClientID int64  `json:"egressClientId"`
	At             *int   `json:"at"`
	Index          *int   `json:"index"`
	To             *int   `json:"to"`
	Disabled       bool   `json:"disabled"`
	Enabled        bool   `json:"enabled"`
	Confirmed      bool   `json:"confirmed"`
}

func uiIndex(value *int) int {
	if value == nil {
		return -1
	}
	return *value
}

// egressLoad reads the configuration the editor works on, answering the request itself when it cannot.
func (u *localUI) egressLoad(w http.ResponseWriter) ([]byte, string, client.Config, bool) {
	data, revision, err := uiReadConfig(u.path)
	if err != nil {
		uiError(w, 422, err.Error())
		return nil, "", client.Config{}, false
	}
	if revision == "missing" {
		uiError(w, 422, "配置文件不存在；请先在「连接设置」保存配置")
		return nil, "", client.Config{}, false
	}
	config, err := client.ParseConfigWithDiagnostics(data, func(string) {})
	if err != nil {
		uiError(w, 422, "配置无法加载（"+err.Error()+"）；请先修正后再编辑出口规则")
		return nil, "", client.Config{}, false
	}
	return data, revision, config, true
}

func (u *localUI) egressRules(w http.ResponseWriter) {
	_, revision, config, ok := u.egressLoad(w)
	if !ok {
		return
	}
	listing, _ := egressListing(u.path, config)
	listing["schemaVersion"] = 1
	listing["revision"] = revision
	uiJSON(w, 200, listing)
}

func (u *localUI) egressChange(w http.ResponseWriter, r *http.Request) {
	var body uiEgressChange
	if !uiDecode(w, r, &body) {
		return
	}
	data, revision, config, ok := u.egressLoad(w)
	if !ok {
		return
	}
	if body.Revision != revision {
		uiError(w, 409, errUIConflict.Error())
		return
	}
	planned, failure := egressPlan(config, egressChange{
		Op: body.Op, Match: body.Match, Action: body.Action, EgressClientID: body.EgressClientID,
		At: uiIndex(body.At), Index: uiIndex(body.Index), To: uiIndex(body.To),
		Disabled: body.Disabled, Enabled: body.Enabled, Confirmed: body.Confirmed,
	})
	switch {
	case failure != "":
		uiError(w, 422, failure)
		return
	case planned.NeedsConfirmation:
		uiError(w, 422, "开启接管前需要确认其影响；未做任何修改")
		return
	case planned.Unchanged:
		listing, _ := egressListing(u.path, config)
		listing["schemaVersion"], listing["revision"], listing["saved"] = 1, revision, false
		uiJSON(w, 200, listing)
		return
	}
	patched, err := uiPatchRawConfig(data, map[string][]byte{planned.Key: planned.Value})
	if err != nil {
		uiError(w, 422, err.Error())
		return
	}
	edited, err := client.ParseConfigWithDiagnostics(patched, func(string) {})
	if err != nil {
		uiError(w, 422, "修改后的配置无法加载（"+err.Error()+"）；未写入")
		return
	}
	if err := uiWriteConfig(u.path, revision, patched); err != nil {
		code := 422
		if errors.Is(err, errUIConflict) {
			code = 409
		}
		uiError(w, code, err.Error())
		return
	}
	_, written, _ := uiReadConfig(u.path)
	listing, _ := egressListing(u.path, edited)
	listing["schemaVersion"], listing["revision"], listing["saved"] = 1, written, true
	// Only what the page does not already say itself: the notice is shown before it asks.
	warnings := []string{}
	for _, line := range planned.Preface {
		if strings.HasPrefix(line, "Warning: ") {
			warnings = append(warnings, line)
		}
	}
	listing["warnings"] = warnings
	uiJSON(w, 200, listing)
}

func (u *localUI) egressTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Address string `json:"address"`
	}
	if !uiDecode(w, r, &body) {
		return
	}
	address := strings.TrimSpace(body.Address)
	if problem := egressAddressProblem(address); problem != "" {
		uiError(w, 422, problem)
		return
	}
	_, _, config, ok := u.egressLoad(w)
	if !ok {
		return
	}
	data, _ := egressPreview(u.path, config, address)
	data["schemaVersion"] = 1
	uiJSON(w, 200, data)
}
