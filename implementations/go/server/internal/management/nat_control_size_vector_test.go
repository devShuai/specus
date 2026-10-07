package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// natControlSizeVector is the part of protocol/test-vectors/nat-control-size-v1.json replayed here:
// the management steps around the 1 MiB NAT_CONTROL limit. The nat package replays the sizing.
type natControlSizeVector struct {
	MessageBodyLimitBytes int    `json:"messageBodyLimitBytes"`
	MaxJSONBytes          int    `json:"maxJsonBytesWithEmptyClientName"`
	ErrorContains         string `json:"errorContains"`
	Management            struct {
		FillRemainingJSONBytes int                  `json:"fillRemainingJsonBytes"`
		Steps                  []natControlSizeStep `json:"steps"`
	} `json:"management"`
}

type natControlSizeStep struct {
	Op                   string `json:"op"`
	Route                string `json:"route"`
	Mapping              string `json:"mapping"`
	TargetBaseURL        string `json:"targetBaseUrl"`
	Enabled              *bool  `json:"enabled"`
	DetailCaptureEnabled *bool  `json:"detailCaptureEnabled"`
	GrowTargetBaseURLBy  int    `json:"growTargetBaseUrlBy"`
	Expect               int    `json:"expect"`
}

func readNatControlSizeVector(t *testing.T) natControlSizeVector {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for depth := 0; depth < 8; depth++ {
		data, err := os.ReadFile(filepath.Join(dir, "protocol", "test-vectors", "nat-control-size-v1.json"))
		if err == nil {
			var vector natControlSizeVector
			if err := json.Unmarshal(data, &vector); err != nil {
				t.Fatalf("decode vector: %v", err)
			}
			return vector
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate protocol/test-vectors/nat-control-size-v1.json")
	return natControlSizeVector{}
}

const natControlTargetPrefix = "http://127.0.0.1:8080/"

// natControlSizeHarness drives one client's mappings and routes through the real management
// handlers and measures the client's NAT_CONTROL with the server's own encoding.
type natControlSizeHarness struct {
	*workbenchHarness
	vector   natControlSizeVector
	client   store.ClientAccount
	token    string
	routes   map[string]store.HTTPRouteMapping
	mappings map[string]store.SpecusMapping
	nextPort int
}

// enabled is the client's stored enabled configuration, as a NAT_CONTROL carries it.
func (h *natControlSizeHarness) enabled() ([]store.SpecusMapping, []store.HTTPRouteMapping) {
	h.t.Helper()
	mappings, err := h.db.ListEnabledSpecusMappings(h.ctx, h.client.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	routes, err := h.db.ListEnabledHTTPRoutes(h.ctx, h.client.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	return mappings, routes
}

// jsonBytes is the NAT_CONTROL JSON of these entries with an empty client name: the J of the vector.
func (h *natControlSizeHarness) jsonBytes(mappings []store.SpecusMapping, routes []store.HTTPRouteMapping) int {
	h.t.Helper()
	payload, err := h.api.natControl.MessageJSON("", mappings, routes)
	if err != nil {
		h.t.Fatal(err)
	}
	return len(payload)
}

// stored is every mapping and route of the client, enabled or not, to compare across a refusal.
func (h *natControlSizeHarness) stored() ([]store.SpecusMapping, []store.HTTPRouteMapping) {
	h.t.Helper()
	mappings, err := h.db.ListSpecusMappings(h.ctx, &h.client.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	routes, err := h.db.ListHTTPRoutes(h.ctx, &h.client.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	return mappings, routes
}

// fill writes enabled routes straight to the database until the NAT_CONTROL JSON is exactly
// fillRemainingJsonBytes short of the largest one that fits.
func (h *natControlSizeHarness) fill() {
	h.t.Helper()
	target := h.vector.MaxJSONBytes - h.vector.Management.FillRemainingJSONBytes
	const padding = 32 * 1024
	filler := func(index, pad int) store.HTTPRouteMapping {
		now := time.Now()
		return store.HTTPRouteMapping{ID: int64(700_000 + index), TenantID: h.client.TenantID, ClientID: h.client.ID,
			ClientName: h.client.ClientName, Route: fmt.Sprintf("fill-%03d", index),
			TargetBaseURL: natControlTargetPrefix + strings.Repeat("f", pad), Enabled: true, CreatedAt: now,
			UpdatedAt: now}
	}
	var routes []store.HTTPRouteMapping
	for h.jsonBytes(nil, append(routes, filler(len(routes), padding)))+100 <= target {
		routes = append(routes, filler(len(routes), padding))
	}
	last := filler(len(routes), 0)
	last.TargetBaseURL += strings.Repeat("f", target-h.jsonBytes(nil, append(routes, last)))
	routes = append(routes, last)
	if got := h.jsonBytes(nil, routes); got != target {
		h.t.Fatalf("filled NAT_CONTROL JSON is %d bytes, want %d", got, target)
	}
	for _, route := range routes {
		if err := h.db.InsertHTTPRoute(h.ctx, route); err != nil {
			h.t.Fatalf("insert %s: %v", route.Route, err)
		}
	}
}

// exactTarget is the target that brings the NAT_CONTROL JSON to exactly the largest that fits once
// a route named route joins the client's enabled configuration.
func (h *natControlSizeHarness) exactTarget(route string) string {
	h.t.Helper()
	mappings, routes := h.enabled()
	probe := store.HTTPRouteMapping{Route: route, TargetBaseURL: natControlTargetPrefix, Enabled: true}
	missing := h.vector.MaxJSONBytes - h.jsonBytes(mappings, append(routes, probe))
	if missing < 0 {
		h.t.Fatalf("no room left for route %s: %d bytes over", route, -missing)
	}
	return natControlTargetPrefix + strings.Repeat("e", missing)
}

func (h *natControlSizeHarness) run(index int, step natControlSizeStep) {
	h.t.Helper()
	label := fmt.Sprintf("step %d %s %s%s", index, step.Op, step.Route, step.Mapping)
	beforeMappings, beforeRoutes := h.stored()
	var (
		method, path string
		body         any
	)
	switch step.Op {
	case "createRoute":
		target := step.TargetBaseURL
		if target == "exact" {
			target = h.exactTarget(step.Route)
		}
		method, path = http.MethodPost, "/api/admin/clients/"+strconv.FormatInt(h.client.ID, 10)+"/http-routes"
		body = map[string]any{"route": step.Route, "targetBaseUrl": target, "enabled": *step.Enabled}
	case "createMapping":
		h.nextPort++
		method, path = http.MethodPost, "/api/admin/clients/"+strconv.FormatInt(h.client.ID, 10)+"/specus-mappings"
		body = map[string]any{"listenPort": h.nextPort, "targetAddress": "127.0.0.1", "targetPort": 8080,
			"enabled": *step.Enabled}
	case "updateRoute":
		route := h.routes[step.Route]
		enabled, detail := route.Enabled, route.DetailCaptureEnabled
		if step.Enabled != nil {
			enabled = *step.Enabled
		}
		if step.DetailCaptureEnabled != nil {
			detail = *step.DetailCaptureEnabled
		}
		method, path = http.MethodPut, "/api/admin/http-routes/"+strconv.FormatInt(route.ID, 10)
		body = map[string]any{"route": route.Route,
			"targetBaseUrl": route.TargetBaseURL + strings.Repeat("g", step.GrowTargetBaseURLBy),
			"enabled":       enabled, "detailCaptureEnabled": detail}
	case "updateMapping":
		mapping := h.mappings[step.Mapping]
		method, path = http.MethodPut, "/api/admin/specus-mappings/"+strconv.FormatInt(mapping.ID, 10)
		body = map[string]any{"listenPort": mapping.ListenPort, "targetAddress": mapping.TargetAddress,
			"targetPort": mapping.TargetPort, "enabled": *step.Enabled}
	case "deleteRoute":
		method, path = http.MethodDelete, "/api/admin/http-routes/"+strconv.FormatInt(h.routes[step.Route].ID, 10)
	default:
		h.t.Fatalf("%s: unknown op", label)
	}

	response, payload := h.do(method, path, h.token, body)
	if response.StatusCode != step.Expect {
		h.t.Fatalf("%s: status %d, want %d; body=%s", label, response.StatusCode, step.Expect, payload)
	}
	if step.Expect == http.StatusBadRequest {
		var answer struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(payload, &answer); err != nil || !strings.Contains(answer.Error, h.vector.ErrorContains) {
			h.t.Fatalf("%s: error %q does not name %s", label, payload, h.vector.ErrorContains)
		}
		afterMappings, afterRoutes := h.stored()
		if !reflect.DeepEqual(beforeMappings, afterMappings) || !reflect.DeepEqual(beforeRoutes, afterRoutes) {
			h.t.Fatalf("%s: the refused change was stored", label)
		}
	} else if step.Op != "deleteRoute" {
		h.remember(step, payload)
	}

	// Whatever was accepted still reaches the client: its NAT_CONTROL fits with the room for any name.
	mappings, routes := h.enabled()
	reserved, err := h.api.natControl.ReservedBodyBytes(mappings, routes)
	if err != nil {
		h.t.Fatal(err)
	}
	if reserved > h.vector.MessageBodyLimitBytes {
		h.t.Fatalf("%s: the accepted configuration takes %d bytes", label, reserved)
	}
	if step.TargetBaseURL == "exact" && h.jsonBytes(mappings, routes) != h.vector.MaxJSONBytes {
		h.t.Fatalf("%s: NAT_CONTROL JSON is %d bytes, not the largest that fits", label, h.jsonBytes(mappings, routes))
	}
}

// remember reads back the mapping or route an accepted step created or changed.
func (h *natControlSizeHarness) remember(step natControlSizeStep, payload []byte) {
	h.t.Helper()
	var view struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(payload, &view); err != nil {
		h.t.Fatalf("%s: %v", step.Op, err)
	}
	if step.Route != "" {
		route, err := h.db.GetHTTPRoute(h.ctx, view.ID)
		if err != nil {
			h.t.Fatal(err)
		}
		h.routes[step.Route] = *route
		return
	}
	mapping, err := h.db.GetSpecus(h.ctx, view.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	h.mappings[step.Mapping] = *mapping
}

// Replays the management steps of protocol/test-vectors/nat-control-size-v1.json: a route that
// takes the client's NAT_CONTROL to exactly 1 MiB is accepted, one byte more is not, and neither is
// creating or enabling another enabled mapping or route; changes that leave entries disabled are.
func TestNatControlSizeLimitVector(t *testing.T) {
	vector := readNatControlSizeVector(t)
	if vector.MessageBodyLimitBytes != nat.MessageBodyLimit {
		t.Fatalf("vector limit %d, server limit %d", vector.MessageBodyLimitBytes, nat.MessageBodyLimit)
	}
	base := newWorkbenchHarness(t, time.Now())
	base.addFixtureAdmin("t1")
	h := &natControlSizeHarness{workbenchHarness: base, vector: vector, client: base.addClient("t1", "owner"),
		token: base.fixtureToken("t1"), routes: map[string]store.HTTPRouteMapping{},
		mappings: map[string]store.SpecusMapping{}, nextPort: 42000}
	h.fill()
	for index, step := range vector.Management.Steps {
		h.run(index, step)
	}
}
