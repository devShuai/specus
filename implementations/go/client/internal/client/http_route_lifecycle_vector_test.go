package client

import (
	"io"
	"log"
	"maps"
	"testing"

	"github.com/devShuai/specus/implementations/go/client/internal/protocol"
)

// httpRouteLifecycleClientVectors is the client half of
// protocol/test-vectors/http-route-lifecycle-v1.json: every NAT_CONTROL is the full route snapshot.
type httpRouteLifecycleClientVectors struct {
	Client struct {
		Cases []struct {
			ID            string             `json:"id"`
			LoginSnapshot []HTTPSpecusConfig `json:"loginSnapshot"`
			Steps         []struct {
				NatControl   string            `json:"natControl"`
				ExpectRoutes map[string]string `json:"expectRoutes"`
			} `json:"steps"`
		} `json:"cases"`
	} `json:"client"`
}

func TestHTTPRouteLifecycleVectorClientCases(t *testing.T) {
	var vectors httpRouteLifecycleClientVectors
	readRepositoryJSON(t, "protocol/test-vectors/http-route-lifecycle-v1.json", &vectors)
	if len(vectors.Client.Cases) == 0 {
		t.Fatal("http-route-lifecycle-v1.json has no client cases")
	}
	for _, testCase := range vectors.Client.Cases {
		t.Run(testCase.ID, func(t *testing.T) {
			specusClient := New(Config{}, log.New(io.Discard, "", 0))
			specusClient.applyRuntime(RuntimeConfig{
				ClientName:           "route-lifecycle",
				HTTPSpecusConfigList: testCase.LoginSnapshot,
			})
			for index, step := range testCase.Steps {
				deliverNatControl(t, specusClient, step.NatControl)
				want := step.ExpectRoutes
				if want == nil {
					want = map[string]string{}
				}
				if got := httpRouteTargets(specusClient); !maps.Equal(got, want) {
					t.Fatalf("step %d: routes = %v, want %v after NAT_CONTROL %s", index, got, want, step.NatControl)
				}
			}
		})
	}
}

// A NAT_CONTROL is the client's full snapshot. An older server omitted httpSpecusConfigList after
// the last route was deleted, so a missing list must clear the routes instead of keeping them.
func TestNatControlWithoutHTTPRouteListDropsStaleRoutes(t *testing.T) {
	specusClient := New(Config{}, log.New(io.Discard, "", 0))
	specusClient.applyRuntime(RuntimeConfig{
		ClientName:           "route-lifecycle",
		HTTPSpecusConfigList: []HTTPSpecusConfig{{Route: "web", TargetBaseURL: "http://127.0.0.1:8080"}},
	})
	if _, found := specusClient.routeConfig("web"); !found {
		t.Fatal("login snapshot route web was not applied")
	}

	deliverNatControl(t, specusClient, `{"clientName":"route-lifecycle","specusConfigList":[]}`)

	if route, found := specusClient.routeConfig("web"); found {
		t.Fatalf("route web survived a NAT_CONTROL without httpSpecusConfigList: %#v", route)
	}
}

// deliverNatControl runs a raw NAT_CONTROL payload through the control-connection message handler.
// MESSAGE_RESPONSE shares the MESSAGE_REQUEST body layout (clientName, toClientName, type, message),
// so the request encoder builds the frame body the server would send.
func deliverNatControl(t *testing.T, specusClient *Client, payload string) {
	t.Helper()
	body := protocol.EncodeMessageRequest("", "route-lifecycle", protocol.MessageTypeNatControl, payload)
	if err := specusClient.handleMessageResponse(nil, body); err != nil {
		t.Fatalf("handle NAT_CONTROL %s: %v", payload, err)
	}
}

func httpRouteTargets(specusClient *Client) map[string]string {
	specusClient.routesMu.RLock()
	defer specusClient.routesMu.RUnlock()
	targets := make(map[string]string, len(specusClient.routes))
	for route, config := range specusClient.routes {
		targets[route] = config.TargetBaseURL
	}
	return targets
}
