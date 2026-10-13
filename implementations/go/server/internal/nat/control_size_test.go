package nat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// natControlSizeVector is the part of protocol/test-vectors/nat-control-size-v1.json this package
// replays; the management package replays its "management" steps.
type natControlSizeVector struct {
	MessageBodyLimitBytes int `json:"messageBodyLimitBytes"`
	ClientNameReserve     struct {
		MaxCharacters int `json:"maxCharacters"`
	} `json:"clientNameReserve"`
	Sizing []struct {
		JSONBytes int  `json:"jsonBytesWithEmptyClientName"`
		BodyBytes int  `json:"bodyBytes"`
		Fits      bool `json:"fits"`
	} `json:"sizing"`
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

// emptyNameJSONBytes is the size of the NAT_CONTROL JSON for these entries with an empty client name.
func emptyNameJSONBytes(t *testing.T, service *ControlService, routes []store.HTTPRouteMapping) int {
	t.Helper()
	payload, err := service.MessageJSON("", nil, routes)
	if err != nil {
		t.Fatal(err)
	}
	return len(payload)
}

// routesOfJSONBytes is one route whose padded target makes the NAT_CONTROL JSON, with an empty
// client name, exactly want bytes long.
func routesOfJSONBytes(t *testing.T, service *ControlService, want int) []store.HTTPRouteMapping {
	t.Helper()
	routes := []store.HTTPRouteMapping{{ID: 1, Route: "sized", TargetBaseURL: "http://127.0.0.1:8080/",
		Enabled: true}}
	shortest := emptyNameJSONBytes(t, service, routes)
	if want < shortest {
		t.Fatalf("a NAT_CONTROL of %d JSON bytes is shorter than the %d of one route", want, shortest)
	}
	routes[0].TargetBaseURL += strings.Repeat("a", want-shortest)
	if got := emptyNameJSONBytes(t, service, routes); got != want {
		t.Fatalf("padded NAT_CONTROL JSON is %d bytes, want %d", got, want)
	}
	return routes
}

func TestNatControlSizingMatchesTheVector(t *testing.T) {
	vector := readNatControlSizeVector(t)
	if vector.MessageBodyLimitBytes != MessageBodyLimit {
		t.Fatalf("vector limit %d, server limit %d", vector.MessageBodyLimitBytes, MessageBodyLimit)
	}
	if vector.ClientNameReserve.MaxCharacters != clientNameReserveCharacters {
		t.Fatalf("vector reserves %d characters, server %d", vector.ClientNameReserve.MaxCharacters,
			clientNameReserveCharacters)
	}
	service := NewControlService(nil, nil, 7010, "")
	for _, sizing := range vector.Sizing {
		routes := routesOfJSONBytes(t, service, sizing.JSONBytes)
		got, err := service.ReservedBodyBytes(nil, routes)
		if err != nil {
			t.Fatal(err)
		}
		if got != sizing.BodyBytes || (got <= MessageBodyLimit) != sizing.Fits {
			t.Fatalf("J=%d: reserved body %d (fits %v), want %d (fits %v)", sizing.JSONBytes, got,
				got <= MessageBodyLimit, sizing.BodyBytes, sizing.Fits)
		}
	}
}

// Whatever a rename makes the client's name, its NAT_CONTROL as sent is never larger than the body
// the size check counted for it.
func TestNatControlReserveCoversEveryNameARenameAllows(t *testing.T) {
	service := NewControlService(nil, nil, 7010, "203.0.113.10")
	mappings := []store.SpecusMapping{{ID: 1, ListenPort: 42001, TargetAddress: "127.0.0.1", TargetPort: 22,
		Enabled: true}}
	routes := []store.HTTPRouteMapping{{ID: 2, Route: "web", TargetBaseURL: "http://127.0.0.1:8080/?a=1&b=<2>",
		Enabled: true}}
	reserved, err := service.ReservedBodyBytes(mappings, routes)
	if err != nil {
		t.Fatal(err)
	}
	// 120 UTF-16 code units each: the longest name every server's rename accepts.
	for _, name := range []string{
		strings.Repeat("\x01", 120), strings.Repeat("\"", 120), strings.Repeat("中", 120),
		strings.Repeat("😀", 60), strings.Repeat("\u2028", 120), strings.Repeat("a", 120),
	} {
		message, err := service.buildMessage(name, mappings, routes)
		if err != nil {
			t.Fatal(err)
		}
		body, err := protocol.EncodeBody(message)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > reserved {
			t.Fatalf("name %q: NAT_CONTROL body %d bytes, %d reserved", name[:3], len(body), reserved)
		}
	}
}
