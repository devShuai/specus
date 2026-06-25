package nat

import (
	"encoding/json"
	"testing"
)

func TestNatMetadataHelpersMatchJavaCoercion(t *testing.T) {
	meta := map[string]any{
		"channelId":  12345,
		"stringPort": "10022",
		"jsonPort":   json.Number("10023"),
		"floatPort":  float64(10024.9),
		"int64Port":  int64(10025),
	}

	if got := asString(meta, "channelId"); got != "12345" {
		t.Fatalf("asString should match Java Object.toString for numeric values, got %q", got)
	}

	cases := map[string]int{
		"stringPort": 10022,
		"jsonPort":   10023,
		"floatPort":  10024,
		"int64Port":  10025,
	}
	for key, want := range cases {
		got, ok := asInt(meta, key)
		if !ok || got != want {
			t.Fatalf("asInt(%s) = %d, %t; want %d, true", key, got, ok, want)
		}
	}
}
