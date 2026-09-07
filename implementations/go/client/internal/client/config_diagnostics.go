package client

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func configWarnings(data []byte, config Config, warn func(string)) {
	var raw, known map[string]any
	if unmarshalJSONC(data, &raw) != nil {
		return
	}
	shape, _ := json.Marshal(Config{})
	_ = json.Unmarshal(shape, &known)
	warnUnknownConfig(raw, known, "", warn)
	for key, actual := range map[string]int{"peerMeshMtu": config.PeerMeshMTU, "updateCheckIntervalHours": config.UpdateCheckIntervalHours} {
		for input, value := range raw {
			if strings.EqualFold(input, key) && value != float64(actual) {
				warn(fmt.Sprintf("%s normalized to %d", key, actual))
			}
		}
	}
}

func warnUnknownConfig(raw, known map[string]any, prefix string, warn func(string)) {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := raw[key]
		matched := ""
		for candidate := range known {
			if strings.EqualFold(candidate, key) {
				matched = candidate
				break
			}
		}
		if matched == "" {
			if prefix == "" && key == "openUpdatePage" {
				warn("openUpdatePage is a shared configuration field not used by Go")
			} else {
				warn(fmt.Sprintf("Unknown configuration field %q; ignored", prefix+key))
			}
			continue
		}
		child, object := value.(map[string]any)
		shape, nested := known[matched].(map[string]any)
		if object && nested {
			warnUnknownConfig(child, shape, prefix+matched+".", warn)
		}
	}
}
