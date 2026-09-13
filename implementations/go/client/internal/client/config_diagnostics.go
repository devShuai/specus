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
	// The known fields are read from what a configuration marshals to, and an omitempty field is
	// absent from an empty one. peerEgressRules is populated here for that reason: without it every
	// configuration that used the field was told "Unknown configuration field; ignored" -- a warning
	// saying the operator's egress rules were thrown away, while the client was in fact applying
	// them.
	shape, _ := json.Marshal(Config{PeerEgressRules: []egressRule{{}}})
	_ = json.Unmarshal(shape, &known)
	warnUnknownConfig(raw, known, "", warn)
	for key, actual := range map[string]int{"peerMeshMtu": config.PeerMeshMTU, "updateCheckIntervalHours": config.UpdateCheckIntervalHours} {
		for input, value := range raw {
			if strings.EqualFold(input, key) && value != float64(actual) {
				warn(fmt.Sprintf("%s normalized to %d", key, actual))
			}
		}
	}
	warnEgressRules(config.PeerEgressRules, warn)
}

// warnEgressRules names every egress rule that will not be in force, before anything connects.
//
// A warning rather than a failure, matching what happens at runtime: a refused rule is skipped and
// the rest take effect, because a rule set is rarely wrong all at once and refusing all of it would
// leave one typo sending every destination out locally. The index and the code are printed and the
// match is not, since configuration warnings do not print configuration values.
//
// Checked against the default mesh network. The real one arrives from the server at login, so a
// rule that overlaps only a customised mesh network is caught when the rules are applied, not here.
func warnEgressRules(rules []egressRule, warn func(string)) {
	for _, refused := range validateEgressRuleSet(rules, egressDefaultMeshCIDR) {
		warn(fmt.Sprintf("peerEgressRules[%d] is not in force: %s", refused.Index, refused.Code))
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
