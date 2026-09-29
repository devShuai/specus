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
	// peerEgressDnsTakeover and peerEgressFakeIpCidr carry no omitempty for the same reason.
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
	warnEgressRules(config, warn)
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
//
// Rules kept with the master switch off are the one state where nothing is in force by design, and
// that is said once rather than left to be discovered. A rule the user switched off is not warned
// about: it is out of force because they asked, which is not a problem with the configuration.
//
// Domain rules are judged as phase two would judge them with the master switch on: accepted when
// peerEgressDnsTakeover is on and the pool is usable against the default mesh network, refused as
// in phase one otherwise. A pool that is not usable is said once, in the words the Java and .NET
// clients use, since otherwise the operator sees only the domain rules refused and not why. What the
// pool overlaps on this device is only known when phase two starts.
func warnEgressRules(config Config, warn func(string)) {
	rules := config.PeerEgressRules
	if len(rules) > 0 && !config.PeerEgressEnabled {
		warn(fmt.Sprintf("peerEgressRules has %d rule(s) but peerEgressEnabled is false: none is in force", len(rules)))
	}
	if config.PeerEgressDNSTakeover {
		if code := validateEgressFakeIPPool(effectiveEgressFakeIPCIDR(config.PeerEgressFakeIPCIDR), egressDefaultMeshCIDR); code != "" {
			warn("peerEgressFakeIpCidr is not usable: " + code + "; domain rules are not in force")
		}
	}
	for _, refused := range validateEgressRuleSetIn(rules, egressDefaultMeshCIDR, offlineEgressFakeIPPool(config)) {
		if refused.Code == egressCodeRuleDisabled {
			continue
		}
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
