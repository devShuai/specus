package client

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// What a consumer reads from egress-catalog: which egresses resolve names.
//
// The server lists every egress this device may use, with its capabilities as announced at login.
// Only domainTargetCapable changes what a consumer does -- a domain rule sent to an egress that
// cannot resolve names is out of force -- so only that is kept. Availability still comes from the
// mesh's own view of which peers are online, not from the catalogue's online field.
//
// The decoding rules are protocol/spec/peer-egress-dns.md's 能力协商 and the catalog cases of
// protocol/test-vectors/peer-egress-dns-v1.json. They are strict about shape and lenient about
// content: a message of the wrong shape is refused whole and changes nothing, while an entry that
// cannot be read is skipped and an unknown key ignored, so that a server adding a field never stops
// an older client from reading the rest.

const peerControlTypeEgressCatalog = "egress-catalog"

// egressCatalogReader keeps the last accepted catalogue's capabilities. Not safe for concurrent
// use; the mesh's lock covers it.
type egressCatalogReader struct {
	// floor is the last revision accepted in this control session, 0 before the first. The rule is
	// egress-config's: rising within a session, a snapshot at or below the floor ignored, so a
	// reordered or replayed push cannot walk the capabilities back.
	floor   int64
	capable map[int64]bool
}

func newEgressCatalogReader() *egressCatalogReader {
	return &egressCatalogReader{capable: map[int64]bool{}}
}

// newSession resets the revision floor for a new control session. The capabilities are kept: what
// the last catalogue said is still the best answer until the next one replaces it, and forgetting
// it would take every domain rule out of force for the length of a reconnect.
func (r *egressCatalogReader) newSession() { r.floor = 0 }

// read applies one catalogue and reports whether it was accepted. An accepted catalogue replaces
// what was known entirely: an egress it does not list is taken not to resolve names.
func (r *egressCatalogReader) read(payload []byte) bool {
	var message map[string]json.RawMessage
	if err := json.Unmarshal(payload, &message); err != nil || message == nil {
		return false
	}
	var messageType string
	if raw, present := message["type"]; !present || json.Unmarshal(raw, &messageType) != nil ||
		messageType != peerControlTypeEgressCatalog {
		return false
	}
	revision, ok := positiveJSONInteger(message["revision"])
	if !ok {
		return false
	}
	var entries []json.RawMessage
	if raw, present := message["egresses"]; present {
		// Present but null is not "absent": only a missing list reads as empty.
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) || json.Unmarshal(raw, &entries) != nil {
			return false
		}
	}
	if r.floor != 0 && revision <= r.floor {
		return false
	}
	r.floor = revision
	capable := make(map[int64]bool, len(entries))
	for _, raw := range entries {
		var entry map[string]json.RawMessage
		if json.Unmarshal(raw, &entry) != nil || entry == nil {
			continue
		}
		clientID, usable := positiveJSONInteger(entry["clientId"])
		if !usable {
			continue
		}
		// Only a JSON true counts. "true" and 1 are what a server that got the type wrong would
		// send, and reading them as yes would send names to an egress that may not take them.
		capable[clientID] = bytes.Equal(bytes.TrimSpace(entry["domainTargetCapable"]), []byte("true"))
	}
	r.capable = capable
	return true
}

// domainCapable is a copy of which egresses resolve names.
func (r *egressCatalogReader) domainCapable() map[int64]bool {
	out := make(map[int64]bool, len(r.capable))
	for id, able := range r.capable {
		out[id] = able
	}
	return out
}

// capableIDs lists the egresses that resolve names, in order.
func (r *egressCatalogReader) capableIDs() []int64 {
	ids := make([]int64, 0, len(r.capable))
	for id, able := range r.capable {
		if able {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// positiveJSONInteger reads a JSON number written as a positive integer. A string, a boolean, a
// fraction or an exponent is not one, even when its value would be: the field is typed, and a value
// of the wrong type is the sender's mistake to fix rather than ours to guess at.
func positiveJSONInteger(raw json.RawMessage) (int64, bool) {
	text := bytes.TrimSpace(raw)
	if len(text) == 0 || text[0] < '1' || text[0] > '9' {
		return 0, false
	}
	for _, digit := range text {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(string(text), 10, 64)
	return value, err == nil
}
