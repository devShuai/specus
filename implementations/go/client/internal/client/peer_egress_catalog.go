package client

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
)

// What a consumer reads from egress-catalog: which egresses it lists, the egressVersion each one's
// online session announced, and which resolve names.
//
// The server lists every egress this device may use, with its capabilities as announced at login.
// Three things in it change what a consumer does, so only they are kept. Whether an egress is
// listed at all, and the version it announced, give it its catalogue standing
// (protocol/spec/peer-egress.md, 能力不支持): an egress the catalogue leaves out, or one whose client
// announced no peer egress, would take a flow and drop it without a word, so its destinations are
// blocked and the reason said instead. domainTargetCapable says whether a domain rule sent to it is
// in force. Availability still comes from the mesh's own view of which peers are online, not from
// the catalogue's online field.
//
// The decoding rules are protocol/spec/peer-egress-dns.md's 能力协商 and the catalog cases of
// protocol/test-vectors/peer-egress-dns-v1.json. They are strict about shape and lenient about
// content: a message of the wrong shape is refused whole and changes nothing, while an entry that
// cannot be read is skipped and an unknown key ignored, so that a server adding a field never stops
// an older client from reading the rest.

const peerControlTypeEgressCatalog = "egress-catalog"

// egressCatalogListing is what an accepted catalogue said about one egress it lists.
type egressCatalogListing struct {
	DomainTargetCapable bool
	// Version is the egressVersion the egress's online session announced, when VersionKnown. A
	// server older than the field sends none, and that reads as unknown rather than as 0: 0 says the
	// egress's client announced no peer egress, which blocks, and an older server must block nothing.
	Version      int64
	VersionKnown bool
}

// egressCatalogView is what the consumer is given of the catalogue: whether one was accepted in
// this control session, and what the last accepted one listed.
type egressCatalogView struct {
	Received bool
	Listed   map[int64]egressCatalogListing
}

// egressCatalogReader keeps the last accepted catalogue. Not safe for concurrent use; the mesh's
// lock covers it.
type egressCatalogReader struct {
	// floor is the last revision accepted in this control session, 0 before the first. The rule is
	// egress-config's: rising within a session, a snapshot at or below the floor ignored, so a
	// reordered or replayed push cannot walk the capabilities back.
	floor int64
	// received says a catalogue was accepted in this control session. Until one is, every egress's
	// standing is unknown and its flows go out: an older server never sends a catalogue, and
	// blocking on its silence would break a deployment that works today.
	received bool
	listed   map[int64]egressCatalogListing
}

func newEgressCatalogReader() *egressCatalogReader {
	return &egressCatalogReader{listed: map[int64]egressCatalogListing{}}
}

// newSession starts a new control session: the revision floor goes, and so does "a catalogue was
// accepted", until this session's first one arrives. What the last catalogue listed is kept: it is
// still the best answer to which egresses resolve names until the next one replaces it, and
// forgetting it would take every domain rule out of force for the length of a reconnect.
func (r *egressCatalogReader) newSession() {
	r.floor = 0
	r.received = false
}

// read applies one catalogue and reports whether it was accepted. An accepted catalogue replaces
// what was known entirely: an egress it does not list is not offered to this device, and is taken
// not to resolve names.
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
	listed := make(map[int64]egressCatalogListing, len(entries))
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
		listing := egressCatalogListing{
			DomainTargetCapable: bytes.Equal(bytes.TrimSpace(entry["domainTargetCapable"]), []byte("true")),
		}
		// Only a non-negative integer is a version. Anything else reads as no field at all, which is
		// what an older server sends, so a server that got the type wrong blocks nothing.
		listing.Version, listing.VersionKnown = nonNegativeJSONInteger(entry["egressVersion"])
		listed[clientID] = listing
	}
	r.listed = listed
	r.received = true
	return true
}

// view is a copy of what the consumer needs.
func (r *egressCatalogReader) view() egressCatalogView {
	listed := make(map[int64]egressCatalogListing, len(r.listed))
	for id, listing := range r.listed {
		listed[id] = listing
	}
	return egressCatalogView{Received: r.received, Listed: listed}
}

// domainCapable is a copy of which egresses resolve names.
func (r *egressCatalogReader) domainCapable() map[int64]bool {
	out := make(map[int64]bool, len(r.listed))
	for id, listing := range r.listed {
		out[id] = listing.DomainTargetCapable
	}
	return out
}

// capableIDs lists the egresses that resolve names, in order.
func (r *egressCatalogReader) capableIDs() []int64 {
	ids := make([]int64, 0, len(r.listed))
	for id, listing := range r.listed {
		if listing.DomainTargetCapable {
			ids = append(ids, id)
		}
	}
	return sortEgressIDs(ids)
}

// listedIDs lists the egresses the last accepted catalogue named, in order.
func (r *egressCatalogReader) listedIDs() []int64 {
	ids := make([]int64, 0, len(r.listed))
	for id := range r.listed {
		ids = append(ids, id)
	}
	return sortEgressIDs(ids)
}

// egressVersions is the version each listed egress announced, leaving out those that carried none.
func (r *egressCatalogReader) egressVersions() map[int64]int64 {
	versions := make(map[int64]int64, len(r.listed))
	for id, listing := range r.listed {
		if listing.VersionKnown {
			versions[id] = listing.Version
		}
	}
	return versions
}

func sortEgressIDs(ids []int64) []int64 {
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

// nonNegativeJSONInteger is positiveJSONInteger that also takes zero, which JSON may write as -0
// and a decoder that reads numbers reads as 0 all the same.
func nonNegativeJSONInteger(raw json.RawMessage) (int64, bool) {
	if text := string(bytes.TrimSpace(raw)); text == "0" || text == "-0" {
		return 0, true
	}
	return positiveJSONInteger(raw)
}
