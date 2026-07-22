package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

const (
	peerPathMTUMin          = 576
	peerPathMTUMax          = 9000
	peerPathMTUProbeTimeout = 750 * time.Millisecond
	peerPathMTUCacheTTL     = 10 * time.Minute
	peerPathMTUMaxAttempts  = 3
	peerPathMTUProbeType    = byte(1)
	peerPathMTUAckType      = byte(2)
	peerPathMTUHeaderBytes  = 6 + 1 + 8 + 2
)

var peerPathMTUMagic = []byte("SPMTU2")

type peerPathMTUMessage struct {
	Probe    bool
	Nonce    uint64
	InnerMTU int
}

type peerPathMTUProbe struct {
	Nonce    uint64
	InnerMTU int
}

type peerPathMTUTransition struct {
	Probe        *peerPathMTUProbe
	CompletedMTU int
}

type cachedPeerPathMTU struct {
	InnerMTU   int
	ValidUntil time.Time
}

func encodePeerPathMTUProbe(nonce uint64, innerMTU int) []byte {
	if nonce == 0 || innerMTU < peerPathMTUMin || innerMTU > peerPathMTUMax {
		return nil
	}
	payload := make([]byte, innerMTU)
	writePeerPathMTUHeader(payload, peerPathMTUProbeType, nonce, innerMTU)
	return payload
}

func encodePeerPathMTUAck(nonce uint64, innerMTU int) []byte {
	if nonce == 0 || innerMTU < peerPathMTUMin || innerMTU > peerPathMTUMax {
		return nil
	}
	payload := make([]byte, peerPathMTUHeaderBytes)
	writePeerPathMTUHeader(payload, peerPathMTUAckType, nonce, innerMTU)
	return payload
}

func writePeerPathMTUHeader(payload []byte, kind byte, nonce uint64, innerMTU int) {
	copy(payload, peerPathMTUMagic)
	payload[len(peerPathMTUMagic)] = kind
	binary.BigEndian.PutUint64(payload[7:15], nonce)
	binary.BigEndian.PutUint16(payload[15:17], uint16(innerMTU))
}

func looksLikePeerPathMTU(payload []byte) bool {
	return len(payload) >= len(peerPathMTUMagic) && bytes.Equal(payload[:len(peerPathMTUMagic)], peerPathMTUMagic)
}

func decodePeerPathMTU(payload []byte) (peerPathMTUMessage, bool) {
	if len(payload) < peerPathMTUHeaderBytes || !looksLikePeerPathMTU(payload) {
		return peerPathMTUMessage{}, false
	}
	kind := payload[6]
	nonce := binary.BigEndian.Uint64(payload[7:15])
	innerMTU := int(binary.BigEndian.Uint16(payload[15:17]))
	if nonce == 0 || innerMTU < peerPathMTUMin || innerMTU > peerPathMTUMax {
		return peerPathMTUMessage{}, false
	}
	if kind == peerPathMTUProbeType && len(payload) == innerMTU {
		return peerPathMTUMessage{Probe: true, Nonce: nonce, InnerMTU: innerMTU}, true
	}
	if kind == peerPathMTUAckType && len(payload) == peerPathMTUHeaderBytes {
		return peerPathMTUMessage{Nonce: nonce, InnerMTU: innerMTU}, true
	}
	return peerPathMTUMessage{}, false
}

type peerPathMTUDiscovery struct {
	mu sync.Mutex

	pathKey      string
	ceiling      int
	lower        int
	upper        int
	effective    int
	pendingSize  int
	pendingNonce uint64
	attempts     int
	sawFailure   bool
	validUntil   time.Time
}

func (state *peerPathMTUDiscovery) activate(pathKey string, configuredMTU int,
	cached *cachedPeerPathMTU, now time.Time) peerPathMTUTransition {
	state.mu.Lock()
	defer state.mu.Unlock()
	configuredMTU = normalizePeerPathMTU(configuredMTU)
	if state.pathKey == pathKey && state.pendingSize > 0 {
		return peerPathMTUTransition{}
	}
	if state.pathKey == pathKey && now.Before(state.validUntil) {
		return peerPathMTUTransition{}
	}
	state.pathKey = pathKey
	state.ceiling = configuredMTU
	state.lower = peerPathMTUMin
	state.upper = configuredMTU
	state.pendingSize = 0
	state.pendingNonce = 0
	state.attempts = 0
	state.sawFailure = false
	if cached != nil && now.Before(cached.ValidUntil) {
		state.effective = min(configuredMTU, normalizePeerPathMTU(cached.InnerMTU))
		state.lower = state.effective
		state.upper = state.effective
		state.validUntil = cached.ValidUntil
		return peerPathMTUTransition{}
	}
	state.effective = configuredMTU
	state.validUntil = time.Time{}
	return state.issue(configuredMTU)
}

func (state *peerPathMTUDiscovery) acknowledge(nonce uint64, innerMTU int, now time.Time) peerPathMTUTransition {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pendingSize == 0 || state.pendingNonce != nonce || state.pendingSize != innerMTU {
		return peerPathMTUTransition{}
	}
	state.lower = max(state.lower, innerMTU)
	if state.sawFailure {
		state.effective = state.lower
	} else {
		state.effective = state.ceiling
	}
	state.pendingSize = 0
	state.pendingNonce = 0
	state.attempts = 0
	if state.lower >= state.upper {
		return state.complete(now)
	}
	return state.issue(state.lower + (state.upper-state.lower+1)/2)
}

func (state *peerPathMTUDiscovery) timeout(nonce uint64, now time.Time) peerPathMTUTransition {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pendingSize == 0 || state.pendingNonce != nonce {
		return peerPathMTUTransition{}
	}
	if state.attempts < peerPathMTUMaxAttempts {
		state.attempts++
		probe := &peerPathMTUProbe{Nonce: state.pendingNonce, InnerMTU: state.pendingSize}
		return peerPathMTUTransition{Probe: probe}
	}
	state.sawFailure = true
	state.upper = max(peerPathMTUMin, state.pendingSize-1)
	state.effective = min(state.effective, state.upper)
	state.pendingSize = 0
	state.pendingNonce = 0
	state.attempts = 0
	if state.upper <= state.lower {
		state.effective = state.lower
		return state.complete(now)
	}
	return state.issue(state.lower + (state.upper-state.lower+1)/2)
}

func (state *peerPathMTUDiscovery) effectiveMTU(configuredMTU int) int {
	state.mu.Lock()
	defer state.mu.Unlock()
	return min(normalizePeerPathMTU(configuredMTU), max(peerPathMTUMin, state.effective))
}

func (state *peerPathMTUDiscovery) currentPathKey() string {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.pathKey
}

func (state *peerPathMTUDiscovery) issue(size int) peerPathMTUTransition {
	nonce := randomPeerPathMTUNonce()
	state.pendingSize = max(peerPathMTUMin, min(state.ceiling, size))
	state.pendingNonce = nonce
	state.attempts = 1
	return peerPathMTUTransition{Probe: &peerPathMTUProbe{Nonce: nonce, InnerMTU: state.pendingSize}}
}

func (state *peerPathMTUDiscovery) complete(now time.Time) peerPathMTUTransition {
	state.effective = max(peerPathMTUMin, min(state.ceiling, state.effective))
	state.validUntil = now.Add(peerPathMTUCacheTTL)
	return peerPathMTUTransition{CompletedMTU: state.effective}
}

func normalizePeerPathMTU(value int) int {
	return max(peerPathMTUMin, min(peerPathMTUMax, value))
}

func randomPeerPathMTUNonce() uint64 {
	var raw [8]byte
	for {
		if _, err := rand.Read(raw[:]); err == nil {
			nonce := binary.BigEndian.Uint64(raw[:]) & ((1 << 63) - 1)
			if nonce != 0 {
				return nonce
			}
		}
	}
}
