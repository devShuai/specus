package security

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// UnknownClientAddress is the fallback when no address can be resolved. Public-transfer
// "same network" grouping excludes this value so address-less clients are never grouped together.
const UnknownClientAddress = "unknown"

// ClientAddressResolver is the single entry point for resolving the real client address. Rate
// limiting, pairing, uploads, WebSocket tickets and same-network discovery all share it.
//
// Forwarded headers are honoured only when the connection peer belongs to a configured trusted
// proxy CIDR. With no trusted proxies (the default) X-Forwarded-For and X-Real-IP are ignored
// entirely, so a direct client cannot rewrite its own source address by sending headers.
//
// For trusted peers X-Forwarded-For is walked right to left: trailing trusted hops are skipped and
// the first untrusted address is the real client. Malformed entries are discarded.
type ClientAddressResolver struct {
	trustedProxies []*net.IPNet
}

func NewClientAddressResolver(trustedProxies []string, logger *slog.Logger) *ClientAddressResolver {
	if logger == nil {
		logger = slog.Default()
	}
	resolver := &ClientAddressResolver{}
	for _, value := range trustedProxies {
		network := parseTrustedProxy(value)
		if network == nil {
			if strings.TrimSpace(value) != "" {
				logger.Warn("ignoring invalid trusted proxy CIDR", "value", value)
			}
			continue
		}
		resolver.trustedProxies = append(resolver.trustedProxies, network)
	}
	if len(resolver.trustedProxies) > 0 {
		logger.Info("trusted proxy forwarding enabled", "ranges", len(resolver.trustedProxies))
	}
	return resolver
}

// Resolve returns the real client address for a request.
func (r *ClientAddressResolver) Resolve(request *http.Request) string {
	if request == nil {
		return UnknownClientAddress
	}
	peer := peerHost(request.RemoteAddr)
	if r == nil || !r.isTrustedProxy(peer) {
		// Untrusted source: forwarded headers take no part in the decision.
		if peer == "" {
			return UnknownClientAddress
		}
		return peer
	}
	if forwarded := r.resolveForwarded(
		request.Header.Get("X-Forwarded-For"), request.Header.Get("X-Real-IP")); forwarded != "" {
		return forwarded
	}
	if peer == "" {
		return UnknownClientAddress
	}
	return peer
}

func (r *ClientAddressResolver) resolveForwarded(forwardedFor, realIP string) string {
	// X-Forwarded-For carries the full chain: walk right to left for the first untrusted hop.
	if strings.TrimSpace(forwardedFor) != "" {
		hops := strings.Split(forwardedFor, ",")
		for index := len(hops) - 1; index >= 0; index-- {
			candidate := normalizeAddress(hops[index])
			if candidate == "" || net.ParseIP(candidate) == nil {
				continue
			}
			if !r.isTrustedProxy(candidate) {
				return candidate
			}
		}
	}
	// Whole chain trusted, or no XFF at all: fall back to the proxy's single-value override.
	candidate := normalizeAddress(realIP)
	if candidate != "" && net.ParseIP(candidate) != nil {
		return candidate
	}
	return ""
}

func (r *ClientAddressResolver) isTrustedProxy(address string) bool {
	if r == nil || len(r.trustedProxies) == 0 || address == "" {
		return false
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	for _, network := range r.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseTrustedProxy(value string) *net.IPNet {
	trimmed := normalizeAddress(value)
	if trimmed == "" {
		return nil
	}
	if strings.Contains(trimmed, "/") {
		_, network, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil
		}
		return network
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
}

// normalizeAddress trims whitespace, strips IPv6 brackets and drops any zone id.
func normalizeAddress(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "[") {
		if end := strings.Index(trimmed, "]"); end > 0 {
			trimmed = trimmed[1:end]
		}
	}
	if zone := strings.Index(trimmed, "%"); zone > 0 {
		trimmed = trimmed[:zone]
	}
	return trimmed
}

func peerHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return normalizeAddress(host)
	}
	return normalizeAddress(remoteAddr)
}
