package stunserver

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	defaultSoftware = "specus-rfc5780-stun"
	maxUDPPacket    = 65507
)

type Config struct {
	Topology Topology
	Software string
	Legacy   bool
	Protect  ProtectionConfig
	Metrics  MetricsConfig
}

type ProtectionConfig struct {
	SourceRatePerSecond int
	SourceBurst         int
	GlobalRatePerSecond int
	GlobalBurst         int
	MaxTrackedSources   int
	SourceIdleSeconds   int
	MaxPacketBytes      int
	MaxPaddingBytes     int
}

type MetricsConfig struct {
	BindAddress net.IP
	Port        int
}

func DefaultProtectionConfig() ProtectionConfig {
	return ProtectionConfig{
		SourceRatePerSecond: 100,
		SourceBurst:         200,
		GlobalRatePerSecond: 10000,
		GlobalBurst:         20000,
		MaxTrackedSources:   65536,
		SourceIdleSeconds:   300,
		MaxPacketBytes:      maxUDPPacket,
		MaxPaddingBytes:     1472,
	}
}

func ConfigFromEnvironment() (Config, error) {
	return ConfigFromMap(environmentMap())
}

func ConfigFromMap(env map[string]string) (Config, error) {
	primaryPort, err := envInt(env, "STUN_PRIMARY_PORT", 3478, 1, 65535)
	if err != nil {
		return Config{}, err
	}
	alternatePort, err := envInt(env, "STUN_ALTERNATE_PORT", 3479, 0, 65535)
	if err != nil {
		return Config{}, err
	}
	if alternatePort == primaryPort {
		return Config{}, fmt.Errorf("STUN_ALTERNATE_PORT must differ from STUN_PRIMARY_PORT")
	}

	primaryBind, err := resolveIP(envValue(env, "STUN_PRIMARY_BIND_ADDRESS", "0.0.0.0"))
	if err != nil {
		return Config{}, fmt.Errorf("STUN_PRIMARY_BIND_ADDRESS: %w", err)
	}
	primaryPublicText := envValue(env, "STUN_PRIMARY_PUBLIC_ADDRESS", "")
	if primaryPublicText == "" {
		if primaryBind.IsUnspecified() {
			return Config{}, fmt.Errorf("STUN_PRIMARY_PUBLIC_ADDRESS is required when STUN_PRIMARY_BIND_ADDRESS is wildcard")
		}
		primaryPublicText = primaryBind.String()
	}
	primaryPublic, err := resolveIP(primaryPublicText)
	if err != nil {
		return Config{}, fmt.Errorf("STUN_PRIMARY_PUBLIC_ADDRESS: %w", err)
	}

	alternateBindText := envValue(env, "STUN_ALTERNATE_BIND_ADDRESS", "")
	alternatePublicText := envValue(env, "STUN_ALTERNATE_PUBLIC_ADDRESS", "")
	alternateConfigured := alternateBindText != "" || alternatePublicText != ""
	if alternateConfigured && (alternateBindText == "" || alternatePublicText == "") {
		return Config{}, fmt.Errorf("STUN_ALTERNATE_BIND_ADDRESS and STUN_ALTERNATE_PUBLIC_ADDRESS must be configured together")
	}

	var topology Topology
	if alternateConfigured {
		if alternatePort == 0 {
			return Config{}, fmt.Errorf("STUN_ALTERNATE_PORT must be enabled for RFC 5780 four-endpoint mode")
		}
		alternateBind, resolveErr := resolveIP(alternateBindText)
		if resolveErr != nil {
			return Config{}, fmt.Errorf("STUN_ALTERNATE_BIND_ADDRESS: %w", resolveErr)
		}
		alternatePublic, resolveErr := resolveIP(alternatePublicText)
		if resolveErr != nil {
			return Config{}, fmt.Errorf("STUN_ALTERNATE_PUBLIC_ADDRESS: %w", resolveErr)
		}
		topology, err = NewRFC5780Topology(
			endpoint(Primary, primaryBind, primaryPublic, primaryPort),
			endpoint(PrimaryAlternatePort, primaryBind, primaryPublic, alternatePort),
			endpoint(AlternatePrimaryPort, alternateBind, alternatePublic, primaryPort),
			endpoint(Alternate, alternateBind, alternatePublic, alternatePort),
		)
	} else {
		var alternate *Endpoint
		if alternatePort > 0 {
			value := endpoint(PrimaryAlternatePort, primaryBind, primaryPublic, alternatePort)
			alternate = &value
		}
		topology, err = NewBasicTopology(
			endpoint(Primary, primaryBind, primaryPublic, primaryPort),
			alternate,
		)
	}
	if err != nil {
		return Config{}, err
	}

	protect := DefaultProtectionConfig()
	if protect.SourceRatePerSecond, err = envInt(env, "STUN_RATE_LIMIT_PER_SECOND", protect.SourceRatePerSecond, 1, 1000000); err != nil {
		return Config{}, err
	}
	if protect.SourceBurst, err = envInt(env, "STUN_RATE_LIMIT_BURST", protect.SourceBurst, 1, 2000000); err != nil {
		return Config{}, err
	}
	if protect.GlobalRatePerSecond, err = envInt(env, "STUN_GLOBAL_RATE_LIMIT_PER_SECOND", protect.GlobalRatePerSecond, 1, 10000000); err != nil {
		return Config{}, err
	}
	if protect.GlobalBurst, err = envInt(env, "STUN_GLOBAL_RATE_LIMIT_BURST", protect.GlobalBurst, 1, 20000000); err != nil {
		return Config{}, err
	}
	if protect.MaxTrackedSources, err = envInt(env, "STUN_MAX_TRACKED_SOURCES", protect.MaxTrackedSources, 1, 1000000); err != nil {
		return Config{}, err
	}
	if protect.SourceIdleSeconds, err = envInt(env, "STUN_SOURCE_IDLE_SECONDS", protect.SourceIdleSeconds, 1, 86400); err != nil {
		return Config{}, err
	}
	if protect.MaxPacketBytes, err = envInt(env, "STUN_MAX_PACKET_BYTES", protect.MaxPacketBytes, stunHeaderBytes, maxUDPPacket); err != nil {
		return Config{}, err
	}
	if protect.MaxPaddingBytes, err = envInt(env, "STUN_MAX_PADDING_RESPONSE_BYTES", protect.MaxPaddingBytes, 0, 65503); err != nil {
		return Config{}, err
	}
	metricsIP, err := resolveIP(envValue(env, "STUN_METRICS_BIND_ADDRESS", "127.0.0.1"))
	if err != nil {
		return Config{}, fmt.Errorf("STUN_METRICS_BIND_ADDRESS: %w", err)
	}
	metricsPort, err := envInt(env, "STUN_METRICS_PORT", 9108, 0, 65535)
	if err != nil {
		return Config{}, err
	}
	legacy, err := envBool(env, "STUN_LEGACY_SINGLE_IP_OTHER_ADDRESS", false)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Topology: topology,
		Software: envValue(env, "STUN_SOFTWARE", defaultSoftware),
		Legacy:   legacy,
		Protect:  protect,
		Metrics:  MetricsConfig{BindAddress: metricsIP, Port: metricsPort},
	}, nil
}

func (c Config) Describe() string {
	mode := "basic"
	if c.Topology.SupportsRFC5780() {
		mode = "rfc5780"
	}
	return fmt.Sprintf(
		"mode=%s, software=%s, endpoints=%s, source=%d/s burst=%d, global=%d/s burst=%d, trackedSources=%d, metrics=%s",
		mode,
		c.Software,
		c.Topology.Describe(),
		c.Protect.SourceRatePerSecond,
		c.Protect.SourceBurst,
		c.Protect.GlobalRatePerSecond,
		c.Protect.GlobalBurst,
		c.Protect.MaxTrackedSources,
		c.MetricsAddress(),
	)
}

func (c Config) MetricsAddress() string {
	if c.Metrics.Port == 0 {
		return "disabled"
	}
	return net.JoinHostPort(c.Metrics.BindAddress.String(), strconv.Itoa(c.Metrics.Port))
}

func endpoint(id EndpointID, bindIP, publicIP net.IP, port int) Endpoint {
	return Endpoint{
		ID:         id,
		Bind:       &net.UDPAddr{IP: cloneIP(bindIP), Port: port},
		Advertised: &net.UDPAddr{IP: cloneIP(publicIP), Port: port},
	}
}

func resolveIP(value string) (net.IP, error) {
	text := strings.TrimSpace(value)
	if parsed := net.ParseIP(text); parsed != nil {
		return parsed, nil
	}
	addresses, err := net.LookupIP(text)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("cannot resolve %q", value)
	}
	return addresses[0], nil
}

func envInt(env map[string]string, name string, fallback, minimum, maximum int) (int, error) {
	raw := envValue(env, name, strconv.Itoa(fallback))
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %s", name, raw)
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", name, minimum, maximum)
	}
	return value, nil
}

func envBool(env map[string]string, name string, fallback bool) (bool, error) {
	raw := strings.ToLower(envValue(env, name, strconv.FormatBool(fallback)))
	switch raw {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false: %s", name, raw)
	}
}

func envValue(env map[string]string, name, fallback string) string {
	if value := strings.TrimSpace(env[name]); value != "" {
		return value
	}
	return fallback
}

func environmentMap() map[string]string {
	result := make(map[string]string)
	for _, item := range os.Environ() {
		name, value, ok := strings.Cut(item, "=")
		if ok {
			result[name] = value
		}
	}
	return result
}

func cloneIP(ip net.IP) net.IP {
	return append(net.IP(nil), ip...)
}
