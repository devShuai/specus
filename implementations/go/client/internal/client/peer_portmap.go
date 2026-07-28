package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type natPortMappingProtocol string

const (
	portMappingUPNP   natPortMappingProtocol = "UPNP"
	portMappingNATPMP natPortMappingProtocol = "NAT_PMP"
	portMappingPCP    natPortMappingProtocol = "PCP"

	portMappingTimeout = 4 * time.Second
)

type natPortMapping struct {
	Protocol        natPortMappingProtocol
	ExternalAddress string
	ExternalPort    int
	InternalPort    int
	LeaseSeconds    int
	CreatedAt       time.Time
}

func (mapping natPortMapping) shouldRenew(now time.Time) bool {
	lease := mapping.LeaseSeconds
	if lease <= 0 {
		lease = peerPortMappingLease
	}
	return now.After(mapping.CreatedAt.Add(time.Duration(lease-60) * time.Second))
}

type natPortMapper interface {
	protocol() natPortMappingProtocol
	addMapping(ctx context.Context, internalPort, preferredExternal, leaseSeconds int, description string) (*natPortMapping, error)
	deleteMapping(mapping natPortMapping)
}

type natPortMappingService struct {
	logger  *log.Logger
	mappers []natPortMapper
}

func newNatPortMappingService(logger *log.Logger) *natPortMappingService {
	if logger == nil {
		logger = log.Default()
	}
	return &natPortMappingService{
		logger: logger,
		mappers: []natPortMapper{
			newUPNPPortMapper(logger),
			natPMPPortMapper{logger: logger},
			newPCPPortMapper(logger),
		},
	}
}

func (service *natPortMappingService) tryAcquireMapping(internalPort, preferredExternal, leaseSeconds int, description string) (*natPortMapping, error) {
	if service == nil || internalPort <= 0 || internalPort > 65535 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), portMappingTimeout)
	defer cancel()
	type result struct {
		mapping *natPortMapping
		err     error
	}
	results := make(chan result, len(service.mappers))
	for _, mapper := range service.mappers {
		mapper := mapper
		go func() {
			mapping, err := mapper.addMapping(ctx, internalPort, preferredExternal, leaseSeconds, description)
			results <- result{mapping: mapping, err: err}
		}()
	}
	var lastErr error
	for i := 0; i < len(service.mappers); i++ {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		case item := <-results:
			if item.mapping != nil {
				cancel()
				return item.mapping, nil
			}
			if item.err != nil {
				lastErr = item.err
				service.logger.Printf("NAT port mapping protocol failed: %v", item.err)
			}
		}
	}
	return nil, lastErr
}

func (service *natPortMappingService) renewMapping(mapping natPortMapping, leaseSeconds int, description string) (*natPortMapping, error) {
	if service == nil {
		return nil, errors.New("missing NAT port mapping service")
	}
	for _, mapper := range service.mappers {
		if mapper.protocol() != mapping.Protocol {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), portMappingTimeout)
		defer cancel()
		return mapper.addMapping(ctx, mapping.InternalPort, mapping.ExternalPort, leaseSeconds, description)
	}
	return nil, fmt.Errorf("unsupported NAT port mapping protocol %s", mapping.Protocol)
}

func (service *natPortMappingService) releaseMapping(mapping natPortMapping) {
	if service == nil {
		return
	}
	for _, mapper := range service.mappers {
		if mapper.protocol() == mapping.Protocol {
			mapper.deleteMapping(mapping)
			return
		}
	}
}

type natPMPPortMapper struct {
	logger *log.Logger
}

func (natPMPPortMapper) protocol() natPortMappingProtocol { return portMappingNATPMP }

func (mapper natPMPPortMapper) addMapping(ctx context.Context, internalPort, preferredExternal, leaseSeconds int, _ string) (*natPortMapping, error) {
	var lastErr error
	for _, gateway := range defaultGatewayCandidates() {
		external, err := mapper.requestExternalAddress(ctx, gateway)
		if err != nil {
			lastErr = err
			continue
		}
		req := make([]byte, 12)
		req[0] = 0
		req[1] = 1
		binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
		binary.BigEndian.PutUint16(req[6:8], uint16(preferredExternal))
		binary.BigEndian.PutUint32(req[8:12], uint32(leaseSeconds))
		rsp, err := udpRequest(ctx, gateway, 5351, req, 16, 1500*time.Millisecond)
		if err != nil {
			lastErr = err
			continue
		}
		if len(rsp) < 16 || rsp[0] != 0 || rsp[1] != 129 {
			lastErr = fmt.Errorf("NAT-PMP map response shape unexpected")
			continue
		}
		if code := binary.BigEndian.Uint16(rsp[2:4]); code != 0 {
			lastErr = fmt.Errorf("NAT-PMP map rejected: code=%d", code)
			continue
		}
		mappedExternal := int(binary.BigEndian.Uint16(rsp[10:12]))
		grantedLifetime := int(binary.BigEndian.Uint32(rsp[12:16]))
		return &natPortMapping{
			Protocol:        portMappingNATPMP,
			ExternalAddress: external,
			ExternalPort:    mappedExternal,
			InternalPort:    internalPort,
			LeaseSeconds:    maxInt(60, grantedLifetime),
			CreatedAt:       time.Now(),
		}, nil
	}
	return nil, firstErr(lastErr, errors.New("NAT-PMP failed against all gateway candidates"))
}

func (mapper natPMPPortMapper) deleteMapping(mapping natPortMapping) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	for _, gateway := range defaultGatewayCandidates() {
		req := make([]byte, 12)
		req[0] = 0
		req[1] = 1
		binary.BigEndian.PutUint16(req[4:6], uint16(mapping.InternalPort))
		_, _ = udpRequest(ctx, gateway, 5351, req, 16, 700*time.Millisecond)
	}
	_ = mapper
}

func (mapper natPMPPortMapper) requestExternalAddress(ctx context.Context, gateway net.IP) (string, error) {
	rsp, err := udpRequest(ctx, gateway, 5351, []byte{0, 0}, 12, 1500*time.Millisecond)
	if err != nil {
		return "", err
	}
	if len(rsp) < 12 || rsp[0] != 0 || rsp[1]&0x7f != 0 {
		return "", errors.New("NAT-PMP external address response shape unexpected")
	}
	if code := binary.BigEndian.Uint16(rsp[2:4]); code != 0 {
		return "", fmt.Errorf("NAT-PMP external address rejected: code=%d", code)
	}
	return net.IPv4(rsp[8], rsp[9], rsp[10], rsp[11]).String(), nil
}

type pcpPortMapper struct {
	logger *log.Logger
	nonce  [12]byte
}

func newPCPPortMapper(logger *log.Logger) *pcpPortMapper {
	mapper := &pcpPortMapper{logger: logger}
	_, _ = rand.Read(mapper.nonce[:])
	return mapper
}

func (*pcpPortMapper) protocol() natPortMappingProtocol { return portMappingPCP }

func (mapper *pcpPortMapper) addMapping(ctx context.Context, internalPort, preferredExternal, leaseSeconds int, _ string) (*natPortMapping, error) {
	var lastErr error
	for _, gateway := range defaultGatewayCandidates() {
		clientIP, err := clientIPMappedIPv6(gateway)
		if err != nil {
			lastErr = err
			continue
		}
		req := make([]byte, 60)
		req[0] = 2
		req[1] = 1
		binary.BigEndian.PutUint32(req[4:8], uint32(leaseSeconds))
		copy(req[8:24], clientIP)
		copy(req[24:36], mapper.nonce[:])
		req[36] = 17
		binary.BigEndian.PutUint16(req[40:42], uint16(internalPort))
		binary.BigEndian.PutUint16(req[42:44], uint16(preferredExternal))
		rsp, err := udpRequest(ctx, gateway, 5351, req, 60, 1500*time.Millisecond)
		if err != nil {
			lastErr = err
			continue
		}
		if len(rsp) < 60 || rsp[0] != 2 || rsp[1] != 0x81 {
			lastErr = errors.New("PCP MAP response shape unexpected")
			continue
		}
		if code := rsp[3]; code != 0 {
			lastErr = fmt.Errorf("PCP MAP rejected: code=%d", code)
			continue
		}
		if !bytes.Equal(rsp[24:36], mapper.nonce[:]) {
			lastErr = errors.New("PCP MAP response nonce mismatch")
			continue
		}
		external := extractMappedIPv4(rsp[44:60])
		if external == "" || external == "::" {
			lastErr = errors.New("PCP MAP response missing external address")
			continue
		}
		return &natPortMapping{
			Protocol:        portMappingPCP,
			ExternalAddress: external,
			ExternalPort:    int(binary.BigEndian.Uint16(rsp[42:44])),
			InternalPort:    internalPort,
			LeaseSeconds:    maxInt(60, int(binary.BigEndian.Uint32(rsp[4:8]))),
			CreatedAt:       time.Now(),
		}, nil
	}
	return nil, firstErr(lastErr, errors.New("PCP failed against all gateway candidates"))
}

func (mapper *pcpPortMapper) deleteMapping(mapping natPortMapping) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, _ = mapper.addMapping(ctx, mapping.InternalPort, 0, 0, "")
}

type upnpPortMapper struct {
	logger  *log.Logger
	mu      sync.Mutex
	gateway *upnpGateway
	client  *http.Client
}

type upnpGateway struct {
	controlURL  string
	serviceType string
	localIP     string
	externalIP  string
}

func newUPNPPortMapper(logger *log.Logger) *upnpPortMapper {
	return &upnpPortMapper{
		logger: logger,
		client: &http.Client{Timeout: 2500 * time.Millisecond},
	}
}

func (*upnpPortMapper) protocol() natPortMappingProtocol { return portMappingUPNP }

func (mapper *upnpPortMapper) addMapping(ctx context.Context, internalPort, preferredExternal, leaseSeconds int, description string) (*natPortMapping, error) {
	gateway, err := mapper.ensureGateway(ctx)
	if err != nil {
		return nil, err
	}
	externalPort := preferredExternal
	if externalPort <= 0 {
		externalPort = internalPort
	}
	if description == "" {
		description = "specus"
	}
	for attempt := 0; attempt < 4; attempt++ {
		if err := mapper.soap(ctx, gateway, "AddPortMapping", upnpAddPortMappingBody(externalPort, internalPort, gateway.localIP, leaseSeconds, description), nil); err == nil {
			return &natPortMapping{
				Protocol:        portMappingUPNP,
				ExternalAddress: gateway.externalIP,
				ExternalPort:    externalPort,
				InternalPort:    internalPort,
				LeaseSeconds:    peerPortMappingLease,
				CreatedAt:       time.Now(),
			}, nil
		}
		externalPort = randomEphemeralPort()
	}
	return nil, fmt.Errorf("UPnP AddPortMapping rejected for internal port %d", internalPort)
}

func (mapper *upnpPortMapper) deleteMapping(mapping natPortMapping) {
	mapper.mu.Lock()
	gateway := mapper.gateway
	mapper.mu.Unlock()
	if gateway == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_ = mapper.soap(ctx, gateway, "DeletePortMapping", upnpDeletePortMappingBody(mapping.ExternalPort), nil)
}

func (mapper *upnpPortMapper) ensureGateway(ctx context.Context) (*upnpGateway, error) {
	mapper.mu.Lock()
	if mapper.gateway != nil {
		gateway := mapper.gateway
		mapper.mu.Unlock()
		return gateway, nil
	}
	mapper.mu.Unlock()
	locations, err := discoverUPNPLocations(ctx)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, location := range locations {
		gateway, err := mapper.gatewayFromLocation(ctx, location)
		if err != nil {
			lastErr = err
			continue
		}
		mapper.mu.Lock()
		mapper.gateway = gateway
		mapper.mu.Unlock()
		return gateway, nil
	}
	return nil, firstErr(lastErr, errors.New("UPnP SSDP discovery found no usable IGD"))
}

func (mapper *upnpPortMapper) gatewayFromLocation(ctx context.Context, location string) (*upnpGateway, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	resp, err := mapper.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("UPnP device description status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	base, _ := url.Parse(location)
	serviceType, controlURL, err := parseUPNPService(body, base)
	if err != nil {
		return nil, err
	}
	localIP := localIPv4ForRemote(base.Hostname(), 80)
	gateway := &upnpGateway{controlURL: controlURL, serviceType: serviceType, localIP: localIP}
	var externalIP string
	if err := mapper.soap(ctx, gateway, "GetExternalIPAddress", "", &externalIP); err != nil {
		return nil, err
	}
	gateway.externalIP = externalIP
	if gateway.localIP == "" {
		return nil, errors.New("UPnP cannot determine local address")
	}
	return gateway, nil
}

func (mapper *upnpPortMapper) soap(ctx context.Context, gateway *upnpGateway, action, inner string, externalIP *string) error {
	envelope := `<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:` + action + ` xmlns:u="` + gateway.serviceType + `">` + inner + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.controlURL, strings.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+gateway.serviceType+`#`+action+`"`)
	resp, err := mapper.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("UPnP %s status %d", action, resp.StatusCode)
	}
	if externalIP != nil {
		*externalIP = xmlElementText(body, "NewExternalIPAddress")
		if strings.TrimSpace(*externalIP) == "" {
			return errors.New("UPnP GetExternalIPAddress returned empty address")
		}
	}
	return nil
}

func discoverUPNPLocations(ctx context.Context) ([]string, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	searchTargets := []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
	}
	for _, st := range searchTargets {
		request := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"ST: " + st + "\r\n\r\n"
		_, _ = conn.WriteTo([]byte(request), group)
	}
	deadline := time.Now().Add(2200 * time.Millisecond)
	_ = conn.SetDeadline(deadline)
	locations := make([]string, 0, 4)
	seen := make(map[string]struct{})
	for {
		select {
		case <-ctx.Done():
			return locations, ctx.Err()
		default:
		}
		var buf [2048]byte
		n, _, err := conn.ReadFrom(buf[:])
		if err != nil {
			break
		}
		location := headerValue(string(buf[:n]), "location")
		if location == "" {
			continue
		}
		if _, ok := seen[location]; !ok {
			seen[location] = struct{}{}
			locations = append(locations, location)
		}
	}
	if len(locations) == 0 {
		return nil, errors.New("UPnP SSDP discovery found no locations")
	}
	return locations, nil
}

func parseUPNPService(body []byte, base *url.URL) (string, string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	inService := false
	current := ""
	serviceType := ""
	control := ""
	for {
		token, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", "", err
		}
		switch item := token.(type) {
		case xml.StartElement:
			current = item.Name.Local
			if current == "service" {
				inService = true
				serviceType = ""
				control = ""
			}
		case xml.EndElement:
			if item.Name.Local == "service" {
				if strings.Contains(serviceType, "WANIPConnection") || strings.Contains(serviceType, "WANPPPConnection") {
					ref, err := url.Parse(strings.TrimSpace(control))
					if err != nil {
						return "", "", err
					}
					return serviceType, base.ResolveReference(ref).String(), nil
				}
				inService = false
			}
		case xml.CharData:
			if !inService {
				continue
			}
			switch current {
			case "serviceType":
				serviceType += string(item)
			case "controlURL":
				control += string(item)
			}
		}
	}
	return "", "", errors.New("UPnP WANIPConnection/WANPPPConnection service not found")
}

func upnpAddPortMappingBody(externalPort, internalPort int, localIP string, leaseSeconds int, description string) string {
	return fmt.Sprintf(
		"<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>"+
			"<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"+
			"<NewPortMappingDescription>%s</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>",
		externalPort, internalPort, xmlEscape(localIP), xmlEscape(description), maxInt(60, leaseSeconds))
}

func upnpDeletePortMappingBody(externalPort int) string {
	return fmt.Sprintf("<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>", externalPort)
}

func defaultGatewayCandidates() []net.IP {
	seen := make(map[string]struct{})
	out := make([]net.IP, 0, 8)
	addFromLocal := func(ip net.IP) {
		v4 := ip.To4()
		if v4 == nil || v4[0] == 127 || v4[0] == 169 && v4[1] == 254 {
			return
		}
		for _, last := range []byte{1, 254} {
			candidate := net.IPv4(v4[0], v4[1], v4[2], last)
			key := candidate.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, candidate)
			}
		}
	}
	for _, target := range []string{"1.1.1.1:53", "223.5.5.5:53"} {
		conn, err := net.DialTimeout("udp4", target, 300*time.Millisecond)
		if err == nil {
			if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				addFromLocal(addr.IP)
			}
			_ = conn.Close()
		}
	}
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if ip := ipFromAddr(addr); ip != nil {
					addFromLocal(ip)
				}
			}
		}
	}
	return out
}

func udpRequest(ctx context.Context, host net.IP, port int, payload []byte, minResponse int, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: host, Port: port})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, maxInt(minResponse, 1100))
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < minResponse {
		return nil, fmt.Errorf("UDP response truncated: %d bytes", n)
	}
	return append([]byte(nil), buf[:n]...), nil
}

func clientIPMappedIPv6(gateway net.IP) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gateway, Port: 5351})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return nil, errors.New("cannot determine local IP for PCP")
	}
	v4 := local.IP.To4()
	if v4 == nil {
		return nil, errors.New("PCP only supports IPv4 local address in Go client")
	}
	out := make([]byte, 16)
	out[10] = 0xff
	out[11] = 0xff
	copy(out[12:16], v4)
	return out, nil
}

func extractMappedIPv4(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	mapped := true
	for i := 0; i < 10; i++ {
		if raw[i] != 0 {
			mapped = false
			break
		}
	}
	if mapped && raw[10] == 0xff && raw[11] == 0xff {
		return net.IPv4(raw[12], raw[13], raw[14], raw[15]).String()
	}
	return net.IP(raw).String()
}

func localIPv4ForRemote(host string, port int) string {
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}

func xmlElementText(body []byte, localName string) string {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	current := ""
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		switch item := token.(type) {
		case xml.StartElement:
			current = item.Name.Local
		case xml.CharData:
			if current == localName {
				return strings.TrimSpace(string(item))
			}
		}
	}
}

func headerValue(raw, name string) string {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `\s*:\s*(.+?)\s*$`)
	match := re.FindStringSubmatch(raw)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func xmlEscape(value string) string {
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(value))
	return builder.String()
}

func randomEphemeralPort() int {
	n, err := rand.Int(rand.Reader, big.NewInt(16000))
	if err != nil {
		return 49152 + int(time.Now().UnixNano()%16000)
	}
	return 49152 + int(n.Int64())
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func firstErr(err error, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
