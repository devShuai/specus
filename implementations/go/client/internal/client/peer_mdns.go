package client

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"
)

func browseMdns(timeout time.Duration) []peerMdnsCandidate {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	mdns := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	queries := []string{"_http._tcp.local", "_https._tcp.local", "_ssh._tcp.local", "_udp.local"}
	for _, name := range queries {
		_, _ = conn.WriteToUDP(encodePtrQuery(name), mdns)
	}
	var packets [][]byte
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		packets = append(packets, packet)
	}
	return parseMdnsPackets(packets)
}

func encodePtrQuery(name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[4:], 1)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0, 0, 12, 0, 1)
	return out
}

func parseMdnsPackets(packets [][]byte) []peerMdnsCandidate {
	ptr := map[string]string{}
	srv := map[string]struct {
		target string
		port   int
	}{}
	addr := map[string]string{}
	for _, packet := range packets {
		parseMdnsPacket(packet, ptr, srv, addr)
	}
	seen := map[string]struct{}{}
	var out []peerMdnsCandidate
	for query, instance := range ptr {
		record, ok := srv[strings.ToLower(instance)]
		if !ok {
			continue
		}
		host := addr[strings.ToLower(record.target)]
		if host == "" {
			host = record.target
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" && !isPrivateHost(host) {
			continue
		}
		application := "udp"
		transport := "udp"
		lower := strings.ToLower(query)
		switch {
		case strings.Contains(lower, "_https._tcp"):
			application, transport = "https", "tcp"
		case strings.Contains(lower, "_http._tcp"):
			application, transport = "http", "tcp"
		case strings.Contains(lower, "_ssh._tcp"):
			application, transport = "ssh", "tcp"
		}
		name := instance
		if i := strings.IndexByte(name, '.'); i > 0 {
			name = name[:i]
		}
		key := application + ":" + host + ":" + strconv.Itoa(record.port)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, peerMdnsCandidate{Name: name, Transport: transport, Application: application, TargetHost: host, TargetPort: record.port})
	}
	return out
}

func isPrivateHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func parseMdnsPacket(packet []byte, ptr map[string]string, srv map[string]struct {
	target string
	port   int
}, addr map[string]string) {
	if len(packet) < 12 {
		return
	}
	offset := 12
	questions := int(binary.BigEndian.Uint16(packet[4:6]))
	answers := int(binary.BigEndian.Uint16(packet[6:8]))
	authority := int(binary.BigEndian.Uint16(packet[8:10]))
	additional := int(binary.BigEndian.Uint16(packet[10:12]))
	for i := 0; i < questions && offset < len(packet); i++ {
		_, next := readMdnsName(packet, offset)
		offset = next + 4
	}
	records := answers + authority + additional
	for i := 0; i < records && offset+10 <= len(packet); i++ {
		name, next := readMdnsName(packet, offset)
		offset = next
		if offset+10 > len(packet) {
			return
		}
		typ := binary.BigEndian.Uint16(packet[offset : offset+2])
		rdlength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+rdlength > len(packet) {
			return
		}
		data := packet[offset : offset+rdlength]
		switch typ {
		case 12:
			target, _ := readMdnsName(packet, offset)
			ptr[strings.ToLower(name)] = target
		case 33:
			if rdlength >= 6 {
				port := int(binary.BigEndian.Uint16(data[4:6]))
				target, _ := readMdnsName(packet, offset+6)
				srv[strings.ToLower(name)] = struct {
					target string
					port   int
				}{target, port}
			}
		case 1:
			if rdlength == 4 {
				addr[strings.ToLower(name)] = net.IPv4(data[0], data[1], data[2], data[3]).String()
			}
		}
		offset += rdlength
	}
}

func readMdnsName(packet []byte, offset int) (string, int) {
	var labels []string
	jumped := false
	end := offset
	hops := 0
	for hops < 16 && offset < len(packet) {
		hops++
		length := int(packet[offset])
		if length == 0 {
			if !jumped {
				end = offset + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(packet) {
				break
			}
			if !jumped {
				end = offset + 2
				jumped = true
			}
			offset = int(length&0x3F)<<8 | int(packet[offset+1])
			continue
		}
		offset++
		if offset+length > len(packet) {
			break
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
		if !jumped {
			end = offset
		}
	}
	return strings.Join(labels, "."), end
}
