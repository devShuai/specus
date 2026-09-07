package client

import "net/url"

// DiagnosticSnapshot deliberately projects a small allowlist; runtime tokens, peer keys,
// candidates and messages must never be serialized into the local query interface.
func (c *Client) DiagnosticSnapshot() map[string]any {
	phase := "http-login"
	if c.authenticated.Load() {
		phase = "connecting"
	}
	if c.diagnosticControl.Load() {
		phase = "control-authenticated"
	}
	if c.diagnosticReady.Load() {
		phase = "ready"
	}
	peers := []map[string]any{}
	services := []map[string]any{}
	c.peerMesh.mu.Lock()
	for _, p := range c.peerMesh.peers {
		peers = append(peers, map[string]any{"clientName": p.ClientName, "virtualIp": p.VirtualIP, "online": p.Online})
	}
	catalog := c.peerMesh.services
	c.peerMesh.mu.Unlock()
	if catalog != nil {
		for _, s := range catalog.remoteServices() {
			target := s.AccessTarget
			if parsed, err := url.Parse(target); err == nil {
				parsed.User = nil
				parsed.RawQuery = ""
				parsed.Fragment = ""
				target = parsed.String()
			} else {
				target = "<invalid>"
			}
			services = append(services, map[string]any{"publisher": s.PublisherClientName, "name": s.Service.Name, "application": s.Service.Application, "accessTarget": target, "available": s.Openable})
		}
	}
	control := c.diagnosticControl.Load()
	ready := control && c.diagnosticReady.Load()
	if !control {
		peers = []map[string]any{}
		services = []map[string]any{}
	}
	return map[string]any{"phase": phase, "controlAuthenticated": control, "businessReady": ready, "businessReadinessScope": "control/data authenticated; target reachability not tested", "peers": peers, "services": services}
}
