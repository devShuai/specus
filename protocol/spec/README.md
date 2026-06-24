# shuai-tunnel Protocol Specs

This directory is the home for cross-language protocol documentation.

Java remains the reference implementation for now, but new behavior should be
documented here before Go, C#, or C implementations are aligned.

## Spec Index

- `control-protocol.md`: packet framing, message types, login, heartbeat, and NAT control.
- `client-auth.md`: HTTP login, API key signing, token refresh, and runtime configuration.
- `http-route.md`: direct HTTP routing semantics and traffic observation fields.
- `peer-mesh.md`: private mesh control messages, virtual IPs, ICE/TURN-lite, and data-plane frames.

The files above are intentionally listed before they are fully split out so
future changes have a stable destination instead of drifting back into code
comments or language-specific docs.
