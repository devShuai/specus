package nat

import (
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

func TestRetiredNamespaceCannotAcceptFramesOrOpenStreams(t *testing.T) {
	for _, operation := range []string{"keepalive", "http", "websocket"} {
		t.Run(operation, func(t *testing.T) {
			session := &clientSession{}
			session.dispose()
			defer func() {
				if value := recover(); value != nil {
					t.Errorf("retired namespace touched missing transport/resources: %v", value)
				}
			}()
			var err error
			switch operation {
			case "keepalive":
				err = session.handle(protocol.NatMessage{Type: protocol.NatKeepalive})
			case "http":
				_, err = session.openHTTPStream(nil)
			case "websocket":
				_, err = session.openWSStream(nil, nil)
			}
			if err == nil {
				t.Fatal("retired namespace remained usable")
			}
		})
	}
}
