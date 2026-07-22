package nat

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/control"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
)

const httpStreamEventCapacity = 32

type httpStreamEvent struct {
	kind     int
	metadata map[string]any
	data     []byte
	err      error
}

const (
	httpEventHead = iota + 1
	httpEventData
	httpEventEnd
	httpEventReset
)

// HTTPStream is one mandatory NAT-stream v2 HTTP exchange.
type HTTPStream struct {
	conn     *control.Conn
	streamID uint32
	onClose  func(uint32, *HTTPStream)

	events chan httpStreamEvent
	done   chan struct{}
	once   sync.Once

	windowMu           sync.Mutex
	sendCredit         uint64
	sendOutstanding    uint64
	receiveCredit      uint64
	receiveOutstanding uint64
	notify             chan struct{}
	responseHead       bool
	responseEnded      bool
}

func newHTTPStream(conn *control.Conn, streamID uint32, onClose func(uint32, *HTTPStream)) *HTTPStream {
	return &HTTPStream{
		conn: conn, streamID: streamID, onClose: onClose,
		events: make(chan httpStreamEvent, httpStreamEventCapacity),
		done:   make(chan struct{}), notify: make(chan struct{}, 1),
		sendCredit: natInitialWindowBytes, receiveCredit: natInitialWindowBytes,
	}
}

// SendData forwards one request body chunk after stream credit is available.
func (s *HTTPStream) SendData(ctx context.Context, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if !s.takeSendCredit(ctx, len(data)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.New("HTTP stream is closed")
	}
	return s.conn.Send(protocol.NatMessage{Type: protocol.NatData, StreamID: s.streamID, Data: data})
}

// FinishRequest half-closes the request direction.
func (s *HTTPStream) FinishRequest(metadata map[string]any) error {
	return s.conn.Send(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: s.streamID, Metadata: metadata,
	})
}

// WaitResponseHead waits for the client's response OPEN.
func (s *HTTPStream) WaitResponseHead(ctx context.Context) (map[string]any, error) {
	event, err := s.next(ctx)
	if err != nil {
		return nil, err
	}
	if event.kind != httpEventHead {
		return nil, errors.New("HTTP response did not start with OPEN")
	}
	return event.metadata, nil
}

// ReadResponse returns the next response body chunk or terminal FIN metadata.
func (s *HTTPStream) ReadResponse(ctx context.Context) ([]byte, map[string]any, bool, error) {
	event, err := s.next(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	switch event.kind {
	case httpEventData:
		return event.data, nil, false, nil
	case httpEventEnd:
		return nil, event.metadata, true, nil
	case httpEventReset:
		return nil, nil, false, event.err
	default:
		return nil, nil, false, errors.New("unexpected HTTP stream event")
	}
}

// Consume returns response credit only after the HTTP downstream consumed the chunk.
func (s *HTTPStream) Consume(bytes int) error {
	if bytes <= 0 {
		return nil
	}
	s.windowMu.Lock()
	credit := uint64(bytes)
	if credit > s.receiveOutstanding || credit > natMaximumWindowBytes-s.receiveCredit {
		s.windowMu.Unlock()
		return errors.New("HTTP receive window overflow")
	}
	s.receiveOutstanding -= credit
	s.receiveCredit += credit
	s.windowMu.Unlock()
	return s.conn.SendPriority(protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: s.streamID, Value: uint32(bytes),
	})
}

// Reset cancels both directions and removes the exchange.
func (s *HTTPStream) Reset(code uint32, reason string) {
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.conn.Send(protocol.NatMessage{
		Type: protocol.NatRST, StreamID: s.streamID, Value: code,
		Metadata: map[string]any{"reason": reason},
	})
	s.Close()
}

// Close releases the stream without emitting another wire frame.
func (s *HTTPStream) Close() {
	s.once.Do(func() {
		close(s.done)
		s.signalWindow()
		if s.onClose != nil {
			s.onClose(s.streamID, s)
		}
	})
}

func (s *HTTPStream) onHead(metadata map[string]any) bool {
	s.windowMu.Lock()
	if s.responseHead || s.responseEnded {
		s.windowMu.Unlock()
		return false
	}
	s.responseHead = true
	s.windowMu.Unlock()
	return s.enqueue(httpStreamEvent{kind: httpEventHead, metadata: cloneMetadata(metadata)})
}

func (s *HTTPStream) onData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	s.windowMu.Lock()
	if !s.responseHead || s.responseEnded || uint64(len(data)) > s.receiveCredit {
		s.windowMu.Unlock()
		return false
	}
	s.receiveCredit -= uint64(len(data))
	s.receiveOutstanding += uint64(len(data))
	s.windowMu.Unlock()
	payload := append([]byte(nil), data...)
	return s.enqueue(httpStreamEvent{kind: httpEventData, data: payload})
}

func (s *HTTPStream) onEnd(metadata map[string]any) bool {
	s.windowMu.Lock()
	if !s.responseHead || s.responseEnded {
		s.windowMu.Unlock()
		return false
	}
	s.responseEnded = true
	s.windowMu.Unlock()
	return s.enqueue(httpStreamEvent{kind: httpEventEnd, metadata: cloneMetadata(metadata)})
}

func (s *HTTPStream) onReset(reason string) {
	if reason == "" {
		reason = "HTTP stream reset by client"
	}
	_ = s.enqueue(httpStreamEvent{kind: httpEventReset, err: errors.New(reason)})
	s.Close()
}

func (s *HTTPStream) addSendCredit(credit uint32) bool {
	if credit == 0 || credit > natMaximumWindowBytes {
		return false
	}
	s.windowMu.Lock()
	credit64 := uint64(credit)
	if credit64 > s.sendOutstanding || s.sendCredit+credit64 > natMaximumWindowBytes {
		s.windowMu.Unlock()
		return false
	}
	s.sendOutstanding -= credit64
	s.sendCredit += credit64
	s.windowMu.Unlock()
	s.signalWindow()
	return true
}

func (s *HTTPStream) takeSendCredit(ctx context.Context, size int) bool {
	if size <= 0 || size > natMaximumWindowBytes {
		return false
	}
	needed := uint64(size)
	for {
		s.windowMu.Lock()
		if s.sendCredit >= needed {
			s.sendCredit -= needed
			s.sendOutstanding += needed
			s.windowMu.Unlock()
			return true
		}
		s.windowMu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-s.done:
			return false
		case <-s.notify:
		}
	}
}

func (s *HTTPStream) next(ctx context.Context) (httpStreamEvent, error) {
	select {
	case event := <-s.events:
		if event.kind == httpEventReset && event.err != nil {
			return event, event.err
		}
		return event, nil
	case <-ctx.Done():
		return httpStreamEvent{}, ctx.Err()
	case <-s.done:
		select {
		case event := <-s.events:
			if event.err != nil {
				return event, event.err
			}
			return event, nil
		default:
			return httpStreamEvent{}, errors.New("HTTP stream is closed")
		}
	}
}

func (s *HTTPStream) enqueue(event httpStreamEvent) bool {
	select {
	case <-s.done:
		return false
	case s.events <- event:
		return true
	default:
		return false
	}
}

func (s *HTTPStream) signalWindow() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func cloneMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	result := make(map[string]any, len(metadata))
	for key, value := range metadata {
		result[key] = value
	}
	return result
}

func (s *HTTPStream) String() string { return fmt.Sprintf("http-stream-%d", s.streamID) }
