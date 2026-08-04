package nat

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

const (
	httpMaxQueuedDataEvents = 4096
	httpMaxQueuedDataBytes  = natInitialWindowBytes
	// DATA has an explicit count limit and the extra slot guarantees that FIN/RST
	// can always terminate a stream after the data queue reaches that limit.
	httpStreamEventCapacity   = httpMaxQueuedDataEvents + 1
	httpReceiveWindowLowWater = natInitialWindowBytes / 4
)

type httpStreamEvent struct {
	kind     int
	metadata map[string]any
	data     []byte
	err      error
}

const (
	httpEventData = iota + 1
	httpEventEnd
	httpEventReset
)

type httpStreamFrameResult uint8

const (
	httpStreamFrameAccepted httpStreamFrameResult = iota + 1
	httpStreamFrameClosed
	httpStreamFrameQueueFull
	httpStreamFrameInvalidState
	httpStreamFrameWindowExceeded
)

// HTTPStream is one mandatory NAT-stream v2 HTTP exchange.
type HTTPStream struct {
	conn     *control.Conn
	streamID uint32
	onClose  func(uint32, *HTTPStream)

	head   chan httpStreamEvent
	events chan httpStreamEvent
	done   chan struct{}
	once   sync.Once

	windowMu           sync.Mutex
	sendCredit         uint64
	sendOutstanding    uint64
	receiveCredit      uint64
	receiveOutstanding uint64
	receivePending     uint64
	queuedDataEvents   int
	queuedDataBytes    uint64
	notify             chan struct{}
	requestEnded       bool
	responseHead       bool
	terminalQueued     bool
	closed             bool
}

func newHTTPStream(conn *control.Conn, streamID uint32, onClose func(uint32, *HTTPStream)) *HTTPStream {
	return &HTTPStream{
		conn: conn, streamID: streamID, onClose: onClose,
		head: make(chan httpStreamEvent, 1), events: make(chan httpStreamEvent, httpStreamEventCapacity),
		done: make(chan struct{}), notify: make(chan struct{}, 1),
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
	if s.isClosed() {
		return errors.New("HTTP stream is closed")
	}
	return s.conn.Send(protocol.NatMessage{Type: protocol.NatData, StreamID: s.streamID, Data: data})
}

// FinishRequest half-closes the request direction.
func (s *HTTPStream) FinishRequest(metadata map[string]any) error {
	s.windowMu.Lock()
	if s.closed {
		s.windowMu.Unlock()
		return errors.New("HTTP stream is closed")
	}
	if s.requestEnded {
		s.windowMu.Unlock()
		return nil
	}
	s.requestEnded = true
	s.windowMu.Unlock()
	return s.conn.Send(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: s.streamID, Metadata: metadata,
	})
}

// WaitResponseHead waits for the client's response OPEN.
func (s *HTTPStream) WaitResponseHead(ctx context.Context) (map[string]any, error) {
	select {
	case event := <-s.head:
		if event.err != nil {
			return nil, event.err
		}
		return event.metadata, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		select {
		case event := <-s.head:
			if event.err != nil {
				return nil, event.err
			}
			return event.metadata, nil
		default:
			return nil, errors.New("HTTP stream is closed")
		}
	}
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
	credit, err := s.consumeReceiveCredit(bytes)
	if err != nil || credit == 0 {
		return err
	}
	return s.conn.SendPriority(protocol.NatMessage{
		Type: protocol.NatWindowUpdate, StreamID: s.streamID, Value: credit,
	})
}

func (s *HTTPStream) consumeReceiveCredit(bytes int) (uint32, error) {
	s.windowMu.Lock()
	credit := uint64(bytes)
	if credit > s.receiveOutstanding || credit > natMaximumWindowBytes-s.receivePending {
		s.windowMu.Unlock()
		return 0, errors.New("HTTP receive window overflow")
	}
	s.receiveOutstanding -= credit
	s.receivePending += credit
	if s.receiveCredit > httpReceiveWindowLowWater {
		s.windowMu.Unlock()
		return 0, nil
	}
	if s.receivePending > natMaximumWindowBytes-s.receiveCredit {
		s.windowMu.Unlock()
		return 0, errors.New("HTTP receive window overflow")
	}
	returned := s.receivePending
	s.receiveCredit += returned
	s.receivePending = 0
	s.windowMu.Unlock()
	return uint32(returned), nil
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
		s.windowMu.Lock()
		s.closed = true
		s.windowMu.Unlock()
		close(s.done)
		s.signalWindow()
		if s.onClose != nil {
			s.onClose(s.streamID, s)
		}
	})
}

func (s *HTTPStream) onHead(metadata map[string]any) httpStreamFrameResult {
	status, hasStatus := asInt(metadata, "statusCode")
	if asString(metadata, "source") != "http" || asString(metadata, "phase") != "response" ||
		!hasStatus || status < 100 || status > 599 {
		return httpStreamFrameInvalidState
	}
	s.windowMu.Lock()
	if s.responseHead || s.terminalQueued {
		s.windowMu.Unlock()
		return httpStreamFrameInvalidState
	}
	if s.closed {
		s.windowMu.Unlock()
		return httpStreamFrameClosed
	}
	s.responseHead = true
	s.windowMu.Unlock()
	select {
	case <-s.done:
		return httpStreamFrameClosed
	case s.head <- httpStreamEvent{metadata: cloneMetadata(metadata)}:
		return httpStreamFrameAccepted
	default:
		return httpStreamFrameInvalidState
	}
}

func (s *HTTPStream) onData(data []byte) httpStreamFrameResult {
	if len(data) == 0 {
		return httpStreamFrameInvalidState
	}
	s.windowMu.Lock()
	if s.terminalQueued {
		s.windowMu.Unlock()
		return httpStreamFrameInvalidState
	}
	if s.closed {
		s.windowMu.Unlock()
		return httpStreamFrameClosed
	}
	if !s.responseHead {
		s.windowMu.Unlock()
		return httpStreamFrameInvalidState
	}
	if uint64(len(data)) > s.receiveCredit {
		s.windowMu.Unlock()
		return httpStreamFrameWindowExceeded
	}
	if s.queuedDataEvents >= httpMaxQueuedDataEvents ||
		uint64(len(data)) > httpMaxQueuedDataBytes-s.queuedDataBytes {
		s.windowMu.Unlock()
		return httpStreamFrameQueueFull
	}
	s.receiveCredit -= uint64(len(data))
	s.receiveOutstanding += uint64(len(data))
	s.queuedDataEvents++
	s.queuedDataBytes += uint64(len(data))
	s.windowMu.Unlock()
	payload := append([]byte(nil), data...)
	result := s.enqueue(httpStreamEvent{kind: httpEventData, data: payload})
	if result != httpStreamFrameAccepted {
		s.windowMu.Lock()
		s.receiveCredit += uint64(len(data))
		s.receiveOutstanding -= uint64(len(data))
		s.queuedDataEvents--
		s.queuedDataBytes -= uint64(len(data))
		s.windowMu.Unlock()
	}
	return result
}

func (s *HTTPStream) onEnd(metadata map[string]any) httpStreamFrameResult {
	s.windowMu.Lock()
	if s.terminalQueued {
		s.windowMu.Unlock()
		return httpStreamFrameInvalidState
	}
	if s.closed {
		s.windowMu.Unlock()
		return httpStreamFrameClosed
	}
	if !s.responseHead {
		s.windowMu.Unlock()
		return httpStreamFrameInvalidState
	}
	s.terminalQueued = true
	s.windowMu.Unlock()
	return s.enqueue(httpStreamEvent{kind: httpEventEnd, metadata: cloneMetadata(metadata)})
}

func (s *HTTPStream) onReset(reason string) {
	if reason == "" {
		reason = "HTTP stream reset by client"
	}
	event := httpStreamEvent{kind: httpEventReset, err: errors.New(reason)}
	select {
	case s.head <- event:
	default:
	}
	s.windowMu.Lock()
	if s.terminalQueued {
		s.windowMu.Unlock()
		s.Close()
		return
	}
	s.terminalQueued = true
	s.windowMu.Unlock()
	_ = s.enqueue(event)
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
		if s.closed || s.requestEnded {
			s.windowMu.Unlock()
			return false
		}
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

func (s *HTTPStream) isClosed() bool {
	s.windowMu.Lock()
	defer s.windowMu.Unlock()
	return s.closed
}

func (s *HTTPStream) next(ctx context.Context) (httpStreamEvent, error) {
	select {
	case event := <-s.events:
		return s.finishDequeuedEvent(event)
	case <-ctx.Done():
		return httpStreamEvent{}, ctx.Err()
	case <-s.done:
		select {
		case event := <-s.events:
			return s.finishDequeuedEvent(event)
		default:
			return httpStreamEvent{}, errors.New("HTTP stream is closed")
		}
	}
}

func (s *HTTPStream) finishDequeuedEvent(event httpStreamEvent) (httpStreamEvent, error) {
	if event.kind == httpEventData {
		s.windowMu.Lock()
		s.queuedDataEvents--
		s.queuedDataBytes -= uint64(len(event.data))
		s.windowMu.Unlock()
	}
	if event.kind == httpEventReset && event.err != nil {
		return event, event.err
	}
	return event, nil
}

func (s *HTTPStream) enqueue(event httpStreamEvent) httpStreamFrameResult {
	select {
	case <-s.done:
		return httpStreamFrameClosed
	default:
	}
	select {
	case <-s.done:
		return httpStreamFrameClosed
	case s.events <- event:
		return httpStreamFrameAccepted
	default:
		return httpStreamFrameQueueFull
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
