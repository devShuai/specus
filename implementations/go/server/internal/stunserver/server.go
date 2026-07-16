package stunserver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Server struct {
	config   Config
	binding  *BindingService
	limiter  *RequestLimiter
	metrics  *Metrics
	sockets  map[EndpointID]*net.UDPConn
	http     *http.Server
	listener net.Listener
	mu       sync.Mutex
}

func NewServer(config Config) *Server {
	return &Server{
		config:  config,
		binding: NewBindingService(config.Topology, config.Software, config.Legacy, config.Protect.MaxPaddingBytes),
		limiter: NewRequestLimiter(config.Protect),
		metrics: NewMetrics(),
		sockets: make(map[EndpointID]*net.UDPConn),
	}
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.bindEndpoints(); err != nil {
		s.Close()
		return err
	}
	if err := s.startMetrics(); err != nil {
		s.Close()
		return err
	}
	log.Printf("standalone STUN server started: %s", s.config.Describe())

	var workers sync.WaitGroup
	for _, endpoint := range s.config.Topology.Endpoints() {
		conn := s.sockets[endpoint.ID]
		workers.Add(1)
		go func(id EndpointID, socket *net.UDPConn) {
			defer workers.Done()
			s.receiveLoop(ctx, id, socket)
		}(endpoint.ID, conn)
	}

	<-ctx.Done()
	s.Close()
	workers.Wait()
	return nil
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, socket := range s.sockets {
		_ = socket.Close()
		delete(s.sockets, id)
	}
	if s.http != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = s.http.Shutdown(ctx)
		cancel()
		s.http = nil
	}
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
}

func (s *Server) bindEndpoints() error {
	for _, endpoint := range s.config.Topology.Endpoints() {
		socket, err := net.ListenUDP("udp", endpoint.Bind)
		if err != nil {
			return fmt.Errorf("bind %s to %s: %w", endpoint.ID, endpoint.Bind, err)
		}
		s.sockets[endpoint.ID] = socket
	}
	return nil
}

func (s *Server) startMetrics() error {
	if s.config.Metrics.Port == 0 {
		return nil
	}
	address := net.JoinHostPort(s.config.Metrics.BindAddress.String(), strconv.Itoa(s.config.Metrics.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("bind STUN metrics to %s: %w", address, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = writer.Write([]byte(s.metrics.Render(s.limiter.TrackedSources())))
	})
	s.listener = listener
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	go func() {
		err := s.http.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("STUN metrics server stopped: %v", err)
		}
	}()
	return nil
}

func (s *Server) receiveLoop(ctx context.Context, incoming EndpointID, socket *net.UDPConn) {
	bufferBytes := s.config.Protect.MaxPacketBytes
	if bufferBytes < maxUDPPacket {
		bufferBytes++
	}
	buffer := make([]byte, bufferBytes)
	for {
		n, remote, err := socket.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("STUN receive failed on %s: %v", incoming, err)
			}
			return
		}
		s.process(incoming, remote, buffer[:n])
	}
}

func (s *Server) process(incoming EndpointID, remote *net.UDPAddr, packet []byte) {
	s.metrics.RecordPacket(len(packet))
	if len(packet) > s.config.Protect.MaxPacketBytes {
		s.metrics.RecordDrop("packet_too_large")
		return
	}
	if decision := s.limiter.Allow(remote.IP); decision != LimitAllowed {
		s.metrics.RecordDrop(string(decision))
		return
	}
	request, err := ParseMessage(packet)
	if err != nil {
		s.metrics.RecordDrop("malformed")
		return
	}
	if request.Type != BindingRequest {
		s.metrics.RecordDrop("unsupported_method")
		return
	}
	s.metrics.RecordAcceptedRequest()
	if request.Has(AttrChangeRequest) {
		s.metrics.RecordFeature("change_request")
	}
	if request.Has(AttrResponsePort) {
		s.metrics.RecordFeature("response_port")
	}
	if request.Has(AttrPadding) {
		s.metrics.RecordFeature("padding")
	}

	result, err := s.binding.Process(request, remote, incoming, len(packet))
	if err != nil {
		s.metrics.RecordDrop("processing_error")
		return
	}
	response, err := result.Response.Bytes()
	if err != nil || len(response) > maxUDPPacket {
		s.metrics.RecordDrop("response_too_large")
		return
	}
	socket := s.sockets[result.ResponseEndpoint]
	if socket == nil {
		s.metrics.RecordDrop("response_endpoint_unavailable")
		return
	}
	if _, err := socket.WriteToUDP(response, result.ResponseTarget); err != nil {
		s.metrics.RecordDrop("send_error")
		return
	}
	code := 200
	if result.Response.Type == BindingError {
		code = result.Response.ErrorCode()
	}
	s.metrics.RecordResponse(code, len(response))
}
