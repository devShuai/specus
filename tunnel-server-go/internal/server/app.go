package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/auth"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/control"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/directhttp"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/management"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/nat"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/security"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/session"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/wsevents"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/web"
)

// Demo client seed credentials (match the C# server).
const (
	DemoClientName     = "Demo client"
	DemoClientPassword = "test1234"
)

var errUnauthenticated = errors.New("packet on unauthenticated channel")

// App is the composed server: store + control channel + management HTTP surface.
type App struct {
	cfg         config.Config
	logger      *slog.Logger
	db          *store.DB
	sessions    *session.Registry
	executor    *control.LoginExecutor
	listener    *control.Listener
	dispatcher  *Dispatcher
	traffic     *nat.TrafficService
	natControl  *nat.ControlService
	remotePorts *nat.RemotePortManager
	tokens      *security.LocalTokenService
	directHTTP  *directhttp.Service
	wsHub       *wsevents.Hub
	api         *management.API
	tlsConfig   *tls.Config
	clientAuth  *auth.SessionStore
}

// New opens the database, applies the schema, seeds the demo client, and builds the app.
func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	db, err := store.Open(cfg.Database.Provider, cfg.ConnectionString)
	if err != nil {
		return nil, err
	}

	if cfg.Database.SeedDemoClient {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := seedDemoClient(ctx, db, logger)
		cancel()
		if err != nil {
			db.Close()
			return nil, err
		}
	}

	sessions := session.NewRegistry()
	clientSessions := auth.NewSessionStore()
	executor := control.NewLoginExecutor(cfg.Login.ExecutorMaxSize, cfg.Login.ExecutorQueueCapacity)
	authenticator := auth.NewAuthenticator(db, clientSessions)
	dispatcher := NewDispatcher(db, authenticator, sessions, executor, logger)
	listener := control.NewListener(cfg.Netty.MaxFrameSize, dispatcher)

	traffic := nat.NewTrafficService(db, time.Duration(cfg.Traffic.FlushIntervalMs)*time.Millisecond, logger)
	remotePorts := nat.NewRemotePortManager(cfg.Netty.MaxExternalConnections)
	limits := nat.Limits{
		Global:    cfg.Netty.MaxExternalConnections,
		PerClient: cfg.Netty.MaxExternalConnectionsPerClient,
		PerPort:   cfg.Netty.MaxExternalConnectionsPerPort,
	}
	coordinator := nat.NewCoordinator(remotePorts, traffic, limits, logger)
	natControl := nat.NewControlService(db, sessions, cfg.Netty.Port, cfg.PublicAddress)

	tokens := security.NewLocalTokenService(cfg.Auth)
	oidcValidator := security.NewOidcValidator(cfg.Oidc)
	directHTTP := directhttp.NewService(sessions,
		time.Duration(cfg.HTTP.TimeoutMs)*time.Millisecond, cfg.HTTP.MaxRequestBodySize, traffic)
	api := management.NewAPI(db, sessions, tokens, oidcValidator, natControl, remotePorts, cfg.Oidc,
		func(ctx context.Context) error { return seedDemoClient(ctx, db, logger) })
	wsHub := wsevents.NewHub(api.ValidateToken)

	tlsConfig, err := security.LoadTLSConfig(cfg.TLS)
	if err != nil {
		db.Close()
		return nil, err
	}
	if tlsConfig != nil {
		listener.SetTLS(tlsConfig)
	}

	dispatcher.SetNatHandler(coordinator.Handle)
	dispatcher.SetOnDisconnect(coordinator.Close)
	dispatcher.SetDirectHTTPAck(directHTTP.Ack)
	dispatcher.SetOnConnectionEvent(func(eventType string, record store.ConnectionRecord) {
		wsHub.Broadcast(wsevents.Event{Type: eventType, Connection: toConnectionView(record)})
	})
	dispatcher.SetOnLoginSuccess(func(conn *control.Conn) {
		pushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := natControl.PushToName(pushCtx, conn.ClientName()); err != nil {
			logger.Error("NAT_CONTROL push failed", "client", conn.ClientName(), "err", err)
		}
	})

	return &App{
		cfg:         cfg,
		logger:      logger,
		db:          db,
		sessions:    sessions,
		executor:    executor,
		listener:    listener,
		dispatcher:  dispatcher,
		traffic:     traffic,
		natControl:  natControl,
		remotePorts: remotePorts,
		tokens:      tokens,
		directHTTP:  directHTTP,
		wsHub:       wsHub,
		api:         api,
		tlsConfig:   tlsConfig,
		clientAuth:  clientSessions,
	}, nil
}

// DB exposes the store (used by tests and later phases).
func (a *App) DB() *store.DB { return a.db }

// Sessions exposes the session registry.
func (a *App) Sessions() *session.Registry { return a.sessions }

// ControlPort returns the bound control-channel port (valid after Run has started).
func (a *App) ControlPort() int { return a.listener.BoundPort() }

// RemotePorts exposes the NAT port manager (used by tests).
func (a *App) RemotePorts() *nat.RemotePortManager { return a.remotePorts }

// Traffic exposes the traffic service (used by tests to force a flush).
func (a *App) Traffic() *nat.TrafficService { return a.traffic }

// Tokens exposes the local token service (used by tests).
func (a *App) Tokens() *security.LocalTokenService { return a.tokens }

// Close releases resources.
func (a *App) Close() error { return a.db.Close() }

// Run starts the background workers, binds and serves the control channel, and serves the
// management HTTP surface until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	a.executor.Start(ctx, a.cfg.Login.ExecutorMaxSize)
	go a.traffic.Run(ctx)
	go runArchive(ctx, a.db, a.logger)

	controlAddr := ":" + strconv.Itoa(a.cfg.Netty.Port)
	if err := a.listener.Start(controlAddr); err != nil {
		return err
	}
	a.logger.Info("control channel listening", "port", a.listener.BoundPort())

	errc := make(chan error, 2)
	go func() { errc <- a.listener.Serve(ctx) }()

	httpServer := &http.Server{Addr: a.cfg.ManagementAddr, Handler: a.managementHandler()}
	if a.tlsConfig != nil {
		httpServer.TLSConfig = a.tlsConfig
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	go func() {
		a.logger.Info("management HTTP listening", "addr", a.cfg.ManagementAddr, "tls", a.tlsConfig != nil)
		var err error
		if a.tlsConfig != nil {
			err = httpServer.ListenAndServeTLS("", "")
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// managementHandler builds the full HTTP surface: admin API, Direct HTTP, WebSocket, the SPA,
// and /health, wrapped with security headers.
func (a *App) managementHandler() http.Handler {
	mux := http.NewServeMux()

	a.api.Register(mux)
	mux.HandleFunc("POST /api/client/auth/login", a.handleClientAuthLogin)

	mux.Handle("/http/{clientName}/{route}/{rest...}", a.directHTTP)
	mux.Handle("/http/{clientName}/{route}", a.directHTTP)
	mux.Handle("/ws/connections", a.wsHub)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	fileServer := http.FileServerFS(web.StaticFS())
	mux.Handle("/", fileServer)

	return securityHeaders(mux)
}

// securityHeaders adds the CSP and related response headers, mirroring the C# SecurityConfig.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func toConnectionView(record store.ConnectionRecord) wsevents.ConnectionView {
	view := wsevents.ConnectionView{
		ID:               record.ID,
		ClientID:         record.ClientID,
		ClientName:       record.ClientName,
		ChannelID:        record.ChannelID,
		RemoteAddress:    record.RemoteAddress,
		ConnectedAt:      record.ConnectedAt.Format(time.RFC3339Nano),
		Success:          record.Success,
		FailureReason:    record.FailureReason,
		DisconnectReason: record.DisconnectReason,
	}
	if record.DisconnectedAt != nil {
		formatted := record.DisconnectedAt.Format(time.RFC3339Nano)
		view.DisconnectedAt = &formatted
	}
	if record.DisconnectReason != nil {
		text := store.ReasonText(*record.DisconnectReason)
		view.DisconnectReasonText = &text
	}
	return view
}

func seedDemoClient(ctx context.Context, db *store.DB, logger *slog.Logger) error {
	now := time.Now()
	inserted, err := db.InsertClientIfAbsent(ctx, store.ClientAccount{
		ID:                           auth.NewClientID(),
		ClientName:                   DemoClientName,
		PasswordHash:                 auth.HashPassword(DemoClientPassword),
		Enabled:                      true,
		ConnectionRateLimitPerMinute: 30,
		CreatedAt:                    now,
		UpdatedAt:                    now,
	})
	if err != nil {
		return fmt.Errorf("seed demo client: %w", err)
	}
	if inserted {
		logger.Info("seeded demo client", "client", DemoClientName)
	}
	return nil
}
