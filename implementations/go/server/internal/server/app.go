package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/devShuai/specus/implementations/go/server/internal/auth"
	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/control"
	"github.com/devShuai/specus/implementations/go/server/internal/directhttp"
	"github.com/devShuai/specus/implementations/go/server/internal/management"
	"github.com/devShuai/specus/implementations/go/server/internal/media"
	"github.com/devShuai/specus/implementations/go/server/internal/nat"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/security"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
	"github.com/devShuai/specus/implementations/go/server/internal/transfer"
	"github.com/devShuai/specus/implementations/go/server/internal/wsevents"
	"github.com/devShuai/specus/implementations/go/server/web"
)

// Demo client seed credentials (match the C# server).
const (
	DemoClientName            = "Demo client"
	DemoCredentialAPIKey      = "demo-client"
	DemoCredentialPlainSecret = "test1234"
)

var errUnauthenticated = errors.New("packet on unauthenticated channel")

// App is the composed server: store + control channel + management HTTP surface.
type App struct {
	cfg                     config.Config
	logger                  *slog.Logger
	db                      *store.DB
	sessions                *session.Registry
	executor                *control.LoginExecutor
	listener                *control.Listener
	dispatcher              *Dispatcher
	traffic                 *nat.TrafficService
	natControl              *nat.ControlService
	remotePorts             *nat.RemotePortManager
	tokens                  *security.LocalTokenService
	directHTTP              *directhttp.Service
	wsHub                   *wsevents.Hub
	api                     *management.API
	peerMesh                *peermesh.Service
	tlsConfig               *tls.Config
	clientAuth              *auth.SessionStore
	clientMessages          *clientMessagesHub
	publicTransferDiscovery *publicTransferDiscoveryHub
	attachments             *transfer.Service
	rooms                   *transfer.RoomService
	mediaCapture            *media.Service
	webSocketTickets        *security.WebSocketTicketService
}

// New opens the database, applies the schema, seeds the demo client, and builds the app.
func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	if cfg.Netty.MaxFrameSize < protocol.FrameHeaderSize {
		return nil, fmt.Errorf("netty max frame size must be at least %d", protocol.FrameHeaderSize)
	}
	if err := security.ValidateTLSDeployment(cfg.TLS, cfg.Netty.BindAddress, cfg.ManagementAddr); err != nil {
		return nil, err
	}
	db, err := store.Open(cfg.Database.Provider, cfg.ConnectionString)
	if err != nil {
		return nil, err
	}
	if cfg.Elasticsearch.Configured() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := db.UseElasticsearchTraffic(ctx, store.ElasticsearchTrafficOptions{
			URIs:              cfg.Elasticsearch.EndpointURIs(),
			Username:          cfg.Elasticsearch.Username,
			Password:          cfg.Elasticsearch.Password,
			APIKey:            cfg.Elasticsearch.APIKey,
			HTTPIndex:         cfg.Elasticsearch.HTTPIndex,
			TCPIndex:          cfg.Elasticsearch.TCPIndex,
			HTTPMaxStoreBytes: config.ParseDataSizeBytes(cfg.Elasticsearch.HTTPMaxStoreSize, 100*1024*1024*1024),
			TCPMaxStoreBytes:  config.ParseDataSizeBytes(cfg.Elasticsearch.TCPMaxStoreSize, 10*1024*1024*1024),
		})
		cancel()
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("configure elasticsearch traffic detail: %w", err)
		}
		logger.Info("traffic detail store: elasticsearch",
			"httpIndex", cfg.Elasticsearch.HTTPIndex, "tcpIndex", cfg.Elasticsearch.TCPIndex)
	} else {
		logger.Info("traffic detail store: database")
	}

	if cfg.SeedDemoDataEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := seedDemoClient(ctx, db, logger, cfg.ClientAuth.DefaultMaxOnlineInstances)
		cancel()
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		closed, err := db.CloseClientSessionsByStatus(ctx, auth.StatusNettyOnline, auth.StatusDisconnected, time.Now())
		cancel()
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("close stale client sessions: %w", err)
		}
		if closed > 0 {
			logger.Info("closed stale client sessions at startup", "count", closed)
		}
	}
	// T-4：启动时关闭上一进程遗留的 open 连接记录（SERVER_RESTARTED），
	// 对齐 Java ConnectionRecordService.closeStaleOpenRecordsOnStartup。
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		closed, err := db.CloseStaleOpenConnections(ctx, store.ReasonServerRestarted, time.Now())
		cancel()
		if err != nil {
			logger.Warn("close stale open connections at startup failed", "err", err)
		} else if closed > 0 {
			logger.Info("closed stale open connections at startup", "count", closed, "reason", store.ReasonServerRestarted)
		}
	}

	sessions := session.NewRegistry()
	clientSessions := auth.NewSessionStore()
	executor := control.NewLoginExecutor(cfg.Login.ExecutorCoreSize, cfg.Login.ExecutorMaxSize,
		cfg.Login.ExecutorQueueCapacity)
	authenticator := auth.NewAuthenticator(db, clientSessions, cfg.ClientAuth.PerMachineUserMaxInstances, sessions)
	dispatcher := NewDispatcher(db, authenticator, sessions, executor, logger)
	listener := control.NewListener(control.ListenerOptions{
		MaxFrameSize: cfg.Netty.MaxFrameSize, PreAuthMaxFrameSize: cfg.Netty.PreAuthMaxFrameSize,
		WriteLowWaterMark:  cfg.Netty.WriteBufferLowWaterMark,
		WriteHighWaterMark: cfg.Netty.WriteBufferHighWaterMark,
		BossThreads:        cfg.Netty.BossThreads, WorkerThreads: cfg.Netty.WorkerThreads,
		SOBacklog: cfg.Netty.SOBacklog, ReuseAddress: cfg.Netty.ReuseAddress,
		KeepAlive: cfg.Netty.KeepAlive, TCPNoDelay: cfg.Netty.TCPNoDelay,
	}, dispatcher)

	traffic := nat.NewTrafficService(db, time.Duration(cfg.Traffic.FlushIntervalMs)*time.Millisecond, logger)
	db.ConfigureTrafficDetailQueue(cfg.Traffic.CaptureMaxPending, cfg.Traffic.CaptureFlushBatchSize)
	remotePorts := nat.NewRemotePortManagerWithOptions(cfg.Netty.MaxExternalConnections, nat.RemotePortOptions{
		BossThreads: cfg.Netty.RemoteBossThreads, WorkerThreads: cfg.Netty.RemoteWorkerThreads,
		SOBacklog: cfg.Netty.SOBacklog, ReuseAddress: cfg.Netty.ReuseAddress,
		KeepAlive: cfg.Netty.KeepAlive, TCPNoDelay: cfg.Netty.TCPNoDelay,
	})
	limits := nat.Limits{
		Global:              cfg.Netty.MaxExternalConnections,
		PerClient:           cfg.Netty.MaxExternalConnectionsPerClient,
		PerPort:             cfg.Netty.MaxExternalConnectionsPerPort,
		WriteBufferLowMark:  cfg.Netty.WriteBufferLowWaterMark,
		WriteBufferHighMark: cfg.Netty.WriteBufferHighWaterMark,
	}
	detailOptions := store.TrafficDetailOptions{
		Enabled:        cfg.Traffic.CaptureDetailEnabled,
		PreviewBytes:   cfg.Traffic.CapturePreviewBytes,
		HeaderChars:    cfg.Traffic.CaptureHeaderChars,
		DecodeMaxBytes: cfg.Traffic.CaptureDecodeMaxBytes,
		SampleRate:     cfg.Traffic.CaptureSampleRate,
	}
	coordinator := nat.NewCoordinator(remotePorts, traffic, db, detailOptions, limits, logger)
	natControl := nat.NewControlService(db, sessions, cfg.Netty.Port, cfg.PublicAddress)

	tokens := security.NewLocalTokenService(cfg.Auth)
	webSocketTickets := security.NewWebSocketTicketService(db)
	oidcValidator := security.NewOidcValidator(cfg.Oidc)
	peerMesh := peermesh.New(cfg.PeerMesh, db, sessions, logger)
	publicTransferDiscovery := newPublicTransferDiscoveryHubWithLogger(
		cfg.PublicTransfer, webSocketTickets, logger)
	if publicTransferDiscovery.startupErr != nil {
		_ = db.Close()
		return nil, publicTransferDiscovery.startupErr
	}
	attachments := transfer.NewService(db, cfg.ObjectStorage, cfg.PublicTransfer,
		transfer.SharedRateLimiterFunc(func(ctx context.Context, bucket, identity string,
			limit int, window time.Duration) (bool, error) {
			if publicTransferDiscovery.coordination == nil {
				return false, errors.New("public transfer coordination is unavailable")
			}
			return publicTransferDiscovery.coordination.allowRate(ctx, bucket, identity, limit, window)
		}))
	rooms := transfer.NewRoomService(db, cfg.PublicTransfer, tokens,
		transfer.SharedRateLimiterFunc(func(ctx context.Context, bucket, identity string,
			limit int, window time.Duration) (bool, error) {
			if publicTransferDiscovery.coordination == nil {
				return false, errors.New("public transfer coordination is unavailable")
			}
			return publicTransferDiscovery.coordination.allowRate(ctx, bucket, identity, limit, window)
		}))
	mediaStorage := media.NewRustFSStorage(cfg.MediaCapture)
	{
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := mediaStorage.Initialize(ctx)
		cancel()
		if err != nil {
			_ = publicTransferDiscovery.Close()
			_ = db.Close()
			return nil, fmt.Errorf("configure RustFS media capture: %w", err)
		}
	}
	mediaCapture := media.NewService(db, cfg.MediaCapture, mediaStorage, logger)
	directHTTP := directhttp.NewService(sessions,
		func(clientName string, metadata map[string]any) (directhttp.Stream, error) {
			return coordinator.OpenHTTPStream(clientName, metadata)
		},
		func(clientName string, metadata map[string]any, conn *websocket.Conn) (*directhttp.WebSocketSpecus, error) {
			return coordinator.OpenWSStream(clientName, metadata, conn)
		},
		time.Duration(cfg.HTTP.TimeoutMs)*time.Millisecond, cfg.HTTP.MaxRequestBodySize,
		cfg.HTTP.RewriteMaxBodyBytes, traffic, db, db, detailOptions)
	directHTTP.SetMediaCapture(func(ctx context.Context, clientName, route, method, sourceURL string,
		statusCode int, responseHeaders []string) directhttp.MediaCaptureSession {
		return mediaCapture.Open(ctx, clientName, route, method, sourceURL, statusCode, responseHeaders)
	})
	directHTTP.SetReconnectGrace(3 * time.Second)
	directHTTP.SetRouteCacheTTL(time.Duration(cfg.HTTP.RouteCacheTTLms) * time.Millisecond)
	api := management.NewAPI(db, sessions, tokens, oidcValidator, natControl, remotePorts, cfg.Oidc, cfg.Auth,
		cfg.ClientAuth, cfg.Traffic, traffic, func(ctx context.Context) error {
			return seedDemoClient(ctx, db, logger, cfg.ClientAuth.DefaultMaxOnlineInstances)
		}, peerMesh, attachments, rooms, logger)
	api.SetMediaCapture(mediaCapture)
	wsHub := wsevents.NewHub(webSocketTickets, func(access wsevents.Access, event wsevents.Event) bool {
		if access.Admin {
			return true
		}
		if event.Connection.ClientID == nil {
			return false
		}
		account, err := db.GetClient(context.Background(), *event.Connection.ClientID)
		return err == nil && account != nil &&
			account.TenantID == access.TenantID && account.OwnerUsername == access.Username
	})
	if coordination := publicTransferDiscovery.coordination; coordination.enabled() {
		wsHub.ConfigureCluster(wsevents.ClusterTransport{
			Publish: coordination.publishManagement,
			Subscribe: func(listener func([]byte)) {
				coordination.addListener(func(event publicTransferClusterEvent) {
					if event.kind != clusterEventKindManagement {
						return
					}
					var managementEvent wsevents.Event
					if err := json.Unmarshal(event.payload, &managementEvent); err != nil ||
						strings.TrimSpace(managementEvent.TenantID) == "" ||
						event.groupID != managementGroupID(managementEvent.TenantID) {
						logger.Warn("discarding management cluster event with invalid tenant binding")
						return
					}
					listener(event.payload)
				})
			},
			Report: func(err error) {
				logger.Warn("management cluster event delivery failed", "err", err)
			},
		})
	}
	clientMessages := newClientMessagesHub(db, sessions, webSocketTickets, logger)
	tlsConfig, err := security.LoadTLSConfig(cfg.TLS)
	if err != nil {
		_ = publicTransferDiscovery.Close()
		db.Close()
		return nil, err
	}
	if tlsConfig != nil {
		listener.SetTLS(tlsConfig)
	}

	dispatcher.SetNatHandler(coordinator.Handle)
	dispatcher.SetPeerControlHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
		return peerMesh.HandleSignal(conn.Context(), request, conn.ClientName())
	})
	dispatcher.SetOnDisconnect(coordinator.Close)
	dispatcher.SetOnDataLoginSuccess(coordinator.Attach)
	dispatcher.SetClientMessageHandler(func(conn *control.Conn, request protocol.MessageRequest) error {
		return (&App{db: db, sessions: sessions, peerMesh: peerMesh, clientMessages: clientMessages, logger: logger}).handleClientMessage(conn, request)
	})
	dispatcher.SetOnConnectionEvent(func(eventType string, record store.ConnectionRecord) {
		wsHub.Broadcast(wsevents.Event{
			TenantID:   record.TenantID,
			Type:       eventType,
			Connection: toConnectionView(record),
		})
	})
	dispatcher.SetOnLoginSuccess(func(conn *control.Conn) {
		pushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := natControl.PushToName(pushCtx, conn.ClientName()); err != nil {
			logger.Error("NAT_CONTROL push failed", "client", conn.ClientName(), "err", err)
		}
		if account, err := db.FindClientByName(pushCtx, conn.ClientName()); err == nil && account != nil {
			peerMesh.PushOnLogin(pushCtx, *account)
		}
	})

	return &App{
		cfg:                     cfg,
		logger:                  logger,
		db:                      db,
		sessions:                sessions,
		executor:                executor,
		listener:                listener,
		dispatcher:              dispatcher,
		traffic:                 traffic,
		natControl:              natControl,
		remotePorts:             remotePorts,
		tokens:                  tokens,
		directHTTP:              directHTTP,
		wsHub:                   wsHub,
		api:                     api,
		peerMesh:                peerMesh,
		tlsConfig:               tlsConfig,
		clientAuth:              clientSessions,
		clientMessages:          clientMessages,
		publicTransferDiscovery: publicTransferDiscovery,
		attachments:             attachments,
		rooms:                   rooms,
		mediaCapture:            mediaCapture,
		webSocketTickets:        webSocketTickets,
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
func (a *App) Close() error {
	mediaCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	mediaErr := a.mediaCapture.Close(mediaCtx)
	cancel()
	coordinationErr := a.publicTransferDiscovery.Close()
	databaseErr := a.db.Close()
	if mediaErr != nil {
		return mediaErr
	}
	if coordinationErr != nil {
		return coordinationErr
	}
	return databaseErr
}

// Run starts the background workers, binds and serves the control channel, and serves the
// management HTTP surface until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	a.executor.Start(ctx)
	go a.traffic.Run(ctx)
	go a.peerMesh.Run(ctx)
	go a.peerMesh.RunStunTurn(ctx)
	go a.attachments.RunExpiration(ctx)
	go a.mediaCapture.Run(ctx)
	go a.api.RunRegistrationCleanup(ctx)
	go a.db.RunTrafficDetailFlush(ctx,
		time.Duration(a.cfg.Traffic.CaptureFlushIntervalMs)*time.Millisecond,
		func(err error) { a.logger.Error("traffic detail flush failed", "err", err) })
	go runArchive(ctx, a.db, a.logger, a.cfg.ConnectionRecord)

	controlAddr := net.JoinHostPort(strings.TrimSpace(a.cfg.Netty.BindAddress),
		fmt.Sprint(a.cfg.Netty.Port))
	if err := a.listener.Start(controlAddr); err != nil {
		return err
	}
	a.logger.Info("control channel listening", "port", a.listener.BoundPort())

	errc := make(chan error, 2)
	go func() { errc <- a.listener.Serve(ctx) }()

	httpServer := &http.Server{
		Addr:     a.cfg.ManagementAddr,
		Handler:  a.managementHandler(),
		ErrorLog: slog.NewLogLogger(a.logger.Handler(), slog.LevelError),
	}
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
		// T-4：优雅关停时关闭所有 open 连接记录（SERVER_SHUTDOWN），
		// 对齐 Java ConnectionRecordService.markAllOpenAsShutdownOnContextClose。
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if closed, err := a.db.CloseStaleOpenConnections(shutdownCtx, store.ReasonServerShutdown, time.Now()); err != nil {
			a.logger.Warn("close open connections on shutdown failed", "err", err)
		} else if closed > 0 {
			a.logger.Info("closed open connections on shutdown", "count", closed, "reason", store.ReasonServerShutdown)
		}
		cancel()
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
	mux.HandleFunc("POST /api/admin/ws-tickets", a.handleAdminWebSocketTicket)
	mux.HandleFunc("POST /api/public/transfer/ws-tickets", a.handlePublicWebSocketTicket)
	mux.HandleFunc("GET /api/public/transfer/clients/name-availability", func(w http.ResponseWriter, r *http.Request) {
		result, err := a.publicTransferDiscovery.checkClientNameAvailability(r.Context(),
			r.URL.Query().Get("clientName"), r.URL.Query().Get("excludePeerId"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})

	mux.Handle("/http/{clientName}/{route}/{rest...}", a.directHTTP)
	mux.Handle("/http/{clientName}/{route}", a.directHTTP)
	mux.Handle("/ws/connections", a.wsHub)
	mux.Handle("/ws/client-messages", a.clientMessages)
	mux.Handle("/ws/public-transfer/discovery", a.publicTransferDiscovery)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	fileServer := http.FileServerFS(web.StaticFS())
	mux.Handle("/", staticResourceCacheHeaders(fileServer))

	return a.observeManagementHTTP(securityHeaders(mux, a.cfg.ObjectStorage))
}

func staticResourceCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/assets/"):
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		case strings.HasPrefix(r.URL.Path, "/schemas/"):
			w.Header().Set("Cache-Control", "public, max-age=3600")
		case r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.svg" ||
			r.URL.Path == "/logo.svg" || r.URL.Path == "/gtag-init.js":
			w.Header().Set("Cache-Control", "public, max-age=604800")
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds the CSP and related response headers, mirroring the Java SecurityConfig.
func securityHeaders(next http.Handler, objectStorage config.ObjectStorageConfig) http.Handler {
	ossSuffix := ""
	if origin := objectStorageCSPOrigin(objectStorage); origin != "" {
		ossSuffix = " " + origin
	}
	policy := "default-src 'self'; " +
		"script-src 'self' https://www.googletagmanager.com https://challenges.cloudflare.com 'sha256-18LyML/37soz5WqRSkGT3SWKUgOA6TN/LeY+x9y/X/Q=' 'sha256-sTRDNOsQlwtkSpNEy6tDUxqi0/WSUG1VrhzE550hzwo='; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' blob: data: https://www.google-analytics.com https://*.googletagmanager.com" + ossSuffix + "; " +
		"media-src 'self' blob: data:" + ossSuffix + "; " +
		"object-src 'self' blob:; frame-src 'self' blob: https://challenges.cloudflare.com; font-src 'self' data:; " +
		"connect-src 'self' ws: wss: https://api.github.com https://www.google-analytics.com https://*.analytics.google.com https://*.googletagmanager.com" + ossSuffix + "; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HTTP specus responses belong to the target application. Adding the portal
		// policy here would make browsers enforce both policies and can block target
		// features such as WebAssembly even when the application explicitly allows it.
		if r.URL.Path == "/http" || strings.HasPrefix(r.URL.Path, "/http/") {
			next.ServeHTTP(w, r)
			return
		}
		header := w.Header()
		header.Set("Content-Security-Policy", policy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func objectStorageCSPOrigin(cfg config.ObjectStorageConfig) string {
	if !strings.EqualFold(strings.TrimSpace(cfg.Provider), "aliyun-oss") {
		return ""
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	bucket := strings.TrimSpace(cfg.Bucket)
	if endpoint == "" || bucket == "" {
		return ""
	}
	lowerEndpoint := strings.ToLower(endpoint)
	if strings.HasPrefix(lowerEndpoint, "https://") {
		endpoint = endpoint[len("https://"):]
	} else if strings.HasPrefix(lowerEndpoint, "http://") {
		endpoint = endpoint[len("http://"):]
	}
	if slash := strings.IndexByte(endpoint, '/'); slash >= 0 {
		endpoint = endpoint[:slash]
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	return "https://" + bucket + "." + endpoint
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

func seedDemoClient(ctx context.Context, db *store.DB, logger *slog.Logger, defaultMaxOnlineInstances int) error {
	if defaultMaxOnlineInstances < 1 || defaultMaxOnlineInstances > 10000 {
		defaultMaxOnlineInstances = 2
	}
	now := time.Now()
	inserted, err := db.InsertClientIfAbsent(ctx, store.ClientAccount{
		ID:                           auth.NewClientID(),
		TenantID:                     "default",
		OwnerUsername:                "admin",
		ClientName:                   DemoClientName,
		PasswordHash:                 auth.HashPassword(DemoCredentialPlainSecret),
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
	if _, err := db.InsertCredentialIfAbsent(ctx, store.ClientCredential{
		ID:                 auth.NewClientID(),
		TenantID:           "default",
		OwnerUsername:      "admin",
		APIKey:             DemoCredentialAPIKey,
		SecretHash:         auth.HashPassword(DemoCredentialPlainSecret),
		Enabled:            true,
		MaxOnlineInstances: defaultMaxOnlineInstances,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		return fmt.Errorf("seed demo credential: %w", err)
	}
	return nil
}
