package com.theshuai.tunnel.android;

import android.content.Context;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.SocketFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class TunnelCore {
    static final int CONTROL_READ_IDLE_TIMEOUT_MILLIS = 60_000;

    private TunnelCore() {
    }

    interface StatusListener {
        void onStatus(String status, String detail, boolean running);
    }

    public interface VpnPacketHandler {
        void onPacket(byte[] packet);
    }

    public interface VpnPlatform {
        void startVpn(PeerMeshConfig config, VpnPacketHandler packetHandler) throws Exception;

        void stopVpn();

        boolean protectSocket(Socket socket);

        boolean protectDatagramSocket(java.net.DatagramSocket socket);

        void writeVpnPacket(byte[] packet) throws Exception;
    }

    public static final class Runtime implements Runnable {
        private final Context context;
        private final String configText;
        private final StatusListener listener;
        private final VpnPlatform vpnPlatform;
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final ExecutorService ioPool = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "shuai-tunnel-io");
            thread.setDaemon(true);
            return thread;
        });
        private volatile ControlConnection connection;

        Runtime(Context context, String configText, StatusListener listener, VpnPlatform vpnPlatform) {
            this.context = context.getApplicationContext();
            this.configText = configText;
            this.listener = listener;
            this.vpnPlatform = vpnPlatform;
        }

        public boolean isRunning() {
            return running.get();
        }

        public void stop() {
            running.set(false);
            closeQuietly(connection);
            ioPool.shutdownNow();
        }

        public void sendClientMessage(String toClientName, String message) throws Exception {
            if (!running.get()) {
                throw new IllegalStateException("tunnel runtime is not running");
            }
            ControlConnection current = connection;
            if (current == null) {
                throw new IllegalStateException("control channel is not connected");
            }
            current.sendClientMessage(toClientName, message);
        }

        @Override
        public void run() {
            int attempt = 0;
            try {
                StartupConfig config = StartupConfig.parse(configText);
                while (running.get()) {
                    ControlConnection next = null;
                    try {
                        publish("HTTP login", config.serverBaseUrl, true);
                        TunnelSession session = AuthClient.login(context, config);
                        session.applyStartup(config);
                        startOrStopVpn(session);
                        publish("Control connecting", session.nettyHost + ":" + session.nettyPort, true);
                        next = new ControlConnection(
                                session,
                                ioPool,
                                this::publish,
                                running,
                                vpnPlatform,
                                () -> {
                                    TunnelSession refreshed = AuthClient.login(context, config);
                                    refreshed.applyStartup(config);
                                    return refreshed;
                                });
                        connection = next;
                        next.runBlocking();
                        if (running.get()) {
                            publish("Disconnected", "control channel closed", true);
                        }
                    } catch (Throwable error) {
                        if (!running.get()) {
                            break;
                        }
                        if (next != null && next.exitAction() == ControlExitAction.IMMEDIATE_HTTP_LOGIN) {
                            publish("HTTP relogin", next.exitReason(), true);
                        } else if (next != null && next.exitAction() == ControlExitAction.STOP_RECONNECTING) {
                            publish("Login rejected", next.exitReason(), false);
                        } else {
                            publish("Error", message(error), true);
                        }
                    } finally {
                        closeQuietly(connection);
                        connection = null;
                    }
                    ControlExitAction exitAction = next == null
                            ? ControlExitAction.RETRY_WITH_BACKOFF
                            : next.exitAction();
                    if (exitAction == ControlExitAction.STOP_RECONNECTING) {
                        running.set(false);
                        break;
                    }
                    if (exitAction == ControlExitAction.IMMEDIATE_HTTP_LOGIN && running.get()) {
                        attempt = 0;
                        continue;
                    }
                    if (next != null && next.loginSucceeded()) {
                        attempt = 0;
                    }
                    if (running.get()) {
                        long delay = reconnectDelaySeconds(++attempt);
                        publish("Reconnect pending", delay + "s", true);
                        sleepSeconds(delay);
                    }
                }
            } catch (Throwable error) {
                publish("Stopped", message(error), false);
            } finally {
                running.set(false);
                ioPool.shutdownNow();
                if (vpnPlatform != null) {
                    vpnPlatform.stopVpn();
                }
                publish("Stopped", "", false);
            }
        }

        private void startOrStopVpn(TunnelSession session) throws Exception {
            if (vpnPlatform == null) {
                return;
            }
            PeerMeshConfig peerMesh = session.peerMesh;
            if (peerMesh != null && peerMesh.enabled) {
                vpnPlatform.startVpn(peerMesh, packet -> {
                    // The control-channel peer mesh engine owns the live packet handler once
                    // control login succeeds. This early setup is intentionally inert.
                });
            } else {
                vpnPlatform.stopVpn();
            }
        }

        private void publish(String status, String detail, boolean active) {
            if (listener != null) {
                listener.onStatus(status, detail == null ? "" : detail, active);
            }
        }

        private long reconnectDelaySeconds(int attempt) {
            int shift = Math.min(Math.max(attempt - 1, 0), 5);
            return Math.min(2L * (1L << shift), 60L);
        }

        private void sleepSeconds(long seconds) {
            long end = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(seconds);
            while (running.get() && System.currentTimeMillis() < end) {
                try {
                    Thread.sleep(Math.min(1000L, end - System.currentTimeMillis()));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private interface StatusSink {
        void publish(String status, String detail, boolean running);
    }

    private interface SessionRefresher {
        TunnelSession refresh() throws Exception;
    }

    enum LoginFailureAction {
        REFRESH_CREDENTIALS,
        RETRY_WITH_BACKOFF,
        STOP_RECONNECTING;

        static LoginFailureAction classify(String reason) {
            String value = reason == null ? "" : reason.trim().toLowerCase(Locale.ROOT);
            if (value.contains("访问令牌已过期")
                    || value.contains("令牌已过期")
                    || value.contains("令牌过期")
                    || (value.contains("token") && (value.contains("expired") || value.contains("expire")))) {
                return REFRESH_CREDENTIALS;
            }
            if (value.contains("服务器繁忙")
                    || value.contains("连接频率超过限制")
                    || value.contains("server busy")
                    || value.contains("temporarily busy")
                    || value.contains("rate limit")
                    || value.contains("rate-limit")
                    || value.contains("too many requests")
                    || value.contains("connection frequency")
                    || value.contains("try again later")) {
                return RETRY_WITH_BACKOFF;
            }
            return STOP_RECONNECTING;
        }
    }

    enum ControlExitAction {
        RETRY_WITH_BACKOFF,
        IMMEDIATE_HTTP_LOGIN,
        STOP_RECONNECTING
    }

    static final class HeartbeatPolicy {
        static final long WRITE_IDLE_MILLIS = 5_000L;

        private HeartbeatPolicy() {
        }

        static boolean shouldSend(long nowMillis, long lastWriteAtMillis) {
            return lastWriteAtMillis > 0L && nowMillis - lastWriteAtMillis >= WRITE_IDLE_MILLIS;
        }
    }

    static final class TcpConnectedPolicy {
        private TcpConnectedPolicy() {
        }

        static boolean shouldIgnore(Integer port, String channelId, boolean configuredPort) {
            return port == null || isBlank(channelId) || !configuredPort;
        }
    }

    private static final class StartupConfig {
        final String serverBaseUrl;
        final String apiKey;
        final String secret;
        final String peerMeshDevice;
        final String peerMeshTunName;
        final int peerMeshMtu;

        private StartupConfig(String serverBaseUrl, String apiKey, String secret,
                              String peerMeshDevice, String peerMeshTunName, int peerMeshMtu) {
            this.serverBaseUrl = serverBaseUrl;
            this.apiKey = apiKey;
            this.secret = secret;
            this.peerMeshDevice = peerMeshDevice;
            this.peerMeshTunName = peerMeshTunName;
            this.peerMeshMtu = peerMeshMtu;
        }

        static StartupConfig parse(String jsonc) throws Exception {
            JSONObject json = new JSONObject(Jsonc.toJson(jsonc));
            String serverBaseUrl = required(json, "serverBaseUrl");
            String apiKey = required(json, "apiKey");
            String secret = required(json, "secret");
            return new StartupConfig(
                    trimTrailingSlash(serverBaseUrl),
                    apiKey.trim(),
                    secret.trim(),
                    firstText(json.optString("peerMeshDevice", "noop").trim(), "noop"),
                    firstText(json.optString("peerMeshTunName", "shuai0").trim(), "shuai0"),
                    PeerMeshConfig.normalizeMtu(json.optInt("peerMeshMtu", PeerMeshConfig.DEFAULT_MTU)));
        }

        private static String required(JSONObject json, String name) throws Exception {
            String value = json.optString(name, "");
            if (value.trim().isEmpty()) {
                throw new IllegalArgumentException("config missing " + name);
            }
            return value;
        }
    }

    private static final class AuthClient {
        static TunnelSession login(Context context, StartupConfig config) throws Exception {
            ClientEnvironment environment = ClientEnvironment.collect(context);
            String timestamp = String.valueOf(System.currentTimeMillis());
            String nonce = UUID.randomUUID().toString().replace("-", "");
            String signature = Hmac.signApiKey(config.apiKey, timestamp, nonce, environment, config.secret);

            JSONObject body = new JSONObject();
            body.put("apiKey", config.apiKey);
            body.put("timestamp", timestamp);
            body.put("nonce", nonce);
            body.put("signature", signature);
            body.put("environment", environment.toJson());

            URL url = new URL(config.serverBaseUrl + "/api/client/auth/login");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(10_000);
            connection.setReadTimeout(20_000);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setDoOutput(true);
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(bytes.length);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(bytes);
            }

            int status = connection.getResponseCode();
            byte[] responseBody = readLimited(status >= 400 ? connection.getErrorStream() : connection.getInputStream(), 1024 * 1024);
            String response = new String(responseBody, StandardCharsets.UTF_8);
            if (status < 200 || status >= 300) {
                throw new IOException("HTTP login failed " + status + ": " + response);
            }
            TunnelSession session = TunnelSession.fromLoginJson(new JSONObject(response));
            if (isBlank(session.clientName)
                    || session.clientSessionId == null
                    || session.clientSessionId <= 0
                    || isBlank(session.accessToken)
                    || isBlank(session.nettyHost)
                    || session.nettyPort <= 0) {
                throw new IOException("HTTP login response is incomplete");
            }
            return session;
        }
    }

    static final class ClientEnvironment {
        String machineFingerprint;
        String hostname;
        String osUser;
        String osName;
        String osVersion;
        String osArch;
        String clientVersion;
        String javaVersion;
        String peerPublicKey;
        ClientMessageCapabilities clientMessageCapabilities = new ClientMessageCapabilities();
        List<String> localAddresses = new ArrayList<>();
        String startedAt;

        static ClientEnvironment collect(Context context) {
            PeerMeshEngine.AppContextHolder.context = context == null ? null : context.getApplicationContext();
            ClientEnvironment info = new ClientEnvironment();
            info.machineFingerprint = ConfigStorage.machineId(context);
            info.hostname = Build.MODEL == null ? "android" : Build.MODEL;
            info.osUser = "android";
            info.osName = "Android";
            info.osVersion = Build.VERSION.RELEASE;
            info.osArch = System.getProperty("os.arch", "");
            info.clientVersion = "android-0.1.0";
            info.javaVersion = System.getProperty("java.version", "");
            info.peerPublicKey = PeerMeshEngine.KeyStore.publicKeyBase64(context);
            info.clientMessageCapabilities = ClientMessageCapabilities.androidDefault();
            info.localAddresses = localAddresses();
            info.startedAt = Instant.now().toString();
            return info;
        }

        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject();
            json.put("machineFingerprint", machineFingerprint);
            json.put("hostname", hostname);
            json.put("osUser", osUser);
            json.put("osName", osName);
            json.put("osVersion", osVersion);
            json.put("osArch", osArch);
            json.put("clientVersion", clientVersion);
            json.put("javaVersion", javaVersion);
            json.put("peerPublicKey", peerPublicKey);
            json.put("clientMessageCapabilities", clientMessageCapabilities.toJson());
            json.put("localAddresses", new JSONArray(localAddresses));
            json.put("startedAt", startedAt);
            return json;
        }

        private static List<String> localAddresses() {
            List<String> addresses = new ArrayList<>();
            try {
                for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                        continue;
                    }
                    for (InetAddress address : Collections.list(ni.getInetAddresses())) {
                        if (!address.isLoopbackAddress() && !address.isLinkLocalAddress()) {
                            addresses.add(address.getHostAddress());
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            return addresses;
        }
    }

    static final class ClientMessageCapabilities {
        boolean sendMessages;
        boolean receiveMessages;
        boolean attachments;
        boolean mediaPreview;
        long maxAttachmentBytes;

        static ClientMessageCapabilities androidDefault() {
            ClientMessageCapabilities capabilities = new ClientMessageCapabilities();
            capabilities.sendMessages = true;
            capabilities.receiveMessages = true;
            // Android currently renders STMSG2 attachment metadata, but it does not
            // download attachment objects or preview media. Do not advertise those
            // capabilities until the complete receive path exists.
            capabilities.attachments = false;
            capabilities.mediaPreview = false;
            capabilities.maxAttachmentBytes = 0L;
            return capabilities;
        }

        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject();
            json.put("sendMessages", sendMessages);
            json.put("receiveMessages", receiveMessages);
            json.put("attachments", attachments);
            json.put("mediaPreview", mediaPreview);
            json.put("maxAttachmentBytes", maxAttachmentBytes);
            return json;
        }
    }

    static final class TokenRefresh {
        static final long MIN_LEAD_MILLIS = TimeUnit.SECONDS.toMillis(30L);
        static final long MAX_LEAD_MILLIS = TimeUnit.SECONDS.toMillis(300L);
        static final long MIN_DELAY_MILLIS = TimeUnit.SECONDS.toMillis(5L);
        static final long RETRY_DELAY_MILLIS = TimeUnit.SECONDS.toMillis(60L);

        private TokenRefresh() {
        }

        static long expiresAtMillis(long nowMillis, long ttlSeconds) {
            if (ttlSeconds <= 0L) {
                return 0L;
            }
            long ttlMillis = TimeUnit.SECONDS.toMillis(ttlSeconds);
            return Long.MAX_VALUE - nowMillis < ttlMillis ? Long.MAX_VALUE : nowMillis + ttlMillis;
        }

        static long delayMillis(long expiresAtMillis, long nowMillis) {
            long remainingMillis = expiresAtMillis - nowMillis;
            if (expiresAtMillis <= 0L || remainingMillis <= 0L) {
                return MIN_DELAY_MILLIS;
            }
            long leadMillis;
            if (remainingMillis <= MIN_LEAD_MILLIS * 2L) {
                leadMillis = Math.max(MIN_DELAY_MILLIS, remainingMillis / 2L);
            } else {
                leadMillis = Math.min(MAX_LEAD_MILLIS,
                        Math.max(MIN_LEAD_MILLIS, remainingMillis / 10L));
            }
            return Math.max(MIN_DELAY_MILLIS, remainingMillis - leadMillis);
        }
    }

    static final class TunnelSession {
        volatile String clientName;
        volatile Long clientSessionId;
        volatile String accessToken;
        volatile long tokenTtlSeconds;
        volatile long tokenExpiresAtMillis;
        volatile String nettyHost;
        volatile int nettyPort;
        volatile PeerMeshConfig peerMesh = new PeerMeshConfig();
        volatile List<TunnelEndpoint> tunnels = new ArrayList<>();
        volatile List<HttpRouteEndpoint> httpRoutes = new ArrayList<>();

        static TunnelSession fromLoginJson(JSONObject json) {
            TunnelSession session = new TunnelSession();
            session.clientName = json.optString("clientName", null);
            session.clientSessionId = json.optLong("clientSessionId", 0L);
            session.accessToken = json.optString("accessToken", null);
            session.tokenTtlSeconds = json.optLong("tokenTtlSeconds", 0L);
            if (session.tokenTtlSeconds > 0L) {
                session.tokenExpiresAtMillis = TokenRefresh.expiresAtMillis(
                        System.currentTimeMillis(), session.tokenTtlSeconds);
            }
            session.nettyHost = json.optString("nettyHost", null);
            session.nettyPort = json.optInt("nettyPort", 0);
            session.tunnels = parseTunnels(json.optJSONArray("tunnelConfigList"));
            session.httpRoutes = parseHttpRoutes(json.optJSONArray("httpTunnelConfigList"));
            session.peerMesh = PeerMeshConfig.parse(json.optJSONObject("peerMesh"));
            return session;
        }

        void applyStartup(StartupConfig config) {
            if (peerMesh == null) {
                peerMesh = new PeerMeshConfig();
            }
            peerMesh.mtu = PeerMeshConfig.normalizeMtu(config.peerMeshMtu);
        }

        synchronized void applyRefresh(TunnelSession refreshed) {
            if (refreshed == null
                    || isBlank(refreshed.clientName)
                    || refreshed.clientSessionId == null
                    || refreshed.clientSessionId <= 0L
                    || isBlank(refreshed.accessToken)
                    || isBlank(refreshed.nettyHost)
                    || refreshed.nettyPort <= 0) {
                throw new IllegalArgumentException("refreshed HTTP login response is incomplete");
            }
            clientName = refreshed.clientName;
            clientSessionId = refreshed.clientSessionId;
            accessToken = refreshed.accessToken;
            tokenTtlSeconds = refreshed.tokenTtlSeconds;
            tokenExpiresAtMillis = refreshed.tokenExpiresAtMillis;
            nettyHost = refreshed.nettyHost;
            nettyPort = refreshed.nettyPort;
            tunnels = refreshed.tunnels == null ? new ArrayList<>() : refreshed.tunnels;
            httpRoutes = refreshed.httpRoutes == null ? new ArrayList<>() : refreshed.httpRoutes;
            peerMesh = refreshed.peerMesh == null ? new PeerMeshConfig() : refreshed.peerMesh;
        }

        void applyRuntimeJson(String message) throws Exception {
            JSONObject json = new JSONObject(message);
            JSONArray tunnelArray = json.optJSONArray("tunnelConfigList");
            if (tunnelArray != null) {
                tunnels = parseTunnels(tunnelArray);
            }
            JSONArray routeArray = json.optJSONArray("httpTunnelConfigList");
            if (routeArray != null) {
                httpRoutes = parseHttpRoutes(routeArray);
            }
            String nextName = json.optString("clientName", "");
            if (!nextName.trim().isEmpty()) {
                clientName = nextName;
            }
            JSONObject peerMeshJson = json.optJSONObject("peerMesh");
            if (peerMeshJson != null) {
                PeerMeshConfig updated = PeerMeshConfig.parse(peerMeshJson);
                updated.mtu = peerMesh == null ? 1280 : peerMesh.mtu;
                peerMesh = updated;
            }
        }

        Map<Integer, TunnelEndpoint> tunnelMap() {
            Map<Integer, TunnelEndpoint> map = new HashMap<>();
            for (TunnelEndpoint endpoint : tunnels) {
                map.put(endpoint.port, endpoint);
            }
            return map;
        }

        Map<String, String> routeMap() {
            Map<String, String> map = new HashMap<>();
            for (HttpRouteEndpoint endpoint : httpRoutes) {
                if (endpoint.route != null && !endpoint.route.trim().isEmpty()) {
                    map.put(endpoint.route, endpoint.targetBaseUrl == null ? "" : endpoint.targetBaseUrl);
                }
            }
            return map;
        }

        private static List<TunnelEndpoint> parseTunnels(JSONArray array) {
            List<TunnelEndpoint> result = new ArrayList<>();
            if (array == null) {
                return result;
            }
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                TunnelEndpoint endpoint = new TunnelEndpoint();
                endpoint.port = item.optInt("port", 0);
                endpoint.tunnelAddress = item.optString("tunnelAddress", "127.0.0.1");
                endpoint.tunnelPort = item.optInt("tunnelPort", 0);
                if (endpoint.port > 0 && endpoint.tunnelPort > 0) {
                    result.add(endpoint);
                }
            }
            return result;
        }

        private static List<HttpRouteEndpoint> parseHttpRoutes(JSONArray array) {
            List<HttpRouteEndpoint> result = new ArrayList<>();
            if (array == null) {
                return result;
            }
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                HttpRouteEndpoint endpoint = new HttpRouteEndpoint();
                endpoint.route = item.optString("route", "");
                endpoint.targetBaseUrl = item.optString("targetBaseUrl", "");
                if (!endpoint.route.trim().isEmpty()) {
                    result.add(endpoint);
                }
            }
            return result;
        }
    }

    private static final class TunnelEndpoint {
        int port;
        String tunnelAddress;
        int tunnelPort;
    }

    private static final class HttpRouteEndpoint {
        String route;
        String targetBaseUrl;
    }

    public static final class PeerMeshConfig {
        static final int DEFAULT_MTU = 1280;
        static final int MIN_MTU = 576;
        static final int MAX_MTU = 1280;

        public boolean enabled;
        public long clientId;
        public String clientName;
        public String virtualIp;
        public String cidr;
        public String stunHost;
        public int stunPort;
        public String turnHost;
        public int turnPort;
        public List<String> publicStunServers = new ArrayList<>();
        public String serverPublicKey;
        public String clientPublicKey;
        public volatile String iceUsername;
        public volatile String iceCredential;
        public volatile String iceRealm;
        public volatile String iceNonce;
        public long sessionTtlSeconds;
        public int mtu = DEFAULT_MTU;
        public volatile List<String> peerRoutes = List.of();

        static int normalizeMtu(int mtu) {
            return mtu > 0 ? Math.max(MIN_MTU, Math.min(mtu, MAX_MTU)) : DEFAULT_MTU;
        }

        static List<String> normalizePeerRoutes(List<String> routes, String ownVirtualIp) {
            TreeSet<String> normalized = new TreeSet<>();
            if (routes != null) {
                for (String route : routes) {
                    String address = route == null ? "" : route.trim();
                    if (isIpv4Address(address) && !address.equals(ownVirtualIp)) {
                        normalized.add(address);
                    }
                }
            }
            return List.copyOf(normalized);
        }

        private static boolean isIpv4Address(String address) {
            String[] parts = address.split("\\.", -1);
            if (parts.length != 4) {
                return false;
            }
            for (String part : parts) {
                if (part.isEmpty()) {
                    return false;
                }
                for (int i = 0; i < part.length(); i++) {
                    if (!Character.isDigit(part.charAt(i))) {
                        return false;
                    }
                }
                try {
                    if (Integer.parseInt(part) > 255) {
                        return false;
                    }
                } catch (NumberFormatException error) {
                    return false;
                }
            }
            return true;
        }

        static PeerMeshConfig parse(JSONObject json) {
            PeerMeshConfig config = new PeerMeshConfig();
            if (json == null) {
                return config;
            }
            config.enabled = json.optBoolean("enabled", false);
            config.clientId = json.optLong("clientId", 0L);
            config.clientName = json.optString("clientName", "");
            config.virtualIp = json.optString("virtualIp", "");
            config.cidr = json.optString("cidr", "");
            config.stunHost = json.optString("stunHost", "");
            config.stunPort = json.optInt("stunPort", 0);
            config.turnHost = json.optString("turnHost", "");
            config.turnPort = json.optInt("turnPort", 0);
            config.publicStunServers = parseStringArray(json.optJSONArray("publicStunServers"));
            config.serverPublicKey = json.optString("serverPublicKey", "");
            config.clientPublicKey = json.optString("clientPublicKey", "");
            config.iceUsername = json.optString("iceUsername", "");
            config.iceCredential = json.optString("iceCredential", "");
            config.iceRealm = json.optString("iceRealm", "");
            config.iceNonce = json.optString("iceNonce", "");
            config.sessionTtlSeconds = json.optLong("sessionTtlSeconds", 0L);
            return config;
        }

        private static List<String> parseStringArray(JSONArray array) {
            List<String> result = new ArrayList<>();
            if (array == null) {
                return result;
            }
            for (int i = 0; i < array.length(); i++) {
                String value = array.optString(i, "");
                if (value != null && !value.trim().isEmpty()) {
                    result.add(value.trim());
                }
            }
            return result;
        }
    }

    private static final class ControlConnection implements Closeable {
        private final TunnelSession session;
        private final ExecutorService ioPool;
        private final StatusSink status;
        private final AtomicBoolean running;
        private final VpnPlatform vpnPlatform;
        private final PeerMeshEngine peerMeshEngine;
        private final SessionRefresher sessionRefresher;
        private final Object sendLock = new Object();
        private final Object configurationLock = new Object();
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final AtomicBoolean refreshInProgress = new AtomicBoolean(false);
        private final AtomicLong lastWriteAtMillis = new AtomicLong(0L);
        private final Set<Integer> registeredPorts = new HashSet<>();
        private final ConcurrentHashMap<String, LocalTunnel> localTunnels = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, LocalWebSocketTunnel> localWebSockets = new ConcurrentHashMap<>();
        private final ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "shuai-tunnel-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
        private final ScheduledExecutorService credentialRefresh = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "shuai-tunnel-token-refresh");
            thread.setDaemon(true);
            return thread;
        });
        private volatile Socket socket;
        private volatile InputStream input;
        private volatile OutputStream output;
        private volatile boolean httpRoutesReported;
        private volatile boolean loginSucceeded;
        private volatile ControlExitAction exitAction = ControlExitAction.RETRY_WITH_BACKOFF;
        private volatile String exitReason = "control channel closed";
        private final OkHttpClient webSocketClient;

        ControlConnection(TunnelSession session, ExecutorService ioPool, StatusSink status,
                          AtomicBoolean running, VpnPlatform vpnPlatform,
                          SessionRefresher sessionRefresher) {
            this.session = session;
            this.ioPool = ioPool;
            this.status = status;
            this.running = running;
            this.vpnPlatform = vpnPlatform;
            this.sessionRefresher = sessionRefresher;
            this.webSocketClient = WebSocketSupport.newClient(this::protect);
            this.peerMeshEngine = new PeerMeshEngine(session, vpnPlatform, ioPool, this::sendPeerControl, status::publish);
        }

        void runBlocking() throws Exception {
            Socket s = new Socket();
            socket = s;
            protect(s);
            s.setTcpNoDelay(true);
            s.setKeepAlive(true);
            s.setSoTimeout(CONTROL_READ_IDLE_TIMEOUT_MILLIS);
            s.connect(new InetSocketAddress(session.nettyHost, session.nettyPort), 5000);
            input = s.getInputStream();
            output = s.getOutputStream();
            send(Packet.loginRequest(session.clientName, session.clientSessionId, session.accessToken));
            heartbeat.scheduleAtFixedRate(() -> {
                try {
                    if (running.get() && !closed.get()) {
                        sendHeartbeatIfIdle();
                    }
                } catch (Exception ignored) {
                    closeQuietly(this);
                }
            }, 5, 5, TimeUnit.SECONDS);

            while (running.get()) {
                Packet packet = PacketCodec.read(input);
                handle(packet);
            }
        }

        private void handle(Packet packet) throws Exception {
            switch (packet.command) {
                case Command.LOGIN_RESPONSE:
                    LoginResponse login = (LoginResponse) packet;
                    if (login.success) {
                        loginSucceeded = true;
                        status.publish("Connected", login.clientName, true);
                        synchronized (configurationLock) {
                            peerMeshEngine.startOrUpdate(session.peerMesh);
                            registerTunnels();
                            reportHttpRoutes();
                        }
                        scheduleTokenRefresh();
                    } else {
                        LoginFailureAction action = LoginFailureAction.classify(login.reason);
                        exitReason = firstText(login.reason, "control login rejected");
                        if (action == LoginFailureAction.REFRESH_CREDENTIALS) {
                            exitAction = ControlExitAction.IMMEDIATE_HTTP_LOGIN;
                        } else if (action == LoginFailureAction.RETRY_WITH_BACKOFF) {
                            exitAction = ControlExitAction.RETRY_WITH_BACKOFF;
                        } else {
                            exitAction = ControlExitAction.STOP_RECONNECTING;
                        }
                        throw new IOException("control login rejected: " + exitReason);
                    }
                    break;
                case Command.LOGOUT_REQUEST:
                    exitAction = ControlExitAction.IMMEDIATE_HTTP_LOGIN;
                    exitReason = "server requested logout";
                    throw new IOException(exitReason);
                case Command.MESSAGE_RESPONSE:
                    handleMessage((MessageResponse) packet);
                    break;
                case Command.NAT_MESSAGE:
                    handleNat((NatMessage) packet);
                    break;
                case Command.DIRECT_HTTP_REQUEST:
                    handleDirectHttp((DirectHttpRequest) packet);
                    break;
                case Command.HEARTBEAT_RESPONSE:
                    break;
                default:
                    break;
            }
        }

        private void handleMessage(MessageResponse packet) throws Exception {
            if (packet.messageType == MessageType.NAT_CONTROL) {
                synchronized (configurationLock) {
                    session.applyRuntimeJson(packet.message);
                    applyTunnels();
                    httpRoutesReported = false;
                    reportHttpRoutes();
                    updateVpn();
                }
                status.publish("Routes updated",
                        "tcp=" + session.tunnels.size() + ", http=" + session.httpRoutes.size(), true);
            } else if (packet.messageType == MessageType.PEER_CONTROL) {
                peerMeshEngine.handleControlMessage(packet.message);
            } else if (packet.messageType == MessageType.CLIENT_TO_CLIENT) {
                status.publish("Message received",
                        firstText(packet.clientName, "server") + ": " + clientMessageText(packet.message), true);
            }
        }

        private String clientMessageText(String body) {
            String value = firstText(body, "");
            PeerAppMessageCodec.PeerAppMessage message = PeerAppMessageCodec.decode(value.getBytes(StandardCharsets.UTF_8));
            return message == null ? value : PeerAppMessageCodec.displayText(message);
        }

        private void handlePeerControl(String message) throws Exception {
            JSONObject json = new JSONObject(message == null ? "{}" : message);
            if ("peer-config".equals(json.optString("type", "")) && json.optJSONObject("peerMesh") != null) {
                PeerMeshConfig updated = PeerMeshConfig.parse(json.optJSONObject("peerMesh"));
                updated.mtu = session.peerMesh == null ? 1280 : session.peerMesh.mtu;
                session.peerMesh = updated;
                peerMeshEngine.startOrUpdate(session.peerMesh);
                return;
            }
            status.publish("Peer mesh signal received", json.optString("type", "unknown"), true);
        }

        private void sendPeerControl(String toClientName, String message) throws Exception {
            send(Packet.peerControl(session.clientName, toClientName, message));
        }

        private void sendClientMessage(String toClientName, String message) throws Exception {
            String target = toClientName == null ? "" : toClientName.trim();
            String body = message == null ? "" : message.trim();
            if (target.isEmpty()) {
                throw new IllegalArgumentException("target client is empty");
            }
            if (body.isEmpty()) {
                throw new IllegalArgumentException("message is empty");
            }
            try {
                PeerMeshEngine.ClientMessageSendResult peerResult = peerMeshEngine.sendClientMessage(target, body);
                if (peerResult != null) {
                    status.publish("Message sent", peerResult.transport + " -> " + target, true);
                    return;
                }
            } catch (Exception error) {
                status.publish("Peer message fallback", message(error), true);
            }
            send(Packet.clientMessage(session.clientName, target, body));
            status.publish("Message sent", "server -> " + target, true);
        }

        private void updateVpn() throws Exception {
            if (vpnPlatform == null) {
                return;
            }
            PeerMeshConfig peerMesh = session.peerMesh;
            if (peerMesh != null && peerMesh.enabled) {
                vpnPlatform.startVpn(peerMesh, packet -> {
                    // The live handler is installed by PeerMeshEngine after control login.
                });
            } else {
                vpnPlatform.stopVpn();
            }
        }

        private void handleNat(NatMessage packet) throws Exception {
            if (packet.type == NatMessageType.REGISTER_RESULT) {
                Object success = packet.meta.get("success");
                if (Boolean.FALSE.equals(success)) {
                    throw new IOException("NAT register failed: " + packet.meta.get("reason"));
                }
                return;
            }
            if (packet.type == NatMessageType.CONNECTED) {
                String source = asString(packet.meta.get("source"));
                if ("ws".equals(source)) {
                    openWebSocket(packet.meta);
                    return;
                }
                Integer port = asInt(packet.meta.get("port"));
                String channelId = asString(packet.meta.get("channelId"));
                TunnelEndpoint endpoint = port == null ? null : session.tunnelMap().get(port);
                if (TcpConnectedPolicy.shouldIgnore(port, channelId, endpoint != null)) {
                    status.publish("NAT CONNECTED ignored",
                            port == null || isBlank(channelId)
                                    ? "missing port/channelId"
                                    : "unknown port " + port,
                            true);
                    return;
                }
                LocalTunnel tunnel = new LocalTunnel(channelId, endpoint, this, ioPool);
                localTunnels.put(channelId, tunnel);
                tunnel.start();
                return;
            }
            if (packet.type == NatMessageType.DATA) {
                String channelId = asString(packet.meta.get("channelId"));
                LocalWebSocketTunnel webSocket = channelId == null ? null : localWebSockets.get(channelId);
                if (webSocket != null) {
                    webSocket.write(packet.data);
                    return;
                }
                LocalTunnel tunnel = channelId == null ? null : localTunnels.get(channelId);
                if (tunnel != null) {
                    tunnel.write(packet.data);
                }
                return;
            }
            if (packet.type == NatMessageType.DISCONNECTED) {
                String channelId = asString(packet.meta.get("channelId"));
                LocalWebSocketTunnel webSocket = channelId == null ? null : localWebSockets.remove(channelId);
                if (webSocket != null) {
                    webSocket.closeFromRemote();
                    return;
                }
                LocalTunnel tunnel = channelId == null ? null : localTunnels.remove(channelId);
                if (tunnel != null) {
                    tunnel.closeFromRemote();
                }
            }
        }

        private void handleDirectHttp(DirectHttpRequest packet) {
            Map<String, String> routes = session.routeMap();
            ioPool.submit(() -> {
                DirectHttpResponse response = DirectHttpForwarder.forward(packet, routes);
                try {
                    send(response);
                } catch (Exception e) {
                    status.publish("HTTP response failed", message(e), true);
                }
            });
        }

        private void registerTunnels() throws Exception {
            for (TunnelEndpoint endpoint : session.tunnels) {
                if (!registeredPorts.add(endpoint.port)) {
                    continue;
                }
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("port", endpoint.port);
                meta.put("tunnelAddress", endpoint.tunnelAddress);
                meta.put("tunnelPort", endpoint.tunnelPort);
                meta.put("clientName", session.clientName);
                send(Packet.nat(NatMessageType.REGISTER, meta, null));
            }
        }

        private void applyTunnels() throws Exception {
            Map<Integer, TunnelEndpoint> desired = session.tunnelMap();
            for (Integer port : new HashSet<>(registeredPorts)) {
                if (!desired.containsKey(port)) {
                    Map<String, Object> meta = new LinkedHashMap<>();
                    meta.put("port", port);
                    send(Packet.nat(NatMessageType.UNREGISTER, meta, null));
                    registeredPorts.remove(port);
                }
            }
            registerTunnels();
        }

        private void reportHttpRoutes() throws Exception {
            if (httpRoutesReported) {
                return;
            }
            httpRoutesReported = true;
            List<Map<String, String>> routes = new ArrayList<>();
            for (HttpRouteEndpoint endpoint : session.httpRoutes) {
                Map<String, String> item = new LinkedHashMap<>();
                item.put("route", endpoint.route);
                item.put("targetBaseUrl", endpoint.targetBaseUrl == null ? "" : endpoint.targetBaseUrl);
                routes.add(item);
            }
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("clientName", session.clientName);
            meta.put("routes", routes);
            send(Packet.nat(NatMessageType.HTTP_ROUTES_REPORT, meta, null));
        }

        private void scheduleTokenRefresh() {
            if (sessionRefresher == null || session.tokenExpiresAtMillis <= 0L
                    || closed.get() || !running.get()) {
                return;
            }
            scheduleTokenRefresh(TokenRefresh.delayMillis(
                    session.tokenExpiresAtMillis, System.currentTimeMillis()));
        }

        boolean loginSucceeded() {
            return loginSucceeded;
        }

        ControlExitAction exitAction() {
            return exitAction;
        }

        String exitReason() {
            return firstText(exitReason, "control channel closed");
        }

        private void scheduleTokenRefresh(long delayMillis) {
            if (closed.get() || !running.get() || credentialRefresh.isShutdown()) {
                return;
            }
            try {
                credentialRefresh.schedule(this::refreshCredentials,
                        Math.max(TokenRefresh.MIN_DELAY_MILLIS, delayMillis),
                        TimeUnit.MILLISECONDS);
            } catch (RuntimeException ignored) {
                // The connection may have closed concurrently with scheduling.
            }
        }

        private void refreshCredentials() {
            if (closed.get() || !running.get() || sessionRefresher == null
                    || !refreshInProgress.compareAndSet(false, true)) {
                return;
            }
            boolean succeeded = false;
            try {
                status.publish("HTTP token refresh", session.clientName, true);
                TunnelSession refreshed = sessionRefresher.refresh();
                synchronized (configurationLock) {
                    session.applyRefresh(refreshed);
                    applyTunnels();
                    httpRoutesReported = false;
                    reportHttpRoutes();
                    peerMeshEngine.startOrUpdate(session.peerMesh);
                }
                succeeded = true;
                status.publish("Token refreshed",
                        session.clientName + " session=" + session.clientSessionId, true);
            } catch (Throwable error) {
                status.publish("Token refresh failed", message(error), true);
            } finally {
                refreshInProgress.set(false);
                if (succeeded) {
                    scheduleTokenRefresh();
                } else {
                    scheduleTokenRefresh(TokenRefresh.RETRY_DELAY_MILLIS);
                }
            }
        }

        void sendNatData(String channelId, byte[] data) throws Exception {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("channelId", channelId);
            send(Packet.nat(NatMessageType.DATA, meta, data));
        }

        void sendWsData(String channelId, byte[] data) throws Exception {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("channelId", channelId);
            meta.put("source", "ws");
            send(Packet.nat(NatMessageType.DATA, meta, data));
        }

        void protect(Socket socket) {
            if (vpnPlatform != null) {
                vpnPlatform.protectSocket(socket);
            }
        }

        void sendDisconnected(String channelId, String source) throws Exception {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("channelId", channelId);
            if (source != null) {
                meta.put("source", source);
            }
            send(Packet.nat(NatMessageType.DISCONNECTED, meta, null));
        }

        private void openWebSocket(Map<String, Object> meta) throws Exception {
            String channelId = asString(meta.get("channelId"));
            String route = asString(meta.get("route"));
            if (isBlank(channelId) || isBlank(route)) {
                status.publish("WebSocket route rejected", "missing channelId/route", true);
                if (!isBlank(channelId)) {
                    sendDisconnected(channelId, "ws");
                }
                return;
            }
            String targetBaseUrl = session.routeMap().get(route);
            if (isBlank(targetBaseUrl)) {
                status.publish("WebSocket route rejected", "unknown route " + route, true);
                sendDisconnected(channelId, "ws");
                return;
            }
            try {
                URI target = WebSocketSupport.buildTarget(
                        targetBaseUrl,
                        asString(meta.get("relativePath")),
                        asString(meta.get("rawQuery")));
                LocalWebSocketTunnel tunnel = new LocalWebSocketTunnel(
                        channelId, target, meta.get("headers"), this, webSocketClient);
                LocalWebSocketTunnel replaced = localWebSockets.put(channelId, tunnel);
                if (replaced != null) {
                    replaced.closeFromControl();
                }
                tunnel.start();
            } catch (Throwable error) {
                localWebSockets.remove(channelId);
                status.publish("WebSocket route failed", message(error), true);
                sendDisconnected(channelId, "ws");
            }
        }

        private void send(Packet packet) throws Exception {
            synchronized (sendLock) {
                writePacketLocked(packet);
            }
        }

        private void sendHeartbeatIfIdle() throws Exception {
            synchronized (sendLock) {
                long now = System.currentTimeMillis();
                if (!HeartbeatPolicy.shouldSend(now, lastWriteAtMillis.get())) {
                    return;
                }
                writePacketLocked(Packet.heartbeatRequest());
            }
        }

        private void writePacketLocked(Packet packet) throws Exception {
                OutputStream out = output;
                if (out == null) {
                    throw new EOFException("control channel is not open");
                }
                PacketCodec.write(out, packet);
                out.flush();
                lastWriteAtMillis.set(System.currentTimeMillis());
        }

        @Override
        public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            heartbeat.shutdownNow();
            credentialRefresh.shutdownNow();
            peerMeshEngine.close();
            for (LocalTunnel tunnel : localTunnels.values()) {
                closeQuietly(tunnel);
            }
            localTunnels.clear();
            for (LocalWebSocketTunnel tunnel : localWebSockets.values()) {
                tunnel.closeFromControl();
            }
            localWebSockets.clear();
            webSocketClient.dispatcher().executorService().shutdown();
            webSocketClient.connectionPool().evictAll();
            closeQuietly(input);
            closeQuietly(output);
            closeQuietly(socket);
        }
    }

    private static final class LocalTunnel implements Closeable {
        private final String channelId;
        private final TunnelEndpoint endpoint;
        private final ControlConnection control;
        private final ExecutorService ioPool;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private volatile Socket socket;

        LocalTunnel(String channelId, TunnelEndpoint endpoint, ControlConnection control, ExecutorService ioPool) {
            this.channelId = channelId;
            this.endpoint = endpoint;
            this.control = control;
            this.ioPool = ioPool;
        }

        void start() {
            ioPool.submit(() -> {
                try {
                    Socket local = new Socket();
                    socket = local;
                    control.protect(local);
                    local.setTcpNoDelay(true);
                    local.connect(new InetSocketAddress(endpoint.tunnelAddress, endpoint.tunnelPort), 5000);
                    byte[] buffer = new byte[16 * 1024];
                    InputStream in = local.getInputStream();
                    int read;
                    while (!closed.get() && (read = in.read(buffer)) >= 0) {
                        byte[] data = new byte[read];
                        System.arraycopy(buffer, 0, data, 0, read);
                        control.sendNatData(channelId, data);
                    }
                } catch (Throwable ignored) {
                } finally {
                    control.localTunnels.remove(channelId, this);
                    if (closed.compareAndSet(false, true)) {
                        try {
                            control.sendDisconnected(channelId, null);
                        } catch (Exception ignored) {
                        }
                    }
                    closeQuietly(socket);
                }
            });
        }

        void write(byte[] data) throws IOException {
            Socket local = socket;
            if (local != null && data != null) {
                OutputStream out = local.getOutputStream();
                out.write(data);
                out.flush();
            }
        }

        void closeFromRemote() {
            closed.set(true);
            closeQuietly(socket);
        }

        @Override
        public void close() {
            closeFromRemote();
        }
    }

    static final class WebSocketSupport {
        static final byte FRAME_TEXT = 0x01;
        static final byte FRAME_BINARY = 0x02;
        static final int MAX_MESSAGE_BYTES = 65_536;
        private static final Set<String> SKIPPED_HEADERS = Set.of(
                "connection", "content-length", "host", "keep-alive",
                "proxy-authenticate", "proxy-authorization", "te", "trailer",
                "transfer-encoding", "upgrade", "sec-websocket-key",
                "sec-websocket-version", "sec-websocket-extensions",
                "sec-websocket-protocol", "sec-websocket-accept");

        private WebSocketSupport() {
        }

        interface SocketProtector {
            void protect(Socket socket);
        }

        static OkHttpClient newClient(SocketProtector protector) {
            return new OkHttpClient.Builder()
                    .socketFactory(new ProtectedSocketFactory(protector))
                    .connectTimeout(5, TimeUnit.SECONDS)
                    .readTimeout(0, TimeUnit.MILLISECONDS)
                    .writeTimeout(20, TimeUnit.SECONDS)
                    .retryOnConnectionFailure(false)
                    .build();
        }

        static URI buildTarget(String targetBaseUrl, String relativePath, String rawQuery) {
            if (isBlank(targetBaseUrl)) {
                throw new IllegalArgumentException("HTTP route is not configured");
            }
            String value = targetBaseUrl.trim();
            String lower = value.toLowerCase(Locale.ROOT);
            String webSocketScheme;
            String httpBase;
            if (lower.startsWith("http://")) {
                webSocketScheme = "ws";
                httpBase = value;
            } else if (lower.startsWith("https://")) {
                webSocketScheme = "wss";
                httpBase = value;
            } else if (lower.startsWith("ws://")) {
                webSocketScheme = "ws";
                httpBase = "http://" + value.substring("ws://".length());
            } else if (lower.startsWith("wss://")) {
                webSocketScheme = "wss";
                httpBase = "https://" + value.substring("wss://".length());
            } else {
                throw new IllegalArgumentException("HTTP route only supports http/https/ws/wss");
            }
            URI httpTarget = DirectHttpForwarder.buildTarget(httpBase, relativePath, rawQuery);
            String serialized = httpTarget.toString();
            return URI.create(webSocketScheme + serialized.substring(serialized.indexOf(':')));
        }

        static void copyHandshakeHeaders(Object headers, Request.Builder request) {
            if (!(headers instanceof Iterable<?> values)) {
                return;
            }
            for (Object item : values) {
                if (!(item instanceof String line)) {
                    continue;
                }
                int separator = line.indexOf(':');
                if (separator <= 0) {
                    continue;
                }
                String name = line.substring(0, separator).trim();
                if (name.isEmpty() || SKIPPED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                    continue;
                }
                request.addHeader(name, line.substring(separator + 1).trim());
            }
        }

        static byte[] frameForControl(byte frameType, byte[] payload) {
            byte[] value = payload == null ? new byte[0] : payload;
            byte[] framed = new byte[value.length + 1];
            framed[0] = frameType;
            System.arraycopy(value, 0, framed, 1, value.length);
            return framed;
        }

        private static final class ProtectedSocketFactory extends SocketFactory {
            private final SocketProtector protector;

            private ProtectedSocketFactory(SocketProtector protector) {
                this.protector = protector;
            }

            private Socket protectedSocket() {
                Socket socket = new Socket();
                if (protector != null) {
                    protector.protect(socket);
                }
                return socket;
            }

            @Override
            public Socket createSocket() {
                return protectedSocket();
            }

            @Override
            public Socket createSocket(String host, int port) throws IOException {
                Socket socket = protectedSocket();
                socket.connect(new InetSocketAddress(host, port));
                return socket;
            }

            @Override
            public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
                Socket socket = protectedSocket();
                socket.bind(new InetSocketAddress(localHost, localPort));
                socket.connect(new InetSocketAddress(host, port));
                return socket;
            }

            @Override
            public Socket createSocket(InetAddress host, int port) throws IOException {
                Socket socket = protectedSocket();
                socket.connect(new InetSocketAddress(host, port));
                return socket;
            }

            @Override
            public Socket createSocket(InetAddress address,
                                       int port,
                                       InetAddress localAddress,
                                       int localPort) throws IOException {
                Socket socket = protectedSocket();
                socket.bind(new InetSocketAddress(localAddress, localPort));
                socket.connect(new InetSocketAddress(address, port));
                return socket;
            }
        }
    }

    private static final class LocalWebSocketTunnel {
        private final String channelId;
        private final URI target;
        private final Object headers;
        private final ControlConnection control;
        private final OkHttpClient client;
        private final AtomicBoolean finished = new AtomicBoolean(false);
        private final AtomicBoolean suppressDisconnect = new AtomicBoolean(false);
        private volatile WebSocket webSocket;
        private volatile boolean opened;

        private LocalWebSocketTunnel(String channelId,
                                    URI target,
                                    Object headers,
                                    ControlConnection control,
                                    OkHttpClient client) {
            this.channelId = channelId;
            this.target = target;
            this.headers = headers;
            this.control = control;
            this.client = client;
        }

        void start() {
            Request.Builder request = new Request.Builder().url(target.toString());
            WebSocketSupport.copyHandshakeHeaders(headers, request);
            webSocket = client.newWebSocket(request.build(), new WebSocketListener() {
                @Override
                public void onOpen(WebSocket socket, Response response) {
                    if (finished.get()) {
                        socket.cancel();
                        return;
                    }
                    opened = true;
                    control.status.publish("WebSocket connected", target.getHost(), true);
                }

                @Override
                public void onMessage(WebSocket socket, String text) {
                    byte[] payload = text.getBytes(StandardCharsets.UTF_8);
                    forwardToControl(socket, WebSocketSupport.FRAME_TEXT, payload);
                }

                @Override
                public void onMessage(WebSocket socket, ByteString bytes) {
                    forwardToControl(socket, WebSocketSupport.FRAME_BINARY, bytes.toByteArray());
                }

                @Override
                public void onClosing(WebSocket socket, int code, String reason) {
                    socket.close(code, reason);
                }

                @Override
                public void onClosed(WebSocket socket, int code, String reason) {
                    finish(true, "local websocket closed");
                }

                @Override
                public void onFailure(WebSocket socket, Throwable error, Response response) {
                    finish(true, message(error));
                }
            });
        }

        void write(byte[] data) {
            WebSocket socket = webSocket;
            if (!opened || socket == null || data == null || data.length == 0 || finished.get()) {
                return;
            }
            int payloadLength = data.length - 1;
            if (payloadLength > WebSocketSupport.MAX_MESSAGE_BYTES) {
                socket.close(1009, "message too large");
                finish(true, "websocket message exceeds 65536 bytes");
                return;
            }
            boolean accepted;
            if (data[0] == WebSocketSupport.FRAME_TEXT) {
                accepted = socket.send(new String(data, 1, payloadLength, StandardCharsets.UTF_8));
            } else {
                accepted = socket.send(ByteString.of(data, 1, payloadLength));
            }
            if (!accepted) {
                socket.cancel();
                finish(true, "local websocket write rejected");
            }
        }

        void closeFromRemote() {
            closeWithoutDisconnect();
        }

        void closeFromControl() {
            closeWithoutDisconnect();
        }

        private void closeWithoutDisconnect() {
            suppressDisconnect.set(true);
            finish(false, "");
            WebSocket socket = webSocket;
            if (socket != null) {
                socket.cancel();
            }
        }

        private void forwardToControl(WebSocket socket, byte frameType, byte[] payload) {
            if (payload.length > WebSocketSupport.MAX_MESSAGE_BYTES) {
                socket.close(1009, "message too large");
                finish(true, "websocket message exceeds 65536 bytes");
                return;
            }
            try {
                control.sendWsData(channelId, WebSocketSupport.frameForControl(frameType, payload));
            } catch (Exception error) {
                socket.cancel();
                finish(false, message(error));
            }
        }

        private void finish(boolean notifyControl, String detail) {
            if (!finished.compareAndSet(false, true)) {
                return;
            }
            opened = false;
            control.localWebSockets.remove(channelId, this);
            if (!isBlank(detail)) {
                control.status.publish("WebSocket disconnected", detail, true);
            }
            if (notifyControl && !suppressDisconnect.get() && !control.closed.get()) {
                try {
                    control.sendDisconnected(channelId, "ws");
                } catch (Exception ignored) {
                }
            }
        }
    }

    static final class DirectHttpForwarder {
        static final int MAX_REQUEST_BODY_SIZE = 16 * 1024 * 1024;
        static final int MAX_RESPONSE_BODY_SIZE = 64 * 1024 * 1024;
        static final long MAX_RANGE_BYTES = 8L * 1024 * 1024;
        private static final String[] SKIPPED = {
                "connection", "content-length", "host", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"
        };
        private static final javax.net.ssl.SSLSocketFactory TRUST_ALL_SSL_FACTORY;
        private static final HostnameVerifier TRUST_ALL_HOSTNAMES = (hostname, session) -> true;

        static {
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(null, new TrustManager[]{new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }}, new SecureRandom());
                TRUST_ALL_SSL_FACTORY = context.getSocketFactory();
            } catch (Exception e) {
                throw new ExceptionInInitializerError(e);
            }
        }

        static DirectHttpResponse forward(DirectHttpRequest packet, Map<String, String> routes) {
            DirectHttpResponse response = new DirectHttpResponse();
            response.requestId = packet.requestId;
            HttpURLConnection connection = null;
            try {
                if (packet.body != null && packet.body.length > MAX_REQUEST_BODY_SIZE) {
                    throw new IOException("HTTP request body exceeds limit");
                }
                URI target = buildTarget(routes.get(packet.route), packet.relativePath, packet.rawQuery);
                HttpURLConnection openedConnection = (HttpURLConnection) target.toURL().openConnection();
                connection = openedConnection;
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(20_000);
                connection.setInstanceFollowRedirects(false);
                connection.setRequestMethod(packet.requestMethod == null ? "GET" : packet.requestMethod);
                if (connection instanceof HttpsURLConnection https) {
                    https.setSSLSocketFactory(TRUST_ALL_SSL_FACTORY);
                    https.setHostnameVerifier(TRUST_ALL_HOSTNAMES);
                }
                String originalRange = firstHeader(packet.headers, "range");
                String boundedRange = boundedRange(originalRange);
                copyHeaders(packet.headers, (name, value) -> {
                    if (boundedRange != null && "range".equalsIgnoreCase(name)) {
                        return;
                    }
                    openedConnection.addRequestProperty(name, value);
                });
                if (boundedRange != null) {
                    connection.setRequestProperty("Range", boundedRange);
                }
                // Android's HttpURLConnection otherwise opts into transparent gzip. The
                // reference client forwards the wire body without automatic decompression.
                if (firstHeader(packet.headers, "accept-encoding") == null) {
                    connection.setRequestProperty("Accept-Encoding", "identity");
                }
                if (packet.body != null && packet.body.length > 0) {
                    connection.setDoOutput(true);
                    connection.setFixedLengthStreamingMode(packet.body.length);
                    try (OutputStream out = connection.getOutputStream()) {
                        out.write(packet.body);
                    }
                }
                response.statusCode = connection.getResponseCode();
                response.headers = headers(connection.getHeaderFields());
                long contentLength = connection.getContentLengthLong();
                if (contentLength > MAX_RESPONSE_BODY_SIZE) {
                    throw new IOException("HTTP response body exceeds limit");
                }
                InputStream bodyStream = response.statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
                response.body = readResponseBody(bodyStream);
            } catch (Throwable error) {
                response.statusCode = 502;
                response.error = message(error);
                response.body = new byte[0];
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
            return response;
        }

        static byte[] readResponseBody(InputStream input) throws IOException {
            return readLimited(input, MAX_RESPONSE_BODY_SIZE);
        }

        static URI buildTarget(String targetBaseUrl, String relativePath, String rawQuery) {
            if (targetBaseUrl == null || targetBaseUrl.trim().isEmpty()) {
                throw new IllegalArgumentException("HTTP route is not configured");
            }
            URI base = URI.create(targetBaseUrl);
            if (!"http".equalsIgnoreCase(base.getScheme()) && !"https".equalsIgnoreCase(base.getScheme())) {
                throw new IllegalArgumentException("HTTP route only supports http/https");
            }
            if (base.getHost() == null || base.getRawQuery() != null || base.getRawFragment() != null) {
                throw new IllegalArgumentException("HTTP route address is invalid");
            }
            String path = relativePath == null || relativePath.trim().isEmpty() ? "/" : relativePath;
            if (!path.startsWith("/") || path.contains("\r") || path.contains("\n")) {
                throw new IllegalArgumentException("HTTP forwarding path is invalid");
            }
            String baseUrl = targetBaseUrl.endsWith("/") ? targetBaseUrl.substring(0, targetBaseUrl.length() - 1) : targetBaseUrl;
            URI target = URI.create(baseUrl + path + (rawQuery == null || rawQuery.trim().isEmpty() ? "" : "?" + rawQuery));
            if (!base.getScheme().equalsIgnoreCase(target.getScheme())
                    || !base.getHost().equalsIgnoreCase(target.getHost())
                    || base.getPort() != target.getPort()) {
                throw new IllegalArgumentException("HTTP forwarding target escapes base URL");
            }
            for (String segment : target.getPath().split("/")) {
                if (".".equals(segment) || "..".equals(segment)) {
                    throw new IllegalArgumentException("HTTP forwarding path escapes base URL");
                }
            }
            String basePath = normalizeBasePath(base.getPath());
            String targetPath = target.normalize().getPath();
            if (!"/".equals(basePath) && !targetPath.equals(basePath) && !targetPath.startsWith(basePath + "/")) {
                throw new IllegalArgumentException("HTTP forwarding path escapes base URL");
            }
            return target;
        }

        private static String normalizeBasePath(String path) {
            if (path == null || path.trim().isEmpty()) {
                return "/";
            }
            return path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
        }

        private static List<String> headers(Map<String, List<String>> fields) {
            List<String> result = new ArrayList<>();
            if (fields == null) {
                return result;
            }
            for (Map.Entry<String, List<String>> entry : fields.entrySet()) {
                if (entry.getKey() == null || !shouldForward(entry.getKey())) {
                    continue;
                }
                for (String value : entry.getValue()) {
                    result.add(entry.getKey() + ":" + value);
                }
            }
            return result;
        }

        private static void copyHeaders(List<String> headers, HeaderConsumer consumer) {
            if (headers == null) {
                return;
            }
            for (String header : headers) {
                int separator = header.indexOf(':');
                if (separator > 0) {
                    String name = header.substring(0, separator);
                    if (shouldForward(name)) {
                        consumer.accept(name, header.substring(separator + 1));
                    }
                }
            }
        }

        private static String firstHeader(List<String> headers, String headerName) {
            if (headers == null) {
                return null;
            }
            for (String header : headers) {
                int separator = header.indexOf(':');
                if (separator > 0 && headerName.equalsIgnoreCase(header.substring(0, separator))) {
                    return header.substring(separator + 1);
                }
            }
            return null;
        }

        static String boundedRange(String rangeHeader) {
            if (rangeHeader == null) {
                return null;
            }
            String value = rangeHeader.trim();
            if (!value.regionMatches(true, 0, "bytes=", 0, "bytes=".length())) {
                return null;
            }
            String spec = value.substring("bytes=".length()).trim();
            if (spec.isEmpty() || spec.contains(",")) {
                return null;
            }
            int dash = spec.indexOf('-');
            if (dash < 0) {
                return null;
            }
            String startPart = spec.substring(0, dash).trim();
            String endPart = spec.substring(dash + 1).trim();
            try {
                if (startPart.isEmpty()) {
                    if (endPart.isEmpty()) {
                        return null;
                    }
                    long suffixLength = Long.parseLong(endPart);
                    return suffixLength <= 0 ? null : "bytes=-" + Math.min(suffixLength, MAX_RANGE_BYTES);
                }
                long start = Long.parseLong(startPart);
                if (start < 0) {
                    return null;
                }
                long maxEnd = Long.MAX_VALUE - start < MAX_RANGE_BYTES - 1 ? Long.MAX_VALUE : start + MAX_RANGE_BYTES - 1;
                if (endPart.isEmpty()) {
                    return "bytes=" + start + "-" + maxEnd;
                }
                long end = Long.parseLong(endPart);
                return end < start ? null : "bytes=" + start + "-" + Math.min(end, maxEnd);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        private static boolean shouldForward(String name) {
            if (name == null) {
                return false;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            for (String skipped : SKIPPED) {
                if (skipped.equals(lower)) {
                    return false;
                }
            }
            return true;
        }

        private interface HeaderConsumer {
            void accept(String name, String value);
        }
    }

    static final class PacketCodec {
        static final int MAGIC = 0x14353565;
        static final int HEADER_BYTES = 11;
        static final int MAX_FRAME_SIZE = 32 * 1024 * 1024;
        static final int MAX_BODY_SIZE = MAX_FRAME_SIZE - HEADER_BYTES;
        private static final byte SERIALIZER_FASTJSON = 1;
        private static final byte SERIALIZER_BIN = 4;

        static Packet read(InputStream in) throws Exception {
            byte[] header = readExact(in, HEADER_BYTES);
            int magic = readInt(header, 0);
            if (magic != MAGIC) {
                throw new IOException("bad packet magic");
            }
            byte serializer = header[5];
            byte command = header[6];
            int length = readInt(header, 7);
            validateBodyLength(length);
            byte[] body = readExact(in, length);
            if (command == Command.LOGIN_RESPONSE) {
                requireSerializer(serializer, SERIALIZER_BIN, command);
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                LoginResponse packet = new LoginResponse();
                packet.clientName = input.readString();
                packet.success = input.readBoolean();
                packet.reason = input.readString();
                return finish(packet, input);
            }
            if (command == Command.MESSAGE_RESPONSE) {
                requireSerializer(serializer, SERIALIZER_BIN, command);
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                MessageResponse packet = new MessageResponse();
                packet.clientName = input.readString();
                packet.toClientName = input.readString();
                packet.messageType = input.readMessageType();
                packet.message = input.readString();
                return finish(packet, input);
            }
            if (command == Command.DIRECT_HTTP_REQUEST) {
                requireSerializer(serializer, SERIALIZER_BIN, command);
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                DirectHttpRequest packet = new DirectHttpRequest();
                packet.requestId = input.readUuidString();
                packet.requestMethod = input.readHttpMethod();
                packet.route = input.readString();
                packet.relativePath = input.readString();
                packet.rawQuery = input.readString();
                packet.headers = input.readStringList();
                packet.body = input.readByteArray();
                return finish(packet, input);
            }
            if (command == Command.NAT_MESSAGE) {
                requireSerializer(serializer, SERIALIZER_FASTJSON, command);
                return readNat(body);
            }
            if (command == Command.HEARTBEAT_RESPONSE) {
                requireSerializer(serializer, SERIALIZER_BIN, command);
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                input.requireFullyConsumed();
                return new HeartbeatResponse();
            }
            if (command == Command.LOGOUT_REQUEST) {
                requireSerializer(serializer, SERIALIZER_BIN, command);
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                input.requireFullyConsumed();
                return Packet.logoutRequest();
            }
            return new Packet(command);
        }

        static void write(OutputStream out, Packet packet) throws Exception {
            byte[] body;
            byte serializer = SERIALIZER_BIN;
            if (packet.command == Command.LOGIN_REQUEST) {
                LoginRequest p = (LoginRequest) packet;
                CompactOutput payload = new CompactOutput();
                payload.writeString(p.clientName);
                payload.writeNullableLong(p.clientSessionId);
                payload.writeString(p.accessToken);
                body = CompactPayload.encode(payload.toByteArray());
            } else if (packet.command == Command.MESSAGE_REQUEST) {
                MessageRequest p = (MessageRequest) packet;
                CompactOutput payload = new CompactOutput();
                payload.writeString(p.clientName);
                payload.writeString(p.toClientName);
                payload.writeMessageType(p.messageType);
                payload.writeString(p.message);
                body = CompactPayload.encode(payload.toByteArray());
            } else if (packet.command == Command.HEARTBEAT_REQUEST) {
                body = CompactPayload.encode(new byte[0]);
            } else if (packet.command == Command.DIRECT_HTTP_RESPONSE) {
                DirectHttpResponse p = (DirectHttpResponse) packet;
                CompactOutput payload = new CompactOutput();
                payload.writeUuidString(p.requestId);
                payload.writeVarInt(p.statusCode);
                payload.writeStringList(p.headers);
                payload.writeByteArray(p.body);
                payload.writeString(p.error);
                body = CompactPayload.encode(payload.toByteArray());
            } else if (packet.command == Command.NAT_MESSAGE) {
                serializer = SERIALIZER_FASTJSON;
                body = writeNat((NatMessage) packet);
            } else {
                body = CompactPayload.encode(new byte[0]);
            }
            validateBodyLength(body.length);
            writeHeader(out, serializer, packet.command, body.length);
            out.write(body);
        }

        static void validateBodyLength(int length) throws IOException {
            if (length < 0 || length > MAX_BODY_SIZE) {
                throw new IOException("packet frame exceeds " + MAX_FRAME_SIZE + " bytes");
            }
        }

        private static void requireSerializer(byte actual, byte expected, byte command) throws IOException {
            if (actual != expected) {
                throw new IOException("unsupported serializer " + actual + " for command " + command);
            }
        }

        private static <T extends Packet> T finish(T packet, CompactInput input) {
            input.requireFullyConsumed();
            return packet;
        }

        private static NatMessage readNat(byte[] body) throws Exception {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            int typeCode = readInt(in);
            int metaLength = readInt(in);
            if (metaLength < 0 || metaLength > in.available()) {
                throw new IOException("invalid NAT metadata length");
            }
            byte[] metaBytes = readExact(in, metaLength);
            Map<String, Object> meta = jsonToMap(new JSONObject(new String(metaBytes, StandardCharsets.UTF_8)));
            byte[] remaining = readRemaining(in);
            NatMessage packet = new NatMessage();
            packet.type = NatMessageType.fromCode(typeCode);
            packet.meta = meta;
            packet.data = remaining.length == 0 ? null : CompactPayload.decode(remaining);
            return packet;
        }

        private static byte[] writeNat(NatMessage packet) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeInt(out, packet.type.code);
            byte[] metaBytes = new JSONObject(packet.meta == null ? new LinkedHashMap<>() : packet.meta)
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);
            writeInt(out, metaBytes.length);
            out.write(metaBytes);
            if (packet.data != null && packet.data.length > 0) {
                out.write(CompactPayload.encode(packet.data));
            }
            return out.toByteArray();
        }

        private static void writeHeader(OutputStream out, byte serializer, byte command, int length) throws IOException {
            writeInt(out, MAGIC);
            out.write(1);
            out.write(serializer);
            out.write(command);
            writeInt(out, length);
        }

        private static byte[] readExact(InputStream in, int length) throws IOException {
            byte[] bytes = new byte[length];
            int offset = 0;
            while (offset < length) {
                int read = in.read(bytes, offset, length - offset);
                if (read < 0) {
                    throw new EOFException("stream ended");
                }
                offset += read;
            }
            return bytes;
        }

        private static int readInt(InputStream in) throws IOException {
            byte[] bytes = readExact(in, 4);
            return readInt(bytes, 0);
        }

        private static int readInt(byte[] bytes, int offset) {
            return (bytes[offset] & 0xFF) << 24
                    | (bytes[offset + 1] & 0xFF) << 16
                    | (bytes[offset + 2] & 0xFF) << 8
                    | (bytes[offset + 3] & 0xFF);
        }

        private static void writeInt(OutputStream out, int value) throws IOException {
            out.write((value >>> 24) & 0xFF);
            out.write((value >>> 16) & 0xFF);
            out.write((value >>> 8) & 0xFF);
            out.write(value & 0xFF);
        }

        private static byte[] readRemaining(InputStream in) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    static class Packet {
        final byte command;

        Packet(byte command) {
            this.command = command;
        }

        static Packet loginRequest(String clientName, Long clientSessionId, String accessToken) {
            LoginRequest packet = new LoginRequest();
            packet.clientName = clientName;
            packet.clientSessionId = clientSessionId;
            packet.accessToken = accessToken;
            return packet;
        }

        static Packet heartbeatRequest() {
            return new Packet(Command.HEARTBEAT_REQUEST);
        }

        static Packet logoutRequest() {
            return new Packet(Command.LOGOUT_REQUEST);
        }

        static MessageRequest peerControl(String clientName, String toClientName, String message) {
            MessageRequest packet = new MessageRequest();
            packet.clientName = clientName;
            packet.toClientName = toClientName;
            packet.messageType = MessageType.PEER_CONTROL;
            packet.message = message;
            return packet;
        }

        static MessageRequest clientMessage(String clientName, String toClientName, String message) {
            MessageRequest packet = new MessageRequest();
            packet.clientName = clientName;
            packet.toClientName = toClientName;
            packet.messageType = MessageType.CLIENT_TO_CLIENT;
            packet.message = message;
            return packet;
        }

        static NatMessage nat(NatMessageType type, Map<String, Object> meta, byte[] data) {
            NatMessage packet = new NatMessage();
            packet.type = type;
            packet.meta = meta;
            packet.data = data;
            return packet;
        }
    }

    private static final class LoginRequest extends Packet {
        String clientName;
        Long clientSessionId;
        String accessToken;

        LoginRequest() {
            super(Command.LOGIN_REQUEST);
        }
    }

    private static final class LoginResponse extends Packet {
        String clientName;
        boolean success;
        String reason;

        LoginResponse() {
            super(Command.LOGIN_RESPONSE);
        }
    }

    private static final class MessageRequest extends Packet {
        String clientName;
        String toClientName;
        int messageType;
        String message;

        MessageRequest() {
            super(Command.MESSAGE_REQUEST);
        }
    }

    private static final class HeartbeatResponse extends Packet {
        HeartbeatResponse() {
            super(Command.HEARTBEAT_RESPONSE);
        }
    }

    private static final class MessageResponse extends Packet {
        String clientName;
        String toClientName;
        int messageType;
        String message;

        MessageResponse() {
            super(Command.MESSAGE_RESPONSE);
        }
    }

    private static final class NatMessage extends Packet {
        NatMessageType type;
        Map<String, Object> meta;
        byte[] data;

        NatMessage() {
            super(Command.NAT_MESSAGE);
        }
    }

    private static final class DirectHttpRequest extends Packet {
        String requestId;
        String requestMethod;
        String route;
        String relativePath;
        String rawQuery;
        List<String> headers;
        byte[] body;

        DirectHttpRequest() {
            super(Command.DIRECT_HTTP_REQUEST);
        }
    }

    private static final class DirectHttpResponse extends Packet {
        String requestId;
        int statusCode;
        List<String> headers = new ArrayList<>();
        byte[] body = new byte[0];
        String error;

        DirectHttpResponse() {
            super(Command.DIRECT_HTTP_RESPONSE);
        }
    }

    private static final class Command {
        static final byte LOGIN_REQUEST = 1;
        static final byte LOGIN_RESPONSE = -1;
        static final byte MESSAGE_REQUEST = 2;
        static final byte MESSAGE_RESPONSE = -2;
        static final byte LOGOUT_REQUEST = 3;
        static final byte HEARTBEAT_REQUEST = 4;
        static final byte HEARTBEAT_RESPONSE = -4;
        static final byte NAT_MESSAGE = 6;
        static final byte DIRECT_HTTP_REQUEST = 7;
        static final byte DIRECT_HTTP_RESPONSE = -7;
    }

    private static final class MessageType {
        static final int SERVER_TO_CLIENT = 0;
        static final int CLIENT_TO_SERVER = 1;
        static final int CLIENT_TO_CLIENT = 2;
        static final int NAT_CONTROL = 3;
        static final int PEER_CONTROL = 4;
    }

    private enum NatMessageType {
        REGISTER(1),
        REGISTER_RESULT(2),
        CONNECTED(3),
        DISCONNECTED(4),
        DATA(5),
        KEEPALIVE(6),
        UNREGISTER(7),
        HTTP_ROUTES_REPORT(8);

        final int code;

        NatMessageType(int code) {
            this.code = code;
        }

        static NatMessageType fromCode(int code) {
            for (NatMessageType value : values()) {
                if (value.code == code) {
                    return value;
                }
            }
            return null;
        }
    }

    static final class CompactPayload {
        private static final int RAW = 0;
        private static final int DEFLATED = 1;
        private static final int COMPRESSION_THRESHOLD = 64;
        static final int MAX_INFLATED_SIZE = 16 * 1024 * 1024;

        static byte[] encode(byte[] raw) {
            byte[] compressed = raw.length >= COMPRESSION_THRESHOLD ? deflate(raw) : raw;
            if (compressed.length < raw.length) {
                return withType(DEFLATED, compressed);
            }
            return withType(RAW, raw);
        }

        static byte[] decode(byte[] bytes) {
            if (bytes == null || bytes.length == 0) {
                throw new IllegalArgumentException("empty compact payload");
            }
            byte[] payload = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, payload, 0, payload.length);
            if (bytes[0] == RAW) {
                return payload;
            }
            if (bytes[0] == DEFLATED) {
                return inflate(payload);
            }
            throw new IllegalArgumentException("unknown compact payload type: " + bytes[0]);
        }

        private static byte[] withType(int type, byte[] payload) {
            byte[] result = new byte[payload.length + 1];
            result[0] = (byte) type;
            System.arraycopy(payload, 0, result, 1, payload.length);
            return result;
        }

        private static byte[] deflate(byte[] bytes) {
            Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
            try {
                deflater.setInput(bytes);
                deflater.finish();
                ByteArrayOutputStream output = new ByteArrayOutputStream(bytes.length);
                byte[] buffer = new byte[256];
                while (!deflater.finished()) {
                    int length = deflater.deflate(buffer);
                    output.write(buffer, 0, length);
                }
                return output.toByteArray();
            } finally {
                deflater.end();
            }
        }

        private static byte[] inflate(byte[] bytes) {
            Inflater inflater = new Inflater(true);
            try {
                inflater.setInput(bytes);
                ByteArrayOutputStream output = new ByteArrayOutputStream(bytes.length * 2);
                byte[] buffer = new byte[256];
                while (!inflater.finished()) {
                    int length = inflater.inflate(buffer);
                    if (length == 0) {
                        throw new IllegalArgumentException("invalid deflated payload");
                    }
                    output.write(buffer, 0, length);
                    if (output.size() > MAX_INFLATED_SIZE) {
                        throw new IllegalArgumentException("inflated payload exceeds limit");
                    }
                }
                return output.toByteArray();
            } catch (DataFormatException e) {
                throw new IllegalArgumentException("invalid deflated payload", e);
            } finally {
                inflater.end();
            }
        }
    }

    private static final class CompactOutput {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        void writeByte(int value) {
            out.write(value);
        }

        void writeString(String value) {
            if (value == null) {
                writeVarInt(0);
                return;
            }
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            writeVarInt(bytes.length + 1);
            out.write(bytes, 0, bytes.length);
        }

        void writeNullableLong(Long value) {
            if (value == null) {
                writeByte(0);
                return;
            }
            writeByte(1);
            writeVarLong(zigZagEncode(value));
        }

        void writeByteArray(byte[] value) {
            if (value == null) {
                writeVarInt(0);
                return;
            }
            writeVarInt(value.length + 1);
            out.write(value, 0, value.length);
        }

        void writeMessageType(int value) {
            writeVarInt(value + 1);
        }

        void writeStringList(List<String> value) {
            if (value == null) {
                writeVarInt(0);
                return;
            }
            writeVarInt(value.size() + 1);
            for (String item : value) {
                writeString(item);
            }
        }

        void writeUuidString(String value) {
            if (value == null) {
                writeByte(0);
                return;
            }
            try {
                UUID uuid = UUID.fromString(value);
                if (uuid.toString().equals(value)) {
                    writeByte(1);
                    writeLong(uuid.getMostSignificantBits());
                    writeLong(uuid.getLeastSignificantBits());
                    return;
                }
            } catch (IllegalArgumentException ignored) {
            }
            writeByte(2);
            writeString(value);
        }

        void writeVarInt(int value) {
            if (value < 0) {
                throw new IllegalArgumentException("varint cannot be negative");
            }
            while ((value & ~0x7F) != 0) {
                writeByte((value & 0x7F) | 0x80);
                value >>>= 7;
            }
            writeByte(value);
        }

        void writeVarLong(long value) {
            while ((value & ~0x7FL) != 0) {
                writeByte(((int) value & 0x7F) | 0x80);
                value >>>= 7;
            }
            writeByte((int) value);
        }

        void writeLong(long value) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                writeByte((int) (value >>> shift));
            }
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }

    static final class CompactInput {
        private static final String[] HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"};
        private final byte[] bytes;
        private int index;

        CompactInput(byte[] bytes) {
            this.bytes = bytes;
        }

        String readString() {
            int marker = readVarInt();
            if (marker == 0) {
                return null;
            }
            return new String(readBytes(marker - 1), StandardCharsets.UTF_8);
        }

        Long readNullableLong() {
            int type = readUnsignedByte();
            if (type == 0) {
                return null;
            }
            if (type == 1) {
                return zigZagDecode(readVarLong());
            }
            throw new IllegalArgumentException("invalid nullable long type");
        }

        boolean readBoolean() {
            int value = readUnsignedByte();
            if (value > 1) {
                throw new IllegalArgumentException("invalid boolean");
            }
            return value == 1;
        }

        int readMessageType() {
            return readVarInt() - 1;
        }

        String readHttpMethod() {
            int type = readUnsignedByte();
            if (type == 0) {
                return null;
            }
            if (type <= HTTP_METHODS.length) {
                return HTTP_METHODS[type - 1];
            }
            if (type == HTTP_METHODS.length + 1) {
                return readString();
            }
            throw new IllegalArgumentException("invalid HTTP method");
        }

        String readUuidString() {
            int type = readUnsignedByte();
            if (type == 0) {
                return null;
            }
            if (type == 1) {
                return new UUID(readLong(), readLong()).toString();
            }
            if (type == 2) {
                return readString();
            }
            throw new IllegalArgumentException("invalid UUID string");
        }

        List<String> readStringList() {
            int marker = readVarInt();
            if (marker == 0) {
                return null;
            }
            List<String> result = new ArrayList<>(marker - 1);
            for (int i = 0; i < marker - 1; i++) {
                result.add(readString());
            }
            return result;
        }

        byte[] readByteArray() {
            int marker = readVarInt();
            return marker == 0 ? null : readBytes(marker - 1);
        }

        int readUnsignedByte() {
            if (index >= bytes.length) {
                throw new IllegalArgumentException("unexpected end of compact payload");
            }
            return bytes[index++] & 0xFF;
        }

        byte[] readBytes(int length) {
            if (length < 0 || bytes.length - index < length) {
                throw new IllegalArgumentException("unexpected end of compact payload");
            }
            byte[] result = new byte[length];
            System.arraycopy(bytes, index, result, 0, length);
            index += length;
            return result;
        }

        int readVarInt() {
            int value = 0;
            for (int shift = 0; shift < 32; shift += 7) {
                int b = readUnsignedByte();
                value |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) {
                    return value;
                }
            }
            throw new IllegalArgumentException("varint too long");
        }

        long readVarLong() {
            long value = 0L;
            for (int shift = 0; shift < 64; shift += 7) {
                int b = readUnsignedByte();
                value |= (long) (b & 0x7F) << shift;
                if ((b & 0x80) == 0) {
                    return value;
                }
            }
            throw new IllegalArgumentException("varlong too long");
        }

        long readLong() {
            long value = 0;
            for (int i = 0; i < Long.BYTES; i++) {
                value = (value << 8) | readUnsignedByte();
            }
            return value;
        }

        void requireFullyConsumed() {
            if (index != bytes.length) {
                throw new IllegalArgumentException("compact payload has trailing bytes");
            }
        }
    }

    static final class Hmac {
        static String signApiKey(String apiKey, String timestamp, String nonce,
                                 ClientEnvironment environment, String secret) throws Exception {
            if (environment == null) {
                throw new NullPointerException("environment");
            }
            return signApiKey(apiKey, timestamp, nonce,
                    environment.machineFingerprint, environment.osUser, secret);
        }

        static String signApiKey(String apiKey, String timestamp, String nonce,
                                 String machineFingerprint, String osUser, String secret) throws Exception {
            String canonical = canonicalApiKeyMessage(apiKey, timestamp, nonce, machineFingerprint, osUser);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sha256(secret), "HmacSHA256"));
            return hex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        }

        static String canonicalApiKeyMessage(String apiKey, String timestamp, String nonce,
                                             String machineFingerprint, String osUser) {
            return value(apiKey) + "\n"
                    + value(timestamp) + "\n"
                    + value(nonce) + "\n"
                    + value(machineFingerprint) + "\n"
                    + value(osUser);
        }

        private static byte[] sha256(String value) throws Exception {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        }

        private static String hex(byte[] bytes) {
            char[] alphabet = "0123456789abcdef".toCharArray();
            char[] result = new char[bytes.length * 2];
            for (int i = 0; i < bytes.length; i++) {
                result[i * 2] = alphabet[(bytes[i] >>> 4) & 0x0F];
                result[i * 2 + 1] = alphabet[bytes[i] & 0x0F];
            }
            return new String(result);
        }

        private static String value(String value) {
            return value == null ? "" : value;
        }
    }

    private static final class Jsonc {
        static String toJson(String jsonc) {
            return removeTrailingCommas(stripComments(jsonc == null ? "" : jsonc));
        }

        private static String stripComments(String input) {
            StringBuilder out = new StringBuilder(input.length());
            boolean string = false;
            boolean escape = false;
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                if (string) {
                    out.append(c);
                    if (escape) {
                        escape = false;
                    } else if (c == '\\') {
                        escape = true;
                    } else if (c == '"') {
                        string = false;
                    }
                    continue;
                }
                if (c == '"') {
                    string = true;
                    out.append(c);
                    continue;
                }
                if (c == '/' && i + 1 < input.length()) {
                    char next = input.charAt(i + 1);
                    if (next == '/') {
                        i += 2;
                        while (i < input.length() && input.charAt(i) != '\n' && input.charAt(i) != '\r') {
                            i++;
                        }
                        if (i < input.length()) {
                            out.append(input.charAt(i));
                        }
                        continue;
                    }
                    if (next == '*') {
                        i += 2;
                        while (i + 1 < input.length() && !(input.charAt(i) == '*' && input.charAt(i + 1) == '/')) {
                            i++;
                        }
                        i++;
                        continue;
                    }
                }
                out.append(c);
            }
            return out.toString();
        }

        private static String removeTrailingCommas(String input) {
            StringBuilder out = new StringBuilder(input.length());
            boolean string = false;
            boolean escape = false;
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                if (string) {
                    out.append(c);
                    if (escape) {
                        escape = false;
                    } else if (c == '\\') {
                        escape = true;
                    } else if (c == '"') {
                        string = false;
                    }
                    continue;
                }
                if (c == '"') {
                    string = true;
                    out.append(c);
                    continue;
                }
                if (c == ',') {
                    int j = i + 1;
                    while (j < input.length() && Character.isWhitespace(input.charAt(j))) {
                        j++;
                    }
                    if (j < input.length() && (input.charAt(j) == '}' || input.charAt(j) == ']')) {
                        continue;
                    }
                }
                out.append(c);
            }
            return out.toString();
        }
    }

    private static Map<String, Object> jsonToMap(JSONObject json) throws Exception {
        Map<String, Object> map = new LinkedHashMap<>();
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            map.put(key, unwrapJson(json.get(key)));
        }
        return map;
    }

    private static Object unwrapJson(Object value) throws Exception {
        if (value == JSONObject.NULL) {
            return null;
        }
        if (value instanceof JSONObject object) {
            return jsonToMap(object);
        }
        if (value instanceof JSONArray array) {
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) {
                list.add(unwrapJson(array.get(i)));
            }
            return list;
        }
        return value;
    }

    static byte[] readLimited(InputStream in, int maxBytes) throws IOException {
        if (in == null) {
            return new byte[0];
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            if (out.size() + read > maxBytes) {
                throw new IOException("response body exceeds limit");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String trimTrailingSlash(String value) {
        String normalized = value == null ? "" : value.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String message(Throwable error) {
        if (error == null) {
            return "unknown";
        }
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }

    private static String firstText(String value, String fallback) {
        return isBlank(value) ? (fallback == null ? "" : fallback) : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static Integer asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String string) {
            try {
                return Integer.parseInt(string);
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static long zigZagEncode(long value) {
        return (value << 1) ^ (value >> 63);
    }

    private static long zigZagDecode(long value) {
        return (value >>> 1) ^ -(value & 1L);
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception ignored) {
        }
    }
}
