package com.theshuai.tunnel.android;

import android.content.Context;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

public final class TunnelCore {
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
                    try {
                        publish("HTTP login", config.serverBaseUrl, true);
                        TunnelSession session = AuthClient.login(context, config);
                        session.applyStartup(config);
                        startOrStopVpn(session);
                        attempt = 0;
                        publish("Control connecting", session.nettyHost + ":" + session.nettyPort, true);
                        ControlConnection next = new ControlConnection(session, ioPool, this::publish, running, vpnPlatform);
                        connection = next;
                        next.runBlocking();
                        if (running.get()) {
                            publish("Disconnected", "control channel closed", true);
                        }
                    } catch (Throwable error) {
                        if (!running.get()) {
                            break;
                        }
                        publish("Error", message(error), true);
                    } finally {
                        closeQuietly(connection);
                        connection = null;
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
                    json.optString("peerMeshDevice", "noop"),
                    json.optString("peerMeshTunName", "shuai0"),
                    json.optInt("peerMeshMtu", 1280));
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
            if (session.clientName == null || session.accessToken == null || session.nettyHost == null || session.nettyPort <= 0) {
                throw new IOException("HTTP login response is incomplete");
            }
            return session;
        }
    }

    private static final class ClientEnvironment {
        String machineFingerprint;
        String hostname;
        String osUser;
        String osName;
        String osVersion;
        String osArch;
        String clientVersion;
        String javaVersion;
        String peerPublicKey;
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

    static final class TunnelSession {
        String clientName;
        Long clientSessionId;
        String accessToken;
        long tokenTtlSeconds;
        String nettyHost;
        int nettyPort;
        PeerMeshConfig peerMesh = new PeerMeshConfig();
        List<TunnelEndpoint> tunnels = new ArrayList<>();
        List<HttpRouteEndpoint> httpRoutes = new ArrayList<>();

        static TunnelSession fromLoginJson(JSONObject json) {
            TunnelSession session = new TunnelSession();
            session.clientName = json.optString("clientName", null);
            session.clientSessionId = json.optLong("clientSessionId", 0L);
            session.accessToken = json.optString("accessToken", null);
            session.tokenTtlSeconds = json.optLong("tokenTtlSeconds", 0L);
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
            peerMesh.mtu = config.peerMeshMtu;
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
        public long sessionTtlSeconds;
        public int mtu = 1280;

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
        private final Object sendLock = new Object();
        private final Set<Integer> registeredPorts = new HashSet<>();
        private final ConcurrentHashMap<String, LocalTunnel> localTunnels = new ConcurrentHashMap<>();
        private final ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "shuai-tunnel-heartbeat");
            thread.setDaemon(true);
            return thread;
        });
        private volatile Socket socket;
        private volatile InputStream input;
        private volatile OutputStream output;
        private volatile boolean httpRoutesReported;

        ControlConnection(TunnelSession session, ExecutorService ioPool, StatusSink status,
                          AtomicBoolean running, VpnPlatform vpnPlatform) {
            this.session = session;
            this.ioPool = ioPool;
            this.status = status;
            this.running = running;
            this.vpnPlatform = vpnPlatform;
            this.peerMeshEngine = new PeerMeshEngine(session, vpnPlatform, ioPool, this::sendPeerControl, status::publish);
        }

        void runBlocking() throws Exception {
            Socket s = new Socket();
            socket = s;
            protect(s);
            s.setTcpNoDelay(true);
            s.setKeepAlive(true);
            s.connect(new InetSocketAddress(session.nettyHost, session.nettyPort), 5000);
            input = s.getInputStream();
            output = s.getOutputStream();
            send(Packet.loginRequest(session.clientName, session.clientSessionId, session.accessToken));
            heartbeat.scheduleAtFixedRate(() -> {
                try {
                    if (running.get()) {
                        send(Packet.heartbeatRequest());
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
                        status.publish("Connected", login.clientName, true);
                        peerMeshEngine.startOrUpdate(session.peerMesh);
                        registerTunnels();
                        reportHttpRoutes();
                    } else {
                        throw new IOException("control login rejected: " + login.reason);
                    }
                    break;
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
                session.applyRuntimeJson(packet.message);
                applyTunnels();
                httpRoutesReported = false;
                reportHttpRoutes();
                updateVpn();
                status.publish("Routes updated",
                        "tcp=" + session.tunnels.size() + ", http=" + session.httpRoutes.size(), true);
            } else if (packet.messageType == MessageType.PEER_CONTROL) {
                peerMeshEngine.handleControlMessage(packet.message);
            } else if (packet.messageType == MessageType.CLIENT_TO_CLIENT) {
                status.publish("Message received",
                        firstText(packet.clientName, "server") + ": " + firstText(packet.message, ""), true);
            }
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
                    sendWsUnsupported(packet.meta);
                    return;
                }
                Integer port = asInt(packet.meta.get("port"));
                String channelId = asString(packet.meta.get("channelId"));
                if (port == null || channelId == null) {
                    return;
                }
                TunnelEndpoint endpoint = session.tunnelMap().get(port);
                if (endpoint == null) {
                    sendDisconnected(channelId, null);
                    return;
                }
                LocalTunnel tunnel = new LocalTunnel(channelId, endpoint, this, ioPool);
                localTunnels.put(channelId, tunnel);
                tunnel.start();
                return;
            }
            if (packet.type == NatMessageType.DATA) {
                String channelId = asString(packet.meta.get("channelId"));
                LocalTunnel tunnel = channelId == null ? null : localTunnels.get(channelId);
                if (tunnel != null) {
                    tunnel.write(packet.data);
                }
                return;
            }
            if (packet.type == NatMessageType.DISCONNECTED) {
                String channelId = asString(packet.meta.get("channelId"));
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

        void sendNatData(String channelId, byte[] data) throws Exception {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("channelId", channelId);
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

        private void sendWsUnsupported(Map<String, Object> meta) throws Exception {
            String channelId = asString(meta.get("channelId"));
            if (channelId != null) {
                sendDisconnected(channelId, "ws");
            }
        }

        private void send(Packet packet) throws Exception {
            synchronized (sendLock) {
                OutputStream out = output;
                if (out == null) {
                    throw new EOFException("control channel is not open");
                }
                PacketCodec.write(out, packet);
                out.flush();
            }
        }

        @Override
        public void close() {
            heartbeat.shutdownNow();
            peerMeshEngine.close();
            for (LocalTunnel tunnel : localTunnels.values()) {
                closeQuietly(tunnel);
            }
            localTunnels.clear();
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

    private static final class DirectHttpForwarder {
        private static final int MAX_REQUEST_BODY_SIZE = 16 * 1024 * 1024;
        private static final int MAX_RESPONSE_BODY_SIZE = 64 * 1024 * 1024;
        private static final long MAX_RANGE_BYTES = 8L * 1024 * 1024;
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
            try {
                if (packet.body != null && packet.body.length > MAX_REQUEST_BODY_SIZE) {
                    throw new IOException("HTTP request body exceeds limit");
                }
                URI target = buildTarget(routes.get(packet.route), packet.relativePath, packet.rawQuery);
                HttpURLConnection connection = (HttpURLConnection) target.toURL().openConnection();
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
                    connection.addRequestProperty(name, value);
                });
                if (boundedRange != null) {
                    connection.setRequestProperty("Range", boundedRange);
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
                InputStream bodyStream = response.statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream();
                response.body = readLimited(bodyStream, MAX_RESPONSE_BODY_SIZE);
            } catch (Throwable error) {
                response.statusCode = 502;
                response.error = message(error);
                response.body = new byte[0];
            }
            return response;
        }

        private static URI buildTarget(String targetBaseUrl, String relativePath, String rawQuery) {
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

        private static String boundedRange(String rangeHeader) {
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

    private static final class PacketCodec {
        private static final int MAGIC = 0x14353565;
        private static final int MAX_FRAME = 32 * 1024 * 1024;
        private static final byte SERIALIZER_FASTJSON = 1;
        private static final byte SERIALIZER_BIN = 4;

        static Packet read(InputStream in) throws Exception {
            byte[] header = readExact(in, 11);
            int magic = readInt(header, 0);
            if (magic != MAGIC) {
                throw new IOException("bad packet magic");
            }
            byte serializer = header[5];
            byte command = header[6];
            int length = readInt(header, 7);
            if (length < 0 || length > MAX_FRAME) {
                throw new IOException("packet frame is too large");
            }
            byte[] body = readExact(in, length);
            if (command == Command.LOGIN_RESPONSE) {
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                LoginResponse packet = new LoginResponse();
                packet.clientName = input.readString();
                packet.success = input.readBoolean();
                packet.reason = input.readString();
                return packet;
            }
            if (command == Command.MESSAGE_RESPONSE) {
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                MessageResponse packet = new MessageResponse();
                packet.clientName = input.readString();
                packet.toClientName = input.readString();
                packet.messageType = input.readMessageType();
                packet.message = input.readString();
                return packet;
            }
            if (command == Command.DIRECT_HTTP_REQUEST) {
                CompactInput input = new CompactInput(CompactPayload.decode(body));
                DirectHttpRequest packet = new DirectHttpRequest();
                packet.requestId = input.readUuidString();
                packet.requestMethod = input.readHttpMethod();
                packet.route = input.readString();
                packet.relativePath = input.readString();
                packet.rawQuery = input.readString();
                packet.headers = input.readStringList();
                packet.body = input.readByteArray();
                return packet;
            }
            if (command == Command.NAT_MESSAGE) {
                return readNat(body);
            }
            if (command == Command.HEARTBEAT_RESPONSE) {
                return new HeartbeatResponse();
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
            writeHeader(out, serializer, packet.command, body.length);
            out.write(body);
        }

        private static NatMessage readNat(byte[] body) throws Exception {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            int typeCode = readInt(in);
            int metaLength = readInt(in);
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

    private static class Packet {
        final byte command;

        Packet(byte command) {
            this.command = command;
        }

        static LoginRequest loginRequest(String clientName, Long clientSessionId, String accessToken) {
            LoginRequest packet = new LoginRequest();
            packet.clientName = clientName;
            packet.clientSessionId = clientSessionId;
            packet.accessToken = accessToken;
            return packet;
        }

        static Packet heartbeatRequest() {
            return new Packet(Command.HEARTBEAT_REQUEST);
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
            return KEEPALIVE;
        }
    }

    private static final class CompactPayload {
        private static final int RAW = 0;
        private static final int DEFLATED = 1;
        private static final int COMPRESSION_THRESHOLD = 64;
        private static final int MAX_INFLATED_SIZE = 16 * 1024 * 1024;

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

    private static final class CompactInput {
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

        long readLong() {
            long value = 0;
            for (int i = 0; i < Long.BYTES; i++) {
                value = (value << 8) | readUnsignedByte();
            }
            return value;
        }
    }

    private static final class Hmac {
        static String signApiKey(String apiKey, String timestamp, String nonce,
                                 ClientEnvironment environment, String secret) throws Exception {
            String canonical = value(apiKey) + "\n"
                    + value(timestamp) + "\n"
                    + value(nonce) + "\n"
                    + value(environment.machineFingerprint) + "\n"
                    + value(environment.osUser);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sha256(secret), "HmacSHA256"));
            return hex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
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

    private static byte[] readLimited(InputStream in, int maxBytes) throws IOException {
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
