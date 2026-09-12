package com.theshuai.specusclient;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.bean.MachineCredential;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.specusclient.peer.PeerKeyStore;
import com.theshuai.specusclient.update.ClientUpdateChecker;
import com.theshuai.specusclient.update.DesktopUpdateNotifier;
import com.theshuai.specusclient.cli.ClientCli;
import com.theshuai.specusclient.cli.ClientExitStatus;
import com.theshuai.specusclient.cli.CliOutput;
import com.theshuai.specusclient.cli.CliState;
import com.theshuai.specusclient.auth.FirstLoginRetry;
import com.theshuai.specusclient.auth.HttpLoginFailure;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
public class SpecusClientApplication {
    private static final String CONFIG_FILE = "client.jsonc";

    public static void main(String[] args) {
        ClientCli.Options options;
        try {
            options = ClientCli.parse(args);
        } catch (IllegalArgumentException error) {
            System.exit(CliOutput.result(java.util.Arrays.asList(args).contains("--json"),"arguments",2,null,"specus-client: " + error.getMessage()));
            return;
        }
        if (options.help()) { CliOutput.result(options.json(),"help",0,java.util.Map.of("help",ClientCli.HELP),ClientCli.HELP); return; }
        if (options.version()) { CliOutput.result(options.json(),"version",0,java.util.Map.of("version",currentVersion()),currentVersion()); return; }
        if (java.util.Set.of("status","peers","services","egress").contains(options.command())) { System.exit(CliState.query(options)); return; }
        if ("ui".equals(options.command())) { System.exit(com.theshuai.specusclient.cli.LocalUi.run(options, currentVersion())); return; }
        ClientStartupConfig loaded;
        try {
            loaded = ClientCli.load(options.config(), warning -> System.err.println("Warning: " + warning));
        } catch (Exception error) {
            System.exit(CliOutput.result(options.json(),options.command(),2,null,"specus-client: invalid config " + options.config() + ": " + error.getMessage()
                    + "\nCheck the configuration or run --help for usage."));
            return;
        }
        if ("validate".equals(options.command())) {
            CliOutput.result(options.json(),"config validate",0,java.util.Map.of("configPath",options.config().toString(),"offline",true),"Configuration valid: " + options.config() + " (offline; connectivity not tested)");
            return;
        }
        if (options.noUpdate()) loaded.setUpdateCheckEnabled(false);
        if ("show".equals(options.command())) {
            var effective = CliOutput.redactedConfig(loaded);
            CliOutput.result(options.json(),"config show",0,java.util.Map.of("configPath",options.config().toString(),"config",effective),options.config()+"\n"+effective.toPrettyString()); return;
        }
        if ("doctor".equals(options.command())) { System.exit(doctor(options,loaded)); return; }
        SpringApplication application = new SpringApplication(SpecusClientApplication.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.setBannerMode(org.springframework.boot.Banner.Mode.OFF);
        // Explicit CLI options take precedence over environment/application properties.
        application.addInitializers(context -> context.getEnvironment().getPropertySources().addFirst(
                new org.springframework.core.env.MapPropertySource("specus-cli", java.util.Map.of(
                        "specus.cli.config", options.config().toString(),
                        "specus.cli.no-update", options.noUpdate(),
                        "specus.cli.login-timeout", options.loginTimeoutSeconds(),
                        "logging.level.root", options.debug() ? "DEBUG" : "INFO"))));
        application.setDefaultProperties(java.util.Map.of("logging.level.root", options.debug() ? "DEBUG" : "INFO"));
        // DevTools replays the arguments supplied to run when restarting main. Retain
        // our validated arguments, and let its special silent-exit exception reach its
        // handler rather than catching it and terminating the restarted process.
        org.springframework.context.ConfigurableApplicationContext context;
        try {
            context = application.run(args);
        } catch (org.springframework.beans.BeansException error) {
            // DevTools' uncaught-exception handler otherwise reports bean startup
            // failures as a successful process exit. Do not catch its restart signal.
            System.err.println("specus-client: startup failed; check the preceding configuration/login error.");
            Throwable cause = error;
            while (cause.getCause()!=null) cause=cause.getCause();
            System.exit(cause instanceof HttpLoginFailure failure ? failure.exitCode() : cause instanceof IOException ? 2 : 1);
            return;
        }
        int exitCode = context.getBean(ClientExitStatus.class).await();
        SpringApplication.exit(context, () -> exitCode);
        System.exit(exitCode);
    }

    @Bean
    public ClientStartupConfig clientStartupConfig(
            @Value("${specus.cli.config:client.jsonc}") String configPath,
            @Value("${specus.cli.no-update:false}") boolean noUpdate) throws IOException {
        Path path = Path.of(configPath).toAbsolutePath().normalize();
        log.info("加载 specus client 配置: {}", path);
        ClientStartupConfig startupConfig = ClientCli.load(path);
        if (noUpdate) startupConfig.setUpdateCheckEnabled(false);
        return startupConfig;
    }

    @Bean
    public SpecusBean specusBean(ClientStartupConfig startupConfig,
            @Value("${specus.cli.login-timeout:60}") int loginTimeoutSeconds, CliState cliState) {
        return FirstLoginRetry.login(Duration.ofSeconds(loginTimeoutSeconds),
                remaining -> loginAndBuildSpecus(startupConfig, remaining), message -> log.warn("{}", message));
    }

    @Bean(destroyMethod = "close")
    public ClientUpdateChecker clientUpdateChecker(ClientStartupConfig startupConfig) {
        ClientUpdateChecker checker = new ClientUpdateChecker(
                startupConfig,
                currentVersion(),
                new DesktopUpdateNotifier(startupConfig));
        checker.start();
        return checker;
    }

    private static SpecusBean loginAndBuildSpecus(ClientStartupConfig startupConfig) {
        return loginAndBuildSpecus(startupConfig, Duration.ofSeconds(20));
    }

    @Bean(destroyMethod="close")
    public CliState cliState(@Value("${specus.cli.config:client.jsonc}") String configPath) throws IOException {
        return new CliState(Path.of(configPath));
    }

    private static int doctor(ClientCli.Options options, ClientStartupConfig config) {
        String scope = options.probe() ? "server-tcp" : "offline";
        var data = java.util.Map.of("configPath",options.config().toString(),"scope",scope,"authenticationTested",false,"businessTested",false);
        if (options.probe()) {
            var executor = java.util.concurrent.Executors.newSingleThreadExecutor(r -> { var thread=new Thread(r,"cli-doctor"); thread.setDaemon(true); return thread; });
            try (var socket = new java.net.Socket()) {
                var future = executor.submit(() -> {
                    URI uri = URI.create(config.getServerBaseUrl());
                    socket.connect(new java.net.InetSocketAddress(uri.getHost(),uri.getPort()>0 ? uri.getPort() : "https".equals(uri.getScheme()) ? 443 : 80),5000); return true;
                });
                future.get(5,TimeUnit.SECONDS);
            } catch (Exception error) {
                return CliOutput.result(options.json(),"doctor",4,data,"Server TCP probe failed or timed out. Check DNS, proxy, firewall and server availability; authentication was not attempted.");
            } finally { executor.shutdownNow(); }
        }
        return CliOutput.result(options.json(),"doctor",0,data,"Doctor passed ("+scope+"); authentication, TLS and business readiness not tested.");
    }

    public static SpecusBean loginAndBuildSpecus(ClientStartupConfig startupConfig, Duration timeout) {
        long attemptStarted = System.nanoTime();
        ClientEnvironmentInfo environment = collectEnvironment();
        ClientAuthLoginRequest loginRequest = new ClientAuthLoginRequest();
        loginRequest.setEnvironment(environment);
        if (!StringUtils.hasText(startupConfig.getApiKey()) || !StringUtils.hasText(startupConfig.getSecret())) {
            throw new IllegalStateException(CONFIG_FILE + " 必须包含 apiKey 和 secret");
        }
        loginRequest.setApiKey(startupConfig.getApiKey().trim());
        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        loginRequest.setTimestamp(timestamp);
        loginRequest.setNonce(nonce);
        // Resolved per login rather than cached: rotating the credential should take effect on the
        // next reconnect, not the next restart. An inline secret resolves to itself.
        loginRequest.setSignature(ClientAuthSigner.signApiKey(
                loginRequest.getApiKey(),
                timestamp,
                nonce,
                environment,
                MachineCredential.resolve(startupConfig.getSecret())
        ));

        Duration remaining = timeout.minusNanos(System.nanoTime() - attemptStarted);
        if (remaining.isNegative() || remaining.isZero())
            throw new HttpLoginFailure("HTTP login preparation exceeded the request budget.", true);
        ClientAuthLoginResponse response = postLogin(startupConfig, loginRequest, remaining);
        SpecusBean specusBean = new SpecusBean();
        specusBean.setClientName(response.getClientName());
        specusBean.setClientSessionId(response.getClientSessionId());
        specusBean.setAccessToken(response.getAccessToken());
        specusBean.setTokenTtlSeconds(response.getTokenTtlSeconds());
        if (response.getTokenTtlSeconds() > 0) {
            specusBean.setTokenExpiresAtMillis(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(response.getTokenTtlSeconds()));
        }
        specusBean.setRemoteAddress(response.getNettyHost());
        specusBean.setRemotePort(response.getNettyPort());
        specusBean.setNettyTls(response.isNettyTls());
        specusBean.setMaxOnlineInstances(response.getMaxOnlineInstances());
        specusBean.setSpecusConfigList(toSpecusConfigs(response.getSpecusConfigList()));
        specusBean.setHttpSpecusConfigList(toHttpSpecusConfigs(response.getHttpSpecusConfigList()));
        specusBean.setPeerMesh(response.getPeerMesh());
        specusBean.setPeerMeshDevice(startupConfig.getPeerMeshDevice());
        specusBean.setPeerMeshTunName(startupConfig.getPeerMeshTunName());
        specusBean.setPeerMeshMtu(startupConfig.getPeerMeshMtu());
        specusBean.setAuthRefresher(() -> loginAndBuildSpecus(startupConfig));
        log.info("客户端 HTTP 登录成功: clientName={}, session={}, specus={}:{}, tcp={}, http={}, peerMesh={}, peerMeshDevice={}, peerMeshMtu={}, maxOnlineInstances={}",
                specusBean.getClientName(),
                specusBean.getClientSessionId(),
                specusBean.getRemoteAddress(),
                specusBean.getRemotePort(),
                specusBean.getSpecusConfigList().size(),
                specusBean.getHttpSpecusConfigList().size(),
                response.getPeerMesh() != null && response.getPeerMesh().isEnabled(),
                specusBean.getPeerMeshDevice(),
                specusBean.getPeerMeshMtu(),
                specusBean.getMaxOnlineInstances());
        return specusBean;
    }

    static ClientAuthLoginResponse postLogin(ClientStartupConfig startupConfig, ClientAuthLoginRequest loginRequest, Duration timeout) {
        long requestStarted = System.nanoTime();
        String url = trimTrailingSlash(startupConfig.getServerBaseUrl()) + "/api/client/auth/login";
        String body = JsonUtil.objectToString(loginRequest);
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout.compareTo(Duration.ofSeconds(10)) < 0 ? timeout : Duration.ofSeconds(10))
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout.compareTo(Duration.ofSeconds(20)) < 0 ? timeout : Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        var pending = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        try {
            // HttpRequest.timeout alone does not bound a stalled response body on JDK 21.
            long remainingNanos = request.timeout().orElseThrow().toNanos() - (System.nanoTime() - requestStarted);
            if (remainingNanos <= 0) throw new java.util.concurrent.TimeoutException();
            HttpResponse<String> response = pending.get(remainingNanos, TimeUnit.NANOSECONDS);
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw HttpLoginFailure.forStatus(response.statusCode(), response.headers().firstValue("Retry-After").orElse(null));
            }
            ClientAuthLoginResponse loginResponse;
            try {
                // JsonUtil logs invalid input verbatim, which may contain access tokens.
                loginResponse = new com.fasterxml.jackson.databind.ObjectMapper()
                        .disable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                        .readValue(response.body(), ClientAuthLoginResponse.class);
            } catch (com.fasterxml.jackson.core.JsonProcessingException error) {
                throw new HttpLoginFailure("Invalid HTTP login response. Check serverBaseUrl and server/client compatibility.", false);
            }
            if (loginResponse == null || !StringUtils.hasText(loginResponse.getAccessToken())
                    || !StringUtils.hasText(loginResponse.getClientName())
                    || !StringUtils.hasText(loginResponse.getNettyHost())
                    || loginResponse.getClientSessionId() <= 0
                    || loginResponse.getNettyPort() <= 0 || loginResponse.getNettyPort() > 65535) {
                throw new HttpLoginFailure("Invalid HTTP login response: missing client/session/token/netty endpoint.", false);
            }
            return loginResponse;
        } catch (java.util.concurrent.TimeoutException e) {
            throw new HttpLoginFailure("HTTP login request timeout. Check network/server availability.", true);
        } catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof javax.net.ssl.SSLException)
                throw new HttpLoginFailure("HTTP login TLS failure. Check the server certificate, hostname and system trust store; do not disable verification.", false);
            throw new HttpLoginFailure("HTTP login network failure. Check DNS, proxy and server availability.", e.getCause() instanceof IOException);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HttpLoginFailure("HTTP login cancelled.", false);
        } finally {
            pending.cancel(true);
            // close() waits for unfinished exchanges and can undo the deadline guarantee.
            httpClient.shutdownNow();
        }
    }

    private static ClientEnvironmentInfo collectEnvironment() {
        ClientEnvironmentInfo info = new ClientEnvironmentInfo();
        info.setMachineFingerprint(machineFingerprint());
        info.setHostname(hostname());
        info.setOsUser(System.getProperty("user.name", "unknown"));
        info.setOsName(System.getProperty("os.name", ""));
        info.setOsVersion(System.getProperty("os.version", ""));
        info.setOsArch(System.getProperty("os.arch", ""));
        info.setJavaVersion(System.getProperty("java.version", ""));
        info.setClientVersion(currentVersion());
        info.setLocalAddresses(localAddresses());
        info.setPeerPublicKey(PeerKeyStore.publicKeyBase64());
        info.setStartedAt(Instant.now().toString());
        ClientEnvironmentInfo.ClientPeerServiceCapabilities discovery =
                new ClientEnvironmentInfo.ClientPeerServiceCapabilities();
        discovery.setVersion(PeerServiceDiscovery.PROTOCOL_VERSION);
        discovery.setApplications(new ArrayList<>(PeerServiceDiscovery.APPLICATIONS));
        info.setClientPeerServiceCapabilities(discovery);
        return info;
    }

    private static String machineFingerprint() {
        try {
            Path directory = Path.of(System.getProperty("user.home"), ".specus");
            Path file = directory.resolve("machine-id");
            if (Files.exists(file)) {
                String existing = Files.readString(file, StandardCharsets.UTF_8).trim();
                if (StringUtils.hasText(existing)) {
                    return existing;
                }
            }
            Files.createDirectories(directory);
            String generated = "m_" + UUID.randomUUID();
            Files.writeString(file, generated, StandardCharsets.UTF_8);
            return generated;
        } catch (Exception e) {
            String fallback = hostname() + "\n" + System.getProperty("os.name", "")
                    + "\n" + System.getProperty("os.arch", "");
            return "m_" + HexFormat.of().formatHex(com.theshuai.common.security.HmacSigner.sha256(fallback)).substring(0, 32);
        }
    }

    private static String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "unknown-host";
        }
    }

    private static List<String> localAddresses() {
        List<String> addresses = new ArrayList<>();
        try {
            for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!networkInterface.isUp() || networkInterface.isLoopback() || networkInterface.isVirtual()) {
                    continue;
                }
                for (InetAddress address : Collections.list(networkInterface.getInetAddresses())) {
                    if (!address.isLoopbackAddress() && !address.isLinkLocalAddress()) {
                        addresses.add(address.getHostAddress());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("采集本地 IP 失败: {}", e.getMessage());
        }
        return addresses;
    }

    private static List<SpecusConfig> toSpecusConfigs(List<ClientAuthLoginResponse.SpecusEndpoint> endpoints) {
        List<SpecusConfig> configs = new ArrayList<>();
        if (endpoints == null) {
            return configs;
        }
        for (ClientAuthLoginResponse.SpecusEndpoint endpoint : endpoints) {
            SpecusConfig config = new SpecusConfig();
            config.setPort(endpoint.getPort());
            config.setSpecusAddress(endpoint.getSpecusAddress());
            config.setSpecusPort(endpoint.getSpecusPort());
            configs.add(config);
        }
        return configs;
    }

    private static List<HttpSpecusConfig> toHttpSpecusConfigs(List<ClientAuthLoginResponse.HttpRouteEndpoint> endpoints) {
        List<HttpSpecusConfig> configs = new ArrayList<>();
        if (endpoints == null) {
            return configs;
        }
        for (ClientAuthLoginResponse.HttpRouteEndpoint endpoint : endpoints) {
            HttpSpecusConfig config = new HttpSpecusConfig();
            config.setRoute(endpoint.getRoute());
            config.setTargetBaseUrl(endpoint.getTargetBaseUrl());
            config.setInsecureSkipVerify(endpoint.isInsecureSkipVerify());
            configs.add(config);
        }
        return configs;
    }

    private static String trimTrailingSlash(String value) {
        String normalized = value == null ? "" : value.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    /** Manifest version injected by release packaging; deterministic development fallback otherwise. */
    static String currentVersion() {
        String version = SpecusClientApplication.class.getPackage().getImplementationVersion();
        return StringUtils.hasText(version) ? version.trim() : "0.0.0-dev";
    }
}
