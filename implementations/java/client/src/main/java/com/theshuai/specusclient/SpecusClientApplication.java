package com.theshuai.specusclient;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.peer.PeerKeyStore;
import com.theshuai.specusclient.update.ClientUpdateChecker;
import com.theshuai.specusclient.update.DesktopUpdateNotifier;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.FileInputStream;
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
        SpringApplication application = new SpringApplication(SpecusClientApplication.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        application.run(args);
    }

    @Bean
    public ClientStartupConfig clientStartupConfig() {
        String configString = loadConfigString();
        if (!StringUtils.hasLength(configString)) {
            throw new IllegalStateException("未找到 " + CONFIG_FILE + " 配置，无法启动 specus client");
        }
        ClientStartupConfig startupConfig = JsonUtil.stringToObject(configString, ClientStartupConfig.class);
        if (startupConfig == null || !StringUtils.hasText(startupConfig.getServerBaseUrl())) {
            throw new IllegalStateException(CONFIG_FILE + " 必须使用 HTTP 登录配置，至少包含 serverBaseUrl");
        }
        if (startupConfig.getControlTls() == null) {
            startupConfig.setControlTls(new com.theshuai.specusclient.bean.ControlTlsConfig());
        }
        startupConfig.getControlTls().validate(startupConfig.getServerBaseUrl());
        return startupConfig;
    }

    @Bean
    public SpecusBean specusBean(ClientStartupConfig startupConfig) {
        return loginAndBuildSpecus(startupConfig);
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
        loginRequest.setSignature(ClientAuthSigner.signApiKey(
                loginRequest.getApiKey(),
                timestamp,
                nonce,
                environment,
                startupConfig.getSecret().trim()
        ));

        ClientAuthLoginResponse response = postLogin(startupConfig, loginRequest);
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

    private static ClientAuthLoginResponse postLogin(ClientStartupConfig startupConfig, ClientAuthLoginRequest loginRequest) {
        String url = trimTrailingSlash(startupConfig.getServerBaseUrl()) + "/api/client/auth/login";
        String body = JsonUtil.objectToString(loginRequest);
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("客户端 HTTP 登录失败 HTTP " + response.statusCode() + ": " + response.body());
            }
            ClientAuthLoginResponse loginResponse = JsonUtil.stringToObject(response.body(), ClientAuthLoginResponse.class);
            if (loginResponse == null || !StringUtils.hasText(loginResponse.getAccessToken())
                    || !StringUtils.hasText(loginResponse.getClientName())
                    || !StringUtils.hasText(loginResponse.getNettyHost())
                    || loginResponse.getNettyPort() <= 0) {
                throw new IllegalStateException("客户端 HTTP 登录返回无效");
            }
            return loginResponse;
        } catch (IOException e) {
            throw new IllegalStateException("客户端 HTTP 登录请求失败: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("客户端 HTTP 登录请求被中断", e);
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

    private static String loadConfigString() {
        File configFile = new File(System.getProperty("user.dir") + File.separator + CONFIG_FILE);

        try {
            if (configFile.exists()) {
                log.info("加载 specus client 配置: {}", configFile.getAbsolutePath());
                return readFile(configFile);
            }
            log.warn("未找到 {}。已检查路径: [{}]", CONFIG_FILE, configFile.getAbsolutePath());
            return "";
        } catch (Exception e) {
            log.error("处理 specus client 配置失败", e);
            return "";
        }
    }

    private static String readFile(File file) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            byte[] bytes = new byte[fileInputStream.available()];
            IOUtils.readFully(fileInputStream, bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        }
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
