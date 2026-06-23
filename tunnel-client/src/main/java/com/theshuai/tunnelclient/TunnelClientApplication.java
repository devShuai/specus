package com.theshuai.tunnelclient;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.ClientStartupConfig;
import com.theshuai.tunnelclient.bean.HttpTunnelConfig;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
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
public class TunnelClientApplication {
    private static final String CONFIG_FILE = "tunnelClientConfig.json";

    public static void main(String[] args) {
        SpringApplication.run(TunnelClientApplication.class, args);
    }

    @Bean
    public TunnelBean tunnelBean() {
        String configString = loadConfigString();
        if (!StringUtils.hasLength(configString)) {
            throw new IllegalStateException("未找到 " + CONFIG_FILE + " 配置，无法启动 tunnel client");
        }
        ClientStartupConfig startupConfig = JsonUtil.stringToObject(configString, ClientStartupConfig.class);
        if (startupConfig == null || !StringUtils.hasText(startupConfig.getServerBaseUrl())) {
            throw new IllegalStateException(CONFIG_FILE + " 必须使用 HTTP 登录配置，至少包含 serverBaseUrl");
        }
        return loginAndBuildTunnel(startupConfig);
    }

    private static TunnelBean loginAndBuildTunnel(ClientStartupConfig startupConfig) {
        ClientEnvironmentInfo environment = collectEnvironment();
        ClientAuthLoginRequest loginRequest = new ClientAuthLoginRequest();
        loginRequest.setEnvironment(environment);
        String authType = StringUtils.hasText(startupConfig.getAuthType()) ? startupConfig.getAuthType() : "apiKey";
        loginRequest.setAuthType(authType);
        if ("password".equalsIgnoreCase(authType)) {
            loginRequest.setUsername(startupConfig.getUsername());
            loginRequest.setPassword(startupConfig.getPassword());
        } else {
            loginRequest.setApiKey(startupConfig.getApiKey());
            String timestamp = String.valueOf(System.currentTimeMillis());
            String nonce = UUID.randomUUID().toString().replace("-", "");
            loginRequest.setTimestamp(timestamp);
            loginRequest.setNonce(nonce);
            loginRequest.setSignature(ClientAuthSigner.signApiKey(
                    startupConfig.getApiKey(),
                    timestamp,
                    nonce,
                    environment,
                    startupConfig.getSecret()
            ));
        }

        ClientAuthLoginResponse response = postLogin(startupConfig, loginRequest);
        TunnelBean tunnelBean = new TunnelBean();
        tunnelBean.setClientName(response.getClientName());
        tunnelBean.setClientSessionId(response.getClientSessionId());
        tunnelBean.setAccessToken(response.getAccessToken());
        tunnelBean.setTokenTtlSeconds(response.getTokenTtlSeconds());
        if (response.getTokenTtlSeconds() > 0) {
            tunnelBean.setTokenExpiresAtMillis(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(response.getTokenTtlSeconds()));
        }
        tunnelBean.setRemoteAddress(response.getNettyHost());
        tunnelBean.setRemotePort(response.getNettyPort());
        tunnelBean.setMaxOnlineInstances(response.getMaxOnlineInstances());
        tunnelBean.setTunnelConfigList(toTunnelConfigs(response.getTunnelConfigList()));
        tunnelBean.setHttpTunnelConfigList(toHttpTunnelConfigs(response.getHttpTunnelConfigList()));
        tunnelBean.setAuthRefresher(() -> loginAndBuildTunnel(startupConfig));
        log.info("客户端 HTTP 登录成功: clientName={}, session={}, tunnel={}:{}, tcp={}, http={}, maxOnlineInstances={}",
                tunnelBean.getClientName(),
                tunnelBean.getClientSessionId(),
                tunnelBean.getRemoteAddress(),
                tunnelBean.getRemotePort(),
                tunnelBean.getTunnelConfigList().size(),
                tunnelBean.getHttpTunnelConfigList().size(),
                tunnelBean.getMaxOnlineInstances());
        return tunnelBean;
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
        info.setClientVersion(TunnelClientApplication.class.getPackage().getImplementationVersion());
        info.setLocalAddresses(localAddresses());
        info.setStartedAt(Instant.now().toString());
        return info;
    }

    private static String machineFingerprint() {
        try {
            Path directory = Path.of(System.getProperty("user.home"), ".shuai-tunnel");
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
                log.info("加载 tunnel client 配置: {}", configFile.getAbsolutePath());
                return readFile(configFile);
            }
            log.warn("未找到 {}。已检查路径: [{}]", CONFIG_FILE, configFile.getAbsolutePath());
            return "";
        } catch (Exception e) {
            log.error("处理 tunnel client 配置失败", e);
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

    private static List<TunnelConfig> toTunnelConfigs(List<ClientAuthLoginResponse.TunnelEndpoint> endpoints) {
        List<TunnelConfig> configs = new ArrayList<>();
        if (endpoints == null) {
            return configs;
        }
        for (ClientAuthLoginResponse.TunnelEndpoint endpoint : endpoints) {
            TunnelConfig config = new TunnelConfig();
            config.setPort(endpoint.getPort());
            config.setTunnelAddress(endpoint.getTunnelAddress());
            config.setTunnelPort(endpoint.getTunnelPort());
            configs.add(config);
        }
        return configs;
    }

    private static List<HttpTunnelConfig> toHttpTunnelConfigs(List<ClientAuthLoginResponse.HttpRouteEndpoint> endpoints) {
        List<HttpTunnelConfig> configs = new ArrayList<>();
        if (endpoints == null) {
            return configs;
        }
        for (ClientAuthLoginResponse.HttpRouteEndpoint endpoint : endpoints) {
            HttpTunnelConfig config = new HttpTunnelConfig();
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
}
