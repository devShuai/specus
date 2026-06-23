package com.theshuai.tunnelclient.peer;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APIOptions;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
final class WindowsWintunPeerVirtualDevice implements PeerVirtualDevice {
    private static final int RING_CAPACITY = 0x400000;

    private final PeerVirtualDeviceOptions options;
    private final ClientAuthLoginResponse.PeerMeshConfig config;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile Wintun wintun;
    private volatile Pointer adapter;
    private volatile Pointer session;
    private volatile Thread readerThread;

    WindowsWintunPeerVirtualDevice(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
        this.options = options;
        this.config = config;
    }

    @Override
    public String name() {
        return options.tunName();
    }

    @Override
    public synchronized void start(PacketHandler outboundHandler) {
        if (running.get()) {
            return;
        }
        if (config == null || !StringUtils.hasText(config.getVirtualIp()) || !StringUtils.hasText(config.getCidr())) {
            throw new IllegalStateException("peer mesh Wintun 缺少 virtualIp/cidr");
        }
        Wintun api = loadWintun();
        Pointer nextAdapter = api.WintunOpenAdapter(name());
        if (nextAdapter == null) {
            nextAdapter = api.WintunCreateAdapter(name(), "shuai-tunnel", null);
        }
        if (nextAdapter == null) {
            throw new IllegalStateException("Wintun adapter 创建失败，确认 wintun.dll 已在 PATH/工作目录且当前进程有管理员权限");
        }
        Pointer nextSession = api.WintunStartSession(nextAdapter, RING_CAPACITY);
        if (nextSession == null) {
            api.WintunCloseAdapter(nextAdapter);
            throw new IllegalStateException("Wintun session 启动失败");
        }
        wintun = api;
        adapter = nextAdapter;
        session = nextSession;
        try {
            configureInterface(name(), config.getVirtualIp(), config.getCidr(), options.mtu());
            running.set(true);
            Thread thread = new Thread(() -> readLoop(outboundHandler), "peer-mesh-wintun");
            thread.setDaemon(true);
            readerThread = thread;
            thread.start();
            log.info("Peer mesh Wintun 已启用: dev={}, ip={}, cidr={}, mtu={}",
                    name(), config.getVirtualIp(), config.getCidr(), options.mtu());
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    @Override
    public void writePacket(byte[] packet) {
        Wintun api = wintun;
        Pointer currentSession = session;
        if (api == null || currentSession == null || packet == null || packet.length == 0) {
            return;
        }
        Pointer sendPacket = api.WintunAllocateSendPacket(currentSession, packet.length);
        if (sendPacket == null) {
            throw new IllegalStateException("Wintun send packet 分配失败");
        }
        sendPacket.write(0, packet, 0, packet.length);
        api.WintunSendPacket(currentSession, sendPacket);
    }

    @Override
    public synchronized void close() {
        running.set(false);
        Wintun api = wintun;
        Pointer currentSession = session;
        Pointer currentAdapter = adapter;
        session = null;
        adapter = null;
        if (api != null && currentSession != null) {
            api.WintunEndSession(currentSession);
        }
        if (api != null && currentAdapter != null) {
            api.WintunCloseAdapter(currentAdapter);
        }
        Thread thread = readerThread;
        readerThread = null;
        if (thread != null) {
            thread.interrupt();
        }
    }

    private void readLoop(PacketHandler outboundHandler) {
        IntByReference packetSize = new IntByReference();
        while (running.get()) {
            Wintun api = wintun;
            Pointer currentSession = session;
            if (api == null || currentSession == null) {
                return;
            }
            Pointer packet = api.WintunReceivePacket(currentSession, packetSize);
            if (packet == null) {
                sleepQuietly(5);
                continue;
            }
            try {
                int size = packetSize.getValue();
                if (size > 0) {
                    outboundHandler.handle(packet.getByteArray(0, size));
                }
            } finally {
                api.WintunReleaseReceivePacket(currentSession, packet);
            }
        }
    }

    private Wintun loadWintun() {
        String configuredLibrary = System.getProperty("shuai.peerMesh.wintunDll");
        if (StringUtils.hasText(configuredLibrary)) {
            try {
                return Native.load(configuredLibrary, Wintun.class, W32APIOptions.UNICODE_OPTIONS);
            } catch (UnsatisfiedLinkError e) {
                throw new IllegalStateException("加载指定的 wintun.dll 失败: " + configuredLibrary, e);
            }
        }
        Path bundled = extractBundledWintun();
        if (bundled != null) {
            try {
                return Native.load(bundled.toAbsolutePath().toString(), Wintun.class, W32APIOptions.UNICODE_OPTIONS);
            } catch (UnsatisfiedLinkError e) {
                throw new IllegalStateException("加载随包 wintun.dll 失败: " + bundled, e);
            }
        }
        try {
            return Native.load("wintun", Wintun.class, W32APIOptions.UNICODE_OPTIONS);
        } catch (UnsatisfiedLinkError e) {
            throw new IllegalStateException("加载 wintun.dll 失败，客户端包内没有对应架构的 native/windows/*/wintun.dll；"
                    + "可将 wintun.dll 放到工作目录/PATH，或设置 -Dshuai.peerMesh.wintunDll=完整路径", e);
        }
    }

    private Path extractBundledWintun() {
        String arch = nativeArch();
        if (!StringUtils.hasText(arch)) {
            return null;
        }
        String resource = "native/windows/" + arch + "/wintun.dll";
        try (InputStream input = WindowsWintunPeerVirtualDevice.class.getClassLoader().getResourceAsStream(resource)) {
            if (input == null) {
                return null;
            }
            Path targetDir = nativeCacheDir().resolve("windows").resolve(arch);
            Files.createDirectories(targetDir);
            Path target = targetDir.resolve("wintun.dll");
            if (Files.exists(target)) {
                return target;
            }
            Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        } catch (Exception e) {
            throw new IllegalStateException("解压随包 wintun.dll 失败: " + resource, e);
        }
    }

    private Path nativeCacheDir() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (StringUtils.hasText(localAppData)) {
            return Path.of(localAppData, "shuai-tunnel", "native");
        }
        return Path.of(System.getProperty("java.io.tmpdir"), "shuai-tunnel", "native");
    }

    private String nativeArch() {
        String osArch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (osArch.equals("amd64") || osArch.equals("x86_64")) {
            return "x86_64";
        }
        if (osArch.equals("aarch64") || osArch.equals("arm64")) {
            return "aarch64";
        }
        if (osArch.equals("x86") || osArch.equals("i386") || osArch.equals("i686")) {
            return "x86";
        }
        return "";
    }

    private void configureInterface(String name, String virtualIp, String cidr, int mtu) {
        String mask = ipv4Mask(cidrPrefix(cidr));
        runCommand(Duration.ofSeconds(10), "netsh", "interface", "ip", "set", "address",
                "name=" + name, "static", virtualIp, mask);
        runCommand(Duration.ofSeconds(10), "netsh", "interface", "ipv4", "set", "subinterface",
                name, "mtu=" + mtu, "store=active");
        runCommand(Duration.ofSeconds(10), "netsh", "interface", "ipv4", "add", "route",
                cidr, name, "store=active");
    }

    private int cidrPrefix(String cidr) {
        int slash = cidr == null ? -1 : cidr.indexOf('/');
        if (slash < 0 || slash == cidr.length() - 1) {
            throw new IllegalArgumentException("peer mesh cidr 无效: " + cidr);
        }
        return Integer.parseInt(cidr.substring(slash + 1));
    }

    private String ipv4Mask(int prefix) {
        if (prefix < 0 || prefix > 32) {
            throw new IllegalArgumentException("peer mesh prefix 无效: " + prefix);
        }
        int mask = prefix == 0 ? 0 : (int) (0xFFFF_FFFFL << (32 - prefix));
        return ((mask >>> 24) & 0xFF) + "."
                + ((mask >>> 16) & 0xFF) + "."
                + ((mask >>> 8) & 0xFF) + "."
                + (mask & 0xFF);
    }

    private void runCommand(Duration timeout, String... command) {
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            boolean exited = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            String output = readAll(process.getInputStream());
            if (!exited) {
                process.destroyForcibly();
                throw new IllegalStateException("命令超时: " + String.join(" ", command));
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException("命令失败(" + process.exitValue() + "): "
                        + String.join(" ", command) + " " + output);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("命令被中断: " + String.join(" ", command), e);
        } catch (Exception e) {
            throw new IllegalStateException("配置 Wintun 失败: " + e.getMessage(), e);
        }
    }

    private String readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        input.transferTo(output);
        return output.toString(StandardCharsets.UTF_8).trim();
    }

    private void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private interface Wintun extends Library {
        Pointer WintunOpenAdapter(String name);

        Pointer WintunCreateAdapter(String name, String tunnelType, Pointer requestedGuid);

        void WintunCloseAdapter(Pointer adapter);

        Pointer WintunStartSession(Pointer adapter, int capacity);

        void WintunEndSession(Pointer session);

        Pointer WintunReceivePacket(Pointer session, IntByReference packetSize);

        void WintunReleaseReceivePacket(Pointer session, Pointer packet);

        Pointer WintunAllocateSendPacket(Pointer session, int packetSize);

        void WintunSendPacket(Pointer session, Pointer packet);
    }
}
