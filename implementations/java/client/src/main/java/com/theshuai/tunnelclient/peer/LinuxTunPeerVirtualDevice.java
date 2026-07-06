package com.theshuai.tunnelclient.peer;

import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
final class LinuxTunPeerVirtualDevice implements PeerVirtualDevice {
    private static final int O_RDWR = 0x0002;
    private static final int IFNAMSIZ = 16;
    private static final int IFREQ_SIZE = 40;
    private static final short IFF_TUN = 0x0001;
    private static final short IFF_NO_PI = 0x1000;
    private static final long TUNSETIFF = 0x400454caL;
    private static final String TUN_DEVICE = "/dev/net/tun";
    private static final LibC LIBC = Native.load("c", LibC.class);

    private final PeerVirtualDeviceOptions options;
    private final ClientAuthLoginResponse.PeerMeshConfig config;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile int fd = -1;
    private volatile String ifName;
    private volatile Thread readerThread;
    private final Set<String> syncedPeerRoutes = ConcurrentHashMap.newKeySet();

    LinuxTunPeerVirtualDevice(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
        this.options = options;
        this.config = config;
    }

    @Override
    public String name() {
        return StringUtils.hasText(ifName) ? ifName : options.tunName();
    }

    @Override
    public synchronized void start(PacketHandler outboundHandler) {
        if (running.get()) {
            return;
        }
        if (config == null || !StringUtils.hasText(config.getVirtualIp()) || !StringUtils.hasText(config.getCidr())) {
            throw new IllegalStateException("peer mesh Linux TUN 缺少 virtualIp/cidr");
        }
        int nextFd = openTun(options.tunName());
        fd = nextFd;
        try {
            configureInterface(name(), config.getVirtualIp(), config.getCidr(), options.mtu());
            running.set(true);
            Thread thread = new Thread(() -> readLoop(outboundHandler), "peer-mesh-linux-tun");
            thread.setDaemon(true);
            readerThread = thread;
            thread.start();
            log.info("Peer mesh Linux TUN 已启用: dev={}, ip={}, cidr={}, mtu={}",
                    name(), config.getVirtualIp(), config.getCidr(), options.mtu());
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    @Override
    public synchronized void syncPeerRoutes(Collection<String> peerVirtualIps) {
        Set<String> desired = normalizePeerRoutes(peerVirtualIps);
        for (String routeIp : new HashSet<>(syncedPeerRoutes)) {
            if (!desired.contains(routeIp)) {
                deletePeerRoute(routeIp);
            }
        }
        for (String routeIp : desired) {
            if (!syncedPeerRoutes.contains(routeIp)) {
                addPeerRoute(routeIp);
            }
        }
    }

    @Override
    public void writePacket(byte[] packet) {
        int current = fd;
        if (current < 0 || packet == null || packet.length == 0) {
            return;
        }
        int offset = 0;
        while (offset < packet.length) {
            int written = write(current, packet, offset, packet.length - offset);
            if (written <= 0) {
                throw new IllegalStateException("写入 Linux TUN 失败");
            }
            offset += written;
        }
    }

    @Override
    public synchronized void close() {
        try {
            syncPeerRoutes(Set.of());
        } catch (Exception e) {
            log.debug("Peer mesh Linux TUN 清理 peer routes 失败: {}", e.getMessage());
        }
        running.set(false);
        int current = fd;
        fd = -1;
        if (current >= 0) {
            try {
                LIBC.close(current);
            } catch (Exception ignored) {
                // best effort close
            }
        }
        Thread thread = readerThread;
        readerThread = null;
        if (thread != null) {
            thread.interrupt();
        }
    }

    private int openTun(String requestedName) {
        int nextFd = open(TUN_DEVICE, O_RDWR);
        Memory ifreq = new Memory(IFREQ_SIZE);
        byte[] nameBytes = requestedName.getBytes(StandardCharsets.US_ASCII);
        ifreq.write(0, nameBytes, 0, Math.min(nameBytes.length, IFNAMSIZ - 1));
        ifreq.setShort(IFNAMSIZ, (short) (IFF_TUN | IFF_NO_PI));
        int result = ioctl(nextFd, TUNSETIFF, ifreq);
        if (result < 0) {
            closeFd(nextFd);
            throw new IllegalStateException("Linux TUN TUNSETIFF 失败: " + lastError());
        }
        this.ifName = readInterfaceName(ifreq);
        return nextFd;
    }

    private void configureInterface(String name, String virtualIp, String cidr, int mtu) {
        runCommand(Duration.ofSeconds(10), "ip", "addr", "replace", virtualIp + "/32", "dev", name);
        runCommand(Duration.ofSeconds(10), "ip", "link", "set", "dev", name, "mtu", String.valueOf(mtu), "up");
        if (StringUtils.hasText(cidr)) {
            runCommandQuiet(Duration.ofSeconds(5), "ip", "route", "del", cidr, "dev", name);
        }
    }

    private Set<String> normalizePeerRoutes(Collection<String> peerVirtualIps) {
        Set<String> desired = new HashSet<>();
        if (peerVirtualIps == null) {
            return desired;
        }
        for (String peerVirtualIp : peerVirtualIps) {
            String normalized = peerVirtualIp == null ? "" : peerVirtualIp.trim();
            if (isIpv4(normalized) && !normalized.equals(config.getVirtualIp())) {
                desired.add(normalized);
            }
        }
        return desired;
    }

    private void addPeerRoute(String peerVirtualIp) {
        String route = peerVirtualIp + "/32";
        try {
            runCommand(Duration.ofSeconds(10), "ip", "route", "replace", route, "dev", name());
            syncedPeerRoutes.add(peerVirtualIp);
            log.debug("Peer mesh Linux TUN peer route 已同步: {}", route);
        } catch (Exception e) {
            log.warn("Peer mesh Linux TUN 添加 peer route 失败: route={}, reason={}", route, e.getMessage());
        }
    }

    private void deletePeerRoute(String peerVirtualIp) {
        String route = peerVirtualIp + "/32";
        runCommandQuiet(Duration.ofSeconds(5), "ip", "route", "del", route, "dev", name());
        syncedPeerRoutes.remove(peerVirtualIp);
        log.debug("Peer mesh Linux TUN peer route 已移除: {}", route);
    }

    private void readLoop(PacketHandler outboundHandler) {
        byte[] buffer = new byte[Math.max(1500, options.mtu() + 128)];
        while (running.get()) {
            int current = fd;
            if (current < 0) {
                return;
            }
            int read = read(current, buffer, buffer.length);
            if (read > 0) {
                outboundHandler.handle(Arrays.copyOf(buffer, read));
            } else if (running.get()) {
                log.debug("Peer mesh Linux TUN read returned {}", read);
            }
        }
    }

    private String readInterfaceName(Memory ifreq) {
        byte[] bytes = ifreq.getByteArray(0, IFNAMSIZ);
        int length = 0;
        while (length < bytes.length && bytes[length] != 0) {
            length++;
        }
        return new String(bytes, 0, length, StandardCharsets.US_ASCII);
    }

    private boolean isIpv4(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
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
            throw new IllegalStateException("配置 Linux TUN 失败: " + e.getMessage(), e);
        }
    }

    private boolean runCommandQuiet(Duration timeout, String... command) {
        try {
            runCommand(timeout, command);
            return true;
        } catch (Exception e) {
            log.debug("忽略命令失败: {} {}", String.join(" ", command), e.getMessage());
            return false;
        }
    }

    private String readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        input.transferTo(output);
        return output.toString(StandardCharsets.UTF_8).trim();
    }

    private int open(String path, int flags) {
        try {
            int result = LIBC.open(path, flags);
            if (result < 0) {
                throw new IllegalStateException("打开 " + path + " 失败: " + lastError());
            }
            return result;
        } catch (LastErrorException e) {
            throw new IllegalStateException("打开 " + path + " 失败: errno=" + e.getErrorCode(), e);
        }
    }

    private int ioctl(int fileDescriptor, long request, Pointer argp) {
        try {
            return LIBC.ioctl(fileDescriptor, request, argp);
        } catch (LastErrorException e) {
            return -1;
        }
    }

    private int read(int fileDescriptor, byte[] buffer, int length) {
        try {
            return LIBC.read(fileDescriptor, buffer, length);
        } catch (LastErrorException e) {
            if (running.get()) {
                log.debug("Linux TUN read failed: errno={}", e.getErrorCode());
            }
            return -1;
        }
    }

    private int write(int fileDescriptor, byte[] buffer, int offset, int length) {
        byte[] slice = offset == 0 && length == buffer.length ? buffer : Arrays.copyOfRange(buffer, offset, offset + length);
        try {
            return LIBC.write(fileDescriptor, slice, length);
        } catch (LastErrorException e) {
            throw new IllegalStateException("Linux TUN write failed: errno=" + e.getErrorCode(), e);
        }
    }

    private void closeFd(int fileDescriptor) {
        try {
            LIBC.close(fileDescriptor);
        } catch (Exception ignored) {
            // best effort close
        }
    }

    private String lastError() {
        return "errno=" + Native.getLastError();
    }

    private interface LibC extends Library {
        int open(String pathname, int flags) throws LastErrorException;

        int ioctl(int fd, long request, Pointer argp) throws LastErrorException;

        int read(int fd, byte[] buffer, int count) throws LastErrorException;

        int write(int fd, byte[] buffer, int count) throws LastErrorException;

        int close(int fd) throws LastErrorException;
    }
}
