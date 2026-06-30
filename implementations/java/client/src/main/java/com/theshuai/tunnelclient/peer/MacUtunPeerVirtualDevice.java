package com.theshuai.tunnelclient.peer;

import com.sun.jna.LastErrorException;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
final class MacUtunPeerVirtualDevice implements PeerVirtualDevice {
    private static final int AF_INET = 2;
    private static final int AF_INET6 = 30;
    private static final int AF_SYSTEM = 32;
    private static final int PF_SYSTEM = AF_SYSTEM;
    private static final int SOCK_DGRAM = 2;
    private static final int SYSPROTO_CONTROL = 2;
    private static final int AF_SYS_CONTROL = 2;
    private static final int UTUN_OPT_IFNAME = 2;
    private static final int CTL_INFO_SIZE = 100;
    private static final int MAX_KCTL_NAME = 96;
    private static final int SOCKADDR_CTL_SIZE = 32;
    private static final long CTLIOCGINFO = 0xC0644E03L;
    private static final String UTUN_CONTROL_NAME = "com.apple.net.utun_control";
    private static final LibC LIBC = Native.load("c", LibC.class);

    private final PeerVirtualDeviceOptions options;
    private final ClientAuthLoginResponse.PeerMeshConfig config;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile int fd = -1;
    private volatile String ifName;
    private volatile Thread readerThread;

    MacUtunPeerVirtualDevice(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
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
            throw new IllegalStateException("peer mesh macOS utun 缺少 virtualIp/cidr");
        }
        int nextFd = openUtun(options.tunName());
        fd = nextFd;
        try {
            configureInterface(name(), config.getVirtualIp(), config.getCidr(), options.mtu());
            running.set(true);
            Thread thread = new Thread(() -> readLoop(outboundHandler), "peer-mesh-mac-utun");
            thread.setDaemon(true);
            readerThread = thread;
            thread.start();
            log.info("Peer mesh macOS utun 已启用: dev={}, ip={}, cidr={}, mtu={}",
                    name(), config.getVirtualIp(), config.getCidr(), options.mtu());
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    @Override
    public void writePacket(byte[] packet) {
        int current = fd;
        if (current < 0 || packet == null || packet.length == 0) {
            return;
        }
        int addressFamily = addressFamily(packet);
        if (addressFamily == 0) {
            log.trace("Peer mesh macOS utun drop non-IP packet: {} bytes", packet.length);
            return;
        }
        byte[] frame = new byte[packet.length + 4];
        frame[3] = (byte) addressFamily;
        System.arraycopy(packet, 0, frame, 4, packet.length);
        int offset = 0;
        while (offset < frame.length) {
            int written = write(current, frame, offset, frame.length - offset);
            if (written <= 0) {
                throw new IllegalStateException("写入 macOS utun 失败");
            }
            offset += written;
        }
    }

    @Override
    public synchronized void close() {
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

    private int openUtun(String requestedName) {
        int socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        try {
            int controlId = lookupUtunControlId(socket);
            Memory sockaddr = new Memory(SOCKADDR_CTL_SIZE);
            sockaddr.clear();
            sockaddr.setByte(0, (byte) SOCKADDR_CTL_SIZE);
            sockaddr.setByte(1, (byte) AF_SYSTEM);
            sockaddr.setShort(2, (short) AF_SYS_CONTROL);
            sockaddr.setInt(4, controlId);
            sockaddr.setInt(8, requestedUtunUnit(requestedName));
            int result = connect(socket, sockaddr, SOCKADDR_CTL_SIZE);
            if (result < 0) {
                throw new IllegalStateException("连接 macOS utun control 失败: " + lastError());
            }
            this.ifName = readUtunInterfaceName(socket, requestedName);
            return socket;
        } catch (RuntimeException e) {
            closeFd(socket);
            throw e;
        }
    }

    private int lookupUtunControlId(int socket) {
        Memory info = new Memory(CTL_INFO_SIZE);
        info.clear();
        byte[] nameBytes = UTUN_CONTROL_NAME.getBytes(StandardCharsets.US_ASCII);
        info.write(4, nameBytes, 0, Math.min(nameBytes.length, MAX_KCTL_NAME - 1));
        int result = ioctl(socket, CTLIOCGINFO, info);
        if (result < 0) {
            throw new IllegalStateException("查询 macOS utun control id 失败: " + lastError());
        }
        int id = info.getInt(0);
        if (id <= 0) {
            throw new IllegalStateException("macOS utun control id 无效: " + id);
        }
        return id;
    }

    private String readUtunInterfaceName(int socket, String requestedName) {
        byte[] name = new byte[64];
        IntByReference length = new IntByReference(name.length);
        try {
            int result = LIBC.getsockopt(socket, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, length);
            if (result == 0) {
                int actualLength = Math.max(0, Math.min(length.getValue(), name.length));
                int end = 0;
                while (end < actualLength && name[end] != 0) {
                    end++;
                }
                if (end > 0) {
                    return new String(name, 0, end, StandardCharsets.US_ASCII);
                }
            }
        } catch (LastErrorException e) {
            log.debug("读取 macOS utun 接口名失败: errno={}", e.getErrorCode());
        }
        return requestedName != null && requestedName.toLowerCase(Locale.ROOT).startsWith("utun")
                ? requestedName
                : "utun";
    }

    private int requestedUtunUnit(String requestedName) {
        if (!StringUtils.hasText(requestedName)) {
            return 0;
        }
        String normalized = requestedName.trim().toLowerCase(Locale.ROOT);
        if (!normalized.startsWith("utun") || normalized.length() == 4) {
            return 0;
        }
        try {
            int index = Integer.parseInt(normalized.substring(4));
            return index >= 0 ? index + 1 : 0;
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private void configureInterface(String name, String virtualIp, String cidr, int mtu) {
        String mask = ipv4Mask(cidrPrefix(cidr));
        runCommand(Duration.ofSeconds(10), false,
                "ifconfig", name, "inet", virtualIp, virtualIp, "netmask", mask, "mtu", String.valueOf(mtu), "up");
        runCommand(Duration.ofSeconds(10), true,
                "route", "-n", "delete", "-net", cidr);
        runCommand(Duration.ofSeconds(10), false,
                "route", "-n", "add", "-net", cidr, "-interface", name);
    }

    private void readLoop(PacketHandler outboundHandler) {
        byte[] buffer = new byte[Math.max(1500, options.mtu() + 128) + 4];
        while (running.get()) {
            int current = fd;
            if (current < 0) {
                return;
            }
            int read = read(current, buffer, buffer.length);
            if (read > 4) {
                outboundHandler.handle(Arrays.copyOfRange(buffer, 4, read));
            } else if (running.get()) {
                log.debug("Peer mesh macOS utun read returned {}", read);
            }
        }
    }

    private int addressFamily(byte[] packet) {
        int version = (packet[0] >>> 4) & 0x0F;
        if (version == 4) {
            return AF_INET;
        }
        if (version == 6) {
            return AF_INET6;
        }
        return 0;
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

    private void runCommand(Duration timeout, boolean ignoreFailure, String... command) {
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
            if (process.exitValue() != 0 && !ignoreFailure) {
                throw new IllegalStateException("命令失败(" + process.exitValue() + "): "
                        + String.join(" ", command) + " " + output);
            }
            if (process.exitValue() != 0) {
                log.debug("忽略命令失败({}): {} {}", process.exitValue(), String.join(" ", command), output);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("命令被中断: " + String.join(" ", command), e);
        } catch (Exception e) {
            throw new IllegalStateException("配置 macOS utun 失败: " + e.getMessage(), e);
        }
    }

    private String readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        input.transferTo(output);
        return output.toString(StandardCharsets.UTF_8).trim();
    }

    private int socket(int domain, int type, int protocol) {
        try {
            int result = LIBC.socket(domain, type, protocol);
            if (result < 0) {
                throw new IllegalStateException("创建 macOS utun socket 失败: " + lastError());
            }
            return result;
        } catch (LastErrorException e) {
            throw new IllegalStateException("创建 macOS utun socket 失败: errno=" + e.getErrorCode(), e);
        }
    }

    private int ioctl(int fileDescriptor, long request, Pointer argp) {
        try {
            return LIBC.ioctl(fileDescriptor, request, argp);
        } catch (LastErrorException e) {
            return -1;
        }
    }

    private int connect(int socket, Pointer address, int addressLength) {
        try {
            return LIBC.connect(socket, address, addressLength);
        } catch (LastErrorException e) {
            return -1;
        }
    }

    private int read(int fileDescriptor, byte[] buffer, int length) {
        try {
            return LIBC.read(fileDescriptor, buffer, length);
        } catch (LastErrorException e) {
            if (running.get()) {
                log.debug("macOS utun read failed: errno={}", e.getErrorCode());
            }
            return -1;
        }
    }

    private int write(int fileDescriptor, byte[] buffer, int offset, int length) {
        byte[] slice = offset == 0 && length == buffer.length ? buffer : Arrays.copyOfRange(buffer, offset, offset + length);
        try {
            return LIBC.write(fileDescriptor, slice, length);
        } catch (LastErrorException e) {
            throw new IllegalStateException("macOS utun write failed: errno=" + e.getErrorCode(), e);
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
        int socket(int domain, int type, int protocol) throws LastErrorException;

        int ioctl(int fd, long request, Pointer argp) throws LastErrorException;

        int connect(int socket, Pointer address, int addressLength) throws LastErrorException;

        int getsockopt(int socket, int level, int optionName, byte[] optionValue, IntByReference optionLength)
                throws LastErrorException;

        int read(int fd, byte[] buffer, int count) throws LastErrorException;

        int write(int fd, byte[] buffer, int count) throws LastErrorException;

        int close(int fd) throws LastErrorException;
    }
}
