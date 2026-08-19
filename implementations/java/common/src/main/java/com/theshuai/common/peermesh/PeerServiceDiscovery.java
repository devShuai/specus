package com.theshuai.common.peermesh;

import com.theshuai.common.util.JsonUtil;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Protocol baseline for Peer Mesh local service discovery. Validation lives here so Java
 * tests and the server share one set of limits.
 */
public final class PeerServiceDiscovery {
    public static final int PROTOCOL_VERSION = 1;
    public static final int MAX_SERVICES_PER_SESSION = 32;
    public static final int MAX_SNAPSHOT_BYTES = 16 * 1024;
    public static final int MAX_NAME_LENGTH = 80;
    public static final int MAX_DESCRIPTION_LENGTH = 200;
    public static final int MAX_PATH_LENGTH = 128;
    public static final int MAX_SERVICE_ID_LENGTH = 64;
    public static final int MIN_SERVICE_ID_LENGTH = 8;
    public static final int MAX_INSTANCE_ID_LENGTH = 64;
    public static final Duration CATALOG_TTL = Duration.ofMinutes(5);
    public static final int REPORT_RATE_LIMIT = 20;
    public static final Duration REPORT_RATE_WINDOW = Duration.ofMinutes(1);

    public static final String TRANSPORT_TCP = "tcp";
    public static final String TRANSPORT_UDP = "udp";
    public static final String VISIBILITY_OWNER = "OWNER";
    public static final String VISIBILITY_ACL = "ACL";
    public static final String APPLICATION_HTTP = "http";
    public static final String APPLICATION_HTTPS = "https";
    public static final String APPLICATION_SSH = "ssh";
    public static final String APPLICATION_TCP = "tcp";
    public static final String APPLICATION_UDP = "udp";

    public static final List<String> APPLICATIONS = List.of(
            APPLICATION_HTTP, APPLICATION_HTTPS, APPLICATION_SSH, APPLICATION_TCP, APPLICATION_UDP);
    public static final int MAX_ALLOWED_CLIENTS = 32;

    private static final Pattern SERVICE_ID = Pattern.compile("^[A-Za-z0-9._-]{8,64}$");
    private static final Pattern INSTANCE_ID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");
    private static final Pattern PATH = Pattern.compile("^/[A-Za-z0-9._~/-]*$");
    private static final Set<String> APPLICATION_SET = new LinkedHashSet<>(APPLICATIONS);

    private PeerServiceDiscovery() {
    }

    public static int normalizeVersion(int version) {
        return version < 1 ? 0 : Math.min(version, PROTOCOL_VERSION);
    }

    public static List<String> normalizeApplications(Iterable<String> raw, int version) {
        if (version < 1 || raw == null) {
            return List.of();
        }
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        for (String item : raw) {
            String application = normalizeApplication(item);
            if (application != null) {
                unique.add(application);
            }
        }
        return List.copyOf(unique);
    }

    public static String encodeApplications(Iterable<String> applications) {
        List<String> normalized = normalizeApplications(applications, PROTOCOL_VERSION);
        return String.join(",", normalized);
    }

    public static List<String> decodeApplications(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<String> items = new ArrayList<>();
        for (String part : raw.split(",")) {
            String application = normalizeApplication(part);
            if (application != null && !items.contains(application)) {
                items.add(application);
            }
        }
        return List.copyOf(items);
    }

    public static String requireServiceId(String raw) {
        String value = trimRequired(raw, "serviceId");
        if (!SERVICE_ID.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid serviceId");
        }
        return value;
    }

    public static String requireName(String raw) {
        String value = trimRequired(raw, "name");
        rejectControlCharacters(value, "name");
        if (value.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("name exceeds " + MAX_NAME_LENGTH + " characters");
        }
        return value;
    }

    public static String normalizeDescription(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String value = raw.trim();
        rejectControlCharacters(value, "description");
        if (value.length() > MAX_DESCRIPTION_LENGTH) {
            throw new IllegalArgumentException("description exceeds " + MAX_DESCRIPTION_LENGTH + " characters");
        }
        return value;
    }

    public static String requireTransport(String raw) {
        String value = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (!TRANSPORT_TCP.equals(value) && !TRANSPORT_UDP.equals(value)) {
            throw new IllegalArgumentException("transport must be tcp or udp");
        }
        return value;
    }

    public static String requireTransportForApplication(String transport, String application) {
        String value = transport == null ? "" : transport.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            value = APPLICATION_UDP.equals(application) ? TRANSPORT_UDP : TRANSPORT_TCP;
        }
        String normalized = requireTransport(value);
        if (APPLICATION_UDP.equals(application) && !TRANSPORT_UDP.equals(normalized)) {
            throw new IllegalArgumentException("udp application requires udp transport");
        }
        if (!APPLICATION_UDP.equals(application) && TRANSPORT_UDP.equals(normalized)) {
            throw new IllegalArgumentException("http/https/ssh/tcp applications require tcp transport");
        }
        return normalized;
    }

    public static String requireApplication(String raw) {
        String application = normalizeApplication(raw);
        if (application == null) {
            throw new IllegalArgumentException("unsupported application");
        }
        return application;
    }

    public static String normalizeApplication(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        return APPLICATION_SET.contains(value) ? value : null;
    }

    public static int requirePort(Integer port, String field) {
        if (port == null || port < 1 || port > 65535) {
            throw new IllegalArgumentException(field + " must be 1..65535");
        }
        return port;
    }

    public static String requireTargetHost(String raw) {
        String value = trimRequired(raw, "targetHost");
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.contains("/") || lower.contains("\\") || lower.contains("@")
                || lower.contains("?") || lower.contains("#") || lower.contains("://")) {
            throw new IllegalArgumentException("targetHost must be a local address, not a URL");
        }
        if (value.startsWith("[") && value.endsWith("]")) {
            value = value.substring(1, value.length() - 1);
        }
        if ("localhost".equalsIgnoreCase(value) || "::1".equals(value) || "127.0.0.1".equals(value)) {
            return value;
        }
        InetAddress address;
        try {
            address = InetAddress.getByName(value);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("targetHost must be a unicast IP or localhost");
        }
        if (!value.equals(address.getHostAddress()) && !isIpv6Literal(value, address)) {
            throw new IllegalArgumentException("targetHost must be a unicast IP or localhost");
        }
        if (address.isAnyLocalAddress() || address.isMulticastAddress()) {
            throw new IllegalArgumentException("targetHost cannot be wildcard or multicast");
        }
        if (!(address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                || isUniqueLocalIpv6(address))) {
            throw new IllegalArgumentException("targetHost must be loopback or a local interface address");
        }
        return value;
    }

    public static String normalizePath(String raw, String application) {
        if (raw == null || raw.isBlank()) {
            return APPLICATION_HTTP.equals(application) || APPLICATION_HTTPS.equals(application) ? "/" : "";
        }
        String value = raw.trim();
        if (value.contains("://") || value.contains("\\") || value.contains("..") || value.contains(" ")) {
            throw new IllegalArgumentException("path must be a safe relative HTTP path");
        }
        if (!value.startsWith("/")) {
            throw new IllegalArgumentException("path must start with /");
        }
        if (value.length() > MAX_PATH_LENGTH) {
            throw new IllegalArgumentException("path exceeds " + MAX_PATH_LENGTH + " characters");
        }
        if (!PATH.matcher(value).matches()) {
            throw new IllegalArgumentException("path contains unsupported characters");
        }
        return value;
    }

    public static String requireVisibility(String raw) {
        if (raw == null || raw.isBlank()) {
            return VISIBILITY_OWNER;
        }
        String value = raw.trim().toUpperCase(Locale.ROOT);
        if (!VISIBILITY_OWNER.equals(value) && !VISIBILITY_ACL.equals(value)) {
            throw new IllegalArgumentException("visibility must be OWNER or ACL");
        }
        return value;
    }

    public static String normalizeInstanceId(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String value = raw.trim();
        if (!INSTANCE_ID.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid instanceId");
        }
        return value;
    }

    public static PeerAdvertisedService sanitizeAdvertised(PeerAdvertisedService raw) {
        if (raw == null) {
            throw new IllegalArgumentException("service is required");
        }
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId(requireServiceId(raw.getServiceId()));
        service.setName(requireName(raw.getName()));
        service.setDescription(normalizeDescription(raw.getDescription()));
        service.setApplication(requireApplication(raw.getApplication()));
        service.setTransport(requireTransportForApplication(raw.getTransport(), service.getApplication()));
        service.setPublishedPort(requirePort(raw.getPublishedPort(), "publishedPort"));
        service.setPath(normalizePath(raw.getPath(), service.getApplication()));
        return service;
    }

    public static List<PeerAdvertisedService> sanitizeAdvertisedList(List<PeerAdvertisedService> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        if (raw.size() > MAX_SERVICES_PER_SESSION) {
            throw new IllegalArgumentException("at most " + MAX_SERVICES_PER_SESSION + " services per session");
        }
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        LinkedHashSet<Integer> ports = new LinkedHashSet<>();
        List<PeerAdvertisedService> sanitized = new ArrayList<>(raw.size());
        for (PeerAdvertisedService item : raw) {
            PeerAdvertisedService service = sanitizeAdvertised(item);
            if (!ids.add(service.getServiceId())) {
                throw new IllegalArgumentException("duplicate serviceId: " + service.getServiceId());
            }
            if (!ports.add(service.getPublishedPort())) {
                throw new IllegalArgumentException("duplicate publishedPort: " + service.getPublishedPort());
            }
            sanitized.add(service);
        }
        int bytes = snapshotBytes(sanitized);
        if (bytes > MAX_SNAPSHOT_BYTES) {
            throw new IllegalArgumentException("service snapshot exceeds " + MAX_SNAPSHOT_BYTES + " bytes");
        }
        return List.copyOf(sanitized);
    }

    public static int snapshotBytes(List<PeerAdvertisedService> services) {
        String json = JsonUtil.objectToString(services == null ? List.of() : services);
        return json == null ? 0 : json.getBytes(StandardCharsets.UTF_8).length;
    }

    public static PeerAdvertisedService copyAdvertised(PeerAdvertisedService source) {
        if (source == null) {
            return null;
        }
        PeerAdvertisedService copy = new PeerAdvertisedService();
        copy.setServiceId(source.getServiceId());
        copy.setName(source.getName());
        copy.setDescription(source.getDescription());
        copy.setTransport(source.getTransport());
        copy.setApplication(source.getApplication());
        copy.setPublishedPort(source.getPublishedPort());
        copy.setPath(source.getPath());
        return copy;
    }

    public static String encodeClientIds(Iterable<Long> ids) {
        LinkedHashSet<Long> unique = new LinkedHashSet<>();
        if (ids != null) {
            for (Long id : ids) {
                if (id != null && id > 0) {
                    unique.add(id);
                }
            }
        }
        if (unique.size() > MAX_ALLOWED_CLIENTS) {
            throw new IllegalArgumentException("at most " + MAX_ALLOWED_CLIENTS + " allowedClientIds");
        }
        return unique.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(","));
    }

    public static List<Long> decodeClientIds(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        LinkedHashSet<Long> ids = new LinkedHashSet<>();
        for (String part : raw.split(",")) {
            String value = part.trim();
            if (value.isEmpty()) {
                continue;
            }
            try {
                long id = Long.parseLong(value);
                if (id > 0) {
                    ids.add(id);
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return List.copyOf(ids);
    }

    public static boolean probe(LocalPeerService local, int timeoutMillis) {
        if (local == null) {
            return false;
        }
        String transport = local.getTransport() == null ? "" : local.getTransport().trim();
        if (TRANSPORT_UDP.equalsIgnoreCase(transport) || APPLICATION_UDP.equalsIgnoreCase(local.getApplication())) {
            return probeUdp(local.getTargetHost(), local.getTargetPort(), timeoutMillis);
        }
        return probeTcp(local.getTargetHost(), local.getTargetPort(), timeoutMillis);
    }

    public static boolean probeTcp(String host, int port, int timeoutMillis) {
        if (host == null || host.isBlank() || port < 1 || port > 65535) {
            return false;
        }
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), Math.max(50, timeoutMillis));
            return socket.isConnected();
        } catch (Exception ignored) {
            return false;
        }
    }

    public static boolean probeUdp(String host, int port, int timeoutMillis) {
        if (host == null || host.isBlank() || port < 1 || port > 65535) {
            return false;
        }
        try (java.net.DatagramSocket socket = new java.net.DatagramSocket()) {
            socket.setSoTimeout(Math.max(50, timeoutMillis));
            socket.connect(new java.net.InetSocketAddress(host, port));
            socket.send(new java.net.DatagramPacket(new byte[]{0}, 1));
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    public static List<PeerMdnsCandidate> sanitizeMdnsCandidates(List<PeerMdnsCandidate> raw) {
        if (raw == null || raw.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        List<PeerMdnsCandidate> sanitized = new ArrayList<>();
        for (PeerMdnsCandidate item : raw) {
            if (item == null || sanitized.size() >= MAX_SERVICES_PER_SESSION) {
                continue;
            }
            try {
                PeerMdnsCandidate candidate = new PeerMdnsCandidate();
                candidate.setName(requireName(item.getName()));
                candidate.setApplication(requireApplication(item.getApplication()));
                candidate.setTransport(requireTransportForApplication(item.getTransport(), candidate.getApplication()));
                candidate.setTargetHost(requireTargetHost(item.getTargetHost()));
                candidate.setTargetPort(requirePort(item.getTargetPort(), "targetPort"));
                if (keys.add(candidate.getTargetHost() + ":" + candidate.getTargetPort() + ":" + candidate.getApplication())) {
                    sanitized.add(candidate);
                }
            } catch (RuntimeException ignored) {
            }
        }
        return List.copyOf(sanitized);
    }

    public static String accessUrl(String virtualIp, PeerAdvertisedService service) {
        if (virtualIp == null || virtualIp.isBlank() || service == null) {
            return "";
        }
        String application = service.getApplication();
        if (APPLICATION_HTTP.equals(application) || APPLICATION_HTTPS.equals(application)) {
            String path = service.getPath() == null || service.getPath().isBlank() ? "/" : service.getPath();
            return application + "://" + virtualIp + ":" + service.getPublishedPort() + path;
        }
        return virtualIp + ":" + service.getPublishedPort();
    }

    private static String trimRequired(String raw, String field) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return raw.trim();
    }

    private static void rejectControlCharacters(String value, String field) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < 32) {
                throw new IllegalArgumentException(field + " contains control characters");
            }
        }
    }

    private static boolean isIpv6Literal(String value, InetAddress address) {
        return address.getAddress().length == 16 && value.indexOf(':') >= 0;
    }

    private static boolean isUniqueLocalIpv6(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
