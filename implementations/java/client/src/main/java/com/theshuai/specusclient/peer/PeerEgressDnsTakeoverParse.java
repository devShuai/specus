package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The pure half of the system DNS takeover (protocol/spec/peer-egress-dns.md, section six): reading
 * each platform's DNS settings out of the text its tools print, deciding whether they can be taken
 * over and which upstreams the responder forwards to, the exact commands that take over and give
 * back, and what giving back does when someone else changed the setting meanwhile.
 *
 * <p>Nothing here runs anything. Every function is pinned by a section of
 * {@code protocol/test-vectors/peer-egress-dns-takeover-v1.json}, because these are the decisions
 * the three clients must make identically. Running the commands, the journal and the timing are in
 * {@link PeerEgressDnsTakeover}.
 */
public final class PeerEgressDnsTakeoverParse {

    /** Marks the one NRPT rule the takeover adds, and is how it finds that rule again and no other. */
    public static final String NRPT_COMMENT = "specus-peer-egress";
    public static final String RESOLV_CONF = "/etc/resolv.conf";
    /** systemd-resolved's stub listeners: a resolv.conf naming only these sends everything through it. */
    public static final List<String> RESOLVED_STUBS = List.of("127.0.0.53", "127.0.0.54");

    /** The platforms a journal names, one per way of taking over. */
    public static final String PLATFORM_RESOLVED = "linux-resolved";
    public static final String PLATFORM_RESOLV_CONF = "linux-resolvconf";
    public static final String PLATFORM_MACOS = "macos";
    public static final String PLATFORM_WINDOWS = "windows";

    /** The takeover's refusals, as the status names them. */
    public static final String REFUSED_POOL_ROUTE = "pool-route-not-installed";
    public static final String REFUSED_LOOPBACK = "system-dns-loopback";
    public static final String REFUSED_VIRTUAL = "system-dns-virtual";
    public static final String REFUSED_NO_UPSTREAM = "no-upstream";
    public static final String REFUSED_MANAGED = "resolv-conf-managed";
    public static final String REFUSED_NRPT = "nrpt-root-occupied";
    public static final String REFUSED_UNSUPPORTED = "unsupported-platform";

    public static final String CODE_REFUSED = com.theshuai.common.peeregress.PeerEgressCodes.DNS_TAKEOVER_REFUSED;
    public static final String CODE_FAILED = com.theshuai.common.peeregress.PeerEgressCodes.DNS_TAKEOVER_FAILED;

    /** The Windows readers, run as PowerShell scripts; their JSON is read by the parsers below. */
    public static final String WINDOWS_READ_SERVERS = "$up = @(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | "
            + "Select-Object -ExpandProperty InterfaceIndex); "
            + "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientServerAddress -AddressFamily IPv4 | "
            + "Where-Object { $up -contains $_.InterfaceIndex } | "
            + "Select-Object InterfaceAlias,InterfaceIndex,ServerAddresses)";
    public static final String WINDOWS_READ_NRPT = "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-DnsClientNrptRule | "
            + "Select-Object Namespace,Comment,NameServers)";
    /**
     * Every IPv4 address with its adapter's index and IANA interface type, for finding the
     * tunnel-type ones (53, virtual; 131, tunnel). Indexes, types and addresses only: adapter names
     * are localised and come back in the console's code page, which can break the JSON (see the
     * route commands).
     */
    public static final String WINDOWS_READ_INTERFACES = "$types = @{}; "
            + "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            + "ForEach-Object { $types[[int]$_.ifIndex] = [int]$_.InterfaceType }; "
            + "ConvertTo-Json -Compress -Depth 3 -InputObject @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            + "ForEach-Object { [pscustomobject]@{ InterfaceIndex = $_.InterfaceIndex; "
            + "InterfaceType = $types[[int]$_.InterfaceIndex]; IPAddress = $_.IPAddress } })";

    /** The interface reader's JSON as interfaces, one per index with all its addresses. */
    public static List<LocalInterface> parseWindowsInterfaces(String text) throws IOException {
        java.util.Map<Long, LocalInterface> byIndex = new java.util.LinkedHashMap<>();
        for (JsonNode entry : jsonList(text)) {
            if (!entry.isObject() || !entry.path("InterfaceIndex").isNumber()) {
                continue;
            }
            long index = entry.path("InterfaceIndex").asLong();
            int type = entry.path("InterfaceType").isNumber() ? entry.path("InterfaceType").asInt() : -1;
            String address = entry.path("IPAddress").asText("");
            LocalInterface known = byIndex.get(index);
            List<String> addresses = new ArrayList<>(known == null ? List.of() : known.addresses());
            if (Ipv4Cidr.parseAddress(address) != null) {
                addresses.add(address);
            }
            byIndex.put(index, new LocalInterface("", index, false, type, List.copyOf(addresses)));
        }
        return List.copyOf(byIndex.values());
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern RESOLVECTL_LINK = Pattern.compile("^Link \\d+ \\(([^)]*)\\):(.*)$");
    private static final Pattern SCUTIL_RESOLVER = Pattern.compile("^resolver #\\d+$");
    private static final Pattern SCUTIL_FIELD = Pattern.compile("^(\\w+)(?:\\[(\\d+)\\])?\\s*:\\s*(.*)$");
    private static final Pattern SPACES = Pattern.compile("\\s+");

    private PeerEgressDnsTakeoverParse() {
    }

    /** What /etc/resolv.conf holds while the takeover has it: fixed text, so giving back can tell. */
    public static String resolvConfWritten(String listen) {
        return "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n"
                + "# and is put back when the client stops or when `egress dns restore` runs.\n"
                + "nameserver " + listen + "\n";
    }

    /** A command line that runs one PowerShell script, without a profile or a prompt. */
    public static List<String> powershell(String script) {
        return List.of("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script);
    }

    // ----------------------------------------------------------------------------------------------
    // Reading the platforms
    // ----------------------------------------------------------------------------------------------

    /**
     * A server as a tool prints it, without a DNS-over-TLS name ({@code 1.1.1.1#one.one.one.one}) or
     * an IPv6 zone ({@code fe80::1%eth0}).
     */
    static String stripServer(String text) {
        String value = text == null ? "" : text;
        int hash = value.indexOf('#');
        if (hash >= 0) {
            value = value.substring(0, hash);
        }
        int percent = value.indexOf('%');
        if (percent >= 0) {
            value = value.substring(0, percent);
        }
        return value.trim();
    }

    /** A tool's output as lines, whatever it ended them with. */
    static List<String> lines(String text) {
        List<String> out = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return out;
        }
        String[] split = text.split("\r\n|\n|\r", -1);
        int count = split.length;
        if (count > 0 && split[count - 1].isEmpty()) {
            count--;
        }
        for (int index = 0; index < count; index++) {
            out.add(split[index]);
        }
        return out;
    }

    private static List<String> words(String text) {
        List<String> out = new ArrayList<>();
        for (String word : SPACES.split(text.trim())) {
            if (!word.isEmpty()) {
                out.add(word);
            }
        }
        return out;
    }

    /**
     * {@code resolvectl dns}: a {@code Global:} line and one {@code Link N (name):} line each,
     * servers after the colon. Global first, then the links in the order printed, skipping this
     * client's own tunnel.
     */
    public static List<String> parseResolvectl(String output, String tunnel) {
        List<String> servers = new ArrayList<>();
        for (String raw : lines(output)) {
            String line = raw.trim();
            String rest;
            if (line.startsWith("Global:")) {
                rest = line.substring("Global:".length());
            } else {
                Matcher link = RESOLVECTL_LINK.matcher(line);
                if (!link.matches() || link.group(1).equals(tunnel)) {
                    continue;
                }
                rest = link.group(2);
            }
            for (String item : words(rest)) {
                String server = stripServer(item);
                if (!server.isEmpty()) {
                    servers.add(server);
                }
            }
        }
        return servers;
    }

    /** {@code nameserver} lines in order. A comment starts with # or ; and runs to the end of the line. */
    public static List<String> parseResolvConf(String text) {
        List<String> servers = new ArrayList<>();
        for (String raw : lines(text)) {
            String line = raw;
            for (int index = 0; index < line.length(); index++) {
                char c = line.charAt(index);
                if (c == '#' || c == ';') {
                    line = line.substring(0, index);
                    break;
                }
            }
            List<String> fields = words(line);
            if (fields.size() >= 2 && fields.get(0).equals("nameserver")) {
                servers.add(stripServer(fields.get(1)));
            }
        }
        return servers;
    }

    /**
     * {@code networksetup -listallnetworkservices}: the first line explains the asterisk; a service
     * whose name starts with {@code *} is disabled and is not touched.
     */
    public static List<String> parseMacServices(String output) {
        List<String> all = lines(output);
        List<String> services = new ArrayList<>();
        for (int index = 1; index < all.size(); index++) {
            String name = all.get(index);
            if (name.isBlank() || name.startsWith("*")) {
                continue;
            }
            services.add(name);
        }
        return services;
    }

    /**
     * {@code networksetup -getdnsservers <service>}: one address per line, or a sentence saying
     * there are none, which is recorded as {@code Empty} -- the word networksetup takes back to mean
     * "use what DHCP gives".
     */
    public static List<String> parseMacDnsServers(String output) {
        List<String> servers = new ArrayList<>();
        for (String raw : lines(output)) {
            String text = raw.trim();
            if (text.isEmpty()) {
                continue;
            }
            if (!isAddressLiteral(stripServer(text))) {
                return List.of("Empty");
            }
            servers.add(text);
        }
        return servers.isEmpty() ? List.of("Empty") : servers;
    }

    /**
     * {@code scutil --dns}: the servers of the first resolver of the unscoped section that has no
     * {@code domain} line -- the one every name without a more specific resolver goes to.
     */
    public static List<String> parseScutil(String output) {
        record Resolver(boolean[] domain, List<String> servers) {
        }
        List<Resolver> resolvers = new ArrayList<>();
        Resolver current = null;
        for (String raw : lines(output)) {
            String text = raw.trim();
            if (text.startsWith("DNS configuration (for scoped queries)")) {
                break;
            }
            if (SCUTIL_RESOLVER.matcher(text).matches()) {
                current = new Resolver(new boolean[1], new ArrayList<>());
                resolvers.add(current);
                continue;
            }
            if (current == null) {
                continue;
            }
            Matcher field = SCUTIL_FIELD.matcher(text);
            if (!field.matches()) {
                continue;
            }
            if (field.group(1).equals("domain")) {
                current.domain()[0] = true;
            } else if (field.group(1).equals("nameserver")) {
                current.servers().add(stripServer(field.group(3)));
            }
        }
        for (Resolver resolver : resolvers) {
            if (!resolver.domain()[0] && !resolver.servers().isEmpty()) {
                return resolver.servers();
            }
        }
        return List.of();
    }

    /**
     * The JSON the Windows server reader prints: one object or an array of
     * {InterfaceAlias, InterfaceIndex, ServerAddresses}. ServerAddresses is a string when there is
     * one address, an array when there are several, null or absent when there are none. The
     * tunnel's own adapter is left out: its server is the responder.
     *
     * @throws IOException when the output is not the JSON the reader writes
     */
    public static List<String> parseWindowsServers(String text, long tunnelIndex) throws IOException {
        List<String> servers = new ArrayList<>();
        for (JsonNode entry : jsonList(text)) {
            if (!entry.isObject()) {
                continue;
            }
            JsonNode index = entry.path("InterfaceIndex");
            if (index.isNumber() && index.asLong() == tunnelIndex) {
                continue;
            }
            for (String address : stringOrStrings(entry.path("ServerAddresses"))) {
                String server = stripServer(address);
                if (!server.isEmpty()) {
                    servers.add(server);
                }
            }
        }
        return servers;
    }

    /**
     * The JSON of the NRPT reader: whether a rule for the root namespace that is not ours is
     * already there. Namespace is a string or an array of strings.
     */
    public static boolean parseWindowsNrpt(String text) throws IOException {
        for (JsonNode entry : jsonList(text)) {
            if (!entry.isObject()) {
                continue;
            }
            if (stringOrStrings(entry.path("Namespace")).contains(".")
                    && !NRPT_COMMENT.equals(entry.path("Comment").isTextual() ? entry.path("Comment").asText() : null)) {
                return true;
            }
        }
        return false;
    }

    /** A PowerShell reader's JSON as a list: empty output is none, an object is one. */
    private static List<JsonNode> jsonList(String text) throws IOException {
        List<JsonNode> out = new ArrayList<>();
        if (text == null || text.isBlank()) {
            return out;
        }
        JsonNode document = MAPPER.readTree(text);
        if (document == null || document.isNull()) {
            return out;
        }
        if (document.isObject()) {
            out.add(document);
            return out;
        }
        if (!document.isArray()) {
            throw new IOException("not a list of objects");
        }
        document.forEach(out::add);
        return out;
    }

    private static List<String> stringOrStrings(JsonNode node) {
        List<String> out = new ArrayList<>();
        if (node.isTextual()) {
            out.add(node.asText());
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                if (item.isTextual()) {
                    out.add(item.asText());
                }
            }
        }
        return out;
    }

    // ----------------------------------------------------------------------------------------------
    // Deciding
    // ----------------------------------------------------------------------------------------------

    /** The Linux ways of taking over, as {@link #linuxMode} names them. */
    public static final String MODE_RESOLVED = "resolved";
    public static final String MODE_RESOLV_CONF = "resolvconf";

    /** The way Linux is taken over, or why it cannot be. */
    public record LinuxMode(String mode, String reason) {
        /** The platform a journal names for this mode. */
        public String platform() {
            return MODE_RESOLVED.equals(mode) ? PLATFORM_RESOLVED : MODE_RESOLV_CONF.equals(mode) ? PLATFORM_RESOLV_CONF : null;
        }
    }

    /**
     * systemd-resolved is used only when it runs and applications reach it through its stub;
     * otherwise /etc/resolv.conf is rewritten, but only when it is a plain file -- a symbolic link
     * means another program manages it and would overwrite what we write.
     */
    public static LinuxMode linuxMode(boolean resolvectlOk, List<String> resolvConfServers, boolean resolvConfIsSymlink) {
        if (resolvectlOk && !resolvConfServers.isEmpty() && RESOLVED_STUBS.containsAll(resolvConfServers)) {
            return new LinuxMode(MODE_RESOLVED, null);
        }
        if (resolvConfIsSymlink) {
            return new LinuxMode(null, REFUSED_MANAGED);
        }
        return new LinuxMode(MODE_RESOLV_CONF, null);
    }

    /** The upstreams to forward to, or why the takeover is refused. */
    public record Upstreams(String code, String reason, List<String> upstreams) {
        static Upstreams refused(String reason) {
            return new Upstreams(CODE_REFUSED, reason, List.of());
        }
    }

    /**
     * Which of the system's DNS servers the responder forwards to. IPv4 only, deduplicated in the
     * order read; IPv6 is not forwarded in this version and is no reason to refuse, except loopback.
     *
     * <p>A server on loopback, in the pool or the mesh, or on one of this machine's tunnel-type
     * interfaces means someone else already sits where the system sends its queries. Recording it
     * as the value to put back would, on rollback, point the system at something that may no longer
     * exist.
     */
    public static Upstreams classifyUpstreams(List<String> servers, List<String> virtualAddresses, String pool, String mesh) {
        Ipv4Cidr poolNetwork = Ipv4Cidr.parse(pool);
        Ipv4Cidr meshNetwork = Ipv4Cidr.parse(mesh);
        Set<String> virtual = Set.copyOf(virtualAddresses == null ? List.of() : virtualAddresses);
        List<String> upstreams = new ArrayList<>();
        for (String text : servers) {
            String server = stripServer(text);
            Integer v4 = Ipv4Cidr.parseAddress(server);
            if (v4 == null) {
                // IPv6, or nothing an address can be read from. Only its loopback refuses.
                if (server.indexOf(':') >= 0 && isIpv6Loopback(server)) {
                    return Upstreams.refused(REFUSED_LOOPBACK);
                }
                continue;
            }
            if ((v4 >>> 24) == 127) {
                return Upstreams.refused(REFUSED_LOOPBACK);
            }
            if (v4 == 0) {
                continue;
            }
            String canonical = Ipv4Cidr.format(v4);
            if ((poolNetwork != null && poolNetwork.contains(v4)) || (meshNetwork != null && meshNetwork.contains(v4))
                    || virtual.contains(canonical)) {
                return Upstreams.refused(REFUSED_VIRTUAL);
            }
            if (!upstreams.contains(canonical)) {
                upstreams.add(canonical);
            }
        }
        if (upstreams.isEmpty()) {
            return Upstreams.refused(REFUSED_NO_UPSTREAM);
        }
        return new Upstreams(null, null, List.copyOf(upstreams));
    }

    /** One interface as the tunnel-address check sees it; type is Windows' IANA ifType, else -1. */
    public record LocalInterface(String name, long index, boolean pointToPoint, int type, List<String> addresses) {
    }

    /**
     * The addresses of this machine's tunnel-type interfaces other than this client's own TUN:
     * Linux interfaces flagged point-to-point, macOS interfaces named utun, ipsec or ppp, Windows
     * adapters of type 53 (virtual) or 131 (tunnel). Our own TUN's address is in the mesh, which is
     * refused by its own rule.
     */
    public static List<String> tunnelAddresses(String platform, List<LocalInterface> interfaces, String tunnel,
            long tunnelIndex) {
        List<String> out = new ArrayList<>();
        for (LocalInterface candidate : interfaces == null ? List.<LocalInterface>of() : interfaces) {
            boolean tunnelType = switch (platform) {
                case "linux" -> candidate.pointToPoint() && !candidate.name().equals(tunnel);
                case "macos" -> (candidate.name().startsWith("utun") || candidate.name().startsWith("ipsec")
                        || candidate.name().startsWith("ppp")) && !candidate.name().equals(tunnel);
                case "windows" -> (candidate.type() == 53 || candidate.type() == 131)
                        && (tunnelIndex <= 0 || candidate.index() != tunnelIndex);
                default -> false;
            };
            if (tunnelType) {
                out.addAll(candidate.addresses());
            }
        }
        return out;
    }

    // ----------------------------------------------------------------------------------------------
    // Taking over and giving back
    // ----------------------------------------------------------------------------------------------

    /**
     * One step: a command line run without a shell, a file written whole, the original resolv.conf
     * put back (see {@link #revertResolvConf}), or one macOS service put back (see
     * {@link #revertMacService}).
     */
    public record Step(List<String> argv, String write, String content, String restore, String restoreService) {
        static Step command(List<String> argv) {
            return new Step(List.copyOf(argv), null, null, null, null);
        }
    }

    /** The commands that take over, and the ones that give back. */
    public record Plan(List<Step> apply, List<Step> revert) {
    }

    /**
     * Taking over and giving back, per platform. Giving back is safe to run in full whatever part of
     * taking over happened, which is what lets a failed takeover and a journal left by a killed
     * process be undone the same way. Null for a platform this client does not know.
     */
    public static Plan plan(String platform, String listen, String tunnel, List<String> services) {
        switch (platform) {
            case PLATFORM_RESOLVED -> {
                return new Plan(
                        List.of(Step.command(List.of("resolvectl", "dns", tunnel, listen)),
                                Step.command(List.of("resolvectl", "domain", tunnel, "~.")),
                                Step.command(List.of("resolvectl", "flush-caches"))),
                        List.of(Step.command(List.of("resolvectl", "revert", tunnel)),
                                Step.command(List.of("resolvectl", "flush-caches"))));
            }
            case PLATFORM_RESOLV_CONF -> {
                return new Plan(List.of(new Step(null, RESOLV_CONF, resolvConfWritten(listen), null, null)),
                        List.of(new Step(null, null, null, RESOLV_CONF, null)));
            }
            case PLATFORM_MACOS -> {
                List<Step> flush = List.of(Step.command(List.of("dscacheutil", "-flushcache")),
                        Step.command(List.of("killall", "-HUP", "mDNSResponder")));
                List<Step> apply = new ArrayList<>();
                List<Step> revert = new ArrayList<>();
                for (String service : services == null ? List.<String>of() : services) {
                    apply.add(Step.command(List.of("networksetup", "-setdnsservers", service, listen)));
                    revert.add(new Step(null, null, null, null, service));
                }
                apply.addAll(flush);
                revert.addAll(flush);
                return new Plan(List.copyOf(apply), List.copyOf(revert));
            }
            case PLATFORM_WINDOWS -> {
                return new Plan(
                        List.of(Step.command(powershell("Add-DnsClientNrptRule -Namespace '.' -NameServers '" + listen
                                + "' -Comment '" + NRPT_COMMENT + "'; Clear-DnsClientCache"))),
                        List.of(Step.command(powershell("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '"
                                + NRPT_COMMENT + "' } | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache"))));
            }
            default -> {
                return null;
            }
        }
    }

    /** What giving back does with one setting: put the original back, or keep someone else's. */
    public record Revert(String action, String content, List<String> command, String warning) {
        public boolean restore() {
            return "restore".equals(action);
        }
    }

    /**
     * The original resolv.conf goes back only if the file still holds what we wrote. Anything else
     * was written by someone after us, and theirs is kept with a warning rather than overwritten.
     */
    public static Revert revertResolvConf(String current, String original, String listen) {
        if (resolvConfWritten(listen).equals(current)) {
            return new Revert("restore", original, null, null);
        }
        return new Revert("keep", null, null, "resolv-conf-changed");
    }

    /**
     * The same for one macOS service: only one still pointing at the responder alone is put back,
     * to exactly what it had, {@code Empty} included.
     */
    public static Revert revertMacService(String service, List<String> current, List<String> original, String listen) {
        if (current.equals(List.of(listen))) {
            List<String> command = new ArrayList<>(List.of("networksetup", "-setdnsservers", service));
            command.addAll(original);
            return new Revert("restore", null, List.copyOf(command), null);
        }
        return new Revert("keep", null, null, "service-dns-changed");
    }

    // ----------------------------------------------------------------------------------------------

    /** Whether text is an IPv4 or IPv6 address literal. Never resolves anything. */
    static boolean isAddressLiteral(String text) {
        return Ipv4Cidr.parseAddress(text) != null || parseIpv6(text) != null;
    }

    /** Only ::1 itself: an IPv4-mapped loopback is not IPv6's. */
    private static boolean isIpv6Loopback(String text) {
        byte[] address = parseIpv6(text);
        if (address == null) {
            return false;
        }
        for (int index = 0; index < 15; index++) {
            if (address[index] != 0) {
                return false;
            }
        }
        return address[15] == 1;
    }

    /**
     * The sixteen bytes of an IPv6 literal (RFC 4291 text forms, an IPv4 tail included, no zone),
     * or null. Parsed here rather than by {@link InetAddress#getByName}, which hands text it cannot
     * read as a literal to the resolver: reading a tool's output must never cause a DNS lookup.
     */
    static byte[] parseIpv6(String text) {
        if (text == null || text.isEmpty() || text.length() > 45) {
            return null;
        }
        int lastColon = text.lastIndexOf(':');
        if (lastColon < 0) {
            return null;
        }
        String head = text;
        Integer tail = null;
        if (text.indexOf('.', lastColon) >= 0) {
            tail = Ipv4Cidr.parseAddress(text.substring(lastColon + 1));
            if (tail == null) {
                return null;
            }
            head = text.substring(0, lastColon + 1) + "0:0";
        }
        int gap = head.indexOf("::");
        if (gap >= 0 && head.indexOf("::", gap + 1) >= 0) {
            return null;
        }
        List<Integer> left = gap >= 0 ? groups(head.substring(0, gap)) : groups(head);
        List<Integer> right = gap >= 0 ? groups(head.substring(gap + 2)) : List.of();
        if (left == null || right == null) {
            return null;
        }
        int present = left.size() + right.size();
        if ((gap < 0 && present != 8) || (gap >= 0 && present > 7)) {
            return null;
        }
        int[] words = new int[8];
        for (int index = 0; index < left.size(); index++) {
            words[index] = left.get(index);
        }
        for (int index = 0; index < right.size(); index++) {
            words[8 - right.size() + index] = right.get(index);
        }
        byte[] out = new byte[16];
        for (int index = 0; index < 8; index++) {
            out[index * 2] = (byte) (words[index] >>> 8);
            out[index * 2 + 1] = (byte) words[index];
        }
        if (tail != null) {
            out[12] = (byte) (tail >>> 24);
            out[13] = (byte) (tail >>> 16);
            out[14] = (byte) (tail >>> 8);
            out[15] = (byte) (int) tail;
        }
        return out;
    }

    /** Colon-separated groups of one to four hex digits; empty text is no groups; null if malformed. */
    private static List<Integer> groups(String text) {
        List<Integer> out = new ArrayList<>();
        if (text.isEmpty()) {
            return out;
        }
        for (String group : text.split(":", -1)) {
            if (group.isEmpty() || group.length() > 4) {
                return null;
            }
            int value = 0;
            for (int index = 0; index < group.length(); index++) {
                int digit = Character.digit(group.charAt(index), 16);
                if (digit < 0) {
                    return null;
                }
                value = value * 16 + digit;
            }
            out.add(value);
        }
        return out;
    }
}
