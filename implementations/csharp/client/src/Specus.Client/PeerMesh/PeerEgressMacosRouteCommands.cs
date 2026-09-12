namespace Specus.Client.PeerMesh;

/// <summary>One row of <c>netstat -rn</c>.</summary>
internal readonly record struct PeerEgressNetstatRoute(string Prefix, string Destination,
    string Gateway, string Flags, string Netif);

/// <summary>
/// Reading what macOS says about its routing table, and building the commands that change it.
/// </summary>
/// <remarks>
/// Kept free of any platform guard for the same reason the Linux and Windows readings are: they
/// depend on output nobody controls, and a macOS-only file would go untested on the machines where
/// most of CI runs.
///
/// <para>The table is read with <c>netstat -rn -f inet</c> and changed with <c>route</c>. Three
/// things about those two, all sampled from a real machine rather than taken from the manual
/// page.</para>
///
/// <para><c>route</c> returns 0 when it fails. A prefix that already exists, a prefix that is not
/// in the table, an interface with no address, a missing argument -- every one of those exits 0 and
/// prints a line that begins exactly like a success. What separates them is that <c>route</c>
/// writes nothing to stderr when it works, which is why the classification is keyed there.</para>
///
/// <para>netstat abbreviates the destination column, and the abbreviations are not guessable:
/// 127.0.0.0/8 prints as "127", 203.0.113.0/24 as "203.0.113", 100.64.0.0/10 as "100.64/10", the
/// default route as "default". Reading them back is what <see cref="NormalisePrefix"/> does.</para>
///
/// <para>None of it is localised. The same commands under zh_CN, ja_JP and de_DE produce
/// byte-identical output, so parsing the keys is safe here in a way it is not on Windows, where the
/// same command prints Chinese column headers under one console code page and English under
/// another.</para>
///
/// <para>Nothing here is quoted or escaped, and unlike the Windows side that is not a decision
/// about character sets: these are argv arrays handed to exec, so there is no shell to reinterpret
/// them. What is left to defend against is a value that reads as an option, and a value that reads
/// as a valid prefix but is not one. The second is the one that matters:
/// <c>route -n add -net 203.0.113.0/33 192.168.64.1</c> is accepted, prints a success line naming
/// 203.0.113.0, exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the
/// gateway. Only the routing table says so. On Windows the same argument is refused by
/// New-NetRoute, so validating first was defence in depth; here it is the only defence there
/// is.</para>
///
/// <para>Shared fixtures: <c>protocol/test-vectors/peer-egress-macos-routes-v1.json</c>.</para>
/// </remarks>
internal static class PeerEgressMacosRouteCommands
{
    /// <summary>
    /// The netstat flag for an entry the kernel generated rather than one anybody configured.
    /// </summary>
    /// <remarks>
    /// Excluded from the conflict answer. BSD keeps address resolution in the routing table, so
    /// every host that has been talked to recently has a /32 of its own, as do the subnet broadcast
    /// address and every multicast group that has been joined. Counting those as conflicts would
    /// refuse the bypass routes -- /32s for the control endpoint, STUN, TURN and the peer
    /// addresses, which are exactly the addresses most likely to have been talked to already --
    /// and a refused bypass route is the leak this feature exists to prevent.
    /// </remarks>
    public const string KernelGeneratedFlag = "W";

    /// <summary>Same three names as the Windows side, so the installer reads the same on both.</summary>
    public const string FailurePermissionDenied = "permission-denied";

    /// <summary>A routing command that failed for some other reason.</summary>
    public const string FailureOther = "failed";

    /// <summary>Nothing failed.</summary>
    public const string FailureNone = "";

    /// <summary>What the refusal says, so a refused argument is told apart from a failed command.</summary>
    public const string Refusal = "refusing to build a route command from this argument";

    /// <summary>
    /// A removal of something already gone, which is the outcome the caller asked for. It matters
    /// more than it looks: the journal is walked at startup, and on a machine that has rebooted
    /// none of its routes are there any more, so every entry in it reports this.
    /// </summary>
    private const string NotInTable = "not in table";

    /// <summary>The failure worth naming, because the fix is to run elevated.</summary>
    private const string MustBeRoot = "must be root";

    private static readonly char[] Whitespace = [' ', '\t', '\r'];

    /// <summary>
    /// Reads <c>route -n get &lt;address&gt;</c>, returning null when there is no usable hop.
    /// </summary>
    /// <remarks>
    /// The gateway is empty for a destination that is on-link, where <c>route</c> prints no gateway
    /// line at all. Sampled rather than assumed: asked about the gateway's own address -- which has
    /// a cloned link-level entry carrying a MAC address -- it still prints no gateway line, so the
    /// field never holds something that is not an address.
    /// </remarks>
    public static PeerEgressRouteHop? ParseRouteGet(string? stdout, string? stderr)
    {
        if (!string.IsNullOrWhiteSpace(stderr))
        {
            return null;
        }
        var gateway = string.Empty;
        var device = string.Empty;
        foreach (var line in (stdout ?? string.Empty).Split('\n'))
        {
            var separator = line.IndexOf(':');
            if (separator < 0)
            {
                continue;
            }
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (key == "gateway")
            {
                gateway = value;
            }
            else if (key == "interface")
            {
                device = value;
            }
        }
        if (device.Length == 0)
        {
            return null;
        }
        if (gateway.Length > 0 && !ValidAddress(gateway))
        {
            // Not an address, so it cannot be a next hop. The only thing done with this value is to
            // put it back on a `route add` command line, where a non-address is either another
            // argument or an error. Treating it as on-link asks for a route out of the interface,
            // which is what an entry without a usable gateway means anyway.
            gateway = string.Empty;
        }
        return new PeerEgressRouteHop(gateway, device);
    }

    /// <summary>
    /// Turns netstat's destination column, or a rule's CIDR, into one canonical
    /// <c>a.b.c.d/len</c>. Anything that is not IPv4 becomes empty, which is how the IPv6 half of
    /// the table is left alone.
    /// </summary>
    /// <remarks>
    /// A destination with no length carries one octet per eight bits: "127" is 127.0.0.0/8 and
    /// "192.168.64" is 192.168.64.0/24. A destination with a length means what it says once the
    /// missing trailing octets are filled in with zeroes: "100.64/10" is 100.64.0.0/10.
    ///
    /// <para>The address is then masked by the length. Two spellings of one prefix have to compare
    /// equal, or the conflict check is answering a different question than the one it was
    /// asked.</para>
    /// </remarks>
    public static string NormalisePrefix(string? text)
    {
        var value = (text ?? string.Empty).Trim();
        if (value.Length == 0)
        {
            return string.Empty;
        }
        if (value == "default")
        {
            return "0.0.0.0/0";
        }
        var slash = value.IndexOf('/');
        var address = slash < 0 ? value : value[..slash];
        var length = slash < 0 ? null : value[(slash + 1)..];
        var octets = address.Split('.');
        if (octets.Length < 1 || octets.Length > 4)
        {
            return string.Empty;
        }
        uint packed = 0;
        for (var index = 0; index < 4; index++)
        {
            uint number = 0;
            if (index < octets.Length)
            {
                var decoded = DecimalValue(octets[index], 255);
                if (decoded < 0)
                {
                    return string.Empty;
                }
                number = (uint)decoded;
            }
            packed |= number << (24 - 8 * index);
        }
        var bits = 8 * octets.Length;
        if (length is not null)
        {
            bits = DecimalValue(length, 32);
            if (bits < 0)
            {
                return string.Empty;
            }
        }
        var mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
        packed &= mask;
        return $"{packed >> 24 & 0xFF}.{packed >> 16 & 0xFF}.{packed >> 8 & 0xFF}.{packed & 0xFF}/{bits}";
    }

    /// <summary>Reads the IPv4 rows of <c>netstat -rn</c>.</summary>
    /// <remarks>
    /// Only the rows under the "Internet:" heading. The gate is load-bearing rather than tidy:
    /// "Internet6:" has default routes of its own -- four on the sampling machine, one per utun --
    /// and "default" is the one destination whose IPv6 spelling is indistinguishable from its IPv4
    /// spelling. Without the gate, asking whether anything owns 0.0.0.0/0 on a machine with IPv6
    /// would find phantom routes and refuse the one rule that takes over everything.
    ///
    /// <para>Rows carry four or five columns. The fifth is Expire, which holds a number, or "!", or
    /// nothing at all, so this must not require it.</para>
    /// </remarks>
    public static List<PeerEgressNetstatRoute> ParseTable(string? stdout)
    {
        var routes = new List<PeerEgressNetstatRoute>();
        var inside = false;
        foreach (var line in (stdout ?? string.Empty).Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }
            if (trimmed.EndsWith(':'))
            {
                inside = trimmed == "Internet:";
                continue;
            }
            if (!inside || trimmed.StartsWith("Destination", StringComparison.Ordinal))
            {
                continue;
            }
            var fields = trimmed.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 4)
            {
                continue;
            }
            var prefix = NormalisePrefix(fields[0]);
            if (prefix.Length == 0)
            {
                continue;
            }
            routes.Add(new PeerEgressNetstatRoute(prefix, fields[0], fields[1], fields[2],
                fields[3]));
        }
        return routes;
    }

    /// <summary>Whether anything already owns this exact prefix.</summary>
    /// <remarks>
    /// Exact prefix, not a longest-prefix lookup, for the same reason as on Windows: the question
    /// is ownership of this prefix, not reachability of an address, and under a default route
    /// everything is reachable. <c>route -n get</c> cannot answer it at all -- asked about an
    /// unrouted address it returns the default route -- which is why the whole table is read.
    /// </remarks>
    public static PeerEgressExistingRoute ConflictFromTable(string? table, string? prefix)
    {
        var wanted = NormalisePrefix(prefix);
        if (wanted.Length == 0)
        {
            return new PeerEgressExistingRoute(false, string.Empty);
        }
        var matching = new List<PeerEgressNetstatRoute>();
        foreach (var route in ParseTable(table))
        {
            if (route.Prefix == wanted &&
                !route.Flags.Contains(KernelGeneratedFlag, StringComparison.Ordinal))
            {
                matching.Add(route);
            }
        }
        return DescribeRoutes(matching);
    }

    /// <summary>Turns the routes on one prefix into a presence and a description.</summary>
    public static PeerEgressExistingRoute DescribeRoutes(List<PeerEgressNetstatRoute> routes)
    {
        if (routes.Count == 0)
        {
            return new PeerEgressExistingRoute(false, string.Empty);
        }
        var description = DescribeRoute(routes[0]);
        if (routes.Count > 1)
        {
            // The count matters to whoever has to clear the prefix: one removal is not going to be
            // enough, and retrying is a worse way to learn that. Reachable because a scoped route
            // can share a prefix with an unscoped one.
            description += $" (+{routes.Count - 1} more)";
        }
        return new PeerEgressExistingRoute(true, description);
    }

    /// <summary>One line an operator can match against their own <c>netstat -rn</c> output.</summary>
    /// <remarks>
    /// The columns are restated in netstat's own words, including calling the second one a gateway
    /// when it holds an interface name: that is what the table says, and an operator comparing this
    /// line against the table should not have to reconcile two vocabularies.
    /// </remarks>
    public static string DescribeRoute(PeerEgressNetstatRoute route) =>
        $"{route.Prefix} gateway {route.Gateway} netif {route.Netif} flags {route.Flags}";

    /// <summary>
    /// Classifies a <c>route add</c> or <c>route delete</c> that may not have worked.
    /// </summary>
    /// <remarks>
    /// The exit status is not consulted, because it is 0 for "File exists", for "not in table", for
    /// "Network is unreachable" and for "Invalid argument" -- every failure sampled except a
    /// malformed address returns success. What does separate them is stderr, which is empty for
    /// every successful mutation sampled and carries
    /// "route: writing to routing socket: &lt;error&gt;" for every failed one.
    ///
    /// <para>Keyed on stderr being non-empty rather than on a list of error texts. Those errors are
    /// strerror of whatever the routing socket returned, so the list has no end, and an
    /// unrecognised error would otherwise read as success -- the direction that leaves a rule
    /// believed installed while its traffic goes out of the physical interface. Noise on stderr
    /// fails the other way: the install is reported failed, the installer withdraws a route it did
    /// install, and nothing leaks.</para>
    /// </remarks>
    public static string ClassifyFailure(string? stdout, string? stderr)
    {
        var combined = (stdout ?? string.Empty) + "\n" + (stderr ?? string.Empty);
        if (combined.Contains(MustBeRoot, StringComparison.Ordinal))
        {
            return FailurePermissionDenied;
        }
        if (combined.Contains(NotInTable, StringComparison.Ordinal))
        {
            return FailureNone;
        }
        return string.IsNullOrWhiteSpace(stderr) ? FailureNone : FailureOther;
    }

    /// <summary>Whether this is an IPv4 address and nothing else.</summary>
    public static bool ValidAddress(string? value)
    {
        if (string.IsNullOrEmpty(value) || value != value.Trim())
        {
            return false;
        }
        var octets = value.Split('.');
        if (octets.Length != 4)
        {
            return false;
        }
        foreach (var octet in octets)
        {
            if (DecimalValue(octet, 255) < 0)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>Whether this is an IPv4 prefix in full: four octets and a length.</summary>
    /// <remarks>
    /// The length is required and 33 is refused, because <c>route</c> does neither. A leading zero
    /// is refused too, in the octets and in the length, because inet_aton would read it as octal
    /// and we would not.
    /// </remarks>
    public static bool ValidPrefix(string? value)
    {
        if (value is null)
        {
            return false;
        }
        var slash = value.IndexOf('/');
        if (slash < 0 || !ValidAddress(value[..slash]))
        {
            return false;
        }
        return DecimalValue(value[(slash + 1)..], 32) >= 0;
    }

    /// <summary>Whether a name can be read as anything but an interface.</summary>
    /// <remarks>
    /// Must start with a letter, so it can never be taken for an option, and must stay inside the
    /// letters, digits, underscore and dot that real names use: en0, utun3, bridge0, vlan1. The
    /// length limit is the kernel's, where IFNAMSIZ is 16 including the terminator.
    ///
    /// <para>Whitelisted rather than escaped, which is the opposite of what the same value gets on
    /// Windows. There the adapter name reaches PowerShell as part of a script and has to be
    /// escaped, because operators legitimately use spaces and non-ASCII in it. Here it is one
    /// element of an argv array, so there is nothing to escape, and the only thing that can go
    /// wrong is <c>route</c> reading the name as an address -- which it does: given an interface
    /// that does not exist it reports "route: bad address: utun99".</para>
    /// </remarks>
    public static bool ValidInterfaceName(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 15 || !IsLetter(value[0]))
        {
            return false;
        }
        foreach (var character in value)
        {
            if (IsLetter(character) || (character >= '0' && character <= '9') ||
                character is '_' or '.')
            {
                continue;
            }
            return false;
        }
        return true;
    }

    /// <summary>
    /// Reads the whole table. IPv4 only: the IPv6 section has a different column layout and this
    /// feature does not route IPv6 yet.
    /// </summary>
    public static string[] ShowTableArgs() => ["netstat", "-rn", "-f", "inet"];

    /// <summary>
    /// Asks where an address would go right now, which is how a bypass next hop is resolved.
    /// </summary>
    /// <remarks>
    /// <c>-n</c> so no name lookup is attempted. It makes no difference to the output -- sampled
    /// both ways -- but a resolver that does not answer would hold the process for as long as the
    /// resolver takes, and this runs while the tunnel is being brought up.
    /// </remarks>
    public static string[] FindRouteArgs(string? address)
    {
        if (!ValidAddress(address))
        {
            throw new ArgumentException($"{Refusal}: {address}", nameof(address));
        }
        return ["route", "-n", "get", address!];
    }

    /// <summary>Sends a prefix out of an interface, which is how a rule's route reaches the TUN.</summary>
    public static string[] InstallInterfaceArgs(string? prefix, string? name)
    {
        if (!ValidPrefix(prefix))
        {
            throw new ArgumentException($"{Refusal}: {prefix}", nameof(prefix));
        }
        if (!ValidInterfaceName(name))
        {
            throw new ArgumentException($"{Refusal}: {name}", nameof(name));
        }
        return ["route", "-n", "add", "-net", prefix!, "-interface", name!];
    }

    /// <summary>
    /// Sends a prefix to a next hop, which is how a bypass keeps the transport off the tunnel.
    /// </summary>
    public static string[] InstallGatewayArgs(string? prefix, string? gateway)
    {
        if (!ValidPrefix(prefix))
        {
            throw new ArgumentException($"{Refusal}: {prefix}", nameof(prefix));
        }
        if (!ValidAddress(gateway))
        {
            throw new ArgumentException($"{Refusal}: {gateway}", nameof(gateway));
        }
        return ["route", "-n", "add", "-net", prefix!, gateway!];
    }

    /// <summary>Withdraws a prefix.</summary>
    /// <remarks>
    /// <c>-net</c> for every prefix including a /32, which is sampled as working. One form means
    /// the withdrawal cannot disagree with the install about what was installed.
    ///
    /// <para>No <c>-ifscope</c>, matching the install. A withdrawal without it takes the unscoped
    /// route and leaves scoped ones alone, which is the right way round: this feature only ever
    /// installs unscoped routes, and a scoped route on the same prefix belongs to somebody
    /// else.</para>
    /// </remarks>
    public static string[] RemoveArgs(string? prefix)
    {
        if (!ValidPrefix(prefix))
        {
            throw new ArgumentException($"{Refusal}: {prefix}", nameof(prefix));
        }
        return ["route", "-n", "delete", "-net", prefix!];
    }

    /// <summary>
    /// The value of a run of decimal digits, or -1 if it is not one or is out of range.
    /// </summary>
    /// <remarks>
    /// A leading zero is refused rather than skipped. <c>route</c> parses addresses with inet_aton,
    /// which reads a leading zero as octal: to it, 010.0.0.1 is 8.0.0.1. Reading the same text as
    /// decimal here would mean the conflict check asking about one prefix while the install created
    /// another, and the way not to have two readings of one string is to accept only the spelling
    /// that has one.
    /// </remarks>
    private static int DecimalValue(string? digits, int limit)
    {
        if (string.IsNullOrEmpty(digits) || digits.Length > 3)
        {
            return -1;
        }
        if (digits.Length > 1 && digits[0] == '0')
        {
            return -1;
        }
        var value = 0;
        foreach (var character in digits)
        {
            if (character is < '0' or > '9')
            {
                return -1;
            }
            value = value * 10 + (character - '0');
        }
        return value <= limit ? value : -1;
    }

    private static bool IsLetter(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z';
}
