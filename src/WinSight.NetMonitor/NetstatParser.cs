namespace WinSight.NetMonitor;

/// <summary>A parsed netstat row before process resolution.</summary>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="Local">Local address:port.</param>
/// <param name="Remote">Foreign address:port.</param>
/// <param name="State">TCP state (empty for UDP).</param>
/// <param name="Pid">Owning process id.</param>
public readonly record struct NetstatRow(string Protocol, string Local, string Remote, string State, int Pid);

/// <summary>
/// Parses `netstat -ano` output. Kept a pure function (no process spawn) so it is
/// fully unit-testable; ConnectionMonitor supplies the real output at runtime.
/// </summary>
public static class NetstatParser
{
    public static IReadOnlyList<NetstatRow> Parse(string output)
    {
        var rows = new List<NetstatRow>();
        foreach (var raw in output.Split('\n'))
        {
            var t = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (t.Length < 4)
            {
                continue;
            }
            switch (t[0].ToUpperInvariant())
            {
                // TCP: Proto Local Foreign State PID
                case "TCP" when t.Length >= 5 && int.TryParse(t[4], out var tpid):
                    rows.Add(new NetstatRow("TCP", t[1], t[2], t[3], tpid));
                    break;
                // UDP has no State column: Proto Local Foreign PID
                case "UDP" when int.TryParse(t[3], out var upid):
                    rows.Add(new NetstatRow("UDP", t[1], t[2], string.Empty, upid));
                    break;
            }
        }
        return rows;
    }

    /// <summary>Extracts the address from an "address:port" endpoint (IPv6-aware).</summary>
    public static string RemoteAddress(string endpoint)
    {
        if (string.IsNullOrEmpty(endpoint))
        {
            return string.Empty;
        }
        var lastColon = endpoint.LastIndexOf(':');
        var addr = lastColon > 0 ? endpoint[..lastColon] : endpoint;
        return addr.Trim('[', ']');
    }

    /// <summary>
    /// True when a remote address is a routable, off-box destination, i.e. not a
    /// wildcard, loopback, or RFC-1918/link-local private address. These are the
    /// connections worth attention (something is talking to the outside world).
    /// </summary>
    public static bool IsExternal(string remoteAddress)
    {
        var a = remoteAddress;
        if (string.IsNullOrEmpty(a) || a is "0.0.0.0" or "*" or "::" or "255.255.255.255")
        {
            return false;
        }
        if (a.StartsWith("127.", StringComparison.Ordinal) || a == "::1")
        {
            return false;
        }
        if (a.StartsWith("0.", StringComparison.Ordinal) ||                   // 0.0.0.0/8 "this network"
            a.StartsWith("10.", StringComparison.Ordinal) ||
            a.StartsWith("192.168.", StringComparison.Ordinal) ||
            a.StartsWith("169.254.", StringComparison.Ordinal) ||
            a.StartsWith("fe80", StringComparison.OrdinalIgnoreCase) ||       // IPv6 link-local
            a.StartsWith("fc", StringComparison.OrdinalIgnoreCase) ||         // IPv6 ULA (fc00::/7)
            a.StartsWith("fd", StringComparison.OrdinalIgnoreCase) ||
            a.StartsWith("ff", StringComparison.OrdinalIgnoreCase))           // IPv6 multicast (ff00::/8)
        {
            return false;
        }
        if (a.StartsWith("172.", StringComparison.Ordinal))
        {
            var parts = a.Split('.');
            if (parts.Length > 1 && int.TryParse(parts[1], out var b) && b is >= 16 and <= 31)
            {
                return false;
            }
        }
        // IPv4 multicast (224.0.0.0/4), local-segment noise (SSDP, mDNS, IGMP), not a
        // routable off-box destination; flagging it would be pure false positives.
        var dot = a.IndexOf('.');
        if (dot > 0 && int.TryParse(a.AsSpan(0, dot), out var firstOctet) &&
            firstOctet is >= 224 and <= 239)
        {
            return false;
        }
        return true;
    }
}
