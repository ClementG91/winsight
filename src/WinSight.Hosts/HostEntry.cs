using System.Net;
using System.Net.Sockets;

namespace WinSight.Hosts;

/// <summary>
/// One active mapping from the Windows hosts file. The hosts file overrides DNS, so
/// malware uses it two ways: redirect a real domain to an attacker IP (phishing/MITM),
/// or blackhole security/update domains so AV and Windows Update can't reach home.
/// </summary>
/// <param name="IpAddress">Target address the hostname resolves to.</param>
/// <param name="Hostname">The overridden hostname.</param>
public sealed record HostEntry(string IpAddress, string Hostname)
{
    // Domains a malware host-file edit typically targets: AV vendors, OS/update, and
    // the big identity/software providers.
    private static readonly string[] SensitiveKeywords =
    {
        "microsoft", "windowsupdate", "windows.com", "defender", "mozilla", "google",
        "mcafee", "symantec", "norton", "avast", "avg", "kaspersky", "bitdefender",
        "sophos", "eset", "malwarebytes", "trendmicro", "clamav", "virustotal", "update",
    };

    /// <summary>True when the target is a loopback/sink address (a block, not a redirect).</summary>
    /// <remarks>
    /// Blocking a domain to a sink address is the common, benign ad/tracker-blocklist pattern, only
    /// noteworthy when the blocked domain is security/update related. The address is parsed, not
    /// compared as text: <c>127.1</c>, <c>0</c>, <c>127.0.0.2</c> and <c>::ffff:127.0.0.1</c> all
    /// point nowhere, and a list of four spellings reported each of them as a redirect to an
    /// external address.
    /// </remarks>
    public bool IsSink => IPAddress.TryParse(IpAddress, out var address) && IsSinkAddress(address);

    /// <summary>
    /// Loopback (127.0.0.0/8, ::1), unspecified (::) or "this network" (0.0.0.0/8): nothing
    /// off the machine answers at any of them.
    /// </summary>
    internal static bool IsSinkAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (IPAddress.IsLoopback(candidate) || candidate.Equals(IPAddress.IPv6Any))
        {
            return true;
        }
        return candidate.AddressFamily == AddressFamily.InterNetwork && candidate.GetAddressBytes()[0] == 0;
    }

    /// <summary>True when the hostname looks security- or update-related.</summary>
    public bool IsSensitive =>
        SensitiveKeywords.Any(k => Hostname.Contains(k, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Noteworthy when the entry redirects to a non-sink address (possible hijack) or
    /// when it sinks a security/update domain (possible AV/Update blackhole).
    /// </summary>
    public bool Notable => !IsSink || IsSensitive;

    /// <summary>Human reason for the flag, or null when benign.</summary>
    public string? Reason =>
        !Notable ? null
        : !IsSink ? "redirects a hostname to an external address (possible hijack)"
        : "blackholes a security/update domain (possible AV/Update block)";
}
