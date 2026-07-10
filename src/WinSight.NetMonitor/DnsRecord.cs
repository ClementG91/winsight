namespace WinSight.NetMonitor;

/// <summary>One resolver-cache DNS record: what was resolved and to what.</summary>
/// <param name="Name">The queried name (e.g. example.com).</param>
/// <param name="Type">The DNS record type (A, AAAA, CNAME, ...).</param>
/// <param name="Data">The answer (an IP, a canonical name, ...).</param>
/// <param name="Ttl">Remaining time-to-live in seconds.</param>
public sealed record DnsRecord(string Name, string Type, string Data, int Ttl);

/// <summary>Maps DNS record type numbers to their names.</summary>
public static class DnsRecordType
{
    public static string Name(int type) => type switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => $"TYPE{type}",
    };
}
