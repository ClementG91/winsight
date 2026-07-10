using System.Management;

namespace WinSight.NetMonitor;

/// <summary>
/// DNSMonitor-class visibility: reads the resolver cache (MSFT_DNSClientCache in
/// root\StandardCimv2 — the same source as Get-DnsClientCache) to show recently
/// resolved domains and their answers. Managed via System.Management (no admin, no
/// process spawn). A real-time ETW consumer (Microsoft-Windows-DNS-Client) is the
/// future enhancement.
/// </summary>
public sealed class DnsCacheReader
{
    public IReadOnlyList<DnsRecord> Read()
    {
        var records = new List<DnsRecord>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT Name, Type, Data, TimeToLive FROM MSFT_DNSClientCache"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                using (o)
                {
                    var name = o["Name"] as string ?? string.Empty;
                    if (name.Length == 0)
                    {
                        continue;
                    }
                    records.Add(new DnsRecord(
                        name,
                        DnsRecordType.Name(ToInt(o["Type"])),
                        o["Data"] as string ?? string.Empty,
                        ToInt(o["TimeToLive"])));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            // Namespace/class unavailable — no cache surfaced.
        }
        return records;
    }

    // MSFT_DNSClientCache stores Type as uint16 and TimeToLive as uint32.
    private static int ToInt(object? value) => value switch
    {
        ushort u => u,
        uint u => (int)u,
        int i => i,
        long l => (int)l,
        _ => 0,
    };
}
