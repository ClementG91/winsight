using System.Management;
using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>
/// DNSMonitor-class visibility: reads the resolver cache (MSFT_DNSClientCache in
/// root\StandardCimv2, the same source as Get-DnsClientCache) to show recently
/// resolved domains and their answers. Managed via System.Management (no admin, no
/// process spawn). A real-time ETW consumer (Microsoft-Windows-DNS-Client) is the
/// future enhancement.
/// </summary>
public sealed class DnsCacheReader
{
    public IReadOnlyList<DnsRecord> Read() => ReadWithCoverage().Items;

    public AcquisitionSnapshot<DnsRecord> ReadWithCoverage()
    {
        var records = new List<DnsRecord>();
        var unreadableSources = 0;
        var unreadableItems = 0;
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT Name, Type, Data, TimeToLive FROM MSFT_DNSClientCache"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                using (o)
                {
                    try
                    {
                        var name = o["Name"] as string;
                        var typeReadable = TryToInt(o["Type"], out var type);
                        var ttlReadable = TryToInt(o["TimeToLive"], out var ttl);
                        if (string.IsNullOrWhiteSpace(name))
                        {
                            unreadableItems++;
                            continue;
                        }
                        if (!typeReadable || !ttlReadable)
                        {
                            unreadableItems++;
                        }
                        records.Add(new DnsRecord(
                            name,
                            typeReadable ? DnsRecordType.Name(type) : "UNKNOWN",
                            o["Data"] as string ?? string.Empty,
                            ttlReadable ? ttl : 0));
                    }
                    catch (Exception ex) when (ex is ManagementException or OverflowException)
                    {
                        unreadableItems++;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            unreadableSources = 1;
        }
        return new AcquisitionSnapshot<DnsRecord>(
            records, unreadableSources, unreadableItems);
    }

    // MSFT_DNSClientCache stores Type as uint16 and TimeToLive as uint32.
    internal static bool TryToInt(object? value, out int result)
    {
        switch (value)
        {
            case ushort u:
                result = u;
                return true;
            case uint u when u <= int.MaxValue:
                result = (int)u;
                return true;
            case int i when i >= 0:
                result = i;
                return true;
            case long l when l is >= 0 and <= int.MaxValue:
                result = (int)l;
                return true;
            default:
                result = 0;
                return false;
        }
    }
}
