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
    /// <summary>
    /// Ceiling on one WMI enumeration. Matches ControlledFolderAccessReader, which is the only
    /// caller in the product that bounded its query before this.
    /// </summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    public IReadOnlyList<DnsRecord> Read() => ReadWithCoverage().Items;

    public AcquisitionSnapshot<DnsRecord> ReadWithCoverage()
    {
        var records = new List<DnsRecord>();
        var unreadableSources = 0;
        var unreadableItems = 0;
        try
        {
            var scope = new ManagementScope(@"\\.\root\StandardCimv2");
            // Bounded like the Controlled Folder Access reader already bounds its own queries. A
            // stuck WMI provider otherwise hangs this command for ever, and the cancellation check
            // inside the loop below cannot help: the block happens inside the enumeration itself,
            // before a single object is yielded.
            using var searcher = new ManagementObjectSearcher(
                scope,
                new ObjectQuery("SELECT Name, Type, Data, TimeToLive FROM MSFT_DNSClientCache"),
                new System.Management.EnumerationOptions
                {
                    Timeout = QueryTimeout,
                    ReturnImmediately = false,
                    Rewindable = false,
                });
            // The collection owns an unmanaged enumerator and a COM reference; a bare
            // foreach over searcher.Get() left both to the finaliser.
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
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
