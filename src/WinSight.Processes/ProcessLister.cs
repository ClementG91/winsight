using System.Management;
using WinSight.Core;

namespace WinSight.Processes;

/// <summary>
/// TaskExplorer-class process lister: snapshots running processes (Win32_Process via
/// System.Management) with their image path, parent and command line, and batch-checks
/// each image's Authenticode signature, so unsigned/untrusted running code stands out.
/// Read-only; no admin needed for the basics.
/// </summary>
public sealed class ProcessLister(ISignatureVerifier? verifier = null)
{
    /// <summary>
    /// Ceiling on one WMI enumeration. Matches ControlledFolderAccessReader, which is the only
    /// caller in the product that bounded its query before this.
    /// </summary>
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);

    private readonly ISignatureVerifier _verifier = verifier ?? new NativeSignatureVerifier();

    public IReadOnlyList<ProcessInfo> Snapshot(CancellationToken cancellationToken = default) =>
        SnapshotWithCoverage(cancellationToken).Items;

    public AcquisitionSnapshot<ProcessInfo> SnapshotWithCoverage(
        CancellationToken cancellationToken = default)
    {
        var raw = new List<(int Pid, string Name, string? Path, int ParentPid, string? Command)>();
        var unreadableSources = 0;
        var unreadableItems = 0;
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            // Bounded like the Controlled Folder Access reader already bounds its own queries. A
            // stuck WMI provider otherwise hangs this command for ever, and the cancellation check
            // inside the loop below cannot help: the block happens inside the enumeration itself,
            // before a single object is yielded.
            using var searcher = new ManagementObjectSearcher(
                scope,
                new ObjectQuery(
                    "SELECT ProcessId, Name, ExecutablePath, ParentProcessId, CommandLine FROM Win32_Process"),
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
                cancellationToken.ThrowIfCancellationRequested();
                using (o)
                {
                    try
                    {
                        if (!TryToUint(o["ProcessId"], out var processId))
                        {
                            unreadableItems++;
                            continue;
                        }
                        var parentReadable = TryToUint(o["ParentProcessId"], out var parentId);
                        var name = o["Name"] as string;
                        if (!parentReadable || string.IsNullOrWhiteSpace(name))
                        {
                            unreadableItems++;
                        }
                        raw.Add((
                            checked((int)processId),
                            string.IsNullOrWhiteSpace(name) ? $"(pid {processId})" : name,
                            o["ExecutablePath"] as string,
                            parentReadable ? checked((int)parentId) : 0,
                            o["CommandLine"] as string));
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
        return new AcquisitionSnapshot<ProcessInfo>(
            Build(raw, cancellationToken), unreadableSources, unreadableItems);
    }

    private List<ProcessInfo> Build(
        List<(int Pid, string Name, string? Path, int ParentPid, string? Command)> raw,
        CancellationToken cancellationToken)
    {
        var verdicts = _verifier.VerifyMany(
            raw.Where(r => r.Path is not null).Select(r => r.Path!).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            cancellationToken);

        return raw.Select(r => new ProcessInfo(
            r.Pid, r.Name, r.Path, r.ParentPid, r.Command,
            r.Path is not null && verdicts.TryGetValue(r.Path, out var v)
                ? v
                // WMI withheld the image path; no on-disk file was observed to be missing.
                : SignatureVerdict.Unknown)).ToList();
    }

    /// <summary>
    /// Reads a WMI numeric property, which arrives boxed as whichever CIM type the provider chose.
    /// </summary>
    /// <remarks>
    /// An invalid value is reported to the caller rather than fabricated as PID 0. The scanner can
    /// then skip a row with no identity, or retain a row with an unknown parent while marking its
    /// coverage incomplete.
    /// </remarks>
    internal static bool TryToUint(object? value, out uint result)
    {
        switch (value)
        {
            case uint u:
                result = u;
                return true;
            case int i when i >= 0:
                result = (uint)i;
                return true;
            case ushort s:
                result = s;
                return true;
            case long l when l is >= 0 and <= uint.MaxValue:
                result = (uint)l;
                return true;
            default:
                result = 0;
                return false;
        }
    }
}
