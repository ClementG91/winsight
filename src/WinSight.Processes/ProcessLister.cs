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
    private readonly ISignatureVerifier _verifier = verifier ?? new NativeSignatureVerifier();

    public IReadOnlyList<ProcessInfo> Snapshot(CancellationToken cancellationToken = default)
    {
        var raw = new List<(int Pid, string Name, string? Path, int ParentPid, string? Command)>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT ProcessId, Name, ExecutablePath, ParentProcessId, CommandLine FROM Win32_Process"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (o)
                {
                    raw.Add((
                        (int)ToUint(o["ProcessId"]),
                        o["Name"] as string ?? string.Empty,
                        o["ExecutablePath"] as string,
                        (int)ToUint(o["ParentProcessId"]),
                        o["CommandLine"] as string));
                }
            }
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException)
        {
            return raw.Count == 0 ? Array.Empty<ProcessInfo>() : Build(raw, cancellationToken);
        }
        return Build(raw, cancellationToken);
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
            r.Path is not null && verdicts.TryGetValue(r.Path, out var v) ? v : SignatureVerdict.Missing)).ToList();
    }

    /// <summary>
    /// Reads a WMI numeric property, which arrives boxed as whichever CIM type the provider chose.
    /// </summary>
    /// <remarks>
    /// The <c>_ => 0</c> arm is a deliberate, and deliberately narrow, decision: a process id that
    /// cannot be read becomes 0, the System Idle Process. That is a real mislabel, so it is pinned
    /// by a test rather than left as an accident — but it is preferred to throwing, because losing
    /// the whole process snapshot over one unreadable row is the worse failure. Win32_Process
    /// declares ProcessId and ParentProcessId as uint32, so every arm above it is the normal path
    /// and the fallback only fires if a provider returns something undeclared or nothing at all.
    /// </remarks>
    internal static uint ToUint(object? value) => value switch
    {
        uint u => u,
        int i => (uint)i,
        ushort s => s,
        long l => (uint)l,
        _ => 0,
    };
}
