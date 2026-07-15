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

    public IReadOnlyList<ProcessInfo> Snapshot()
    {
        var raw = new List<(int Pid, string Name, string? Path, int ParentPid, string? Command)>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(
                "SELECT ProcessId, Name, ExecutablePath, ParentProcessId, CommandLine FROM Win32_Process"));
            foreach (ManagementBaseObject o in searcher.Get())
            {
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
            return raw.Count == 0 ? Array.Empty<ProcessInfo>() : Build(raw);
        }
        return Build(raw);
    }

    private List<ProcessInfo> Build(
        List<(int Pid, string Name, string? Path, int ParentPid, string? Command)> raw)
    {
        var verdicts = _verifier.VerifyMany(
            raw.Where(r => r.Path is not null).Select(r => r.Path!).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

        return raw.Select(r => new ProcessInfo(
            r.Pid, r.Name, r.Path, r.ParentPid, r.Command,
            r.Path is not null && verdicts.TryGetValue(r.Path, out var v) ? v : SignatureVerdict.Missing)).ToList();
    }

    private static uint ToUint(object? value) => value switch
    {
        uint u => u,
        int i => (uint)i,
        ushort s => s,
        long l => (uint)l,
        _ => 0,
    };
}
