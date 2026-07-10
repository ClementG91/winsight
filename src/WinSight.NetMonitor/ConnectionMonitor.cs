using System.ComponentModel;
using System.Diagnostics;
using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>
/// Netiquette-class connection monitor: snapshots the active TCP/UDP table (via
/// `netstat -ano`), attributes each connection to its owning process, and checks
/// that process's Authenticode signature. A reliable, dependency-light first slice;
/// a later revision swaps netstat for GetExtendedTcpTable (CsWin32) for live events.
/// </summary>
public sealed class ConnectionMonitor
{
    private readonly SignatureVerifier _verifier;

    public ConnectionMonitor(SignatureVerifier? verifier = null) =>
        _verifier = verifier ?? new SignatureVerifier();

    public IReadOnlyList<Connection> Snapshot()
    {
        var rows = NetstatParser.Parse(RunNetstat());
        var byPid = new Dictionary<int, (string Name, string? Path)>();
        var connections = new List<Connection>(rows.Count);

        foreach (var r in rows)
        {
            if (!byPid.TryGetValue(r.Pid, out var proc))
            {
                proc = ResolveProcess(r.Pid);
                byPid[r.Pid] = proc;
            }
            var signature = proc.Path is null ? SignatureVerdict.Missing : _verifier.Verify(proc.Path);
            connections.Add(new Connection(
                r.Protocol, r.Local, r.Remote, r.State, r.Pid, proc.Name, proc.Path, signature));
        }
        return connections;
    }

    private static string RunNetstat()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netstat", "-ano")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (p is null)
            {
                return string.Empty;
            }
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10_000);
            return output;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private static (string Name, string? Path) ResolveProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            string? path = null;
            try
            {
                path = p.MainModule?.FileName;
            }
            catch (Exception ex) when (ex is Win32Exception or NotSupportedException or InvalidOperationException)
            {
                // Protected/elevated process — name only, no path.
            }
            return (p.ProcessName, path);
        }
        catch (ArgumentException)
        {
            return ($"(pid {pid})", null); // process already exited
        }
    }
}
