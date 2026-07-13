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
    private readonly ISignatureVerifier _verifier;

    public ConnectionMonitor(ISignatureVerifier? verifier = null) =>
        _verifier = verifier ?? new AuthenticodeVerifier();

    public IReadOnlyList<Connection> Snapshot()
    {
        var rows = ReadTable();

        // Resolve each owning process once, then verify every distinct image in one batch.
        var byPid = new Dictionary<int, (string Name, string? Path)>();
        foreach (var r in rows)
        {
            if (!byPid.ContainsKey(r.Pid))
            {
                byPid[r.Pid] = ResolveProcess(r.Pid);
            }
        }
        var verdicts = _verifier.VerifyMany(
            byPid.Values.Where(p => p.Path is not null).Select(p => p.Path!).ToList());

        var connections = new List<Connection>(rows.Count);
        foreach (var r in rows)
        {
            var proc = byPid[r.Pid];
            var signature = proc.Path is not null && verdicts.TryGetValue(proc.Path, out var v)
                ? v
                : SignatureVerdict.Missing;
            connections.Add(new Connection(
                r.Protocol, r.Local, r.Remote, r.State, r.Pid, proc.Name, proc.Path, signature));
        }
        return connections;
    }

    // Native IP Helper tables, falling back to netstat parsing only if those entry
    // points are unavailable (very old/locked-down Windows).
    private static IReadOnlyList<NetstatRow> ReadTable()
    {
        try
        {
            return NativeConnectionReader.Read();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return NetstatParser.Parse(RunNetstat());
        }
    }

    private static string RunNetstat()
    {
        try
        {
            // Absolute System32 path: never resolve a child binary through the search
            // path (binary-planting resistance).
            var exe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "netstat.exe");
            using var p = Process.Start(new ProcessStartInfo(exe, "-ano")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (p is null)
            {
                return string.Empty;
            }
            // Async read + kill-on-timeout: a hung netstat can't block ReadToEnd
            // forever or leave a zombie process behind.
            var output = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(10_000))
            {
                try
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(5_000);
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    // Already exited — the read completes either way.
                }
            }
            return output.GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
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
