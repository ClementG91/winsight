using System.ComponentModel;
using System.Diagnostics;
using WinSight.Core;

namespace WinSight.NetMonitor;

/// <summary>
/// Netiquette-class connection monitor: snapshots active TCP/UDP endpoints through
/// the native IP Helper tables, attributes each connection to its owning process,
/// and checks that process's Authenticode signature. A bounded absolute-path
/// <c>netstat.exe</c> fallback is used only when the native API cannot be queried.
/// </summary>
public sealed class ConnectionMonitor(ISignatureVerifier? verifier = null)
{
    private readonly ISignatureVerifier _verifier = verifier ?? new NativeSignatureVerifier();

    public IReadOnlyList<Connection> Snapshot(CancellationToken cancellationToken = default)
    {
        var rows = ReadTable(cancellationToken);

        // Resolve each owning process once, then verify every distinct image in one batch.
        var byPid = new Dictionary<int, (string Name, string? Path)>();
        foreach (var r in rows)
        {
            if (!byPid.ContainsKey(r.Pid))
            {
                byPid[r.Pid] = ResolveProcess(r.Pid);
            }
        }
        // Distinct, like ProcessLister and ModuleLister already do. Twenty Chrome tabs are twenty
        // processes sharing one image: without this, one machine with a browser open produced twenty
        // WinVerifyTrust calls and twenty content hashes of the same file, serialised.
        var verdicts = _verifier.VerifyMany(
            byPid.Values
                .Where(p => p.Path is not null)
                .Select(p => p.Path!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            cancellationToken);

        var connections = new List<Connection>(rows.Count);
        foreach (var r in rows)
        {
            var proc = byPid[r.Pid];
            var signature = proc.Path is not null && verdicts.TryGetValue(proc.Path, out var v)
                ? v
                // An exited/protected process is an attribution gap, not evidence of a deleted
                // executable. Preserve that distinction for JSON and report consumers.
                : SignatureVerdict.Unknown;
            connections.Add(new Connection(
                r.Protocol, r.Local, r.Remote, r.State, r.Pid, proc.Name, proc.Path, signature));
        }
        return connections;
    }

    // Native IP Helper tables, falling back to netstat parsing only if those entry
    // points are unavailable (very old/locked-down Windows).
    private static IReadOnlyList<NetstatRow> ReadTable(CancellationToken cancellationToken)
    {
        try
        {
            return NativeConnectionReader.Read();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException
                                     or Win32Exception or InvalidDataException)
        {
            return NetstatParser.Parse(RunNetstat(cancellationToken));
        }
    }

    private static string RunNetstat(CancellationToken cancellationToken)
    {
        try
        {
            // Absolute System32 path: never resolve a child binary through the search
            // path (binary-planting resistance).
            var exe = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "netstat.exe");
            var startInfo = new ProcessStartInfo(exe, "-ano")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            VirusTotalConfiguration.RemoveFromChildEnvironment(startInfo);
            using var p = Process.Start(startInfo);
            if (p is null)
            {
                throw new InvalidOperationException("Windows netstat could not be started.");
            }
            // Cancellation kills netstat immediately (closing stdout ends the read).
            using var registration = cancellationToken.Register(static state =>
            {
                try
                {
                    ((Process)state!).Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    // Already exited; the read completes when the pipe closes.
                }
            }, p);
            // Drain stdout on a background reader thread + kill-on-timeout: a hung netstat
            // can't deadlock on a full pipe buffer or leave a zombie behind. Fully
            // synchronous (no sync-over-async); the builder is read only after the final
            // WaitForExit() flushes the reader.
            var stdout = new System.Text.StringBuilder();
            p.OutputDataReceived += (_, e) =>
            {
                if (e.Data is not null)
                {
                    stdout.AppendLine(e.Data);
                }
            };
            p.BeginOutputReadLine();
            if (!p.WaitForExit(10_000))
            {
                try
                {
                    p.Kill(entireProcessTree: true);
                    p.WaitForExit(5_000);
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
                {
                    // Already exited, the read completes either way.
                }
                throw new TimeoutException("Windows netstat did not complete within the read deadline.");
            }
            p.WaitForExit();
            cancellationToken.ThrowIfCancellationRequested();
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException("Windows netstat returned a failure status.");
            }
            return stdout.ToString();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            throw new InvalidOperationException("The connection table could not be read.", ex);
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
                // Protected/elevated process, name only, no path.
            }
            return (p.ProcessName, path);
        }
        catch (ArgumentException)
        {
            return ($"(pid {pid})", null); // process already exited
        }
    }
}
