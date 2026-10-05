using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;

namespace WinSight.Application.Tests;

// Test-only PS5 execution. Diagnostics contain closed phase names and host reception times only.
internal static class PowerShellProcessEvidence
{
    internal const int OutputLimit = 32768;
    internal const string Marker = "__WINSIGHT_TEST_PHASE__:";
    internal const string Prelude = "function Write-TestPhase($Phase) { [Console]::Out.WriteLine('__WINSIGHT_TEST_PHASE__:' + $Phase); [Console]::Out.Flush() }; Write-TestPhase 'entered'\n";
    // Capture $? immediately: a successful marker must not erase a final native-command failure.
    internal const string BodyEnd = "\n$__winsightBodySucceeded=$?; if ($__winsightBodySucceeded) { Write-TestPhase 'body-end' } else { exit 1 }";

    internal static ProcessStartInfo StartInfo()
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
        return start;
    }

    internal static void EncodedCommand(ProcessStartInfo start, string command)
    {
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
    }

    internal static async Task<Result> Run(ProcessStartInfo start, TimeSpan watchdog, Action<string> report,
        Action<Process>? kill = null)
    {
        var clock = Stopwatch.StartNew();
        using var process = Process.Start(start)!;
        var started = clock.Elapsed.TotalMilliseconds;
        // Keep the existing watchdog origin after Process.Start. Its synchronous OS call remains
        // outside the deadline. Neither a successful cleanup nor an exit code can erase a timeout.
        using var deadline = new CancellationTokenSource(watchdog);
        using var readers = new CancellationTokenSource();
        var phases = new Phases(clock);
        var stdout = new Capture();
        var stderr = new Capture();
        var output = stdout.Read(process.StandardOutput, phases, readers.Token);
        var error = stderr.Read(process.StandardError, null, readers.Token);
        var drained = Task.WhenAll(output, error);
        Exception? primary = null;
        double? exited = null;
        double? drainAt = null;
        var killed = false;
        string? cleanupError = null;
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            exited = clock.Elapsed.TotalMilliseconds;
            // Descendants can keep inherited pipes open after the parent exits. The same original
            // deadline applies to draining, rather than an unbounded ReadToEndAsync after the wait.
            await drained.WaitAsync(deadline.Token);
            if (stdout.Eof && stderr.Eof) { drainAt = clock.Elapsed.TotalMilliseconds; }
            if (stdout.Failure is { } outputFailure) { ExceptionDispatchInfo.Capture(outputFailure).Throw(); }
            if (stderr.Failure is { } errorFailure) { ExceptionDispatchInfo.Capture(errorFailure).Throw(); }
        }
        catch (Exception failure)
        {
            primary = failure;
            try { (kill ?? (p => p.Kill(entireProcessTree: true)))(process); killed = true; }
            catch (Exception secondary) { cleanupError = secondary.GetType().Name; }
            // Separate, fixed cleanup budget; it never extends or changes the assertion deadline.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await process.WaitForExitAsync(cleanup.Token); exited ??= clock.Elapsed.TotalMilliseconds; }
            catch (Exception secondary) { cleanupError ??= secondary.GetType().Name; }
            try
            {
                await drained.WaitAsync(cleanup.Token);
                if (stdout.Eof && stderr.Eof) { drainAt ??= clock.Elapsed.TotalMilliseconds; }
            }
            catch (Exception secondary) { cleanupError ??= secondary.GetType().Name; }
        }
        finally
        {
            // Stop readers even if kill failed or a surviving descendant retained a pipe. Observe
            // their tasks before returning, with a fixed bound, without replacing the first failure.
            readers.Cancel();
            try { await drained.WaitAsync(TimeSpan.FromSeconds(1)); }
            catch (Exception secondary) { cleanupError ??= secondary.GetType().Name; }
        }
        var summary = $"PS5 host reception ms: started={started:F1}, {phases.Summary()}, exited={exited?.ToString("F1") ?? "unobserved"}, drained={drainAt?.ToString("F1") ?? "unobserved"}, cleanup-ended={clock.Elapsed.TotalMilliseconds:F1}; stdout-eof={stdout.Eof}, stderr-eof={stderr.Eof}, stdout-truncated={stdout.Truncated}, stderr-truncated={stderr.Truncated}, kill-returned={killed}, cleanup-error={cleanupError ?? "none"}";
        // Report only after cleanup; a diagnostic callback must never mask the original failure.
        try { report(summary); }
        catch when (primary is not null) { }
        if (primary is not null)
        {
            primary.Data["PowerShellEvidence"] = summary;
            // Partial-output proof without printing arbitrary child text in timeout diagnostics.
            primary.Data["PowerShellStdoutPrefixSha256"] = stdout.PrefixDigest();
            primary.Data["PowerShellStderrPrefixSha256"] = stderr.PrefixDigest();
            ExceptionDispatchInfo.Capture(primary).Throw();
        }
        return new Result(process.ExitCode, stdout.Text(), stderr.Text(), summary);
    }

    private sealed class Capture
    {
        private readonly StringBuilder _text = new();
        private readonly object _gate = new();
        internal bool Eof { get; private set; }
        internal bool Truncated { get; private set; }
        internal Exception? Failure { get; private set; }
        internal string Text() { lock (_gate) { return _text.ToString(); } }
        internal string PrefixDigest() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Text())));

        internal async Task Read(StreamReader reader, Phases? phases, CancellationToken token)
        {
            var buffer = new char[4096];
            try
            {
                while (true)
                {
                    var count = await reader.ReadAsync(buffer.AsMemory(), token);
                    if (count == 0) { Eof = true; return; }
                    lock (_gate)
                    {
                        var retain = Math.Min(count, OutputLimit - _text.Length);
                        _text.Append(buffer, 0, retain);
                        Truncated |= retain != count;
                    }
                    // Continue consuming after the retained-output cap; otherwise pipes can fill.
                    phases?.Receive(buffer.AsSpan(0, count));
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception failure) { Failure = failure; }
        }
    }

    private sealed class Phases(Stopwatch clock)
    {
        private static readonly string[] Known = ["entered", "parsed", "definitions-loaded", "module-imported", "body-begin", "body-end"];
        private readonly StringBuilder _line = new();
        private readonly List<(string Name, double At)> _received = [];
        private readonly object _gate = new();
        private bool _overflow;

        internal void Receive(ReadOnlySpan<char> chars)
        {
            lock (_gate)
            {
                foreach (var ch in chars)
                {
                    if (ch == '\n')
                    {
                        if (!_overflow)
                        {
                            var line = _line.ToString().TrimEnd('\r');
                            if (line.StartsWith(Marker, StringComparison.Ordinal))
                            {
                                var name = line[Marker.Length..];
                                if (Known.Contains(name, StringComparer.Ordinal) && !_received.Any(p => p.Name == name))
                                {
                                    _received.Add((name, clock.Elapsed.TotalMilliseconds));
                                }
                            }
                        }
                        _line.Clear(); _overflow = false;
                    }
                    else if (_line.Length < 128) { _line.Append(ch); }
                    else { _overflow = true; }
                }
            }
        }

        internal string Summary()
        {
            lock (_gate) { return string.Join(", ", _received.Select(p => $"{p.Name}={p.At:F1}")); }
        }
    }

    internal sealed record Result(int ExitCode, string Stdout, string Stderr, string Summary);
}
