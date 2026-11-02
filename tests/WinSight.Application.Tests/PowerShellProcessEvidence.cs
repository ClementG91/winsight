using System.Diagnostics;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;

namespace WinSight.Application.Tests;

// Test-only PS5 execution. Diagnostics contain closed phase names and host reception times only.
internal static class PowerShellProcessEvidence
{
    internal const int OutputLimit = 32768;
    internal const string Marker = "__WINSIGHT_TEST_PHASE__:";
    internal const string ChildClockMarker = "__WINSIGHT_TEST_CHILD_CLOCK__:";
    internal const string Prelude = "function Write-TestPhase($Phase) { [Console]::Out.WriteLine('__WINSIGHT_TEST_PHASE__:' + $Phase); [Console]::Out.Flush(); "
        + "[Console]::Out.WriteLine('__WINSIGHT_TEST_CHILD_CLOCK__:' + $Phase + ':' + [DateTime]::UtcNow.Ticks + ':' + [Diagnostics.Stopwatch]::GetTimestamp() + ':' + [Diagnostics.Stopwatch]::Frequency); [Console]::Out.Flush() }; Write-TestPhase 'entered'\n";
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
        var launchClock = HostClock(clock);
        var launchPool = PoolSnapshot();
        using var process = Process.Start(start)!;
        var started = clock.Elapsed.TotalMilliseconds;
        // Keep the existing watchdog origin after Process.Start. Its synchronous OS call remains
        // outside the deadline. Neither a successful cleanup nor an exit code can erase a timeout.
        using var deadline = new CancellationTokenSource(watchdog);
        // This is an upper observation of arming, not its exact instant. The existing `started`
        // value is its lower monotonic bound; no new sampling moves the CTS after Process.Start.
        var armedClock = HostClock(clock);
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
        var failureClock = "not-observed";
        var failurePool = "not-observed";
        var beforeKill = "not-observed";
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
            failureClock = HostClock(clock);
            failurePool = PoolSnapshot();
            // Retain the same Process object. PID lookups could bind a recycled process, while
            // a real native exit preceding late observation must remain visible before Kill.
            beforeKill = NativeProcessSnapshot(process);
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
        var cleanupEnded = clock.Elapsed.TotalMilliseconds;
        var finalClock = HostClock(clock);
        var finalPool = PoolSnapshot();
        var finalProcess = NativeProcessSnapshot(process);
        var summary = $"PS5 host reception ms: started={started:F1}, {phases.Summary()}, exited={exited?.ToString("F1") ?? "unobserved"}, drained={drainAt?.ToString("F1") ?? "unobserved"}, cleanup-ended={cleanupEnded:F1}; stdout-eof={stdout.Eof}, stderr-eof={stderr.Eof}, stdout-truncated={stdout.Truncated}, stderr-truncated={stderr.Truncated}, kill-returned={killed}, cleanup-error={cleanupError ?? "none"}"
            + FormattableString.Invariant($"; watchdogMs={watchdog.TotalMilliseconds}; host-launch=[{launchClock}]; host-armed=[{armedClock}]; host-failure=[{failureClock}]; host-final=[{finalClock}]; pool-launch=[{launchPool}]; pool-failure=[{failurePool}]; pool-final=[{finalPool}]; native-before-kill=[{beforeKill}]; native-process-final=[{finalProcess}]; child-clocks=[{phases.ChildSummary()}]");
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
        private static readonly string[] Known = ["entered", "parsed", "definitions-loaded", "module-imported", "body-begin", "body-end", "probe-begin", "probe-first-complete", "probe-repeat-complete"];
        private readonly StringBuilder _line = new();
        private readonly List<(string Name, double At)> _received = [];
        private readonly List<(string Name, long UtcTicks, long Counter, long Frequency)> _childClocks = [];
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
                            else if (line.StartsWith(ChildClockMarker, StringComparison.Ordinal))
                            {
                                var fields = line[ChildClockMarker.Length..].Split(':');
                                if (fields.Length == 4 && Known.Contains(fields[0], StringComparer.Ordinal)
                                    && !_childClocks.Any(p => p.Name == fields[0])
                                    && CanonicalCounter(fields[1], out var utcTicks) && utcTicks <= DateTime.MaxValue.Ticks
                                    && CanonicalCounter(fields[2], out var counter)
                                    && CanonicalCounter(fields[3], out var frequency) && frequency > 0)
                                {
                                    _childClocks.Add((fields[0], utcTicks, counter, frequency));
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

        internal string ChildSummary()
        {
            lock (_gate)
            {
                return string.Join(", ", _childClocks.Select(p => FormattableString.Invariant($"{p.Name}:utcTicks={p.UtcTicks}/counter={p.Counter}/frequency={p.Frequency}")));
            }
        }

        private static bool CanonicalCounter(string value, out long parsed) =>
            long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed) && parsed >= 0
            && string.Equals(value, parsed.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    internal sealed record Result(int ExitCode, string Stdout, string Stderr, string Summary);

    // Best-effort diagnostics never decide the result or replace a primary exception. Values are
    // closed fields, not exception messages, process arguments or arbitrary child output.
    private static string Diagnostic(Func<string> capture)
    {
        try { return capture(); }
        catch (Exception failure) { return "unavailable=" + failure.GetType().Name; }
    }

    private static string HostClock(Stopwatch clock) => Diagnostic(() =>
        FormattableString.Invariant($"utc={DateTime.UtcNow:O}; elapsedMs={clock.Elapsed.TotalMilliseconds:F1}; counter={Stopwatch.GetTimestamp()}; frequency={Stopwatch.Frequency}"));

    private static string PoolSnapshot() => Diagnostic(() =>
    {
        ThreadPool.GetAvailableThreads(out var availableWorker, out var availableIo);
        ThreadPool.GetMaxThreads(out var maximumWorker, out var maximumIo);
        return FormattableString.Invariant($"count={ThreadPool.ThreadCount}; pending={ThreadPool.PendingWorkItemCount}; availableWorker={availableWorker}; availableIo={availableIo}; maximumWorker={maximumWorker}; maximumIo={maximumIo}");
    });

    private static string NativeProcessSnapshot(Process process) => Diagnostic(() =>
    {
        var startUtc = process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        return process.HasExited
            ? FormattableString.Invariant($"startUtc={startUtc}; exited=True; exitUtc={process.ExitTime.ToUniversalTime():O}; exitCode={process.ExitCode}")
            : $"startUtc={startUtc}; exited=False; exitUtc=not-observed; exitCode=not-observed";
    });
}
