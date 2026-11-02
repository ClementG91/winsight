using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;

using WinSight.Core;

using Xunit;
using Xunit.Abstractions;

namespace WinSight.Response.Tests;

// Regression for N1: unrelated kernel object names cannot disable per-user state.
public sealed class PersistentResponseLockTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-review-v2-").FullName;
    private readonly ITestOutputHelper _out;

    public PersistentResponseLockTests(ITestOutputHelper output) => _out = output;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    private string Journal => Path.Combine(_root, "action-journal.jsonl");

    private static ActionJournalEntry Entry(string target = "target") => new(Guid.NewGuid(),
        ResponseActionKind.AddRule, ResponseOutcome.Succeeded, target, DateTimeOffset.UtcNow, true);

    private static readonly ProcessIdentity Process = new(4321, 100, @"C:\app\evil.exe", null);

    private sealed class Inspector : IProcessInspector
    {
        public ProcessIdentity? Capture(int pid, bool hashImage = false) => Process;
    }

    private sealed class Controller : IProcessController
    {
        public int Calls { get; private set; }
        public ProcessControlOutcome SuspendThreads(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
        public ProcessControlOutcome ResumeThreads(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
        public ProcessControlOutcome TerminateProcess(ProcessIdentity expected) { Calls++; return ProcessControlOutcome.Succeeded; }
    }

    private (ResponseResult Suspend, ResponseResult Resume, ResponseResult Terminate, int Calls) ActAll()
    {
        var controller = new Controller();
        var responder = new ProcessResponder(new Inspector(), controller, new ActionJournal(Journal));
        var s = responder.Suspend(Process, "evil.exe");
        var r = responder.Resume(Process, "evil.exe");
        var t = responder.Terminate(Process, "evil.exe");
        _out.WriteLine($"suspend={s.Outcome} resume={r.Outcome} terminate={t.Outcome} calls={controller.Calls} detail={s.Detail}");
        return (s, r, t, controller.Calls);
    }

    [Fact]
    public void OldGlobalSquattingDoesNotDisableResponsesOrRules()
    {
        var rules = Path.Combine(_root, "response-rules.json");
        using var journalSquatter = Squat(OldNameFor(Journal, "ActionJournal"));
        using var rulesSquatter = Squat(OldNameFor(rules, "ResponseRules"));
        _out.WriteLine($"journal lock: {OldNameFor(Journal, "ActionJournal")}");
        var (s, r, t, calls) = ActAll();
        var added = new RuleStore(rules).Add(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "reg:x"), out var write);
        _out.WriteLine($"rule add={write.Status}");
        Assert.Equal(ResponseOutcome.Succeeded, s.Outcome);
        Assert.Equal(ResponseOutcome.Succeeded, r.Outcome);
        Assert.Equal(ResponseOutcome.Succeeded, t.Outcome);
        Assert.Equal(3, calls);
        Assert.NotNull(added);
        Assert.Equal(RuleStoreStatus.Written, write.Status);
    }

    private static string OldNameFor(string path, string kind)
    {
        var key = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(Path.GetFullPath(path).ToUpperInvariant())))[..32];
        return $@"Global\WinSight.{kind}.{key}";
    }

    [Fact]
    public void OldLocalNamesAreAlsoIrrelevantAndReadersCreateNothing()
    {
        var rules = Path.Combine(_root, "response-rules.json");
        using var journalSquatter = Squat(OldNameFor(Journal, "ActionJournal").Replace("Global", "Local", StringComparison.Ordinal));
        using var rulesSquatter = Squat(OldNameFor(rules, "ResponseRules").Replace("Global", "Local", StringComparison.Ordinal));
        var nested = Path.Combine(_root, "missing-parent", "journal.jsonl");
        Assert.False(new ActionJournal(nested).ReadWithCoverage().Unreadable);
        Assert.Empty(new RuleStore(Path.Combine(_root, "missing-rules", "rules.json")).ActiveRules(RuleScopeKind.Persistence));
        Assert.False(Directory.Exists(Path.GetDirectoryName(nested)));
        Assert.False(Directory.Exists(Path.Combine(_root, "missing-rules")));
        File.WriteAllText(Journal, JsonSerializer.Serialize(Entry()) + "\n");
        Assert.Single(new ActionJournal(Journal).ReadWithCoverage().Entries);
        Assert.False(File.Exists(LockPath(Journal)));
        Assert.Equal(ResponseOutcome.Succeeded, ActAll().Suspend.Outcome);
        Assert.True(File.Exists(LockPath(Journal)));
    }

    [Fact]
    public void ADirectoryAtEitherLockPathHasAPreciseRefusal()
    {
        var rules = Path.Combine(_root, "rules.json");
        Directory.CreateDirectory(LockPath(Journal));
        Directory.CreateDirectory(LockPath(rules));
        Assert.Equal("UnsafeLockPath", new ActionJournal(Journal).TryAppendWithStatus(Entry()).Status.ToString());
        Assert.Equal("UnsafeLockPath", LockFailure(new ActionJournal(Journal).ReadWithCoverage()));
        Assert.Null(new RuleStore(rules).Add(new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence,
            RuleDecision.Allow, RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "reg:x"), out var result));
        Assert.Equal("UnsafeLockPath", result.Status.ToString());
        Assert.False(File.Exists(Journal));
        Assert.False(File.Exists(rules));
    }

    [Fact]
    public async Task AReparseSidecarIsRefusedWithoutTouchingItsTarget()
    {
        var target = Directory.CreateDirectory(Path.Combine(_root, "target")).FullName;
        var sidecar = LockPath(Journal);
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("ComSpec")!)
        {
            Arguments = $"/d /c mklink /J \"{sidecar}\" \"{target}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var child = System.Diagnostics.Process.Start(start)!;
        try
        {
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(0, child.ExitCode);
            Assert.True(File.GetAttributes(sidecar).HasFlag(FileAttributes.ReparsePoint));
            Assert.Equal("UnsafeLockPath", new ActionJournal(Journal).TryAppendWithStatus(Entry()).Status.ToString());
            Assert.Equal("UnsafeLockPath", LockFailure(new ActionJournal(Journal).ReadWithCoverage()));
            Assert.Empty(Directory.GetFileSystemEntries(target));
            Assert.False(File.Exists(Journal));
        }
        finally
        {
            Kill(child);
            if (Directory.Exists(sidecar))
            {
                Directory.Delete(sidecar);
            }
        }
    }

    [Fact]
    public void AccessDeniedSidecarIsNotMissingAndDoesNotCreateData()
    {
        var path = LockPath(Journal);
        File.WriteAllText(path, string.Empty);
        var file = new FileInfo(path);
        var original = file.GetAccessControl();
        var denied = file.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.ReadData, AccessControlType.Deny));
        try
        {
            file.SetAccessControl(denied);
            Assert.Equal("LockUnavailable", new ActionJournal(Journal).TryAppendWithStatus(Entry()).Status.ToString());
            Assert.Equal("LockUnavailable", LockFailure(new ActionJournal(Journal).ReadWithCoverage()));
            Assert.False(File.Exists(Journal));
        }
        finally
        {
            file.SetAccessControl(original);
        }
    }

    [Fact]
    public void EstablishedSidecarDoesNotNeedAnExclusiveDirectoryDataHandle()
    {
        var journal = new ActionJournal(Journal);
        Assert.True(journal.TryAppend(Entry()));
        using var watcher = StableRead(_root);
        Assert.NotNull(watcher);
        Assert.Equal(true, watcher.GetType().GetProperty("IsDirectory")!.GetValue(watcher));
        Assert.True(journal.TryAppend(Entry()));
        Assert.Equal(2, journal.ReadWithCoverage().Entries.Count);
    }

    [Fact]
    public async Task FirstWriterWaitsForLegacyReadAndThenPublishesWithinBudget()
    {
        File.WriteAllText(Journal, JsonSerializer.Serialize(Entry()) + "\n");
        Task<ActionJournalWriteResult> write;
        using (var read = LegacyRead(Journal, TimeSpan.FromMilliseconds(50)))
        {
            Assert.True(read.IsCurrent);
            Assert.False(AutomaticFileAccess.TryAppendFile(Journal, "x"u8));
            write = Task.Run(() => new ActionJournal(Journal, TimeSpan.FromSeconds(2)).TryAppendWithStatus(Entry()));
            await Task.Delay(50);
            Assert.False(write.IsCompleted);
            Assert.False(File.Exists(LockPath(Journal)));
            Assert.True(read.IsCurrent);
        }
        Assert.True((await write.WaitAsync(TimeSpan.FromSeconds(3))).Durable);
        Assert.Equal(2, new ActionJournal(Journal).ReadWithCoverage().Entries.Count);
    }

    [Fact]
    public async Task KilledExclusiveHolderReleasesJournalAndRulesWithoutDeletingSidecars()
    {
        var rules = Path.Combine(_root, "rules.json");
        using var holder = StartProbe("hold", LockPath(Journal));
        Process? ruleHolder = null;
        try
        {
            await Ready(holder);
            ruleHolder = StartProbe("hold", LockPath(rules));
            await Ready(ruleHolder);
            var journal = new ActionJournal(Journal, TimeSpan.FromMilliseconds(50));
            Assert.Equal("LockTimeout", journal.TryAppendWithStatus(Entry()).Status.ToString());
            Assert.Equal("LockTimeout", LockFailure(journal.ReadWithCoverage()));
            var store = new RuleStore(rules, null, TimeSpan.FromMilliseconds(50));
            var rule = new ResponseRule(Guid.NewGuid(), RuleScopeKind.Persistence, RuleDecision.Allow,
                RuleDuration.Permanent, DateTimeOffset.UtcNow, Item: "reg:x");
            Assert.Null(store.Add(rule, out var result));
            Assert.Equal("LockTimeout", result.Status.ToString());
            holder.Kill(entireProcessTree: true);
            ruleHolder.Kill(entireProcessTree: true);
            await Task.WhenAll(holder.WaitForExitAsync(), ruleHolder.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.True(File.Exists(LockPath(Journal)));
            Assert.True(File.Exists(LockPath(rules)));
            var appended = journal.TryAppendWithStatus(Entry());
            Assert.True(appended.Durable, $"Post-kill append (50 ms lock budget): {appended.Detail}");
            Assert.NotNull(store.Add(rule));
        }
        finally
        {
            Kill(holder);
            if (ruleHolder is not null)
            {
                Kill(ruleHolder);
                ruleHolder.Dispose();
            }
        }
    }

    [Fact]
    public async Task TwoProcessesPreserveBothPhasesAndUndoAcrossRotationAndRuleUpdates()
    {
        var rules = Path.Combine(_root, "rules.json");
        File.WriteAllText(Journal, string.Concat(Enumerable.Range(0, 9999)
            .Select(_ => JsonSerializer.Serialize(Entry()) + "\n")) + "{ torn\n");
        using var first = StartProbe("write", Journal, rules, "first");
        using var second = StartProbe("write", Journal, rules, "second");
        var firstDiagnostic = new WriterDiagnostics(first.StandardError);
        var secondDiagnostic = new WriterDiagnostics(second.StandardError);
        long waitStarted = 0;
        long waitUtcTicks = 0;
        try
        {
            await Task.WhenAll(Ready(first), Ready(second));
            await Task.WhenAll(first.StandardInput.WriteLineAsync("go"), second.StandardInput.WriteLineAsync("go"));
            waitUtcTicks = DateTime.UtcNow.Ticks;
            waitStarted = Stopwatch.GetTimestamp();
            var outputs = await Task.WhenAll(first.StandardOutput.ReadToEndAsync(), second.StandardOutput.ReadToEndAsync())
                .WaitAsync(TimeSpan.FromSeconds(30));
            await Task.WhenAll(first.WaitForExitAsync(), second.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(0, first.ExitCode);
            Assert.Equal(0, second.ExitCode);
            var ids = outputs.SelectMany(output => JsonSerializer.Deserialize<Guid[]>(output)!).Order().ToArray();
            Assert.Equal(48, ids.Length);
            var rows = File.ReadLines(Journal).Select(line => JsonSerializer.Deserialize<ActionJournalEntry>(line)!).ToArray();
            foreach (var id in ids)
            {
                Assert.Single(rows, row => row.ActionId == id && row.Phase == ActionJournalPhase.Prepared);
                Assert.Single(rows, row => row.ActionId == id && row.Phase == ActionJournalPhase.Completed && row.UndoneByActionId == id);
            }
            Assert.Equal(ids, new RuleStore(rules).ActiveRules(RuleScopeKind.Persistence).Select(rule => rule.Id).Order());
            Assert.True(File.Exists(new ActionJournal(Journal).RecoveryEvidencePath));
            Assert.InRange(new FileInfo(Journal).Length, 1, 16 * 1024 * 1024);
        }
        finally
        {
            WriteWriterDiagnostic(first, firstDiagnostic, "first", "before-cleanup", waitStarted, waitUtcTicks);
            WriteWriterDiagnostic(second, secondDiagnostic, "second", "before-cleanup", waitStarted, waitUtcTicks);
            try
            {
                Kill(first);
                Kill(second);
            }
            finally
            {
                WriteWriterDiagnostic(first, firstDiagnostic, "first", "after-cleanup", waitStarted, waitUtcTicks);
                WriteWriterDiagnostic(second, secondDiagnostic, "second", "after-cleanup", waitStarted, waitUtcTicks);
            }
        }
    }

    private void WriteWriterDiagnostic(Process process, WriterDiagnostics diagnostic, string label, string stage,
        long waitStarted, long waitUtcTicks)
    {
        try
        {
            var observedUtc = DateTime.UtcNow.Ticks;
            var observed = Stopwatch.GetTimestamp();
            long? nativeStarted = null;
            long? nativeExited = null;
            bool? exited = null;
            int? exitCode = null;
            try
            {
                exited = process.HasExited;
                nativeStarted = process.StartTime.ToUniversalTime().Ticks;
                if (exited == true)
                {
                    nativeExited = process.ExitTime.ToUniversalTime().Ticks;
                    exitCode = process.ExitCode;
                }
            }
            catch (Exception) { /* Missing native state stays unknown. */ }
            _out.WriteLine(FormattableString.Invariant(
                $"writer={label};stage={stage};waitUtc={waitUtcTicks};waitQpc={waitStarted};observedUtc={observedUtc};observedQpc={observed};frequency={Stopwatch.Frequency};nativeStartUtc={nativeStarted};nativeExitUtc={nativeExited};exited={exited};exitCode={exitCode};{diagnostic.Snapshot()}"));
        }
        catch (Exception) { /* Never replace the original assertion, timeout or cleanup failure. */ }
    }

    private sealed class WriterDiagnostics
    {
        private readonly object _gate = new();
        private string _latest = "none";
        private int _frames;
        private bool _malformed;
        private bool _eof;
        private bool _drainFailed;

        public WriterDiagnostics(StreamReader error) => _ = DrainAsync(error);

        public string Snapshot()
        {
            lock (_gate)
            {
                return FormattableString.Invariant(
                    $"frames={_frames};latest={_latest};malformed={_malformed};stderrEof={_eof};drainFailed={_drainFailed}");
            }
        }

        private async Task DrainAsync(StreamReader error)
        {
            try
            {
                var buffer = new char[512];
                var line = new char[128];
                var length = 0;
                var overflow = false;
                int count;
                while ((count = await error.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) != 0)
                {
                    for (var i = 0; i < count; i++)
                    {
                        if (buffer[i] == '\n')
                        {
                            Record(line.AsSpan(0, length).TrimEnd('\r'), overflow);
                            length = 0;
                            overflow = false;
                        }
                        else if (length < line.Length) { line[length++] = buffer[i]; }
                        else { overflow = true; }
                    }
                }
                if (length != 0 || overflow) { Record(line.AsSpan(0, length).TrimEnd('\r'), overflow); }
                lock (_gate) { _eof = true; }
            }
            catch (Exception)
            {
                // The fire-and-observe drain owns its faults; never add a wait to the test.
                lock (_gate) { _drainFailed = true; }
            }
        }

        private void Record(ReadOnlySpan<char> line, bool overflow)
        {
            var parts = overflow ? [] : line.ToString().Split(':');
            lock (_gate)
            {
                if (parts.Length != 6 || parts[0] != "WSPROBE"
                    || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var ordinal)
                    || ordinal is < 0 or > 23
                    || parts[2] is not ("prepared" or "completed" or "undo" or "rule")
                    || parts[3] is not ("begin" or "succeeded" or "refused")
                    || !long.TryParse(parts[4], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var elapsed)
                    || !long.TryParse(parts[5], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var frequency)
                    || frequency <= 0)
                {
                    _malformed = true;
                    return;
                }
                if (_frames < int.MaxValue) { _frames++; }
                _latest = FormattableString.Invariant($"{ordinal}:{parts[2]}:{parts[3]}:{elapsed}:{frequency}");
            }
        }
    }

    // Reflection keeps these permanent regressions compilable on the pre-fix49 revision.
    // Missing post-fix APIs fail assertions, rather than creating an import/build-error RED.
    private static string LockPath(string path) => Path.GetFullPath(path) + ".lock";
    private static string? LockFailure(ActionJournalSnapshot snapshot) =>
        typeof(ActionJournalSnapshot).GetProperty("LockFailure")?.GetValue(snapshot)?.ToString();

    private static IDisposable StableRead(string path)
    {
        var method = typeof(AutomaticFileAccess).GetMethod("TryAcquireStableRead");
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<IDisposable>(method.Invoke(null, [path, false]));
    }

    private static TestReadGate LegacyRead(string path, TimeSpan wait)
    {
        var type = typeof(ActionJournal).Assembly.GetType("WinSight.Response.ResponseFileLock");
        Assert.NotNull(type);
        var method = type.GetMethod("AcquireReader", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        var gate = Assert.IsAssignableFrom<IDisposable>(method.Invoke(null, [path, wait]));
        return new TestReadGate(gate);
    }

    private sealed class TestReadGate(IDisposable gate) : IDisposable
    {
        public bool IsCurrent
        {
            get
            {
                var property = gate.GetType().GetProperty("IsCurrent", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
                Assert.NotNull(property);
                return Assert.IsType<bool>(property.GetValue(gate));
            }
        }

        public void Dispose() => gate.Dispose();
    }

    private static Process StartProbe(params string[] args)
    {
        var tests = typeof(PersistentResponseLockTests).Assembly.Location;
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("exec");
        start.ArgumentList.Add("--runtimeconfig");
        start.ArgumentList.Add(Path.ChangeExtension(tests, ".runtimeconfig.json"));
        start.ArgumentList.Add("--depsfile");
        start.ArgumentList.Add(Path.ChangeExtension(tests, ".deps.json"));
        start.ArgumentList.Add(typeof(LockProbe.Program).Assembly.Location);
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        return System.Diagnostics.Process.Start(start)!;
    }

    private static async Task Ready(Process process) =>
        Assert.Equal("ready", await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)));

    private static void Kill(Process process)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
            Assert.True(process.WaitForExit(15_000));
        }
    }

    // A child process creates the Global name first with a DACL that grants only SYNCHRONIZE, then
    // holds it. Another account can do exactly this, because the Global namespace is machine-wide.
    private static Squatter Squat(string name)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-Command");
        start.ArgumentList.Add("$s = [System.Security.AccessControl.MutexSecurity]::new(); "
            + "$e = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0'); "
            + "$s.AddAccessRule([System.Security.AccessControl.MutexAccessRule]::new($e, [System.Security.AccessControl.MutexRights]::Synchronize, 'Allow')); "
            + "$c = $false; $m = [System.Threading.Mutex]::new($false, $env:SQUAT_NAME, [ref]$c, $s); "
            + "if (-not $c) { exit 3 }; [Console]::WriteLine('ready'); [void][Console]::ReadLine(); $m.Dispose()");
        start.Environment["SQUAT_NAME"] = name;
        var process = System.Diagnostics.Process.Start(start)!;
        try
        {
            var line = process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20)).GetAwaiter().GetResult();
            Assert.Equal("ready", line);
            return new Squatter(process);
        }
        catch
        {
            try
            {
                Kill(process);
            }
            catch (Exception cleanup) when (cleanup is InvalidOperationException or System.ComponentModel.Win32Exception or Xunit.Sdk.XunitException)
            {
                // Preserve the readiness/assertion failure. Cleanup never qualifies the child.
            }
            finally
            {
                process.Dispose();
            }
            throw;
        }
    }

    private sealed class Squatter(System.Diagnostics.Process process) : IDisposable
    {
        public void Dispose()
        {
            try { process.StandardInput.WriteLine("release"); process.WaitForExit(10_000); }
            finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); } process.Dispose(); }
        }
    }
}
