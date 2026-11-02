using System.Diagnostics;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

using WinSight.Core;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class QuotaFileCoordinationTests : IDisposable
{
    private const string Legacy = """{"recentRequests":["2026-07-14T11:59:50+00:00"],"utcDay":"2026-07-14","dayCount":3,"utcMonth":"2026-07","monthCount":3}""";
    private static readonly DateTimeOffset Now = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-quota-file-").FullName;
    private string StatePath => Path.Combine(_root, "quota.json");
    private VirusTotalQuotaLimiter Guard(Func<DateTimeOffset>? clock = null) => new(StatePath, clock ?? (() => Now), new(64, 64, 64));
    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void HeldPrivateSidecarPreventsAdmission()
    {
        using var gate = AutomaticFileAccess.TryAcquireExclusiveLockFile(StatePath + ".lock", out var status);
        Assert.NotNull(gate);
        Assert.Equal(LocalFileLockStatus.Acquired, status);
        var watch = Stopwatch.StartNew();
        Assert.False(Guard().TryAcquire(out var snapshot), "An occupied private quota sidecar must refuse admission.");
        Assert.False(snapshot.RequestAllowed);
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5));
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void EmptyObjectIsNotAnInitialState()
    {
        File.WriteAllText(StatePath, "{}");
        Assert.False(Guard().TryAcquire(out _), "An incomplete quota object must not reset accounting.");
        Assert.Equal("{}", File.ReadAllText(StatePath));
    }

    [Fact]
    public void LegacyKernelObjectCannotControlAccounting()
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(StatePath).ToUpperInvariant()));
        var name = $"Local\\WinSight.VirusTotalQuota.{Convert.ToHexString(hash.AsSpan(0, 8))}";
        using var foreignType = new EventWaitHandle(false, EventResetMode.ManualReset, name, out var created);
        Assert.True(created);
        var failure = Record.Exception(() =>
        {
            Assert.True(Guard().TryAcquire(out var snapshot));
            Assert.Equal(new VirusTotalQuotaSnapshot(1, 1, 1, true), snapshot);
            using var state = JsonDocument.Parse(File.ReadAllBytes(StatePath));
            Assert.Equal(1, state.RootElement.GetProperty("dayCount").GetInt32());
        });
        Assert.Null(failure);
    }

    [Fact]
    public void UnsupportedMinuteCapacityIsRejectedAtConstruction() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new VirusTotalQuotaLimiter(StatePath, limits: new(65, 500, 500)));

    [Fact]
    public void UnreadableStateIsNotReplacedByEmptyCounters()
    {
        var original = Encoding.UTF8.GetBytes(Legacy);
        var control = Path.Combine(_root, "replace-control.json");
        File.WriteAllBytes(StatePath, original);
        File.WriteAllBytes(control, original);
        using var identity = WindowsIdentity.GetCurrent();
        var sid = Assert.IsType<SecurityIdentifier>(identity.User);
        var directoryBytes = new DirectoryInfo(_root).GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
        var directoryRestore = new DirectorySecurity();
        directoryRestore.SetSecurityDescriptorBinaryForm(directoryBytes, AccessControlSections.Access);
        var restore = new Dictionary<string, FileSecurity>();
        Exception? primary = null;
        var cleanup = new List<Exception>();
        try
        {
            using (var gate = AutomaticFileAccess.TryAcquireExclusiveLockFile(StatePath + ".lock", out var gateStatus))
            {
                Assert.NotNull(gate);
                Assert.Equal(LocalFileLockStatus.Acquired, gateStatus);
            }
            var deniedDirectory = new DirectorySecurity();
            deniedDirectory.SetSecurityDescriptorBinaryForm(directoryBytes, AccessControlSections.Access);
            deniedDirectory.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ListDirectory, AccessControlType.Deny));
            new DirectoryInfo(_root).SetAccessControl(deniedDirectory);
            foreach (var path in new[] { StatePath, control })
            {
                var bytes = new FileInfo(path).GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
                var saved = new FileSecurity();
                saved.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
                restore.Add(path, saved);
                var denied = new FileSecurity();
                denied.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);
                denied.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.ReadAttributes, AccessControlType.Deny));
                new FileInfo(path).SetAccessControl(denied);
            }
            using (var lease = AutomaticFileAccess.TryAcquire(StatePath, out var missing))
            {
                Assert.Null(lease);
                Assert.False(missing);
            }
            Assert.True(AtomicFile.TryWrite(control, "CONTROL_REPLACED"u8), "Native replacement must actually be possible in this fixture.");
            Assert.False(Guard().TryAcquire(out _), "A real non-missing read refusal must never become zero counters.");
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            Attempt(() => new DirectoryInfo(_root).SetAccessControl(directoryRestore), cleanup);
            foreach (var (path, acl) in restore)
            {
                Attempt(() => new FileInfo(path).SetAccessControl(acl), cleanup);
            }
        }
        Rethrow(primary, cleanup);
        Assert.Equal(original, File.ReadAllBytes(StatePath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompleteLegacyWriterStateRetainsCounters(bool bom)
    {
        File.WriteAllBytes(StatePath, Payload(0, bom));
        Assert.True(Guard().TryAcquire(out var snapshot));
        Assert.Equal(new VirusTotalQuotaSnapshot(2, 4, 4, true), snapshot);
    }

    public static IEnumerable<object[]> UnrecognizedStates()
    {
        yield return ["null"];
        yield return ["[]"];
        yield return [Legacy.Replace("\"dayCount\":3", "\"dayCount\":3,\"dayCount\":0", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3", "\"dayCount\":\"3\"", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3,", "", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3", "\"DayCount\":3", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3", "\"dayCount\":3,\"DayCount\":0", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3", "\"dayCount\":3,\"day\\u0043ount\":0", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"dayCount\":3", "\"dayCount\":-1", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"monthCount\":3", "\"monthCount\":-1", StringComparison.Ordinal)];
        yield return [Legacy.Replace("2026-07-14", "2026-02-30", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"utcMonth\":\"2026-07\"", "\"utcMonth\":\"2026-08\"", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"recentRequests\":[\"2026-07-14T11:59:50+00:00\"]", "\"recentRequests\":null", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"recentRequests\":[\"2026-07-14T11:59:50+00:00\"]", "\"recentRequests\":[null]", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"recentRequests\":[\"2026-07-14T11:59:50+00:00\"]", "\"recentRequests\":[123]", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"utcDay\":\"2026-07-14\"", "\"utcDay\":null", StringComparison.Ordinal)];
        yield return [Legacy.Replace("\"utcMonth\":\"2026-07\"", "\"utcMonth\":7", StringComparison.Ordinal)];
        yield return [Legacy[..^1] + ",\"version\":2}"];
        yield return [Legacy[..^1] + ",\"unrelated\":true}"];
        yield return ["{\"recentRequests\":[" + string.Join(',', Enumerable.Repeat("\"2026-07-14T11:59:50+00:00\"", 65)) + "],\"utcDay\":\"2026-07-14\",\"dayCount\":3,\"utcMonth\":\"2026-07\",\"monthCount\":3}"];
    }

    [Theory]
    [MemberData(nameof(UnrecognizedStates))]
    public void UnrecognizedStateIsPreserved(string json)
    {
        File.WriteAllText(StatePath, json, new UTF8Encoding(false));
        var result = AcquireWithStatus(Guard());
        Assert.False(result.Allowed);
        Assert.Equal("StateInvalidOrUnsupported", result.Status);
        Assert.False(result.Snapshot.RequestAllowed);
        Assert.Equal(json, File.ReadAllText(StatePath));
    }

    [Theory]
    [InlineData(65536, false, true)]
    [InlineData(65536, true, true)]
    [InlineData(65537, false, false)]
    [InlineData(65537, true, false)]
    public void PhysicalBytesIncludeTheSingleInitialBom(int bytes, bool bom, bool allowed)
    {
        var original = Payload(bytes, bom);
        File.WriteAllBytes(StatePath, original);
        var result = AcquireWithStatus(Guard());
        Assert.Equal(allowed, result.Allowed);
        Assert.Equal(allowed ? "Acquired" : "StateOverBudget", result.Status);
        if (!allowed) { Assert.Equal(original, File.ReadAllBytes(StatePath)); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AcquiredReaderRejectsSameObjectGrowth(bool bom)
    {
        var initial = Payload(0, bom);
        File.WriteAllBytes(StatePath, initial);
        using var lease = AutomaticFileAccess.TryAcquire(StatePath, out var missing);
        Assert.NotNull(lease);
        Assert.False(missing);
        File.AppendAllText(StatePath, new string(' ', 65537 - initial.Length), new UTF8Encoding(false));
        Assert.Equal(initial.Length, lease.Length);
        Assert.True(lease.IsCurrent());
        using (var data = lease.OpenRead()) { Assert.Equal(65537, data.Length); }
        var method = typeof(VirusTotalQuotaLimiter).GetMethod("ReadAcquiredState", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        object?[] args = [lease, null];
        Assert.Null(method.Invoke(null, args));
        Assert.Equal("StateOverBudget", args[1]?.ToString());
        Assert.Equal(65537, new FileInfo(StatePath).Length);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RepeatedOrNoninitialBomIsPreserved(bool repeated)
    {
        byte[] bom = [0xef, 0xbb, 0xbf];
        byte[] bytes = repeated ? [.. bom, .. bom, .. Encoding.UTF8.GetBytes(Legacy)] : [(byte)' ', .. bom, .. Encoding.UTF8.GetBytes(Legacy)];
        File.WriteAllBytes(StatePath, bytes);
        Assert.Equal("StateInvalidOrUnsupported", AcquireWithStatus(Guard()).Status);
        Assert.Equal(bytes, File.ReadAllBytes(StatePath));
    }

    [Fact]
    public void InvalidUtf8NeverBecomesRecognizedState()
    {
        var bytes = Encoding.UTF8.GetBytes(Legacy);
        bytes[Array.IndexOf(bytes, (byte)'2')] = 0xff;
        File.WriteAllBytes(StatePath, bytes);
        Assert.Equal("StateInvalidOrUnsupported", AcquireWithStatus(Guard()).Status);
        Assert.Equal(bytes, File.ReadAllBytes(StatePath));
    }

    [Fact]
    public void SixtyFourRecentAdmissionsRemainReadableAndExhausted()
    {
        var guard = Guard();
        for (var i = 0; i < 64; i++) { Assert.True(guard.TryAcquire(out _)); }
        var result = AcquireWithStatus(Guard());
        Assert.Equal("QuotaExhausted", result.Status);
        Assert.Equal(new VirusTotalQuotaSnapshot(64, 64, 64, false), result.Snapshot);
    }

    [Fact]
    public void MissingPublicationDoesNotReplaceANewlyAppearingFile()
    {
        var clocks = 0;
        var guard = Guard(() =>
        {
            clocks++;
            File.WriteAllText(StatePath, Legacy);
            return Now;
        });
        var result = AcquireWithStatus(guard);
        Assert.False(result.Allowed);
        Assert.Equal("WriteFailed", result.Status);
        Assert.Equal(1, clocks);
        Assert.Equal(Legacy, File.ReadAllText(StatePath));
    }

    [Fact]
    public void StatusSeparatesRealExhaustionFromInfrastructureRefusal()
    {
        var guard = new VirusTotalQuotaLimiter(StatePath, () => Now, new(1, 10, 10));
        Assert.Equal("Acquired", AcquireWithStatus(guard).Status);
        var exhausted = AcquireWithStatus(guard);
        Assert.Equal("QuotaExhausted", exhausted.Status);
        Assert.Equal(new VirusTotalQuotaSnapshot(1, 1, 1, false), exhausted.Snapshot);
        using var held = AutomaticFileAccess.TryAcquireExclusiveLockFile(StatePath + ".lock", out _);
        Assert.NotNull(held);
        var unavailable = AcquireWithStatus(guard);
        Assert.Equal("LockTimeout", unavailable.Status);
        Assert.Equal(new VirusTotalQuotaSnapshot(1, 10, 10, false), unavailable.Snapshot);
        Assert.False(unavailable.Allowed);
    }

    [Fact]
    public void ConstructorsDoNotCreateParentsAndOversizedLeafRefusesBeforeSidecarCreation()
    {
        var missing = Path.Combine(_root, "not-created", "quota.json");
        _ = new VirusTotalQuotaLimiter(missing);
        Assert.False(Directory.Exists(Path.GetDirectoryName(missing)));
        var tooLong = Path.Combine(_root, new string('q', 251) + ".json");
        Assert.Equal("UnsafePath", AcquireWithStatus(new VirusTotalQuotaLimiter(tooLong)).Status);
        Assert.Empty(Directory.GetFileSystemEntries(_root));
    }

    [Fact]
    public void ADirectoryStateOrSidecarIsPreserved()
    {
        Directory.CreateDirectory(StatePath);
        Assert.Equal("StateUnavailable", AcquireWithStatus(Guard()).Status);
        Directory.Delete(StatePath);
        File.Delete(StatePath + ".lock");
        Directory.CreateDirectory(StatePath + ".lock");
        Assert.Equal("UnsafePath", AcquireWithStatus(Guard()).Status);
        Assert.True(Directory.Exists(StatePath + ".lock"));
        Assert.False(File.Exists(StatePath));
    }

    [Fact]
    public void SnapshotKeepsFourFieldJsonAndDeconstruction()
    {
        var snapshot = new VirusTotalQuotaSnapshot(1, 2, 3, false);
        var (minute, day, month, allowed) = snapshot;
        Assert.Equal((1, 2, 3, false), (minute, day, month, allowed));
        Assert.Equal("{\"UsedLastMinute\":1,\"UsedToday\":2,\"UsedThisMonth\":3,\"RequestAllowed\":false}", JsonSerializer.Serialize(snapshot));
        Assert.Equal(new VirusTotalQuotaSnapshot(1, 2, 3, false), snapshot);
    }

    [Fact]
    public async Task TwoOwnedProcessesPreserveFortyAdmissions()
    {
        await WithChildren(async children =>
        {
            var first = Start(children, "quota", StatePath);
            var second = Start(children, "quota", StatePath);
            var watch = Stopwatch.StartNew();
            await first.Track(Task.WhenAll(Ready(first), Ready(second))).WaitAsync(Remaining(watch));
            await first.Track(Task.WhenAll(first.Track(first.Process.StandardInput.WriteLineAsync("go")), second.Track(second.Process.StandardInput.WriteLineAsync("go")))).WaitAsync(Remaining(watch));
            var output = await first.Track(Task.WhenAll(first.Track(first.Process.StandardOutput.ReadToEndAsync()), second.Track(second.Process.StandardOutput.ReadToEndAsync()))).WaitAsync(Remaining(watch));
            await first.Track(Task.WhenAll(first.Track(first.Process.WaitForExitAsync()), second.Track(second.Process.WaitForExitAsync()))).WaitAsync(Remaining(watch));
            Assert.Equal(0, first.Process.ExitCode);
            Assert.Equal(0, second.Process.ExitCode);
            Assert.All(output, value => Assert.Equal("20", value.Trim()));
            using var state = JsonDocument.Parse(File.ReadAllBytes(StatePath));
            Assert.Equal(40, state.RootElement.GetProperty("recentRequests").GetArrayLength());
            Assert.Equal(40, state.RootElement.GetProperty("dayCount").GetInt32());
            Assert.Equal(40, state.RootElement.GetProperty("monthCount").GetInt32());
            Assert.True(File.Exists(StatePath + ".lock"));
        });
    }

    [Fact]
    public async Task KilledSidecarHolderReleasesAdmissionWithoutDeletingTheFile()
    {
        await WithChildren(async children =>
        {
            var holder = Start(children, "hold", StatePath + ".lock");
            await Ready(holder).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal("LockTimeout", AcquireWithStatus(Guard()).Status);
            holder.Process.Kill(entireProcessTree: true);
            await holder.Track(holder.Process.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.True(File.Exists(StatePath + ".lock"));
            Assert.Equal("Acquired", AcquireWithStatus(Guard()).Status);
            Assert.True(File.Exists(StatePath + ".lock"));
        });
    }

    private static byte[] Payload(int count, bool bom)
    {
        byte[] json = bom ? [0xef, 0xbb, 0xbf, .. Encoding.UTF8.GetBytes(Legacy)] : Encoding.UTF8.GetBytes(Legacy);
        if (count == 0) { return json; }
        Assert.True(count >= json.Length);
        var result = new byte[count];
        json.CopyTo(result, 0);
        result.AsSpan(json.Length).Fill((byte)' ');
        return result;
    }

    // Only GREEN tests use this additive API. All five qualifying REDs call the old public API.
    private static (bool Allowed, VirusTotalQuotaSnapshot Snapshot, string Status) AcquireWithStatus(VirusTotalQuotaLimiter guard)
    {
        var method = typeof(VirusTotalQuotaLimiter).GetMethods().SingleOrDefault(value => value.Name == "TryAcquire" && value.GetParameters().Length == 2);
        Assert.NotNull(method);
        object?[] args = [null, null];
        var allowed = Assert.IsType<bool>(method.Invoke(guard, args));
        return (allowed, Assert.IsType<VirusTotalQuotaSnapshot>(args[0]), Assert.IsType<string>(args[1]?.ToString()));
    }

    private static OwnedChild Start(List<OwnedChild> children, params string[] args)
    {
        var tests = typeof(QuotaFileCoordinationTests).Assembly.Location;
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in new[] { "exec", "--runtimeconfig", Path.ChangeExtension(tests, ".runtimeconfig.json"), "--depsfile",
                     Path.ChangeExtension(tests, ".deps.json"), typeof(WinSight.Response.LockProbe.Program).Assembly.Location }.Concat(args))
        {
            start.ArgumentList.Add(arg);
        }
        var child = new OwnedChild(Assert.IsType<Process>(Process.Start(start)));
        children.Add(child);
        _ = child.Track(ReadError(child.Process.StandardError));
        return child;
    }

    private static Task Ready(OwnedChild child) => child.Track(AssertReady(child.Track(child.Process.StandardOutput.ReadLineAsync())));
    private static async Task AssertReady(Task<string?> read) => Assert.Equal("ready", await read);
    private static async Task ReadError(StreamReader reader)
    {
        var buffer = new char[1025];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(count));
            if (read == 0) { break; }
            count += read;
        }
        Assert.InRange(count, 0, 1024);
        Assert.Equal(0, count);
    }

    private sealed class OwnedChild(Process process)
    {
        public Process Process { get; } = process;
        public List<Task> Operations { get; } = [];
        public Task Track(Task operation) { Operations.Add(operation); return operation; }
        public Task<T> Track<T>(Task<T> operation) { Operations.Add(operation); return operation; }
    }
    private static TimeSpan Remaining(Stopwatch watch)
    {
        var remaining = TimeSpan.FromSeconds(30) - watch.Elapsed;
        Assert.True(remaining > TimeSpan.Zero, "Owned child operation exceeded its single 30-second budget.");
        return remaining;
    }

    private static async Task WithChildren(Func<List<OwnedChild>, Task> body)
    {
        var children = new List<OwnedChild>();
        Exception? primary = null;
        var cleanup = new List<Exception>();
        try { await body(children); }
        catch (Exception failure) { primary = failure; }
        var watch = Stopwatch.StartNew();
        foreach (var child in children)
        {
            Attempt(() => { if (!child.Process.HasExited) { child.Process.Kill(entireProcessTree: true); } }, cleanup);
            Attempt(() => child.Track(child.Process.WaitForExitAsync()), cleanup);
        }
        foreach (var child in children)
        {
            foreach (var operation in child.Operations)
            {
                try
                {
                    var remaining = TimeSpan.FromSeconds(15) - watch.Elapsed;
                    Assert.True(remaining > TimeSpan.Zero || operation.IsCompleted, "Owned child cleanup exceeded its shared 15-second budget.");
                    if (operation.IsCompleted) { await operation; }
                    else { await operation.WaitAsync(remaining); }
                }
                catch (Exception failure) { cleanup.Add(failure); }
            }
            Attempt(child.Process.Dispose, cleanup);
        }
        Rethrow(primary, cleanup);
    }

    private static void Attempt(Action action, List<Exception> failures)
    {
        try { action(); }
        catch (Exception failure) { failures.Add(failure); }
    }

    private static void Rethrow(Exception? primary, List<Exception> cleanup)
    {
        if (cleanup.Count > 0)
        {
            if (primary is not null) { cleanup.Insert(0, primary); }
            throw new AggregateException("Quota fixture operation or cleanup failed.", cleanup);
        }
        if (primary is not null) { ExceptionDispatchInfo.Capture(primary).Throw(); }
    }
}
