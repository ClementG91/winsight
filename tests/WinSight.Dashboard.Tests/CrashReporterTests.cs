using System.IO;

using WinSight.Dashboard;

using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class CrashReporterTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"wsg-crash-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void Format_CarriesTheExceptionTypeMessageStackAndSource()
    {
        Exception captured;
        try
        {
            throw new InvalidOperationException("scan blew up");
        }
        catch (InvalidOperationException ex)
        {
            captured = ex;
        }

        var report = CrashReporter.Format(captured, "Dispatcher", DateTimeOffset.UtcNow);

        Assert.Contains("InvalidOperationException", report, StringComparison.Ordinal);
        Assert.Contains("scan blew up", report, StringComparison.Ordinal);
        Assert.Contains("source  : Dispatcher", report, StringComparison.Ordinal);
        Assert.Contains(nameof(Format_CarriesTheExceptionTypeMessageStackAndSource), report, StringComparison.Ordinal);
    }

    [Fact]
    public void Format_DoesNotLeakScanFindings_OnlyDiagnostics()
    {
        var report = CrashReporter.Format(new InvalidOperationException("boom"), "AppDomain", DateTimeOffset.UtcNow);

        // A crash report is diagnostics, not an evidence dump: it must carry version/OS/source and
        // the exception, and nothing about what the machine was found to contain.
        Assert.Contains("version :", report, StringComparison.Ordinal);
        Assert.Contains("os      :", report, StringComparison.Ordinal);
        Assert.DoesNotContain("HKLM", report, StringComparison.Ordinal);
    }

    [Fact]
    public void Write_CreatesTheDirectoryAndAReadableReport()
    {
        var dir = Path.Combine(TempDir(), "nested"); // not created yet
        try
        {
            var path = CrashReporter.Write(dir, "hello");

            Assert.True(File.Exists(path));
            Assert.Equal("hello", File.ReadAllText(path));
            Assert.EndsWith(".log", path, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(dir)!, recursive: true);
        }
    }

    [Fact]
    public void Prune_KeepsOnlyTheNewestReports_SoACrashLoopCannotFillTheDisk()
    {
        var dir = TempDir();
        try
        {
            for (var i = 0; i < CrashReporter.MaxReports + 5; i++)
            {
                var path = Path.Combine(dir, $"crash-{i:D3}.log");
                File.WriteAllText(path, "x");
                File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(i));
            }

            CrashReporter.Prune(dir);

            Assert.Equal(CrashReporter.MaxReports, Directory.GetFiles(dir, "crash-*.log").Length);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Prune_MissingDirectory_IsANoOp() =>
        CrashReporter.Prune(Path.Combine(Path.GetTempPath(), $"gone-{Guid.NewGuid():N}"));

    [Fact]
    public void TryCapture_NeverThrows_EvenOnAnUnwritableTarget()
    {
        // Reporting must never become the thing that crashes the app.
        CrashReporter.TryCapture(new InvalidOperationException("boom"), "test");
    }
}
