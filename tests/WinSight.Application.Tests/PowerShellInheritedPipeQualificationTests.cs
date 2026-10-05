using System.Diagnostics;
using System.Reflection;
using System.Text;

using Xunit;
using Xunit.Abstractions;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed class PowerShellInheritedPipeQualificationTests(ITestOutputHelper output)
{
    [Fact]
    public async Task AnExitedParentWithALivePipeOwnerStillHonorsTheFixtureWatchdog()
    {
        var root = Directory.CreateTempSubdirectory("winsight-pipe-watchdog-").FullName;
        var pidPath = Path.Combine(root, "child.pid");
        var childCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(
            "[Console]::Out.WriteLine('synthetic-pipe-owner'); [Console]::Out.Flush(); [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)"));
        var script = $$"""
            $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -NoNewWindow -PassThru -ArgumentList '-NoProfile -NonInteractive -EncodedCommand {{childCommand}}'
            $pidPath = '{{pidPath.Replace("'", "''", StringComparison.Ordinal)}}'
            [IO.File]::WriteAllText($pidPath + '.tmp', [string]$child.Id)
            [IO.File]::Move($pidPath + '.tmp', $pidPath)
            exit 0
            """;
        // Invoke the actual existing fixture launcher. Reflection also lets this regression run
        // against its pre-refactor static form without replacing the launch/wait implementation.
        var fixture = typeof(QualificationLifecycleTests);
        var constructor = Assert.Single(fixture.GetConstructors());
        var instance = constructor.Invoke(constructor.GetParameters().Length == 0 ? [] : [output]);
        var launch = fixture.GetMethod("Run", BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance)!;
        Task? running = null;
        try
        {
            running = (Task)launch.Invoke(instance, ["Invoke-HyperVNetworkLogon.ps1", "Remove-DataDisks", script])!;
            using (var setup = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
            {
                while (!File.Exists(pidPath)) { await Task.Delay(50, setup.Token); }
            }
            using (var child = Process.GetProcessById(int.Parse(File.ReadAllText(pidPath), System.Globalization.CultureInfo.InvariantCulture)))
            {
                Assert.False(child.HasExited, "The pipe owner must really be alive before the watchdog fires.");
            }
            // Outer test containment only. The actual fixture watchdog remains precisely 30 s.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => running.WaitAsync(TimeSpan.FromSeconds(40)));
            Assert.True(File.Exists(pidPath), "The pipe owner must really have been launched.");
        }
        finally
        {
            if (File.Exists(pidPath))
            {
                try
                {
                    using var child = Process.GetProcessById(int.Parse(File.ReadAllText(pidPath), System.Globalization.CultureInfo.InvariantCulture));
                    if (!child.HasExited) { child.Kill(entireProcessTree: true); }
                    await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (Exception secondary) { output.WriteLine($"Pipe-control cleanup: {secondary.GetType().Name}"); }
            }
            if (running is not null)
            {
                try { await running.WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (Exception secondary) { output.WriteLine($"Pipe-control final observation: {secondary.GetType().Name}"); }
            }
            Directory.Delete(root, recursive: true);
        }
    }
}
