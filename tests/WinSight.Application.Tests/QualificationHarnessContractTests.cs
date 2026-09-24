using System.Text;
using System.Text.RegularExpressions;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// RA-01: the Hyper-V qualification harness runs elevated on the host, next to folders an ordinary
/// user can write. These source contracts pin the rules that keep it from being turned against the
/// host or against its own evidence; <c>Test-HarnessHelpers.ps1</c> exercises the helpers themselves.
/// </summary>
public sealed class QualificationHarnessContractTests
{
    private static readonly string Harness = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "scripts", "validation", "hyperv"));

    /// <summary>The scripts that run elevated on the host (the guest folder runs inside the VM).</summary>
    private static IEnumerable<string> HostScripts() => Directory
        .GetFiles(Harness, "*.ps*1", SearchOption.TopDirectoryOnly)
        .Where(path => !Path.GetFileName(path).StartsWith("Verify-", StringComparison.Ordinal)
            && !Path.GetFileName(path).StartsWith("Test-", StringComparison.Ordinal));

    private static string Read(string name) => File.ReadAllText(Path.Combine(Harness, name));

    /// <summary>The code of a script without its comment lines, which name what the code must not do.</summary>
    private static string Code(string path) => string.Join('\n', File.ReadAllLines(path)
        .Where(line => !line.TrimStart().StartsWith('#')));

    [Fact]
    public void NoElevatedHostScriptDeletesRecursively()
    {
        // Windows PowerShell 5.1 Remove-Item -Recurse follows junctions out of the tree it was given.
        Assert.All(HostScripts(), path =>
            Assert.DoesNotMatch(new Regex(@"Remove-Item[^\r\n]*-Recurse", RegexOptions.IgnoreCase), Code(path)));
    }

    [Fact]
    public void TheRunnerNeverWritesMovesOrDeletesInTheRequestFolder()
    {
        var runner = Code(Path.Combine(Harness, "WinSightQualRunner.ps1"));

        Assert.DoesNotContain("Move-Item", runner, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Remove-Item", runner, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Out-File", runner, StringComparison.OrdinalIgnoreCase);
        // Every write goes to the protected runner directory, the sealed store or a protected copy.
        var writes = Regex.Matches(runner, @"(Set-Content|Add-Content)\s+-LiteralPath\s+(?<target>[^\r\n]+)");
        Assert.True(writes.Count >= 5, "the runner's writes were not found");
        foreach (Match write in writes)
        {
            var target = write.Groups["target"].Value;
            Assert.True(
                target.StartsWith("(Join-Path $runnerDir ", StringComparison.Ordinal)
                || target.StartsWith("(Join-Path $sealed ", StringComparison.Ordinal)
                || target.StartsWith("$statusPath", StringComparison.Ordinal)
                || target.StartsWith("$processedPath", StringComparison.Ordinal)
                || target.StartsWith("$manifestPath", StringComparison.Ordinal),
                $"unexpected write target {target}");
        }
    }

    [Fact]
    public void ProtectedDirectoriesAreCreatedWithTheirDaclInOneCallAndVerifiedAfter()
    {
        var module = Read("WinSightHyperV.psm1");

        Assert.Contains("[System.IO.Directory]::CreateDirectory($Path, (New-DirectorySecurity", module, StringComparison.Ordinal);
        Assert.Contains("SetAccessRuleProtection($true, $false)", module, StringComparison.Ordinal);
        var creation = module[module.IndexOf("function New-ProtectedDirectory", StringComparison.Ordinal)..];
        Assert.Contains("Assert-ProtectedPath -Path $Path", creation[creation.IndexOf("CreateDirectory", StringComparison.Ordinal)..], StringComparison.Ordinal);
    }

    [Fact]
    public void TheTransportDiskIsFormattedAndCollectedWithoutFollowingLinks()
    {
        foreach (var name in new[] { "Invoke-HyperVQualification.ps1", "Invoke-HyperVNetworkLogon.ps1" })
        {
            var script = Read(name);
            Assert.Contains("Clear-WinSightDataVolume", script, StringComparison.Ordinal);
            Assert.Contains("Copy-GuestResults", script, StringComparison.Ordinal);
            Assert.Contains("provenance-harness.txt", script, StringComparison.Ordinal);
            Assert.Contains("provenance-candidate.txt", script, StringComparison.Ordinal);
            Assert.Contains("Assert-ProtectedPath", script, StringComparison.Ordinal);
        }
        var module = Read("WinSightHyperV.psm1");
        var collection = module[module.IndexOf("function Copy-GuestResults", StringComparison.Ordinal)..];
        Assert.Contains("ReparsePoint) { $refused.Add(", collection, StringComparison.Ordinal);
    }

    [Fact]
    public void TheRunnerCopiesExactlyTheHarnessFilesThatExist()
    {
        var runner = Read("WinSightQualRunner.ps1");
        var list = Regex.Match(runner, @"\$HarnessFiles = @\((?<files>[^)]*)\)").Groups["files"].Value;
        var files = Regex.Matches(list, "'(?<file>[^']+)'").Select(match => match.Groups["file"].Value).ToArray();

        Assert.NotEmpty(files);
        Assert.All(files, file => Assert.True(File.Exists(Path.Combine(Harness, file)), $"{file} is listed but missing"));
        // What a run stages from the harness must be in the list the runner copies and re-hashes.
        foreach (var staged in new[] { "guest\\qualify.ps1", "guest\\operator-automation.ps1", "guest\\run-guest-checks.ps1", "guest\\control-network-logon.ps1" })
        {
            Assert.Contains(staged, files);
        }
    }

    [Fact]
    public void EveryHarnessScriptIsReadableByWindowsPowerShell51()
    {
        // Without a BOM, Windows PowerShell 5.1 reads UTF-8 as the ANSI code page: non-ASCII text in a
        // BOM-less script turns into mojibake, and a quote character can end a string early.
        foreach (var path in Directory.GetFiles(Harness, "*.ps*1", SearchOption.AllDirectories))
        {
            var bytes = File.ReadAllBytes(path);
            var bom = bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble);
            Assert.True(bom || bytes.All(value => value < 0x80), $"{Path.GetFileName(path)} has non-ASCII bytes and no BOM");
        }
    }
}
