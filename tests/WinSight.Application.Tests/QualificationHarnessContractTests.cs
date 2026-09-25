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

    /// <summary>
    /// The storage check trusts the capability Hyper-V gives its worker process, which Hyper-V grants
    /// on the disks of the VMs it runs, and only in the VM storage.
    /// </summary>
    /// <remarks>
    /// Found at the first storage protection: Hyper-V had granted this capability Write on the control
    /// VM's data disk, and the check, which knew only the per-VM identity, refused the storage. A
    /// capability counts only for an AppContainer token, in the second of its two access checks, so it
    /// never lets a local user write. The SID is derived here the way Windows derives it - the SHA-256
    /// of the capability's upper-case name - so a wrong constant fails.
    /// </remarks>
    [Fact]
    public void TheHyperVWorkerCapabilityIsTrustedOnlyInTheVirtualMachineStorage()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));

        Assert.Contains($"$script:VmWorkerProcessCapability = '{CapabilitySid("vmWorkerProcess")}'", module, StringComparison.Ordinal);
        var start = module.IndexOf("function Test-TrustedWriter", StringComparison.Ordinal);
        Assert.True(start >= 0, "Test-TrustedWriter was not found");
        var body = module[start..module.IndexOf("\n}", start, StringComparison.Ordinal)];
        Assert.Contains(
            "if ($VirtualMachines) { $trusted += $script:VirtualMachines, $script:VmWorkerProcessCapability }",
            body,
            StringComparison.Ordinal);
        // Its definition and the VM-storage branch: trusted nowhere else.
        Assert.Equal(2, Regex.Count(module, @"\$script:VmWorkerProcessCapability\b"));
        Assert.Contains("-not (Test-TrustedWriter $sid -VirtualMachines:$AllowVirtualMachines)", module, StringComparison.Ordinal);
    }

    /// <summary>
    /// CREATOR OWNER is trusted: on each new child it stands for whoever created it, who needed a
    /// create right only a trusted writer holds. CREATOR GROUP is not: it stands for the creator's
    /// primary group, an ordinary group.
    /// </summary>
    /// <remarks>
    /// Found at the second storage protection: Hyper-V puts CREATOR OWNER, GENERIC_ALL, inherit only,
    /// on the folder of each VM, and the check refused it as a writer.
    /// </remarks>
    [Fact]
    public void CreatorOwnerIsTrustedAndCreatorGroupIsNot()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));

        Assert.Contains("$script:CreatorOwner = 'S-1-3-0'", module, StringComparison.Ordinal);
        Assert.Contains("$trusted = @($script:LocalSystem, $script:Administrators, $script:CreatorOwner)", module, StringComparison.Ordinal);
        Assert.DoesNotContain("S-1-3-1", module, StringComparison.Ordinal);
    }

    /// <summary>The storage check lists every refusal in one error, so one run shows all there is to fix.</summary>
    [Fact]
    public void EveryStorageRefusalIsReportedAtOnce()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        var assert = module[module.IndexOf("function Assert-ProtectedPath", StringComparison.Ordinal)..];
        assert = assert[..assert.IndexOf("\n}", StringComparison.Ordinal)];

        Assert.Contains("@(Get-ProtectionRefusals -Items $items -AllowVirtualMachines:$AllowVirtualMachines)", assert, StringComparison.Ordinal);
        Assert.Contains("throw ($refusals -join [Environment]::NewLine)", assert, StringComparison.Ordinal);
        Assert.DoesNotContain("throw \"Writable by", module, StringComparison.Ordinal);
    }

    /// <summary>A capability SID: S-1-15-3-1024 and the SHA-256 of the upper-case name, as eight words.</summary>
    private static string CapabilitySid(string name)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.Unicode.GetBytes(name.ToUpperInvariant()));
        var words = Enumerable.Range(0, 8).Select(i => BitConverter.ToUInt32(hash, i * 4));
        return "S-1-15-3-1024-" + string.Join('-', words);
    }

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
