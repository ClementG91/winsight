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

    /// <summary>
    /// The VM storage seal hashes through every sharing mode and names a file it cannot open, instead
    /// of failing a protection that is already complete.
    /// </summary>
    /// <remarks>
    /// Found at the fourth storage protection: the storage was protected, then Get-FileHash met the
    /// configuration file of a checkpoint that the Hyper-V management service keeps open while the VM is
    /// off, and the seal was never written.
    /// </remarks>
    [Fact]
    public void TheStorageSealReadsFilesHyperVKeepsOpen()
    {
        var protect = Code(Path.Combine(Harness, "Protect-WinSightVmStorage.ps1"));
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));

        Assert.DoesNotContain("Get-FileHash", protect, StringComparison.Ordinal);
        Assert.Contains("Get-SharedFileHash -Path $disk", protect, StringComparison.Ordinal);
        Assert.Contains("held open by another process, not hashed", protect, StringComparison.Ordinal);
        Assert.Contains("([System.IO.FileShare]'ReadWrite, Delete')", module, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every elevated harness script makes Administrators the default owner of what it creates, before
    /// it creates anything.
    /// </summary>
    /// <remarks>
    /// On client Windows an elevated process creates files owned by the operator's own account (the
    /// "Object creator" default): the 400 files the first runner wrote are all owned by it. An owner may
    /// always re-permission, so any process running as the operator could have changed a protected copy
    /// or the sealed evidence - which the provenance check, testing only that a write is refused, would
    /// not have seen.
    /// </remarks>
    [Fact]
    public void ElevatedScriptsCreateFilesOwnedByAdministrators()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        Assert.Contains("function Set-AdministratorsDefaultOwner", module, StringComparison.Ordinal);
        Assert.Contains("SetTokenInformation(token, 4, ref owner, System.IntPtr.Size)", module, StringComparison.Ordinal);

        var elevated = Directory.GetFiles(Harness, "*.ps1")
            .Where(path => File.ReadAllText(path).Contains("#Requires -RunAsAdministrator", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(6, elevated.Length);
        foreach (var path in elevated)
        {
            var code = Code(path);
            var import = code.IndexOf("Import-Module", StringComparison.Ordinal);
            var owner = code.IndexOf("\nSet-AdministratorsDefaultOwner\n", StringComparison.Ordinal);
            Assert.True(import >= 0 && owner > import, $"{Path.GetFileName(path)} does not set the default owner after importing the module");
            foreach (var write in new[] { "New-ProtectedDirectory", "Set-Content", "Add-Content", "Add-SharedLine", "Write-SharedText", "Copy-ListedFile", "Copy-Item", "Copy-GuestResults", "icacls" })
            {
                var first = code.IndexOf(write, StringComparison.Ordinal);
                Assert.True(first < 0 || first > owner, $"{Path.GetFileName(path)} uses {write} before setting the default owner");
            }
        }
    }

    /// <summary>
    /// A run ends once: the guest marks its disk done before shutting down and shuts down at once if
    /// started again, and the host detaches the data disk only when the VM is really off, turning off a
    /// VM that was started again rather than failing with the results uncollected.
    /// </summary>
    /// <remarks>
    /// Found in the first full run: the guest shut itself down after 121 minutes, then detaching the data
    /// disk failed ("cannot be performed while the object is in its current state"), the driver stopped
    /// without collecting, and the VM, started again with its disk still saying "qualify", ran every gate
    /// again over the results. The next run was refused as well: restoring the checkpoint had created a
    /// differencing disk owned by the VM's own identity.
    /// </remarks>
    [Fact]
    public void ARunEndsOnceAndIsAlwaysCollected()
    {
        var guest = Code(Path.Combine(Harness, "guest", "run-guest-checks.ps1"));
        Assert.Contains("'done' {", guest, StringComparison.Ordinal);
        Assert.Contains("Set-Content -LiteralPath '$modeFile' -Value 'done'; Stop-Computer -Force", guest, StringComparison.Ordinal);

        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        Assert.Contains("function Remove-WinSightDataDisk", module, StringComparison.Ordinal);
        Assert.Contains("Stop-VM -Name $VMName -TurnOff -Force", module, StringComparison.Ordinal);
        foreach (var name in new[] { "Invoke-HyperVQualification.ps1", "Invoke-HyperVNetworkLogon.ps1" })
        {
            var driver = Code(Path.Combine(Harness, name));
            Assert.DoesNotContain("Remove-VMHardDiskDrive", driver, StringComparison.Ordinal);
            Assert.Contains("Remove-WinSightDataDisk -VMName $Name -Path $data", driver, StringComparison.Ordinal);
        }

        Assert.Contains("function Test-TrustedOwner([string]$Sid, [switch]$VirtualMachines)", module, StringComparison.Ordinal);
        Assert.Contains("-not (Test-TrustedOwner $owner -VirtualMachines:$AllowVirtualMachines)", module, StringComparison.Ordinal);
    }

    /// <summary>
    /// The network run starts both VMs or neither. Before it changes anything, it checks that the host
    /// can hold both VMs, and it runs the control VM with less memory. If a start fails, it turns both
    /// VMs off and restores them. The runner passes the requested memory to it.
    /// </summary>
    /// <remarks>
    /// Found at the first network run: the target started, then the control could not get its 3 GB
    /// (Hyper-V 0x800705AA). The driver stopped there, and the target stayed on, on the private
    /// switch, with its run staged and nobody to collect it.
    /// </remarks>
    [Fact]
    public void ANetworkRunStartsBothVirtualMachinesOrNeither()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        Assert.Contains("function Assert-WinSightHostMemory([int64]$Bytes, [string]$Advice)", module, StringComparison.Ordinal);
        Assert.Contains("(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB", module, StringComparison.Ordinal);

        var driver = Code(Path.Combine(Harness, "Invoke-HyperVNetworkLogon.ps1"));
        var memory = driver.IndexOf("Assert-WinSightHostMemory -Bytes ($TargetMemoryBytes + $ControlMemoryBytes + 512MB)", StringComparison.Ordinal);
        // The first restore the run itself makes, at staging: a top-level line, not the helper's body.
        var staging = driver.IndexOf("\nRestore-VMCheckpoint", StringComparison.Ordinal);
        Assert.True(memory >= 0 && staging > memory, "the host memory is not checked before the VMs are touched");
        Assert.Contains("[int64]$ControlMemoryBytes = 2GB", driver, StringComparison.Ordinal);
        Assert.Contains("Set-VMMemory -VMName $ControlName -StartupBytes $ControlMemoryBytes", driver, StringComparison.Ordinal);

        // Both starts sit in one try, and its catch turns both VMs off and puts both back.
        Assert.Equal(2, Regex.Count(driver, @"\bStart-VM\b"));
        var guarded = Regex.Matches(driver, @"\ntry \{")
            .Select(match => Block(driver, match.Index))
            .Single(block => block.Contains("Start-VM -Name $Name\n", StringComparison.Ordinal)
                && block.Contains("Start-VM -Name $ControlName\n", StringComparison.Ordinal));
        var after = driver[(driver.IndexOf(guarded, StringComparison.Ordinal) + guarded.Length)..];
        Assert.StartsWith("\ncatch {", after, StringComparison.Ordinal);
        var recovery = Block(after, 0);
        Assert.Contains("Remove-DataDisks", recovery, StringComparison.Ordinal);
        Assert.Contains("Restore-BothVms", recovery, StringComparison.Ordinal);
        Assert.Contains("throw $failure", recovery, StringComparison.Ordinal);
        Assert.Contains("Set-VMMemory -VMName $ControlName -StartupBytes $originalControlMemory", driver, StringComparison.Ordinal);

        var runner = Code(Path.Combine(Harness, "WinSightQualRunner.ps1"));
        Assert.Contains("if ($action -in 'qualify', 'network') {", runner, StringComparison.Ordinal);
        Assert.Contains("'-TargetMemoryBytes'", runner, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Cloud Files gate counts against WinSight only the download requests that come from
    /// WinSight. The probe records which process asked for each request. A request the platform
    /// cannot attribute counts against WinSight.
    /// </summary>
    /// <remarks>
    /// Found at the first full run of the rebuilt harness: the persistence scan over a Run value naming
    /// a cloud-only file saw one download request. The signature verb reading the same file saw none,
    /// and the scan finished in 38 s, less than the minute a download request of its own would have
    /// blocked it for. The probe counted requests without saying who made them. It also started the
    /// scan the moment the Run value was written, when whatever reacts to a new Run value is still
    /// reacting.
    /// </remarks>
    [Fact]
    public void TheCloudFilesGateChargesWinSightOnlyWithItsOwnDownloads()
    {
        var probe = Code(Path.Combine(Harness, "..", "..", "Measure-CloudFilesAccess.ps1"));
        // CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO: without it the platform leaves ProcessInfo empty.
        Assert.Contains("private const uint RequireProcessInfo = 0x2;", probe, StringComparison.Ordinal);
        Assert.Contains("CfConnectSyncRoot(root, table, IntPtr.Zero, RequireProcessInfo, out key)", probe, StringComparison.Ordinal);
        Assert.Contains("public IntPtr ProcessInfo;", probe, StringComparison.Ordinal);
        Assert.Contains("function Get-FetchOwner", probe, StringComparison.Ordinal);
        Assert.Contains("runValueSettle", probe, StringComparison.Ordinal);

        var gate = Code(Path.Combine(Harness, "guest", "qualify.ps1"));
        gate = gate[gate.IndexOf("Invoke-Gate '17-cloud-files'", StringComparison.Ordinal)..];
        gate = gate[..gate.IndexOf("\nInvoke-Gate ", StringComparison.Ordinal)];
        Assert.DoesNotContain("fetchRequestsDuringRead -gt 0", gate, StringComparison.Ordinal);
        Assert.DoesNotContain("fetchRequestsDuringScan -ne 0", gate, StringComparison.Ordinal);
        foreach (var measured in new[] { "$scan", "$settle" })
        {
            Assert.Contains(
                $"[int]{measured}.fetchRequestsByWinSight -ne 0 -or [int]{measured}.fetchRequestsUnattributed -ne 0",
                gate,
                StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// After restoring the checkpoints, the network run retries its queries of the restored VMs, and
    /// the provenance check finds the results of a network run where it keeps them.
    /// </summary>
    /// <remarks>
    /// Found by the first network run of the rebuilt harness to pass (net-711ded0b: gate 36 10/10).
    /// The evidence was sealed, then the adapter query that followed the checkpoint restore failed
    /// ("the object was not found; it may have been deleted": Hyper-V rebuilds the VM's objects during
    /// a restore), and the run ended in error. The provenance check then stopped at its fourth check:
    /// it looked for results.json at the root of the run, where a network run keeps target\results.json.
    /// </remarks>
    [Fact]
    public void TheNetworkRunRetriesRestoredVmQueriesAndItsResultsCanBeVerified()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        Assert.Contains("function Invoke-WinSightVmRetry([scriptblock]$Action, [int]$Seconds = 60)", module, StringComparison.Ordinal);

        var driver = Code(Path.Combine(Harness, "Invoke-HyperVNetworkLogon.ps1"));
        var restore = Block(driver, driver.IndexOf("function Restore-BothVms", StringComparison.Ordinal));
        var queries = restore.Split('\n').Where(line => line.Contains("Get-VMNetworkAdapter", StringComparison.Ordinal)
            || line.Contains("Get-VMMemory", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(queries);
        Assert.All(queries, line => Assert.Contains("Invoke-WinSightVmRetry {", line, StringComparison.Ordinal));
        var restored = driver.Split('\n').Single(line => line.Contains("both VMs restored", StringComparison.Ordinal));
        Assert.Contains("Invoke-WinSightVmRetry {", restored, StringComparison.Ordinal);

        var verifier = Code(Path.Combine(Harness, "Verify-QualificationProvenance.ps1"));
        Assert.Contains("'target\\results.json'", verifier, StringComparison.Ordinal);
        Assert.DoesNotContain("Get-Content -LiteralPath (Join-Path $RunDir 'results.json')", verifier, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Cloud Files probe fails each download request at once, over the whole file, so no request
    /// stays pending and every read, by any process, arrives as a request of its own.
    /// </summary>
    /// <remarks>
    /// Found in the first run with attribution (head-fe953fe): the requests came exactly 60 seconds
    /// apart, one at a time. The platform keeps one request per file and makes every other reader wait
    /// behind it without a callback of its own: the Win32 primitive waited 90 seconds and its window
    /// holds only a request from sihost.exe, which the probe left pending for a minute at a time. A read
    /// by WinSight during the scan, when such a request was pending throughout, would have been counted
    /// nowhere.
    /// </remarks>
    [Fact]
    public void TheCloudFilesProbeFailsEachDownloadRequestAtOnce()
    {
        var probe = Code(Path.Combine(Harness, "..", "..", "Measure-CloudFilesAccess.ps1"));
        Assert.Contains("public static extern int CfExecute(ref OperationInfo operation, ref TransferData transfer);", probe, StringComparison.Ordinal);
        Assert.Contains("public static void DescribeFailure(IntPtr info, out OperationInfo operation, out TransferData transfer)", probe, StringComparison.Ordinal);
        var callback = probe[probe.IndexOf("private static void OnFetch(", StringComparison.Ordinal)..];
        callback = callback[..callback.IndexOf("\n    }", StringComparison.Ordinal)];
        Assert.Contains("CfExecute(ref operation, ref transfer)", callback, StringComparison.Ordinal);
    }

    /// <summary>
    /// The files people read while a campaign runs are written with read sharing and retried: the
    /// runner's log, status and processed list, and the host operations log.
    /// </summary>
    /// <remarks>
    /// Found when the runner restarted for the third campaign: a <c>tail -F</c> kept its log open,
    /// and the next <c>Add-Content</c> failed ("used by another process"), which stopped the runner
    /// between two requests. Measured under Windows PowerShell 5.1: <c>Add-Content</c> and
    /// <c>Set-Content</c> fail while any other process holds the file open for reading, even one that
    /// shares writing. An operator following the log with <c>Get-Content -Wait</c> would do the same,
    /// and a driver writing the host operations log could stop between the guest's end and the
    /// collection.
    /// </remarks>
    [Fact]
    public void FilesReadDuringACampaignAreWrittenWithReadSharing()
    {
        var module = Code(Path.Combine(Harness, "WinSightHyperV.psm1"));
        Assert.Contains("function Write-SharedText(", module, StringComparison.Ordinal);
        Assert.Contains("function Add-SharedLine(", module, StringComparison.Ordinal);
        Assert.Contains("[IO.FileAccess]::Write, [IO.FileShare]::ReadWrite", module, StringComparison.Ordinal);

        Assert.All(HostScripts(), path => Assert.DoesNotContain("Add-Content", Code(path), StringComparison.Ordinal));
        var runner = Code(Path.Combine(Harness, "WinSightQualRunner.ps1"));
        Assert.Contains("Add-SharedLine -Path (Join-Path $runnerDir 'runner.log') -Line $line", runner, StringComparison.Ordinal);
        Assert.Contains("Add-SharedLine -Path $processedPath -Line $next.Name", runner, StringComparison.Ordinal);
        Assert.Contains("Write-SharedText -Path $statusPath -Text", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-Content -LiteralPath $statusPath", runner, StringComparison.Ordinal);
        foreach (var name in new[] { "Invoke-HyperVQualification.ps1", "Invoke-HyperVNetworkLogon.ps1" })
        {
            Assert.Contains("Add-SharedLine -Path $hostLog -Line $line", Code(Path.Combine(Harness, name)), StringComparison.Ordinal);
        }
    }

    /// <summary>The block whose braces balance, from the first brace at or after <paramref name="from"/>.</summary>
    private static string Block(string code, int from)
    {
        var open = code.IndexOf('{', from);
        var depth = 0;
        for (var index = open; index < code.Length; index++)
        {
            depth += code[index] switch { '{' => 1, '}' => -1, _ => 0 };
            if (depth == 0)
            {
                return code[open..(index + 1)];
            }
        }
        throw new InvalidOperationException("The braces do not balance.");
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
        var writes = Regex.Matches(runner, @"((Set-Content|Add-Content)\s+-LiteralPath|(Add-SharedLine|Write-SharedText)\s+-Path)\s+(?<target>[^\r\n]+)");
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
