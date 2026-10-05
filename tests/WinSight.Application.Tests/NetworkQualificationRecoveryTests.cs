using System.Diagnostics;
using System.Text;

using Xunit;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed class NetworkQualificationRecoveryTests
{
    private static readonly string Driver = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
        "..", "..", "..", "..", "..", "scripts", "validation", "hyperv", "Invoke-HyperVNetworkLogon.ps1"));

    [Theory]
    [InlineData("mount")]
    [InlineData("remove")]
    [InlineData("dismount")]
    public async Task FailureOnFirstDiskStillAttemptsSecondDisk(string failure)
    {
        await Run($$"""
            $data = 'target'; $controlData = 'control'
            $script:calls = @()
            function Mount-WinSightData($disk) {
                $script:calls += "mount:$disk"
                if ($disk -eq 'target' -and '{{failure}}' -eq 'mount') { throw 'injected' }
                if ($disk -eq 'target') { return 'W' }; return 'T'
            }
            function Remove-NetworkProbeFixture($Path) {
                if ($Path -like 'W:*' -and '{{failure}}' -eq 'remove') { throw 'injected' }
            }
            function Dismount-WinSightData($disk) {
                if ($disk -eq 'target' -and '{{failure}}' -eq 'dismount') { throw 'injected' }
            }
            $failed = $false
            try { Remove-StagedNetworkFixtures } catch { $failed = $true }
            if ('mount:control' -notin $script:calls) { throw 'ASSERT: second disk cleanup never attempted' }
            if (-not $failed) { throw 'ASSERT: cleanup failure was hidden' }
            """);
    }

    [Fact]
    public async Task FailureOnFirstCheckpointStillAttemptsSecondCheckpoint()
    {
        await Run("""
            $Name = 'target'; $ControlName = 'control'; $Checkpoint = 'S0'; $ControlCheckpoint = 'C0'
            $originalAdapters = @(); $originalMemory = 0; $originalControlMemory = 0
            $script:restored = @()
            function Restore-VMCheckpoint($VMName, $Name, $Confirm) {
                $script:restored += $VMName
                if ($VMName -eq 'target') { throw 'injected' }
            }
            function Get-VMNetworkAdapter($VMName) { return @() }
            function Invoke-WinSightVmRetry($Operation) { & $Operation }
            $failed = $false
            try { Restore-BothVms } catch { $failed = $true }
            if ('control' -notin $script:restored) { throw 'ASSERT: second checkpoint restore never attempted' }
            if (-not $failed) { throw 'ASSERT: checkpoint failure was hidden' }
            """);
    }

    [Fact]
    public async Task StagingAndStartFailuresAttemptRestorationWithoutMaskingTheirCause()
    {
        await Run("""
            $protected = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CatchClauseAst] -and
                ($node.Parent.Body.Extent.Text.Contains('Clear-WinSightDataVolume') -or
                $node.Parent.Body.Extent.Text.Contains('Start-VM'))
            }, $true))
            if ($protected.Count -ne 2) { throw 'ASSERT: staging and start recovery boundaries missing' }
            $AutomaticCredential=$true
            function Write-HostLog($Message) {}
            function Remove-DataDisks {throw 'secondary detach failure'}
            function Remove-StagedNetworkFixtures {throw 'secondary fixture cleanup failure'}
            function Restore-BothVms {$script:restores++}
            foreach ($clause in $protected) {
                $script:restores=0
                $injected=[IO.IOException]::new('primary cause')
                $caught=$null
                try {Invoke-Expression ('try {throw $injected} '+$clause.Extent.Text)} catch {$caught=$_}
                if ($script:restores -ne 1) {throw 'ASSERT: restoration skipped after cleanup failure'}
                if (-not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: recovery masked the primary failure'}
            }
            """);
    }

    private static async Task Run(string script)
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
        start.Environment["WINSIGHT_RECOVERY_DRIVER"] = Driver;
        var command = """
            $ErrorActionPreference = 'Stop'
            $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($env:WINSIGHT_RECOVERY_DRIVER, [ref]$tokens, [ref]$errors)
            if ($errors.Count) { throw 'Driver parse failed' }
            foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                Invoke-Expression $definition.Extent.Text
            }
            """ + "\n" + script;
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        Assert.True(process.ExitCode == 0, $"PowerShell assertion failed: {await stdout}\n{await stderr}");
    }
}
