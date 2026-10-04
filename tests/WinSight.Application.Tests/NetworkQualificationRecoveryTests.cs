using System.Diagnostics;
using System.Text;

using Xunit;

namespace WinSight.Application.Tests;

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
    public async Task FailurePathsGuaranteeCheckpointRestorationInFinally()
    {
        await Run("""
            $protected = @($ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.TryStatementAst] -and $node.Finally -and
                $node.Body.Extent.Text.Contains('Remove-StagedNetworkFixtures') -and
                $node.Finally.Extent.Text.Contains('Restore-BothVms')
            }, $true))
            if ($protected.Count -lt 3) { throw 'ASSERT: staging, start-failure and collection cleanup need independent finally restoration' }
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
            foreach ($functionName in 'Remove-StagedNetworkFixtures', 'Restore-BothVms') {
                $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $true)
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
