using System.Diagnostics;
using System.Text;

using Xunit;
using Xunit.Abstractions;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed class QualificationLifecycleTests(ITestOutputHelper output)
{
    private static readonly string Harness = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
        "..", "..", "..", "..", "..", "scripts", "validation", "hyperv"));

    [Fact]
    public async Task FirstDetachFailureStillAttemptsSecondDetach()
    {
        await Run("Invoke-HyperVNetworkLogon.ps1", "Remove-DataDisks", """
            $Name = 'target'; $ControlName = 'control'; $data = 'target-disk'; $controlData = 'control-disk'
            $script:calls = @()
            function Remove-WinSightDataDisk($VMName, $Path) {
                $script:calls += $VMName
                if ($VMName -eq 'target') { throw 'injected' }
                return $null
            }
            function Write-HostLog($Message) {}
            $failed = $false
            try { Remove-DataDisks } catch { $failed = $true }
            if ('control' -notin $script:calls) { throw 'ASSERT: second detach never attempted' }
            if (-not $failed) { throw 'ASSERT: detach failure was hidden' }
            """);
    }

    [Fact]
    public async Task MissingShellIconUsesExistingGuestOperatorForExactlyRequestedProcess()
    {
        await TrayRun("""
            $result = Invoke-TrayExit @([int]4242)
            if (-not $result -or $script:calledPid -ne 4242 -or $script:calledName -cne 'TRAYEXIT') { throw 'ASSERT: existing operator fallback was not selected for exact requested PID' }
            """, failOperator: false);
    }

    [Fact]
    public async Task FailedOperatorFallbackDoesNotClaimGracefulExit()
    {
        await TrayRun("""
            if (Invoke-TrayExit @([int]4242)) { throw 'ASSERT: failed operator fallback accepted' }
            """, failOperator: true);
    }

    [Theory]
    [InlineData("@([int]0)")]
    [InlineData("@([int]4242,[int]4243)")]
    public async Task AmbiguousOrInvalidTargetCannotSelectAnyDashboard(string ids)
    {
        await TrayRun($$"""
            if (Invoke-TrayExit {{ids}}) { throw 'ASSERT: ambiguous/invalid target accepted' }
            if ($script:calledPid) { throw 'ASSERT: operator selected an unintended process' }
            """, failOperator: false);
    }

    [Fact]
    public void HostBackgroundDriverIsHiddenAndTrayMenuSupportsProductLanguages()
    {
        var runner = File.ReadAllText(Path.Combine(Harness, "WinSightQualRunner.ps1"));
        Assert.Contains("-WindowStyle Hidden -PassThru", runner, StringComparison.Ordinal);
        var automation = File.ReadAllText(Path.Combine(Harness, "guest", "operator-automation.ps1"));
        foreach (var label in new[] { "Exit", "Quitter", "Salir" })
        {
            Assert.Contains($"'{label}'", automation, StringComparison.Ordinal);
        }
    }

    private Task TrayRun(string assertions, bool failOperator)
    {
        return Run("guest/qualify.ps1", "Invoke-TrayExit", $$"""
            # The UIA types are loaded for enum constants only; RootElement is a synthetic empty tree.
            Add-Type -AssemblyName UIAutomationTypes, UIAutomationClient
            Add-Type 'public static class MockUia { public static object RootElement; public static string ControlTypeProperty = "type"; public static string ClassNameProperty = "class"; public static string ProcessIdProperty = "pid"; public static string NameProperty = "name"; } public enum MockScope { Children, Descendants }'
            $tree = New-Object PSObject
            $tree | Add-Member ScriptMethod FindAll { param($Scope,$Condition) return @() }
            $tree | Add-Member ScriptMethod FindFirst { param($Scope,$Condition) return $this }
            [MockUia]::RootElement = $tree; $UIA = [MockUia]; $Scope = [MockScope]
            function New-Condition($Property,$Value) { return $null }
            $Share = Join-Path ([IO.Path]::GetTempPath()) ('winsight-tray-route-' + [Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($Share)
            $script:calledPid = 0; $script:calledName = $null
            $fixture = Join-Path $Share 'operator-automation.ps1'
            [IO.File]::WriteAllText($fixture, 'param($Name,$ProcessId) $script:calledPid = $ProcessId; $script:calledName = $Name; {{(failOperator ? "throw ''injected''" : "")}}')
            try {
                {{assertions}}
            }
            finally { [IO.File]::Delete($fixture); [IO.Directory]::Delete($Share) }
            """);
    }

    private async Task Run(string file, string function, string script)
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
        start.Environment["WINSIGHT_LIFECYCLE_SOURCE"] = Path.Combine(Harness, file);
        start.Environment["WINSIGHT_LIFECYCLE_FUNCTION"] = function;
        var command = PowerShellProcessEvidence.Prelude + """
            $ErrorActionPreference = 'Stop'; $tokens = $null; $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($env:WINSIGHT_LIFECYCLE_SOURCE, [ref]$tokens, [ref]$errors)
            if ($errors.Count) { throw 'Parse failed' }
            Write-TestPhase 'parsed'
            $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $env:WINSIGHT_LIFECYCLE_FUNCTION }, $true)
            Invoke-Expression $definition.Extent.Text
            if ($env:WINSIGHT_LIFECYCLE_FUNCTION -eq 'Invoke-TrayExit') {
                $shell = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-ShellTrayExit' }, $true)
                if ($shell) { Invoke-Expression $shell.Extent.Text }
            }
            Write-TestPhase 'definitions-loaded'
            Write-TestPhase 'body-begin'
            """ + "\n" + script + PowerShellProcessEvidence.BodyEnd;
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.True(result.ExitCode == 0, $"PowerShell assertion failed: {result.Stdout}\n{result.Stderr}");
    }
}
