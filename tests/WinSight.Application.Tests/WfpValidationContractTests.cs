using System.Diagnostics;
using System.Text;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Executes the deterministic fake-operations branches of the VM-only WFP validation workflow.
/// </summary>
public sealed class WfpValidationContractTests
{
    private static readonly TimeSpan ScriptProcessTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan TimedOutProcessTerminationTimeout = TimeSpan.FromSeconds(10);

    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    // The operator runs this script the way a human runs a script: `& 'C:\...\Test-WfpValidation.ps1'`
    // from an already-open elevated console. Only `-File` was ever exercised, and the two modes are
    // not equivalent - `-File` makes the script the top-level scope, while `&` gives it a child
    // scope whose functions a GetNewClosure() closure cannot resolve. On a real VM that difference
    // killed the protocol on its first output call, at "0 checks", while this suite stayed green at
    // 26/26. Both modes are now measured, because the mode nobody tested is the mode people use.
    [Theory(Timeout = 90000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ContractSelfTestPassesUnderBothInvocationModes(bool useCallOperator)
    {
        var normal = await RunContractAsync(negativeControl: false, useCallOperator);

        Assert.True(normal.ExitCode == 0, FormatFailure("Normal contract", normal));
        Assert.Contains("[CONTRACT-SELFTEST PASS] 26 checks", normal.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("[FAIL]", normal.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("n'est pas reconnu", normal.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("is not recognized", normal.StandardOutput, StringComparison.Ordinal);
    }

    // The contract self-test only ever builds scripted host effects, so New-RealHostEffects and the
    // real adapter closures were never executed by any test - which is how a closure that could not
    // resolve its own helper reached a VM and killed the protocol at "0 checks". This drives the real
    // adapter with a path that does not exist. The workflow emits its banner, runs the preconditions,
    // fails "candidate and protected tools exist" and stops - and every SCM operation lives strictly
    // after that check, so this stays safe even on an elevated CI runner.
    [Theory(Timeout = 90000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealAdapterReachesPreconditionsAndStopsBeforeAnyScmCall(bool useCallOperator)
    {
        var absent = Path.Combine(Path.GetTempPath(), "winsight-absent-candidate", "no-such-service.exe");
        Assert.False(File.Exists(absent), "This test requires a candidate path that does not exist.");

        var run = await RunScriptAsync(useCallOperator, "-ServicePath", absent);

        // Proof the real closures ran at all: without them the script dies before the banner.
        Assert.Contains("== WFP validation protocol ==", run.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("n'est pas reconnu", run.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("is not recognized", run.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("zero-output contract", run.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("Result: 0 checks", run.StandardOutput, StringComparison.Ordinal);

        // Stopped in the precondition block, so nothing downstream of it was reached.
        Assert.Contains(
            "preconditions failed before touching SCM or WFP.",
            run.StandardOutput,
            StringComparison.Ordinal);
        Assert.NotEqual(0, run.ExitCode);
    }

    // This case intentionally starts two independent PowerShell processes. Its outer timeout must
    // exceed two process budgets; otherwise a valid pair of slow runs can never finish in CI.
    [Fact(Timeout = 150000)]
    public async Task ContractSelfTestPassesAndLifecyclePollNegativeControlFails()
    {
        var normal = await RunContractAsync(negativeControl: false);

        Assert.True(normal.ExitCode == 0, FormatFailure("Normal contract", normal));
        Assert.Contains("[CONTRACT-SELFTEST PASS] 26 checks", normal.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("NATIVE-NORMALIZED-MARKER", normal.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("[FAIL]", normal.StandardOutput, StringComparison.Ordinal);

        var negative = await RunContractAsync(negativeControl: true);

        Assert.NotEqual(0, negative.ExitCode);
        Assert.Contains("[CONTRACT-SELFTEST FAIL]", negative.StandardOutput, StringComparison.Ordinal);
        Assert.Contains(
            "[FAIL] skip traverses production adapter primitive calls with 17 checks",
            negative.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain("operation-threw", negative.StandardOutput, StringComparison.Ordinal);
    }

    [Fact(Timeout = 90000)]
    public async Task ContractSelfTestFailsWhenExactScmAbsencePredicatesAreBroadened()
    {
        const string exactPredicate = "$query.ExitCode -eq 1060";
        const string broadenedPredicate = "$query.ExitCode -ne 0";
        var source = Path.Combine(RepositoryRoot, "scripts", "Test-WfpValidation.ps1");
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), "winsight-wfp-contract-" + Guid.NewGuid());
        var mutatedScript = Path.Combine(temporaryDirectory, "Test-WfpValidation.ps1");

        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            var script = await File.ReadAllTextAsync(source);
            Assert.Equal(2, CountOccurrences(script, exactPredicate));
            var mutated = script.Replace(exactPredicate, broadenedPredicate, StringComparison.Ordinal);
            Assert.Equal(0, CountOccurrences(mutated, exactPredicate));
            Assert.Equal(2, CountOccurrences(mutated, broadenedPredicate));
            await File.WriteAllTextAsync(mutatedScript, mutated, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var run = await RunScriptAtAsync(false, mutatedScript, "-ContractSelfTest");

            Assert.Equal(1, run.ExitCode);
            Assert.Contains("[CONTRACT-SELFTEST FAIL]", run.StandardOutput, StringComparison.Ordinal);
            Assert.DoesNotContain("operation-threw", run.StandardOutput, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory)) Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact(Timeout = 30000)]
    public async Task TimedOutContractTerminatesThePowerShellProcess()
    {
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), "winsight-wfp-timeout-" + Guid.NewGuid());
        var hangingScript = Path.Combine(temporaryDirectory, "Hang.ps1");
        var pidPath = Path.Combine(temporaryDirectory, "powershell.pid");

        Directory.CreateDirectory(temporaryDirectory);
        try
        {
            const string source = """
                [CmdletBinding()]
                param([Parameter(Mandatory = $true)][string]$PidPath)
                [IO.File]::WriteAllText($PidPath, [string]$PID)
                Start-Sleep -Seconds 300
                """;
            await File.WriteAllTextAsync(
                hangingScript,
                source,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var timeout = await Assert.ThrowsAsync<TimeoutException>(() =>
                RunScriptAtAsync(
                    useCallOperator: false,
                    hangingScript,
                    TimeSpan.FromSeconds(1),
                    "-PidPath",
                    pidPath));

            Assert.Contains("did not exit within 1 seconds (-File)", timeout.Message, StringComparison.Ordinal);
            Assert.True(File.Exists(pidPath), "The PowerShell process did not publish its PID before timeout.");
            var processId = int.Parse(await File.ReadAllTextAsync(pidPath), System.Globalization.CultureInfo.InvariantCulture);
            Assert.Throws<ArgumentException>(() => Process.GetProcessById(processId));
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory)) Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static Task<ContractProcessResult> RunContractAsync(
        bool negativeControl,
        bool useCallOperator = false) =>
        negativeControl
            ? RunScriptAsync(useCallOperator, "-ContractSelfTest", "-ContractNegativeControl")
            : RunScriptAsync(useCallOperator, "-ContractSelfTest");

    private static async Task<ContractProcessResult> RunScriptAsync(
        bool useCallOperator,
        params string[] scriptArguments) =>
        await RunScriptAtAsync(
            useCallOperator,
            Path.Combine(RepositoryRoot, "scripts", "Test-WfpValidation.ps1"),
            scriptArguments);

    private static async Task<ContractProcessResult> RunScriptAtAsync(
        bool useCallOperator,
        string script,
        params string[] scriptArguments) =>
        await RunScriptAtAsync(useCallOperator, script, ScriptProcessTimeout, scriptArguments);

    private static async Task<ContractProcessResult> RunScriptAtAsync(
        bool useCallOperator,
        string script,
        TimeSpan processTimeout,
        params string[] scriptArguments)
    {
        Assert.True(File.Exists(script), $"Missing WFP validation script: {script}");

        // Windows PowerShell 5.1 by absolute path, with no fallback. The point of this contract is
        // that the script parses and runs under 5.1 specifically - that is the shell where reading
        // an unmarked file as ANSI turned a smart quote into an unterminated string, and where
        // $ErrorActionPreference = 'Stop' plus 2>&1 turned native stderr into a terminating error.
        // Quietly running PowerShell 7 instead would let both defects ship behind a green test, and
        // resolving the shell from ambient PATH would decide which one at the mercy of the
        // environment. Absent 5.1, this test has to fail rather than measure something else.
        var shell = Path.Combine(
            Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        Assert.True(
            File.Exists(shell),
            $"Windows PowerShell 5.1 is required to validate this script and was not found at: {shell}");

        var start = new ProcessStartInfo(shell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        if (useCallOperator)
        {
            // How an operator actually runs it: `& 'C:\...\Test-WfpValidation.ps1' -ServicePath '...'`
            // from an already-open console. Single-quoted and doubled, so a path with a quote in it
            // cannot break out of the literal.
            // Parameter names must stay bare; only values are quoted, or PowerShell binds them
            // positionally instead of by name.
            var quoted = scriptArguments.Select(a =>
                a.StartsWith('-') ? a : $"'{a.Replace("'", "''")}'");
            start.ArgumentList.Add("-Command");
            start.ArgumentList.Add($"& '{script.Replace("'", "''")}' {string.Join(" ", quoted)}");
        }
        else
        {
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(script);
            foreach (var argument in scriptArguments) start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(processTimeout);
        }
        catch (TimeoutException)
        {
            // Disposing Process does not terminate it. Kill the whole tree so a hung PowerShell
            // contract cannot leak into sibling tests or keep the CI runner alive after failure.
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimedOutProcessTerminationTimeout);

            var timedOutStdout = await stdoutTask;
            var timedOutStderr = await stderrTask;
            var invocation = useCallOperator ? "call operator" : "-File";
            throw new TimeoutException(
                $"PowerShell contract {Path.GetFileName(script)} did not exit within " +
                $"{processTimeout.TotalSeconds:F0} seconds ({invocation})." +
                $"{Environment.NewLine}stdout:{Environment.NewLine}{timedOutStdout}" +
                $"{Environment.NewLine}stderr:{Environment.NewLine}{timedOutStderr}");
        }

        return new ContractProcessResult(process.ExitCode, await stdoutTask, await stderrTask);
    }

    private static int CountOccurrences(string value, string needle)
    {
        var count = 0;
        var start = 0;
        while ((start = value.IndexOf(needle, start, StringComparison.Ordinal)) >= 0)
        {
            count++;
            start += needle.Length;
        }
        return count;
    }

    private static string FormatFailure(string label, ContractProcessResult result) =>
        $"{label} failed with exit {result.ExitCode}.{Environment.NewLine}" +
        $"stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}" +
        $"stderr:{Environment.NewLine}{result.StandardError}";

    private sealed record ContractProcessResult(int ExitCode, string StandardOutput, string StandardError);
}
