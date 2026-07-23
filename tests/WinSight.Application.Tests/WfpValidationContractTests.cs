using System.Diagnostics;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// Executes the deterministic fake-operations branches of the VM-only WFP validation workflow.
/// </summary>
public sealed class WfpValidationContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact(Timeout = 30000)]
    public async Task ContractSelfTestPassesAndLifecyclePollNegativeControlFails()
    {
        var normal = await RunContractAsync(negativeControl: false);

        Assert.True(normal.ExitCode == 0, FormatFailure("Normal contract", normal));
        Assert.Contains("[CONTRACT-SELFTEST PASS] 24 checks", normal.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("NATIVE-NORMALIZED-MARKER", normal.StandardOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("[FAIL]", normal.StandardOutput, StringComparison.Ordinal);

        var negative = await RunContractAsync(negativeControl: true);

        Assert.NotEqual(0, negative.ExitCode);
        Assert.Contains("[CONTRACT-SELFTEST FAIL]", negative.StandardOutput, StringComparison.Ordinal);
        Assert.Contains(
            "[FAIL] skip traverses production adapter primitive calls with 16 checks",
            negative.StandardOutput,
            StringComparison.Ordinal);
        Assert.DoesNotContain("operation-threw", negative.StandardOutput, StringComparison.Ordinal);
    }

    private static async Task<ContractProcessResult> RunContractAsync(bool negativeControl)
    {
        var script = Path.Combine(RepositoryRoot, "scripts", "Test-WfpValidation.ps1");
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
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(script);
        start.ArgumentList.Add("-ContractSelfTest");
        if (negativeControl) start.ArgumentList.Add("-ContractNegativeControl");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25));
        return new ContractProcessResult(process.ExitCode, await stdoutTask, await stderrTask);
    }

    private static string FormatFailure(string label, ContractProcessResult result) =>
        $"{label} failed with exit {result.ExitCode}.{Environment.NewLine}" +
        $"stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}" +
        $"stderr:{Environment.NewLine}{result.StandardError}";

    private sealed record ContractProcessResult(int ExitCode, string StandardOutput, string StandardError);
}
