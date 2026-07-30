using System.Diagnostics;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>Runs the deterministic CFA provider contract fixtures under Windows PowerShell 5.1.</summary>
public sealed class CfaProviderContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    /// <summary>
    /// The budget is a safety net against a hung harness, not an assertion about how fast a runner is.
    /// </summary>
    /// <remarks>
    /// It was 90 seconds outer and 75 inner, sized when the live cases gave up after one second each.
    /// Raising the process-tree cases to eight seconds - so a cold Arm64 runner has time to start the
    /// child whose termination the case exists to prove - added fourteen seconds to a harness that
    /// also compiles a helper executable and launches Windows PowerShell once per fixture, mutation
    /// and live case. On the slowest image in the fleet that crossed 75 seconds, and one timeout was
    /// traded for another. These are sized with margin instead: a genuinely hung harness still fails,
    /// while a slow machine no longer does.
    /// </remarks>
    [Fact(Timeout = 300000)]
    public async Task FixtureContractPassesUnderProtectedWindowsPowerShell51()
    {
        var shell = Path.Combine(
            Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        Assert.True(File.Exists(shell),
            $"Windows PowerShell 5.1 is required to validate the CFA provider contract and was not found at: {shell}");

        var script = Path.Combine(
            RepositoryRoot,
            "tests",
            "WinSight.Application.Tests",
            "CfaProviderFixtures",
            "Test-CfaProvider.Contract.ps1");
        Assert.True(File.Exists(script), $"Missing CFA provider contract script: {script}");

        var start = new ProcessStartInfo(shell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(script);

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start Windows PowerShell 5.1.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(240));
        }
        catch (TimeoutException)
        {
            await TerminateProcessTreeAndDrainStreamsAsync(process, stdoutTask, stderrTask);
            throw new TimeoutException("CFA provider fixture contract exceeded its 240-second harness timeout; the harness process tree was terminated.");
        }

        var stdout = await ReadStreamWithinAsync(stdoutTask, process.StandardOutput, "stdout");
        var stderr = await ReadStreamWithinAsync(stderrTask, process.StandardError, "stderr");

        Assert.True(process.ExitCode == 0,
            $"CFA provider fixture contract failed with exit {process.ExitCode}.{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
        Assert.Contains("CFA provider contract fixtures: 30/30 passed; 26/26 AC107 mutation checks passed; 7/7 live CliPath checks passed.", stdout, StringComparison.Ordinal);
    }

    private static async Task<string> ReadStreamWithinAsync(Task<string> readTask, StreamReader stream, string streamName)
    {
        try
        {
            return await readTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (TimeoutException)
        {
            stream.Close();
            throw new TimeoutException($"CFA provider fixture contract {streamName} did not drain within five seconds after the harness exited.");
        }
    }

    private static async Task TerminateProcessTreeAndDrainStreamsAsync(
        Process process,
        Task<string> stdoutTask,
        Task<string> stderrTask)
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }

        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (TimeoutException)
        {
            // The outer xUnit timeout remains a final guard if Windows cannot reap the harness process tree.
        }

        process.StandardOutput.Close();
        process.StandardError.Close();

        try
        {
            await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception) when (stdoutTask.IsCompleted && stderrTask.IsCompleted)
        {
            // Closing redirected readers can make the pending read tasks fault; their completion is the cleanup requirement.
        }
    }
}
