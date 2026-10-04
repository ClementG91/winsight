using System.Diagnostics;
using System.Text;

using Xunit;

namespace WinSight.Application.Tests;

public sealed class AutonomousNetworkQualificationTests
{
    private static readonly string Harness = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "scripts", "validation", "hyperv"));

    private const string RunnerFunctions = """
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $harness 'WinSightQualRunner.ps1'), [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw 'Runner parse failed' }
        foreach ($name in 'Get-Field', 'Get-Arguments') {
            $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
            Invoke-Expression $function.Extent.Text
        }
        """;

    [Fact]
    public async Task AutomaticRequestSelectsNonInteractiveCredentialMode()
    {
        await Run(RunnerFunctions + """

            $arguments = Get-Arguments ([pscustomobject]@{ action = 'network'; runName = 'unit-network'; credentialMode = 'automatic' })
            if ('-AutomaticCredential' -notin $arguments) { throw 'ASSERT: automatic network request did not select noninteractive credentials' }
            if (@($arguments | Where-Object { $_ -match 'Password|Secret' }).Count) { throw 'ASSERT: secret argument exposed' }
            """);
    }

    [Theory]
    [InlineData("'unknown'")]
    [InlineData("@('automatic','interactive')")]
    [InlineData("42")]
    [InlineData("$null")]
    public async Task MalformedCredentialModeIsRejected(string value)
    {
        await Run(RunnerFunctions + $$"""

            $rejected = $false
            try { $null = Get-Arguments ([pscustomobject]@{ action = 'network'; runName = 'unit-network'; credentialMode = {{value}} }) }
            catch { $rejected = $true }
            if (-not $rejected) { throw 'ASSERT: malformed credentialMode accepted' }
            """);
    }

    [Fact]
    public async Task MissingModeKeepsInteractiveDefault()
    {
        await Run(RunnerFunctions + """

            foreach ($request in @(
                [pscustomobject]@{ action = 'network'; runName = 'unit-network' },
                [pscustomobject]@{ action = 'network'; runName = 'unit-network'; credentialMode = 'interactive' })) {
                if ('-AutomaticCredential' -in (Get-Arguments $request)) { throw 'ASSERT: interactive default changed' }
            }
            """);
    }

    [Fact]
    public async Task GeneratedFixturesUseDistinctStrongPasswordsAndRoundTrip()
    {
        await ModuleRun("""
            $first = New-NetworkProbeEnvelope
            $second = New-NetworkProbeEnvelope
            $one = ConvertFrom-NetworkProbeEnvelope $first
            $two = ConvertFrom-NetworkProbeEnvelope $first
            $other = ConvertFrom-NetworkProbeEnvelope $second
            try {
                $plain = $one.GetNetworkCredential().Password
                if ($one.UserName -cne 'WinSightNetworkProbe' -or $plain.Length -lt 48) { throw 'ASSERT: wrong user or short password' }
                foreach ($pattern in '[A-Z]', '[a-z]', '[0-9]', '[^A-Za-z0-9]') {
                    if ($plain -cnotmatch $pattern) { throw 'ASSERT: password complexity' }
                }
                if ($plain -cne $two.GetNetworkCredential().Password) { throw 'ASSERT: roundtrip mismatch' }
                if ($plain -ceq $other.GetNetworkCredential().Password) { throw 'ASSERT: reused password' }
                if ($first.Contains($plain)) { throw 'ASSERT: plaintext in fixture' }
            }
            finally { $plain = $null; $one.Password.Dispose(); $two.Password.Dispose(); $other.Password.Dispose() }
            """);
    }

    [Theory]
    [InlineData("$bad.user = 'Administrator'")]
    [InlineData("$bad.version = 2")]
    [InlineData("$bad.key = [Convert]::ToBase64String([byte[]]::new(16))")]
    [InlineData("$bad.cipher = 'not-an-encrypted-password'")]
    [InlineData("$bad | Add-Member -NotePropertyName unexpected -NotePropertyValue 'hidden'")]
    public async Task InvalidFixtureFailsWithRedactedError(string mutation)
    {
        await ModuleRun($$"""
            $bad = New-NetworkProbeEnvelope | ConvertFrom-Json
            {{mutation}}
            $rejected = $false
            try { $null = ConvertFrom-NetworkProbeEnvelope ($bad | ConvertTo-Json -Compress) }
            catch {
                $rejected = $true
                if ($_.Exception.Message -cne 'Invalid disposable credential fixture.') { throw 'ASSERT: credential parser exposed input or internal error' }
            }
            if (-not $rejected) { throw 'ASSERT: malformed fixture accepted' }
            """);
    }

    [Fact]
    public async Task OversizedFixtureAndUnprotectedFilesAreRefused()
    {
        await ModuleRun("""
            $rejected = $false
            try { $null = ConvertFrom-NetworkProbeEnvelope ('x' * 4097) } catch { $rejected = $true }
            if (-not $rejected) { throw 'ASSERT: oversized fixture accepted' }
            $directory = Join-Path ([IO.Path]::GetTempPath()) ('winsight-net-unit-' + [Guid]::NewGuid().ToString('N'))
            [void][IO.Directory]::CreateDirectory($directory)
            $path = Join-Path $directory 'network-credential.json'
            try {
                [IO.File]::WriteAllText($path, (New-NetworkProbeEnvelope))
                $rejected = $false
                try { $null = Receive-NetworkProbeCredential -Path $path } catch { $rejected = $true }
                if (-not $rejected) { throw 'ASSERT: ordinary-user-owned fixture accepted' }
                if (-not [IO.File]::Exists($path)) { throw 'ASSERT: refusal deleted an untrusted file' }
            }
            finally { [IO.File]::Delete($path); [IO.Directory]::Delete($directory) }
            """);
    }

    [Fact]
    public void HostAndGuestsKeepActualNetworkAuthenticationAndSecretCleanup()
    {
        var host = File.ReadAllText(Path.Combine(Harness, "Invoke-HyperVNetworkLogon.ps1"));
        var target = File.ReadAllText(Path.Combine(Harness, "guest", "qualify.ps1"));
        var control = File.ReadAllText(Path.Combine(Harness, "guest", "control-network-logon.ps1"));
        Assert.Contains("SwitchType -ne 'Private'", host, StringComparison.Ordinal);
        Assert.Contains("Remove-NetworkProbeFixture", host, StringComparison.Ordinal);
        Assert.Contains("Receive-NetworkProbeCredential", target, StringComparison.Ordinal);
        Assert.Contains("Receive-NetworkProbeCredential", control, StringComparison.Ordinal);
        Assert.Contains("-UseSSL -Authentication Basic", control, StringComparison.Ordinal);
        Assert.Contains("-NetworkLogon", control, StringComparison.Ordinal);
        Assert.Contains("Result: 7 checks, 0 failure(s).", control, StringComparison.Ordinal);
    }

    private static async Task ModuleRun(string script)
    {
        var module = Path.Combine(Harness, "guest", "NetworkProbeCredential.psm1");
        Assert.True(File.Exists(module), "Disposable credential helper is missing");
        await Run("Import-Module (Join-Path $harness 'guest\\NetworkProbeCredential.psm1') -Force\n" + script);
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
        start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "Modules");
        start.Environment["WINSIGHT_TEST_HARNESS"] = Harness;
        var command = "$ErrorActionPreference = 'Stop'; $harness = $env:WINSIGHT_TEST_HARNESS; " + script;
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        Assert.True(process.ExitCode == 0, $"PowerShell assertion failed: {await output}\n{await error}");
    }
}
