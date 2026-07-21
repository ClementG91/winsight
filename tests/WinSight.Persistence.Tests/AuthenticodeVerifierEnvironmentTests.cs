using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// These tests change a process-wide environment variable, so they must not run beside anything
/// that verifies a signature at the same time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class VerifierEnvironmentCollection
{
    public const string Name = "verifier-environment";
}

/// <summary>
/// Pins the child PowerShell against a hostile inherited environment.
/// </summary>
/// <remarks>
/// This guards a real defect rather than a hypothetical one. The verifier shells out to Windows
/// PowerShell, and a child inherits the parent's environment — including PSModulePath. Launched
/// from a PowerShell 7 session it pointed at PS7's modules, Windows PowerShell 5.1 then failed to
/// import Microsoft.PowerShell.Security, and Get-AuthenticodeSignature simply did not exist. The
/// command produced no output, so every file came back Unknown.
///
/// That failure is invisible twice over: Unknown is deliberately never treated as suspicious, and
/// the child's stderr is discarded. On one machine it turned 450 kernel drivers into 269 trusted /
/// 177 unknown, hiding two genuinely unsigned drivers — while the scan looked perfectly healthy.
/// A test that only ran in a clean environment would never have caught it, which is why this one
/// deliberately pollutes the variable first.
/// </remarks>
[Collection(VerifierEnvironmentCollection.Name)]
public sealed class AuthenticodeVerifierEnvironmentTests
{
    private const string ModulePathVariable = "PSModulePath";

    // A signed binary present on every Windows install, so the assertion is about the verifier
    // running at all rather than about which file was chosen.
    private static readonly string SignedSystemBinary = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");

    [Fact]
    public void VerifiesSignedFiles_EvenWhenLaunchedFromAPowerShell7Session()
    {
        Assert.True(File.Exists(SignedSystemBinary), $"Missing {SignedSystemBinary}");
        using var polluted = new TemporaryEnvironmentVariable(
            ModulePathVariable,
            // What a PowerShell 7 session actually exports, which is what broke it.
            @"C:\Program Files\PowerShell\Modules;c:\program files\powershell\7\Modules;"
                + Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "WindowsPowerShell", "v1.0", "Modules"));

        var verdict = new AuthenticodeVerifier().Verify(SignedSystemBinary);

        Assert.NotEqual(SignatureState.Unknown, verdict.State);
    }

    [Fact]
    public void VerifiesSignedFiles_EvenWithNoModulePathAtAll()
    {
        // The other end of the same problem: an environment that names no module directory must
        // not leave the child unable to find its own inbox modules.
        Assert.True(File.Exists(SignedSystemBinary), $"Missing {SignedSystemBinary}");
        using var polluted = new TemporaryEnvironmentVariable(ModulePathVariable, null);

        var verdict = new AuthenticodeVerifier().Verify(SignedSystemBinary);

        Assert.NotEqual(SignatureState.Unknown, verdict.State);
    }

    private sealed class TemporaryEnvironmentVariable : IDisposable
    {
        private readonly string _name;
        private readonly string? _original;

        public TemporaryEnvironmentVariable(string name, string? value)
        {
            _name = name;
            _original = Environment.GetEnvironmentVariable(name);
            Environment.SetEnvironmentVariable(name, value);
        }

        public void Dispose() => Environment.SetEnvironmentVariable(_name, _original);
    }
}
