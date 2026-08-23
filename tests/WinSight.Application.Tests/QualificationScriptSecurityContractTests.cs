using Xunit;

namespace WinSight.Application.Tests;

public sealed class QualificationScriptSecurityContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void TrustBoundaryNeverInterpolatesOperatorPathsIntoCmd()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Test-TrustBoundary.ps1"));

        Assert.DoesNotContain("cmd /c", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("mklink", script, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rmdir", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("New-Item -ItemType Junction", script, StringComparison.Ordinal);
        Assert.Contains("[IO.Directory]::Delete($item.FullName, $false)", script, StringComparison.Ordinal);
    }

    [Fact]
    public void TrustBoundaryRefusesPreexistingOrBroadCleanupTargets()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Test-TrustBoundary.ps1"));

        Assert.Contains("Refusing to reuse a cleanup-owned directory that already exists", script, StringComparison.Ordinal);
        Assert.Contains("$scratch -cne $scratchRootPath", script, StringComparison.Ordinal);
        Assert.Contains("-not (Test-Path -LiteralPath $scratch)", script, StringComparison.Ordinal);
        Assert.Contains("-not $candidate.StartsWith($scratch", script, StringComparison.Ordinal);
    }

    [Fact]
    public void InnoCompilerReuseRequiresPinnedPublisherAndVersion()
    {
        var script = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Install-InnoSetup.ps1"));

        Assert.Contains("Test-ExpectedPublisher $compiler", script, StringComparison.Ordinal);
        Assert.Contains("Test-ExpectedPublisher $uninstaller", script, StringComparison.Ordinal);
        Assert.Contains("ProductVersion.Trim() -ceq $version", script, StringComparison.Ordinal);
        Assert.Contains("[guid]::NewGuid().ToString('N')", script, StringComparison.Ordinal);
        Assert.Contains("Resolve-Path -LiteralPath $compiler", script, StringComparison.Ordinal);
    }
}
