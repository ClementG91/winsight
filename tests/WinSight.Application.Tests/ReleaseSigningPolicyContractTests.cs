using Xunit;

namespace WinSight.Application.Tests;

public sealed class ReleaseSigningPolicyContractTests
{
    private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public void ReleaseWorkflowRequiresAnExplicitBooleanSigningPolicy()
    {
        var workflow = File.ReadAllText(Path.Combine(
            RepositoryRoot, ".github", "workflows", "release.yml"));

        Assert.Contains(
            "$signingPolicy -notin @(\"true\", \"false\")",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "REQUIRE_SIGNED_RELEASE must be explicitly set to true or false.",
            workflow,
            StringComparison.Ordinal);
        Assert.Contains(
            "$requireSignature = $signingPolicy -eq \"true\"",
            workflow,
            StringComparison.Ordinal);
    }

    [Fact]
    public void UnsignedPolicyIsVisibleInTheReleaseSummary()
    {
        var workflow = File.ReadAllText(Path.Combine(
            RepositoryRoot, ".github", "workflows", "release.yml"));

        Assert.Contains("UNSIGNED RELEASE POLICY", workflow, StringComparison.Ordinal);
        Assert.Contains("REQUIRE_SIGNED_RELEASE=false", workflow, StringComparison.Ordinal);
        Assert.Contains("$env:GITHUB_STEP_SUMMARY", workflow, StringComparison.Ordinal);
        Assert.Contains("-RequireSignature:$requireSignature", workflow, StringComparison.Ordinal);
        Assert.Contains("-DisableSignature:(-not $requireSignature)", workflow, StringComparison.Ordinal);

        var buildScript = File.ReadAllText(Path.Combine(
            RepositoryRoot, "scripts", "Build-Release.ps1"));
        Assert.Contains("[switch]$DisableSignature", buildScript, StringComparison.Ordinal);
        Assert.Contains("$RequireSignature -and $DisableSignature", buildScript, StringComparison.Ordinal);
        Assert.Contains("-CertificateBase64 \"\" -CertificatePassword \"\"", buildScript, StringComparison.Ordinal);
        Assert.Equal(
            2,
            buildScript.Split(
                "-CertificateBase64 \"\" -CertificatePassword \"\"",
                StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void ReleaseTagIsDataAndMustPointToMain()
    {
        var workflow = File.ReadAllText(Path.Combine(
            RepositoryRoot, ".github", "workflows", "release.yml"));

        Assert.Contains("RELEASE_TAG: ${{ github.ref_name }}", workflow, StringComparison.Ordinal);
        Assert.Contains("RELEASE_SHA: ${{ github.sha }}", workflow, StringComparison.Ordinal);
        Assert.Contains("fetch-depth: 0", workflow, StringComparison.Ordinal);
        Assert.Contains("git merge-base --is-ancestor $env:RELEASE_SHA origin/main", workflow, StringComparison.Ordinal);
        Assert.Contains("Release tag does not point to a commit on main.", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("$version = \"${{ github.ref_name }}\"", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("$tagVersion = \"${{ github.ref_name }}\"", workflow, StringComparison.Ordinal);
        Assert.Contains("persist-credentials: false", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void PublisherAcceptsOnlyTheExactChecksummedReleaseSet()
    {
        var workflow = File.ReadAllText(Path.Combine(
            RepositoryRoot, ".github", "workflows", "release.yml"));

        Assert.Contains("Compare-Object $expected $actualArtifacts", workflow, StringComparison.Ordinal);
        Assert.Contains("Release artifact set is incomplete or contains unexpected files.", workflow, StringComparison.Ordinal);
        Assert.Contains("Release checksum set is incomplete or contains unexpected files.", workflow, StringComparison.Ordinal);
        Assert.Contains("(?<hash>[0-9a-f]{64})  (?<name>[^\\\\/]+)", workflow, StringComparison.Ordinal);
        Assert.Contains("$match.Groups['name'].Value -cne $name", workflow, StringComparison.Ordinal);
        Assert.Contains("Get-FileHash -LiteralPath $artifact -Algorithm SHA256", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void SigningPolicyDocumentationMatchesTheCurrentRepositoryDecision()
    {
        var policy = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "CODE_SIGNING.md"));
        var release = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "RELEASE.md"));
        var kit = File.ReadAllText(Path.Combine(
            RepositoryRoot, "docs", "validation", "VM_QUALIFICATION_KIT.md"));

        Assert.Contains("declined the project's free-program application on 2026-07-29", policy, StringComparison.Ordinal);
        Assert.Contains("`REQUIRE_SIGNED_RELEASE=false`", policy, StringComparison.Ordinal);
        Assert.Contains("replaced the per-release waiver model", release, StringComparison.Ordinal);
        Assert.Contains("`REQUIRE_SIGNED_RELEASE=false`", release, StringComparison.Ordinal);
        Assert.Contains("$AcceptUnsignedDistribution = $true", kit, StringComparison.Ordinal);
        Assert.Contains("$ExpectedPublisher = $null", kit, StringComparison.Ordinal);
        Assert.Contains("$sig.Status -ne 'NotSigned'", kit, StringComparison.Ordinal);
    }
}
