using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    private const string SyntheticTree = """
        $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        $work=[IO.Path]::GetFullPath([IO.Path]::Combine($tempRoot,'winsight-qualification-io-'+[guid]::NewGuid().ToString('N')))
        if (-not $work.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)) {throw 'ASSERT: synthetic tree escaped temp root'}
        [void][IO.Directory]::CreateDirectory($work)
        $from=[IO.Path]::Combine($work,'source');$to=[IO.Path]::Combine($work,'target')
        [void][IO.Directory]::CreateDirectory($from);[void][IO.Directory]::CreateDirectory($to)
        function Remove-SyntheticTree {
            $resolved=[IO.Path]::GetFullPath($work)
            if (-not $resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or $resolved -cne $work -or ([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint)) {throw 'ASSERT: refused unsafe synthetic cleanup'}
            [IO.Directory]::Delete($resolved,$true)
        }
        """;

    [Fact]
    public async Task GuestCollectionRefusalReportHasABoundedSizeAfterTheFileBudgetIsExhausted()
    {
        await Run(SyntheticTree + """
            try {
                foreach ($n in 1..500) {[IO.File]::WriteAllText([IO.Path]::Combine($from,('entry-{0:D4}.txt' -f $n)),'synthetic')}
                $actual=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Copy-GuestResults'},$true)
                Invoke-Expression $actual.Extent.Text
                $refused=@(Copy-GuestResults -From $from -To $to -MaximumFiles 1)
                if ($refused.Count -le 0 -or $refused.Count -gt 129 -or ($refused -join "`n").Length -gt 80KB) {throw 'ASSERT: refusal report grows with every excess guest file'}
                if (([IO.Directory]::GetFiles($to)).Count -ne 1) {throw 'ASSERT: file-copy cap lost its one allowed ordinary file'}
                if (-not ($refused -join ' ').Contains('limit')) {throw 'ASSERT: bounded refusal summary does not explain incomplete collection'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Fact]
    public async Task CollectionEntryBudgetBoundsDirectoryOnlyTreesAndStopsDescent()
    {
        await Run(SyntheticTree + """
            try {
                foreach ($n in 1..8) {[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($from,('dir-{0:D2}' -f $n),'nested','deeper'))}
                $actual=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Copy-GuestResults'},$true)
                Invoke-Expression $actual.Extent.Text
                $refused=@(Copy-GuestResults -From $from -To $to -MaximumEntries 2 -MaximumDepth 2)
                $created=@([IO.Directory]::EnumerateDirectories($to,'*',[IO.SearchOption]::AllDirectories))
                if ($created.Count -gt 2 -or $refused.Count -le 0 -or -not ($refused -join ' ').Contains('limit')) {throw 'ASSERT: directory-only traversal escaped configured entry budget'}
                if (@($created|Where-Object {[IO.Path]::GetFileName($_) -ceq 'deeper'}).Count -ne 0) {throw 'ASSERT: traversal descended past exhausted entry/depth budget'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Fact]
    public async Task CollectionDepthBoundPreservesOrdinaryFilesAndReportsTheUnvisitedSubtree()
    {
        await Run(SyntheticTree + """
            try {
                [IO.File]::WriteAllText([IO.Path]::Combine($from,'ordinary.txt'),'ordinary')
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($from,'first','second','third'))
                [IO.File]::WriteAllText([IO.Path]::Combine($from,'first','second','third','deep.txt'),'deep')
                $actual=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Copy-GuestResults'},$true)
                Invoke-Expression $actual.Extent.Text
                $refused=@(Copy-GuestResults -From $from -To $to -MaximumEntries 100 -MaximumDepth 1)
                if ([IO.File]::ReadAllText([IO.Path]::Combine($to,'ordinary.txt')) -cne 'ordinary' -or $refused.Count -le 0) {throw 'ASSERT: depth control lost ordinary evidence or silently skipped a subtree'}
                if ([IO.Directory]::Exists([IO.Path]::Combine($to,'first','second'))) {throw 'ASSERT: collection created a directory below the configured depth'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData("invalid")]
    [InlineData("directory")]
    [InlineData("parent-missing")]
    public async Task FixtureRemovalNeverTurnsAnInvalidOrDirectoryPathIntoConfirmedAbsence(string kind)
    {
        await Run(SyntheticTree + "$kind='" + kind + "';" + """
            $credentialAst=[Management.Automation.Language.Parser]::ParseFile([IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,'guest','NetworkProbeCredential.psm1'),[ref]$null,[ref]$null)
            $actual=$credentialAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Remove-NetworkProbeFixture'},$true)
            Invoke-Expression $actual.Extent.Text
            # This test isolates native absence/delete semantics. Actual admin-only ACL ownership is
            # covered independently by protected bootstrap/fixture tests and final VM qualification.
            function Assert-NetworkProbePath($Path) {}
            try {
                $path=if ($kind -ceq 'invalid') {[IO.Path]::Combine($from,'invalid')+[char]0+'fixture'} elseif ($kind -ceq 'parent-missing') {[IO.Path]::Combine($from,'fixture.json')} else {$from}
                if ($kind -ceq 'parent-missing') {[IO.Directory]::Delete($from)}
                $caught=$null;try {Remove-NetworkProbeFixture -Path $path} catch {$caught=$_}
                if (-not $caught) {throw 'ASSERT: invalid/directory fixture path was silently treated as absent'}
                if ($kind -cne 'parent-missing' -and -not [IO.Directory]::Exists($from)) {throw 'ASSERT: directory fixture refusal changed the tree'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("ordinary")]
    [InlineData("sharing")]
    public async Task FixtureCleanupUsesNativeDeletionOrExactAbsenceAndPreservesLockedBytes(string kind)
    {
        await Run(SyntheticTree + "$kind='" + kind + "';" + """
            $credentialAst=[Management.Automation.Language.Parser]::ParseFile([IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,'guest','NetworkProbeCredential.psm1'),[ref]$null,[ref]$null)
            $actual=$credentialAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Remove-NetworkProbeFixture'},$true)
            Invoke-Expression $actual.Extent.Text
            function Assert-NetworkProbePath($Path) {}
            $path=[IO.Path]::Combine($from,'network-credential.json');$held=$null
            if ($kind -cne 'missing') {[IO.File]::WriteAllText($path,'synthetic-fixture-not-a-password')}
            if ($kind -ceq 'sharing') {$held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
            try {
                $caught=$null;try {Remove-NetworkProbeFixture -Path $path} catch {$caught=$_}
                if ($held) {$held.Dispose();$held=$null}
                if ($kind -ceq 'sharing') {
                    if (-not $caught -or [IO.File]::ReadAllText($path) -cne 'synthetic-fixture-not-a-password') {throw 'ASSERT: locked fixture reported cleaned or its bytes changed'}
                }
                else {
                    if ($caught) {throw 'ASSERT: ordinary deletion or exact native absence failed'}
                    $absent=$false;try {[void][IO.File]::GetAttributes($path)} catch [IO.FileNotFoundException] {$absent=$true}
                    if (-not $absent) {throw 'ASSERT: fixture deletion was not confirmed as native absence'}
                }
            }
            finally {if ($held) {$held.Dispose()};Remove-SyntheticTree}
            """);
    }
}
