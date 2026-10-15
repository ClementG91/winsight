using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    [Fact]
    public async Task PreviousInstallerWithSameNamePreservesCurrentCandidate()
    {
        await Run(InstallerGateSetup + """
            try {
                Invoke-Expression ('& '+$gate.CommandElements[2].Extent.Text)
                if ((Get-Sha256 $script:Installer) -ne $currentHash -or $script:Manifest[$script:Installer] -ne $currentHash) {throw 'ASSERT: previous installer replaced current candidate bytes or manifest'}
                $previousPath=$script:invocation[1]
                if ($previousPath -eq $script:Installer -or [IO.Path]::GetDirectoryName($previousPath) -ne (Join-Path $Artifacts 'previous')) {throw 'ASSERT: previous installer is not isolated from current candidate'}
                if ((Get-Sha256 $previousPath) -ne $oldHash -or $script:Manifest[$previousPath] -ne $oldHash -or $script:invocation[5] -ne $script:Installer) {throw 'ASSERT: invocation or previous manifest does not bind both installers'}
            }
            finally {[IO.Directory]::Delete($work,$true)}
            """, driverFile: "guest\\qualify.ps1");
    }

    [Theory]
    [InlineData("../outside.exe")]
    [InlineData("folder\\setup.exe")]
    [InlineData("setup.exe:stream")]
    [InlineData("setup.exe.")]
    [InlineData("setup.exe ")]
    [InlineData("NUL.exe")]
    public async Task PreviousInstallerWithSameNameRejectsUnsafePreviousLeaf(string leaf)
    {
        await Run(InstallerGateSetup + $$"""
            $Candidate.previous.file='{{leaf.Replace("'", "''", StringComparison.Ordinal)}}'
            $script:copies=0
            function Copy-Item { $script:copies++;throw 'Copy must not run for an invalid leaf' }
            try {
                $caught=$null;try {Invoke-Expression ('& '+$gate.CommandElements[2].Extent.Text)} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'previous.*(file|leaf)' -or $script:copies -ne 0 -or $null -ne $script:invocation) {throw 'ASSERT: invalid previous leaf reached copy or installer invocation'}
                if ((Get-Sha256 $script:Installer) -ne $currentHash) {throw 'ASSERT: rejected previous leaf altered current installer'}
            }
            finally {[IO.Directory]::Delete($work,$true)}
            """, driverFile: "guest\\qualify.ps1");
    }

    [Fact]
    public async Task SameVersionReinstallRejectsStaleInstalledContent()
    {
        await Run(InstallerFlowSetup + """
            $script:replaceContent=$false
            try {
                $caught=$null;try {Invoke-Expression $main.Extent.Text} catch {$caught=$_}
                if (-not $caught -or $caught.Exception.Message -notmatch 'content.*fresh candidate') {throw 'ASSERT: same-version reinstall accepted old installed content or failed for another reason'}
                if ($script:installs -ne 3 -or $script:versions -ne 3) {throw 'ASSERT: regression did not execute fresh, previous and replacement flows'}
            }
            finally {if ([IO.Directory]::Exists($work)) {[IO.Directory]::Delete($work,$true)}}
            """, driverFile: "..\\..\\Test-InstallerUpgrade.ps1");
    }

    [Fact]
    public async Task SameVersionReinstallAcceptsUpdatedInstalledContent()
    {
        await Run(InstallerFlowSetup + """
            $script:replaceContent=$true
            try {
                Invoke-Expression $main.Extent.Text
                if ($script:installs -ne 3 -or $script:versions -ne 3 -or [IO.Directory]::Exists($fresh) -or [IO.Directory]::Exists($upgraded)) {throw 'ASSERT: correct replacement did not complete existing version and uninstall flow'}
            }
            finally {if ([IO.Directory]::Exists($work)) {[IO.Directory]::Delete($work,$true)}}
            """, driverFile: "..\\..\\Test-InstallerUpgrade.ps1");
    }

    private const string InstallerGateSetup = """
        $work=[IO.Path]::Combine([IO.Path]::GetTempPath(),'winsight-installer-gate-'+[guid]::NewGuid().ToString('N'))
        $Share=[IO.Path]::Combine($work,'share');$Artifacts=[IO.Path]::Combine($work,'artifacts');$Source=$work;$Version='0.14.2'
        [IO.Directory]::CreateDirectory([IO.Path]::Combine($Share,'previous'))|Out-Null
        [IO.Directory]::CreateDirectory($Artifacts)|Out-Null
        $leaf='WinSight-0.14.2-setup.exe';$script:Installer=[IO.Path]::Combine($Artifacts,$leaf)
        [IO.File]::WriteAllText($script:Installer,'current-candidate')
        $old=[IO.Path]::Combine($Share,'previous',$leaf);[IO.File]::WriteAllText($old,'published-previous')
        $currentHash=Get-Sha256 $script:Installer;$oldHash=Get-Sha256 $old
        $Candidate=[pscustomobject]@{previous=[pscustomobject]@{file=$leaf;sha256=$oldHash;version='0.14.2';commit=('0'*40)}}
        $script:Manifest=@{};$script:Manifest[$script:Installer]=$currentHash;$script:invocation=$null
        function Invoke-Script($Name,$Path,$Arguments) {$script:invocation=$Arguments;return 0}
        function Tail {}
        function Start-Process {throw 'ASSERT: test must never launch an installer'}
        $gate=$ast.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Gate' -and $n.CommandElements.Count -gt 2 -and $n.CommandElements[1].Value -eq '16-installer-upgrade'},$true)
        if (-not $gate) {throw 'ASSERT: actual installer-upgrade gate missing'}
        """;

    private const string InstallerFlowSetup = """
        $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        $work=[IO.Path]::Combine($tempRoot,'winsight-upgrade-regression-'+[guid]::NewGuid().ToString('N'))
        $fresh=[IO.Path]::Combine($work,'fresh');$upgraded=[IO.Path]::Combine($work,'upgraded')
        $InstallerPath='current-fixture';$PreviousInstallerPath='previous-fixture';$Version='0.14.2';$PreviousVersion='0.14.2'
        $script:installs=0;$script:versions=0
        function Start-Process {throw 'ASSERT: test must never launch an installer'}
        function Install-WinSight($Installer,$Directory) {
            $script:installs++;[IO.Directory]::CreateDirectory($Directory)|Out-Null
            $file=[IO.Path]::Combine($Directory,'WinSight.Application.dll')
            if ($Installer -eq $PreviousInstallerPath) {[IO.File]::WriteAllText($file,'old-content')}
            elseif ($Directory -eq $fresh -or $script:replaceContent) {[IO.File]::WriteAllText($file,'current-content')}
        }
        function Assert-Version($Directory,$Expected) {if ($Expected -ne '0.14.2') {throw 'ASSERT: fixture version changed'};$script:versions++}
        function Uninstall-WinSight($Directory) {if ([IO.Directory]::Exists($Directory)) {[IO.Directory]::Delete($Directory,$true)}}
        function Get-ChildItem($Path,$LiteralPath,[switch]$Recurse,[switch]$File) {
            if ($Path -eq 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall') {return [pscustomobject]@{PSChildName='{8D72DC5E-7BBE-4CF4-9D8B-A76F06C2A614}_is1'}}
            if (-not $LiteralPath -or -not $LiteralPath.StartsWith($work+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'ASSERT: fixture attempted access outside its owned tree'}
            Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Recurse:$Recurse -File:$File
        }
        $main=$ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Body.Extent.Text.Contains('Install-WinSight $InstallerPath $fresh')}|Select-Object -First 1
        if (-not $main) {throw 'ASSERT: actual installer validation flow missing'}
        """;
}
