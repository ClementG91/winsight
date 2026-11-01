using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    // These paths are mocked; the provider drive must exist on x64 and native ARM64 runners.
    private const string FixturePaths = """
        $fixtureRoot=[IO.Path]::Combine([IO.Path]::GetTempPath(),'winsight-qualification-fixture-'+[guid]::NewGuid().ToString('N'))
        $fixtureLetter=[IO.Path]::GetPathRoot($fixtureRoot).Substring(0,1);
        """;

    [Fact]
    public async Task FullCampaignActualStagingBindsTheRunAndEveryRequestedMandatoryGate()
    {
        await Run(FixturePaths + """
            $CandidateDir=[IO.Path]::Combine($fixtureRoot,'candidate');$HarnessDir=[IO.Path]::Combine($fixtureRoot,'harness');$data=[IO.Path]::Combine($fixtureRoot,'synthetic.vhdx');$Name='target';$Checkpoint='S0'
            $runState=[pscustomobject]@{runId='711bd1cf-3153-4ea5-95d5-3938ae1e3610'};$letter=$fixtureLetter
            $Gates=@('17-cloud-files');$expectedGates=@('01-identity-and-protected-root','17-cloud-files','99-residue');$script:stagedJson=$null
            function Restore-VMCheckpoint {}
            function Remove-DataDisk {}
            function Mount-WinSightData {$fixtureLetter}
            function Dismount-WinSightData {}
            function Clear-WinSightDataVolume {}
            function New-Item {}
            function Copy-Item {}
            function Get-Content {return '{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'}
            function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value,$Encoding) {if ($LiteralPath -like '*candidate.json') {$script:stagedJson=$Value} }
            $staging=$ast.FindAll({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)|Sort-Object {$_.Extent.EndOffset-$_.Extent.StartOffset}|Select-Object -First 1
            if (-not $staging) {throw 'ASSERT: full actual staging block missing'}
            Invoke-Expression $staging.Extent.Text
            $observed=$script:stagedJson|ConvertFrom-Json
            if ($observed.qualificationRunId -cne $runState.runId) {throw 'ASSERT: actual full staging omitted exact run binding'}
            foreach ($gate in $expectedGates) {if ($gate -cnotin $observed.gates) {throw 'ASSERT: actual full staging omitted requested mandatory gate'} }
            """, "Invoke-HyperVQualification.ps1");
    }

    [Theory]
    [InlineData("complete", 0)]
    [InlineData("NOT_RUN", 1)]
    [InlineData("unknown", 1)]
    [InlineData("missing-requested", 1)]
    [InlineData("missing-01", 1)]
    [InlineData("missing-99", 1)]
    [InlineData("empty", 1)]
    [InlineData("refused", 1)]
    [InlineData("foreign-commit", 1)]
    [InlineData("foreign-run", 1)]
    [InlineData("missing-finish", 1)]
    [InlineData("invalid-finish", 1)]
    [InlineData("timeout", 1)]
    public async Task FullCampaignActualVerdictRejectsIncompleteUnknownForeignAndRefusedResults(string kind, int expected)
    {
        await Run(FixturePaths + "$kind='" + kind + "';$expected=" + expected + ";" + """
            $EvidenceRoot=[IO.Path]::Combine($fixtureRoot,'evidence');$RunName='full-probe';$runDir=Join-Path $EvidenceRoot $RunName
            $candidate=[pscustomobject]@{commit=('a'*40)};$runState=[pscustomobject]@{runId='711bd1cf-3153-4ea5-95d5-3938ae1e3610'}
            $Gates=@('17-cloud-files');$expectedGates=@('01-identity-and-protected-root','17-cloud-files','99-residue')
            $timedOut=$false;$refused=@();$DriverHeartbeat=$null;$script:logs=@()
            $final=(@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=@{'01-identity-and-protected-root'=@{status='PASS'};'17-cloud-files'=@{status='PASS'};'99-residue'=@{status='PASS'} } }|ConvertTo-Json -Depth 8)|ConvertFrom-Json
            switch ($kind) {
                'NOT_RUN' {$final.gates.'17-cloud-files'.status='NOT_RUN'}
                'unknown' {$final.gates.'17-cloud-files'.status='UNKNOWN'}
                'missing-requested' {$final.gates.PSObject.Properties.Remove('17-cloud-files')}
                'missing-01' {$final.gates.PSObject.Properties.Remove('01-identity-and-protected-root')}
                'missing-99' {$final.gates.PSObject.Properties.Remove('99-residue')}
                'empty' {$final.gates=[pscustomobject]@{}}
                'refused' {$refused=@('guest reparse was refused')}
                'foreign-commit' {$final.candidate.commit=('b'*40)}
                'foreign-run' {$final.candidate.qualificationRunId='other-run'}
                'missing-finish' {$final.finishedUtc=$null}
                'invalid-finish' {$final.finishedUtc='not-finished'}
                'timeout' {$timedOut=$true}
            }
            $fullResults=$final
            function Test-Path($LiteralPath) {$true}
            function Get-Content($LiteralPath,[switch]$Raw) {return ($final|ConvertTo-Json -Depth 8)}
            function Write-Host {}
            function Write-HostLog($Message) {$script:logs+=$Message}
            """ + DecisionTail, "Invoke-HyperVQualification.ps1");
    }

    [Theory]
    [InlineData("copy")]
    [InlineData("seal")]
    [InlineData("host-log")]
    [InlineData("dismount")]
    [InlineData("resume")]
    public async Task FullCampaignSealingAndRecoveryPreserveThePrimaryAndAnIdenticalPartialResume(string failure)
    {
        await Run(FixturePaths + "$failure='" + failure + "';" + """
            $Root=[IO.Path]::Combine($fixtureRoot,'root');$EvidenceRoot=[IO.Path]::Combine($fixtureRoot,'evidence');$CandidateDir=[IO.Path]::Combine($fixtureRoot,'candidate');$HarnessDir=[IO.Path]::Combine($fixtureRoot,'harness');$BootstrapReceipt=[IO.Path]::Combine($fixtureRoot,'bootstrap.json')
            $Name='target';$Checkpoint='S0';$data=[IO.Path]::Combine($Root,'data.vhdx');$RunName='full-recovery';$runDir=Join-Path $EvidenceRoot $RunName
            $Gates=@('17-cloud-files');$expectedGates=@('01-identity-and-protected-root','17-cloud-files','99-residue');$Resume=$true;$DriverHeartbeat=$null;$timedOut=$false;$refused=@();$candidate=[pscustomobject]@{commit=('a'*40)};$runState=[pscustomobject]@{runId='fcfb0447-3ea3-4bf5-a4f6-12a466c2d982'}
            $script:copies=0;$script:restores=0;$script:seals=0;$script:resumeCopy=$false;$script:events=@();$script:logs=@();$primary=[IO.IOException]::new('native '+$failure+' {primary}')
            function Remove-DataDisk {$script:events+='detach'}
            function Get-WinSightVmState($Name) {'Off'}
            function Mount-WinSightData($Path) {$fixtureLetter}
            function Dismount-WinSightData($Path) {$script:events+='dismount';if ($failure -ceq 'dismount') {throw $primary} }
            function Copy-GuestResults($From,$To,[switch]$Resume) {$script:copies++;$script:resumeCopy=$Resume.IsPresent;$script:events+='copy';if ($failure -ceq 'copy') {throw $primary} }
            function Test-Path($LiteralPath) {$true}
            function New-Item {}
            function Assert-ProtectedPath {}
            function Get-FileManifest {}
            function Copy-Item {}
            function Get-ChildItem {}
            function Get-Content {return (@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};gates=@{'01-identity-and-protected-root'=@{status='PASS'};'17-cloud-files'=@{status='PASS'};'99-residue'=@{status='PASS'}};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 8)}
            function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value,$Encoding) {if ($LiteralPath -like '*SHA256SUMS.txt') {$script:seals++;$script:events+='seal';if ($failure -ceq 'seal') {throw $primary} } }
            $hostLog=[IO.Path]::Combine($EvidenceRoot,'host-operations.txt')
            function Add-SharedLine($Path,$Line) {$script:logs+=$Line;if ($failure -ceq 'host-log') {throw $primary} }
            function Write-Host {}
            function Write-WinSightQualificationSeal($RunDir) {$script:seals++;$script:events+='seal';if ($failure -ceq 'seal') {throw $primary} }

            function Restore-VMCheckpoint {$script:restores++;$script:events+='restore'}
            function Restore-FullVm {$script:restores++;$script:events+='restore'}
            $text=Microsoft.PowerShell.Management\Get-Content -LiteralPath $driver -Raw
            $start=$text.IndexOf('# --- Collect and seal')
            $end=$text.LastIndexOf('$resultsFile =')
            if ($start -lt 0 -or $end -le $start) {throw 'ASSERT: actual full collection block missing'}
            $block=$text.Substring($start,$end-$start)
            $caught=$null;try {Invoke-Expression $block} catch {$caught=$_}
            if ($script:copies -ne 1) {throw 'ASSERT: actual full collector did not execute once'}
            if ($failure -ceq 'resume' -and -not $script:resumeCopy) {throw 'ASSERT: actual full collector omitted identical partial Resume'}
            if ($failure -in 'copy','seal','dismount') {
                if ($script:restores -ne 0 -or -not $caught -or -not [object]::ReferenceEquals($caught.Exception,$primary)) {throw 'ASSERT: unsafe full collection restored or replaced primary cause'}
            }
            else {
                if ($script:seals -ne 1 -or $script:restores -ne 1 -or ($script:events -join ',') -notmatch 'seal.*restore') {throw 'ASSERT: full diagnostic/dismount failure prevented seal-before-restoration'}
                if ($failure -ceq 'dismount' -and -not [object]::ReferenceEquals($caught.Exception,$primary)) {throw 'ASSERT: full dismount primary was replaced'}
            }
            """, "Invoke-HyperVQualification.ps1");
    }
}
