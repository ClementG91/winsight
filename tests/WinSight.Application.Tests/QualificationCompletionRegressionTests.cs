using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    private const string DecisionTail = """
        $text=Microsoft.PowerShell.Management\Get-Content -LiteralPath $driver -Raw
        $start=$text.LastIndexOf('$resultsFile =')
        if ($start -lt 0) {throw 'ASSERT: actual qualification decision tail missing'}
        $tail=$text.Substring($start);$parseErrors=$null
        $parsed=[Management.Automation.Language.Parser]::ParseInput($tail,[ref]$null,[ref]$parseErrors)
        if ($parseErrors.Count) {throw 'ASSERT: actual decision tail could not parse'}
        $exits=@($parsed.FindAll({param($n) $n -is [Management.Automation.Language.ExitStatementAst]},$true)|Sort-Object {$_.Extent.StartOffset} -Descending)
        if (-not $exits.Count) {throw 'ASSERT: actual qualification decision has no exit'}
        foreach ($exitAst in $exits) {$at=$exitAst.Extent.StartOffset;$tail=$tail.Substring(0,$at)+'return'+$tail.Substring($at+4)}
        $code=& ([scriptblock]::Create($tail))
        if ($code -isnot [int] -or $code -ne $expected) {throw 'ASSERT: actual decision accepted incomplete, failed or refused campaign'}
        """;

    [Theory]
    [InlineData("complete", 0)]
    [InlineData("01-FAIL", 1)]
    [InlineData("01-NOT_RUN", 1)]
    [InlineData("01-missing", 1)]
    [InlineData("99-FAIL", 1)]
    [InlineData("99-NOT_RUN", 1)]
    [InlineData("99-missing", 1)]
    [InlineData("target-finish-missing", 1)]
    [InlineData("target-finish-null", 1)]
    [InlineData("target-finish-array", 1)]
    [InlineData("target-finish-bool", 1)]
    [InlineData("target-finish-invalid", 1)]
    [InlineData("target-finish-no-zone", 1)]
    [InlineData("target-finish-before-start", 1)]
    [InlineData("control-finish-missing", 1)]
    [InlineData("control-finish-null", 1)]
    [InlineData("control-finish-array", 1)]
    [InlineData("control-finish-bool", 1)]
    [InlineData("control-finish-invalid", 1)]
    [InlineData("control-finish-no-zone", 1)]
    [InlineData("control-finish-before-start", 1)]
    public async Task NetworkCampaignActualVerdictRequiresEveryMandatoryGateAndRealCompletion(string kind, int expected)
    {
        await Run(WaitSetup + "$kind='" + kind + "';$expected=" + expected + ";" + """
            $runDir=Join-Path $EvidenceRoot $RunName;$timedOut=$false;$refused=@()
            $started=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');$finished=[DateTime]::UtcNow.ToString('o')
            # Exercise the actual PS5 JSON conversion used for guest-produced DateTime UTC strings.
            $targetResults=(@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=$started;finishedUtc=$finished;gates=@{'01-identity-and-protected-root'=@{status='PASS'};'36-ipc-network-logon'=@{status='PASS'};'99-residue'=@{status='PASS'} } }|ConvertTo-Json -Depth 8)|ConvertFrom-Json
            $controlResults=(@{qualificationRunId=$runState.runId;startedUtc=$started;finishedUtc=$finished;status='PASS'}|ConvertTo-Json)|ConvertFrom-Json
            if ($kind -match '^(01|99)-(FAIL|NOT_RUN|missing)$') {
                $name=if ($Matches[1] -ceq '01') {'01-identity-and-protected-root'} else {'99-residue'}
                $status=$Matches[2]
                if ($status -ceq 'missing') {$targetResults.gates.PSObject.Properties.Remove($name)} else {$targetResults.gates.$name.status=$status}
            }
            elseif ($kind -match '^(target|control)-finish-(.+)$') {
                $side=if ($Matches[1] -ceq 'target') {$targetResults} else {$controlResults}
                switch ($Matches[2]) {
                    'missing' {$side.PSObject.Properties.Remove('finishedUtc')}
                    'null' {$side.finishedUtc=$null}
                    'array' {$side.finishedUtc=@($finished)}
                    'bool' {$side.finishedUtc=$true}
                    'invalid' {$side.finishedUtc='not-finished'}
                    'no-zone' {$side.finishedUtc='2026-10-15T17:00:00.0000000'}
                    'before-start' {$side.finishedUtc=[DateTime]::UtcNow.AddMinutes(-2).ToString('o')}
                }
            }
            function Test-Path($LiteralPath) {$true}
            function Get-Content($LiteralPath,[switch]$Raw) {if ($LiteralPath -like '*control-result.json') {return ($controlResults|ConvertTo-Json -Depth 8)};return ($targetResults|ConvertTo-Json -Depth 8)}
            function Write-Host {}
            """ + DecisionTail);
    }

    [Theory]
    [InlineData("target")]
    [InlineData("control")]
    public async Task NetworkCampaignMissingCounterpartReceiptNeverCallsAnUnfinishedSidePass(string present)
    {
        await Run(WaitSetup + "$present='" + present + "';" + """
            $script:partialTarget=(@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=$null;gates=@{'01-identity-and-protected-root'=@{status='PASS'};'36-ipc-network-logon'=@{status='PASS'} } }|ConvertTo-Json -Depth 8)
            $script:partialControl=(@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');status='PASS';finishedUtc=$null}|ConvertTo-Json)
            function Get-Content($LiteralPath,[switch]$Raw) {
                $isTarget=$LiteralPath -like '*target\results.json'
                if (($present -ceq 'target') -eq $isTarget) {if ($isTarget) {return $script:partialTarget};return $script:partialControl}
                throw [Management.Automation.ItemNotFoundException]::new('missing counterpart')
            }
            $script:receipt=$null;function Write-NetworkMissingReceipt($Path,$Receipt) {$script:receipt=$Receipt}
            $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
            if ($caught -or -not $script:receipt -or $script:copies -ne 2 -or $script:restores -ne 1) {throw 'ASSERT: closed partial/missing campaign not sealed and restored'}
            if ($script:receipt.$present.status -cne 'NOT_RUN' -or $script:receipt.$present.reason -cne 'result-present') {throw 'ASSERT: unfinished present side falsely labelled PASS in durable receipt'}
            """);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkCampaignHeartbeatAndBrokenStderrCannotSkipTheActualRestorationFinally(bool priorFailure)
    {
        await Run(WaitSetup + "$priorFailure=$" + priorFailure.ToString().ToLowerInvariant() + ";" + """
            $DriverHeartbeat='D:\synthetic-network-heartbeat.json';$script:restoreBeats=0;$primary=[IO.IOException]::new('primary fixture cleanup failure')
            function Write-SharedText($Path,$Text) {if (($Text|ConvertFrom-Json).phase -ceq 'restoring') {$script:restoreBeats++;throw [IO.IOException]::new('heartbeat disk full')} }
            $AutomaticCredential=$priorFailure
            function Remove-NetworkProbeFixture($Path) {if ($priorFailure) {throw $primary} }
            Add-Type -TypeDefinition 'public sealed class BrokenCampaignErrorWriter : System.IO.StringWriter { public override void WriteLine(string value) { throw new System.IO.IOException("stderr full"); } }'
            $originalError=[Console]::Error;$caught=$null
            try {
                [Console]::SetError((New-Object BrokenCampaignErrorWriter))
                try {Invoke-Expression $observationScript} catch {$caught=$_}
            }
            finally {[Console]::SetError($originalError)}
            if ($script:restoreBeats -ne 1 -or $script:copies -ne 2 -or $script:restores -ne 1) {throw 'ASSERT: heartbeat diagnostic failure skipped actual sealed-campaign restoration'}
            if ($priorFailure -and -not [object]::ReferenceEquals($caught.Exception,$primary)) {throw 'ASSERT: heartbeat diagnostic masked preexisting primary failure'}
            if (-not $priorFailure -and $caught) {throw 'ASSERT: best-effort heartbeat became campaign failure'}
            """);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkCampaignPartialMountCleanupPreservesAcquisitionFailureEvenWithBrokenStderr(bool brokenStderr)
    {
        await Run("$brokenStderr=$" + brokenStderr.ToString().ToLowerInvariant() + ";" + """
            $primary=[IO.IOException]::new('native partition acquisition {failure}');$script:cleanup=0
            function Mount-VHD($Path,[switch]$Passthru) {[pscustomobject]@{DiskNumber=8}}
            function Get-Disk {[pscustomobject]@{Number=8}}
            function Get-Partition {throw $primary}
            function Dismount-VHD($Path) {$script:cleanup++;throw [IO.IOException]::new('native cleanup dismount {failure}')}
            $method=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Mount-WinSightData'},$true)
            Invoke-Expression $method.Extent.Text
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error
            if ($brokenStderr) {Add-Type -TypeDefinition 'public sealed class BrokenMountErrorWriter : System.IO.StringWriter { public override void WriteLine(string value) { throw new System.IO.IOException("stderr full"); } }';$stderr=New-Object BrokenMountErrorWriter}
            $caught=$null
            try {[Console]::SetError($stderr);try {Mount-WinSightData 'D:\synthetic.vhdx'|Out-Null} catch {$caught=$_} }
            finally {[Console]::SetError($originalError)}
            if ($script:cleanup -ne 1 -or -not [object]::ReferenceEquals($caught.Exception,$primary)) {throw 'ASSERT: partial-mount cleanup or stderr replaced acquisition failure'}
            if (-not $brokenStderr -and -not $stderr.ToString().Contains('native cleanup dismount {failure}')) {throw 'ASSERT: secondary mount cleanup native cause erased'}
            """);
    }

    [Fact]
    public async Task NetworkCampaignDataDiskDetachRequiresConfirmedOffAfterStopReturns()
    {
        await Run("""
            $script:stops=0;$script:diskQueries=0;$script:detaches=0
            function Get-WinSightVmState($Name) {'Running'}
            function Stop-VM {$script:stops++}
            function Get-VMHardDiskDrive {$script:diskQueries++;[pscustomobject]@{Path='D:\synthetic.vhdx'}}
            function Remove-VMHardDiskDrive {$script:detaches++}
            $method=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Remove-WinSightDataDisk'},$true)
            Invoke-Expression $method.Extent.Text
            $caught=$null;try {Remove-WinSightDataDisk -VMName 'target' -Path 'D:\synthetic.vhdx' -Attempts 1|Out-Null} catch {$caught=$_}
            if (-not $caught -or $script:stops -ne 1 -or $script:diskQueries -ne 0 -or $script:detaches -ne 0) {throw 'ASSERT: an unconfirmed stop authorized hot data-disk access/detachment'}
            """);
    }

    [Theory]
    [InlineData("method")]
    [InlineData("binding")]
    public async Task RealCredentialExceptionsRemainRedactedThroughTheActualWrapperAndStagingCatch(string kind)
    {
        await Run("$kind='" + kind + "';" + """
            $AutomaticCredential=$true;$script:logs=@();$script:fixtures=0;$script:restores=0;$script:captured=$null;$script:invocations=0
            function Write-HostLog($Message) {$script:logs+=$Message}
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            Add-Type -TypeDefinition 'public static class NativeCredentialFailure { public static string Create() { throw new System.IO.IOException("synthetic-credential-secret-from-native-method"); } }'
            if ($kind -ceq 'method') {
                function New-NetworkProbeEnvelope {try {$script:invocations++;[NativeCredentialFailure]::Create()} catch {$script:captured=$_;throw} }
            }
            else {
                function BindingCredential([int]$Value) {}
                function New-NetworkProbeEnvelope {try {$script:invocations++;BindingCredential -Value 'synthetic-credential-secret-from-binding'} catch {$script:captured=$_;throw} }
            }
            $staging=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            $call=$staging.Body.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Invoke-NetworkCredentialOperation' -and $n.Extent.Text.Contains('New-NetworkProbeEnvelope')},$true)
            if (-not $call) {throw 'ASSERT: actual credential operation wrapper missing'}
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error;$caught=$null
            try {[Console]::SetError($stderr);try {Invoke-Expression ('try {'+$call.Extent.Text+'} '+$staging.CatchClauses[0].Extent.Text)} catch {$caught=$_} }
            finally {[Console]::SetError($originalError)}
            if ($script:invocations -ne 1 -or -not $script:captured -or -not [object]::ReferenceEquals($caught.Exception,$script:captured.Exception) -or $script:fixtures -ne 1 -or $script:restores -ne 1) {throw 'ASSERT: actual native/binding credential failure lost identity or skipped recovery'}
            $combined=$stderr.ToString()+($script:logs -join ' ')
            if ($combined.Contains('synthetic-credential-secret') -or -not $combined.Contains('HRESULT')) {throw 'ASSERT: native/binding credential payload leaked or safe diagnostic erased'}
            """);
    }
}
