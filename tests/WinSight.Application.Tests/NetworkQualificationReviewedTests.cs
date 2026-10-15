using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task ReviewedNativeBracesAndBrokenStderrCannotPreventRecovery(bool brokenStderr, bool brokenHostLog)
    {
        await Run("$brokenStderr=$" + brokenStderr.ToString().ToLowerInvariant()
            + ";$brokenHostLog=$" + brokenHostLog.ToString().ToLowerInvariant() + ";" + """
            $AutomaticCredential=$true;$script:logs=@();$script:fixtures=0;$script:restores=0
            function Write-HostLog($Message) {$script:logs+=$Message;if ($brokenHostLog) {throw [IO.IOException]::new('host log full')} }
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            $clause=$ast.Find({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Parent.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            $injected=[IO.IOException]::new('native D:\case{disk}\{0}\disk.vhdx failed');$caught=$null
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error
            if ($brokenStderr) {
                Add-Type -TypeDefinition 'public sealed class BrokenNetworkErrorWriter : System.IO.StringWriter { public override void WriteLine(string value) { throw new System.IO.IOException("stderr full"); } }'
                $stderr=New-Object BrokenNetworkErrorWriter
            }
            try {
                [Console]::SetError($stderr)
                try {Invoke-Expression ('try {throw $injected} '+$clause.Extent.Text)} catch {$caught=$_}
            }
            finally {[Console]::SetError($originalError)}
            if (-not [object]::ReferenceEquals($caught.Exception,$injected) -or $script:fixtures -ne 1 -or $script:restores -ne 1) {throw 'ASSERT: diagnostic formatting or stderr masked primary or skipped recovery'}
            if (-not ($script:logs -join ' ').Contains($injected.Message)) {throw 'ASSERT: native braces are not verbatim protected-log data'}
            if (-not $brokenStderr -and -not $stderr.ToString().Contains($injected.Message)) {throw 'ASSERT: native braces missing from available stderr'}
            """);
    }

    [Theory]
    [InlineData("target", false)]
    [InlineData("target", true)]
    [InlineData("control", false)]
    [InlineData("control", true)]
    public async Task ReviewedActualMountedStagingPreservesPrimaryAcrossDismount(string side, bool secret)
    {
        await Run("$side='" + side + "';$secret=$" + secret.ToString().ToLowerInvariant() + ";" + """
            $AutomaticCredential=$true;$script:logs=@();$script:fixtures=0;$script:restores=0;$script:dismounts=0;$script:primaryCalls=0
            $data='target.vhdx';$controlData='control.vhdx';$letter='D';$staged='D:\candidate';$HarnessDir='D:\harness';$envelope='synthetic'
            $candidate=[pscustomobject]@{commit=('a'*40)};$runState=[pscustomobject]@{runId='run'}
            function Write-HostLog($Message) {$script:logs+=$Message}
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            $injected=[IO.IOException]::new('synthetic-primary-credential-or-native-volume')
            function Clear-WinSightDataVolume($Letter) {if (-not $secret) {$script:primaryCalls++;throw $injected} }
            function Set-NetworkProbeVolumeProtection {}
            function Copy-CandidatePayload {}
            function Copy-Item {}
            function Set-Content {}
            function New-Item {}
            function Get-Content {return '{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'}
            function Get-ChildItem {return @()}
            function Write-NetworkProbeFixture($Path,$Envelope) {$script:primaryCalls++;throw $injected}
            function Dismount-WinSightData($Disk) {$script:dismounts++;throw [IO.IOException]::new('native secondary dismount {disk}')}
            $staging=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            $diskName=if ($side -ceq 'target') {'$data'} else {'$controlData'}
            $mounted=$staging.Body.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Finally -and $n.Finally.Extent.Text.Contains('Dismount-WinSightData '+$diskName) -and $n.Body.Extent.Text.Contains('Write-NetworkProbeFixture')},$true)
            if (-not $mounted) {throw 'ASSERT: actual mounted staging try/finally missing'}
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error;$caught=$null
            try {
                [Console]::SetError($stderr)
                try {Invoke-Expression ('try {'+$mounted.Extent.Text+'} '+$staging.CatchClauses[0].Extent.Text)} catch {$caught=$_}
            }
            finally {[Console]::SetError($originalError)}
            if ($script:primaryCalls -ne 1 -or $script:dismounts -ne 1 -or $script:fixtures -ne 1 -or $script:restores -ne 1 -or -not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: actual staging finally masked primary or skipped recovery'}
            $combined=$stderr.ToString()+($script:logs -join ' ')
            if (-not $combined.Contains('native secondary dismount {disk}')) {throw 'ASSERT: secondary dismount native cause erased'}
            if ($secret -and $combined.Contains($injected.Message)) {throw 'ASSERT: double fault exposed credential operation detail'}
            if (-not $secret -and -not $combined.Contains($injected.Message)) {throw 'ASSERT: non-secret primary native cause erased'}
            """);
    }

    [Fact]
    public async Task ReviewedFixtureCleanupAttemptsBothDisksAndPreservesEveryNativeCause()
    {
        await Run("""
            $data='target.vhdx';$controlData='control.vhdx';$script:logs=@();$script:mounts=0;$script:removes=0;$script:dismounts=0
            $first=[IO.IOException]::new('primary target fixture {cause}')
            function Write-HostLog($Message) {$script:logs+=$Message}
            function Mount-WinSightData($Disk) {$script:mounts++;return 'D'}
            function Remove-NetworkProbeFixture($Path) {$script:removes++;if ($script:removes -eq 1) {throw $first};throw [IO.IOException]::new('primary control fixture {cause}')}
            function Dismount-WinSightData($Disk) {$script:dismounts++;throw [IO.IOException]::new('secondary dismount '+$Disk)}
            $caught=$null;try {Remove-StagedNetworkFixtures} catch {$caught=$_}
            if ($script:mounts -ne 2 -or $script:removes -ne 2 -or $script:dismounts -ne 2 -or -not [object]::ReferenceEquals($caught.Exception,$first)) {throw 'ASSERT: cleanup did not attempt both disks or masked first native cause'}
            foreach ($cause in 'primary target fixture {cause}','primary control fixture {cause}','secondary dismount target.vhdx','secondary dismount control.vhdx') {
                if (-not ($script:logs -join ' ').Contains($cause)) {throw 'ASSERT: cleanup discarded an individual native cause'}
            }
            """);
    }

    [Fact]
    public async Task ReviewedInitialDetachmentFailureStillRunsIndependentStagingRecovery()
    {
        await Run("""
            $Name='target';$ControlName='control';$data='target.vhdx';$controlData='control.vhdx';$AutomaticCredential=$true
            $script:logs=@();$script:detached=@();$script:fixtures=0;$script:restores=0;$injected=[IO.IOException]::new('native control detach {failure}')
            function Write-HostLog($Message) {$script:logs+=$Message}
            function Remove-WinSightDataDisk($VMName,$Path) {$script:detached+=$VMName;if ($VMName -ceq 'control') {throw $injected} }
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            $staging=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            $before=$ast.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Remove-DataDisks' -and $n.Extent.StartOffset -lt $staging.Extent.StartOffset -and $n.Extent.StartOffset -gt 0},$true)
            $text=if ($before) {$before.Extent.Text+"`n"+$staging.Extent.Text} else {$staging.Extent.Text}
            $caught=$null;try {Invoke-Expression $text} catch {$caught=$_}
            if (($script:detached -join ',') -cne 'target,control') {throw 'ASSERT: first-side success prevented second detach attempt'}
            if ($script:fixtures -ne 1 -or $script:restores -ne 1 -or -not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: initial partial detach bypassed staging recovery or masked native primary'}
            """);
    }

    [Theory]
    [InlineData("control-status")]
    [InlineData("control-status-escaped")]
    [InlineData("control-status-case")]
    [InlineData("control-run")]
    [InlineData("target-commit")]
    [InlineData("target-candidate")]
    [InlineData("target-gates")]
    [InlineData("target-gate")]
    [InlineData("target-status")]
    public async Task ReviewedAmbiguousPhysicalResultMembersNeverAuthorizeSealingOrRestoration(string kind)
    {
        await Run(WaitSetup + "$kind='" + kind + "';" + """
            $run=$runState.runId;$commit=$candidate.commit
            $identity='"candidate":{"commit":"'+$commit+'","qualificationRunId":"'+$run+'"}'
            $gate='"gates":{"36-ipc-network-logon":{"status":"PASS"}}'
            $script:targetRaw='{'+$identity+','+$gate+'}'
            $script:controlRaw='{"qualificationRunId":"'+$run+'","status":"PASS"}'
            switch ($kind) {
                'control-status' {$script:controlRaw='{"qualificationRunId":"'+$run+'","status":"FAIL","status":"PASS"}'}
                'control-status-escaped' {$script:controlRaw='{"qualificationRunId":"'+$run+'","sta\u0074us":"FAIL","status":"PASS"}'}
                'control-status-case' {$script:controlRaw='{"qualificationRunId":"'+$run+'","Status":"FAIL","status":"PASS"}'}
                'control-run' {$script:controlRaw='{"qualificationRunId":"foreign","qualificationRunId":"'+$run+'","status":"PASS"}'}
                'target-commit' {$script:targetRaw='{"candidate":{"commit":"foreign","commit":"'+$commit+'","qualificationRunId":"'+$run+'"},'+$gate+'}'}
                'target-candidate' {$script:targetRaw='{"candidate":{"commit":"foreign","qualificationRunId":"foreign"},'+$identity+','+$gate+'}'}
                'target-gates' {$script:targetRaw='{'+$identity+',"gates":{"36-ipc-network-logon":{"status":"FAIL"}},'+$gate+'}'}
                'target-gate' {$script:targetRaw='{'+$identity+',"gates":{"36-ipc-network-logon":{"status":"FAIL"},"36-ipc-network-logon":{"status":"PASS"}}}'}
                'target-status' {$script:targetRaw='{'+$identity+',"gates":{"36-ipc-network-logon":{"status":"FAIL","status":"PASS"}}}'}
            }
            function Get-Content($LiteralPath,[switch]$Raw) {if ($LiteralPath -like '*target\results.json') {return $script:targetRaw};return $script:controlRaw}
            $script:receipts=0;function Write-NetworkMissingReceipt {$script:receipts++}
            $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
            if (-not $caught -or $script:copies -ne 2 -or $script:restores -ne 0 -or $script:receipts -ne 0 -or ($script:logs -join ' ').Contains('evidence sealed')) {throw 'ASSERT: ambiguous physical result keys authorized attribution, sealing or restoration'}
            if (($script:logs -join ' ') -notmatch '-Resume') {throw 'ASSERT: ambiguous result lost Resume guidance'}
            """);
    }

    [Fact]
    public async Task ReviewedUniqueMembersInDifferentObjectsAndOrdinaryArraysRemainValid()
    {
        await Run(WaitSetup + """
            $script:targetRaw=(@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};gates=@{'36-ipc-network-logon'=@{status='PASS';notes=@(@{status='PASS'},@{status='FAIL'});' '=1;'_x0020_'=2;'a b'=3;'a_x0020_b'=4} } }|ConvertTo-Json -Depth 10)
            $script:controlRaw=(@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='PASS';notes=@(@{status='PASS'},@{status='FAIL'})}|ConvertTo-Json -Depth 10)
            function Get-Content($LiteralPath,[switch]$Raw) {if ($LiteralPath -like '*target\results.json') {return $script:targetRaw};return $script:controlRaw}
            Invoke-Expression $observationScript
            if ($script:copies -ne 2 -or $script:restores -ne 1 -or -not ($script:logs -join ' ').Contains('evidence sealed')) {throw 'ASSERT: valid independent object keys or array items refused'}
            """);
    }

    [Theory]
    [InlineData("depth")]
    [InlineData("utf8-bytes")]
    public async Task NetworkResultReaderRejectsDepthAndByteOverflowBeforeAttribution(string kind)
    {
        await Run("$kind='" + kind + "';" + """
            if (-not (Get-Command Read-NetworkGuestResult -ErrorAction SilentlyContinue)) {throw 'ASSERT: actual result reader missing'}
            $candidate=[pscustomobject]@{commit=('a'*40)};$runState=[pscustomobject]@{runId='bounded-run'}
            $prefix='{"candidate":{"commit":"'+$candidate.commit+'","qualificationRunId":"'+$runState.runId+'"},"gates":{"36-ipc-network-logon":{"status":"PASS"}},"notes":'
            $script:boundedRaw=if ($kind -ceq 'depth') {$prefix+('['*100)+'0'+(']'*100)+'}'} else {$prefix+'"'+([string][char]0x00E9)*(9MB)+'"}'}
            $script:reads=0;function Get-Content($LiteralPath,[switch]$Raw) {$script:reads++;return $script:boundedRaw}
            $caught=$null;try {Read-NetworkGuestResult -Path 'D:\nonexistent-winsight-bounded-result.json' -Side 'target'|Out-Null} catch {$caught=$_}
            if (-not $caught -or $script:reads -ne 1) {throw 'ASSERT: actual reader accepted excessive depth/UTF8 bytes or missed read boundary'}
            """);
    }
}
