using System.Diagnostics;
using System.Text;

using Xunit;
using Xunit.Abstractions;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed partial class NetworkQualificationLifecycleRegressionTests(ITestOutputHelper output)
{
    private static readonly string Harness = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
        "..", "..", "..", "..", "..", "scripts", "validation", "hyperv"));

    [Fact]
    public async Task RestoredConfigurationIsCapturedAfterTheCheckpoint()
    {
        await Run("""
            $script:memory = @{ target = 4GB; control = 3GB }
            $Name = 'target'; $ControlName = 'control'; $Checkpoint = 'S0'; $ControlCheckpoint = 'C0'
            function Get-VMNetworkAdapter($VMName) { [pscustomobject]@{Name='network';SwitchName='checkpoint-switch'} }
            function Get-VMMemory($VMName) { [pscustomobject]@{Startup=$script:memory[$VMName]} }
            function Restore-VMCheckpoint($VMName,$Name,$Confirm) { $script:memory[$VMName] = if ($VMName -eq 'target') {2GB} else {1GB} }
            function Invoke-WinSightVmRetry([scriptblock]$Action) { & $Action }
            $initial = $ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text.Contains('-not $Resume')}, $true)
            if (-not $initial) { throw 'ASSERT: initial staging branch missing' }
            foreach ($statement in $initial.Clauses[0].Item2.Statements) {
                $text = $statement.Extent.Text
                if ($text -match '^\$(originalAdapters|originalMemory|originalControlMemory)\s*=' -or
                    $text -match '^(Invoke-WinSightVmRetry\s*\{\s*)?Restore-VMCheckpoint') { Invoke-Expression $text }
            }
            if ($originalMemory -ne 2GB -or $originalControlMemory -ne 1GB) { throw 'ASSERT: captured stale pre-checkpoint memory' }
            """);
    }

    [Fact]
    public async Task SecretFreeStagingPreservesTheOriginalCauseAndNativeMessage()
    {
        await Run("""
            $script:logs=@(); $script:restores=0; $AutomaticCredential=$true
            function Write-HostLog($Message) { $script:logs += $Message }
            function Remove-StagedNetworkFixtures { throw 'secondary cleanup failure' }
            function Restore-BothVms { $script:restores++ }
            $clause=$ast.Find({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and
                $n.Parent.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            if (-not $clause) { throw 'ASSERT: staging catch missing' }
            $injected=[IO.IOException]::new('native staging volume failure')
            $caught=$null
            try { Invoke-Expression ('try { throw $injected } '+$clause.Extent.Text) } catch { $caught=$_ }
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) { throw 'ASSERT: original staging cause masked' }
            if ($script:restores -ne 1) { throw 'ASSERT: restoration skipped after cleanup failure' }
            if (-not ($script:logs -join ' ').Contains('IOException') -or -not ($script:logs -join ' ').Contains('native staging volume failure')) { throw 'ASSERT: original non-secret staging diagnostic missing' }
            """);
    }

    [Fact]
    public async Task TransientQueryFailureNeverTearsDownAPossiblyRunningCampaign()
    {
        await Run(WaitSetup + """
            $script:queries=0; $script:retryCalls=0
            function Get-WinSightVmState($VMName) { $script:queries++; throw [IO.IOException]::new('transient query') }
            function Invoke-WinSightVmRetry([scriptblock]$Action) {
                $script:retryCalls++
                foreach ($attempt in 1..3) { try { return & $Action } catch { if ($attempt -eq 3) { throw } } }
            }
            try { Invoke-Expression $observationScript } catch {}
            if ($script:detaches -ne 0 -or $script:restores -ne 0) { throw 'ASSERT: observation failure destroyed resumable campaign' }
            if ($script:retryCalls -eq 0 -or $script:queries -lt 3) { throw 'ASSERT: observation query was not retried' }
            if (($script:logs -join ' ') -notmatch '-Resume' -or ($script:logs -join ' ') -notmatch $RunName) { throw 'ASSERT: exact Resume guidance missing' }
            """);
    }

    [Fact]
    public async Task FixtureCleanupFailureCannotSkipEitherEvidenceCollection()
    {
        await Run(WaitSetup + """
            $AutomaticCredential=$true
            function Remove-NetworkProbeFixture($Path) { $script:events+='cleanup'; throw [IO.IOException]::new('fixture cleanup') }
            function Remove-StagedNetworkFixtures { $script:events+='cleanup'; throw [IO.IOException]::new('fixture cleanup') }
            try { Invoke-Expression $observationScript } catch {}
            if ($script:copies -ne 2) { throw 'ASSERT: cleanup failure skipped target or control evidence' }
            if ($script:events[0] -ne 'copy' -or $script:restores -ne 1) { throw 'ASSERT: evidence not collected before cleanup and restoration' }
            """);
    }

    [Theory]
    [InlineData("copy")]
    [InlineData("dismount")]
    public async Task CollectionAttemptsBothSidesAndNeverMasksThePrimaryFailure(string operation)
    {
        await Run(WaitSetup + $$"""
            $injected=[IO.IOException]::new('primary collection failure')
            function Copy-GuestResults($From,$To) {
                $script:copies++
                if ('{{operation}}' -eq 'copy' -and $script:copies -eq 1) {throw $injected}
            }
            function Dismount-WinSightData($Disk) {if ('{{operation}}' -eq 'dismount' -and $Disk -eq $data) {throw $injected} }
            function Restore-BothVms {$script:restores++;throw 'secondary restoration failure'}
            $caught=$null
            try {Invoke-Expression $observationScript} catch {$caught=$_}
            if ($script:copies -ne 2) {throw 'ASSERT: first-side failure skipped second-side collection'}
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: primary collection cause masked'}
            if ('{{operation}}' -eq 'copy' -and $script:restores -ne 0) {throw 'ASSERT: incomplete collection should remain resumable'}
            if ('{{operation}}' -eq 'dismount' -and $script:restores -ne 1) {throw 'ASSERT: completed evidence was not sealed before restoration attempt'}
            """);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedCollectionUsesOnlyTwoMountsAndOnlyAutomaticFixturesAreRemoved(bool automatic)
    {
        await Run(WaitSetup + $$"""
            $AutomaticCredential=${{automatic.ToString().ToLowerInvariant()}}
            Invoke-Expression $observationScript
            if ($script:copies -ne 2 -or $script:mounts -ne 2) { throw 'ASSERT: completed collection uses unnecessary mount cycles' }
            $expected=if ($AutomaticCredential) {2} else {0}
            if ($script:fixtureRemovals -ne $expected) { throw 'ASSERT: fixture cleanup is duplicated or runs in interactive mode' }
            """);
    }

    [Fact]
    public async Task HiddenDriverCannotPromptAndPublishesActualChildHeartbeat()
    {
        await Run("""
            $runner=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:WINSIGHT_LIFECYCLE_HARNESS 'WinSightQualRunner.ps1'),[ref]$null,[ref]$null)
            $arguments=@(); $log='mock'; $harness='mock'; $scripts=@{network='driver'}; $entry=@{action='network'}
            function Start-Process($FilePath,$ArgumentList,$RedirectStandardOutput,$RedirectStandardError,$WindowStyle,[switch]$PassThru) { $script:captured=@{style=$WindowStyle;arguments=$ArgumentList}; [pscustomobject]@{} }
            foreach ($name in 'argumentList','process') {
                $statement=$runner.Find({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq ('$'+$name)},$true)
                if (-not $statement) { throw 'ASSERT: driver launch missing' }; Invoke-Expression $statement.Extent.Text
            }
            if ($script:captured.style -ne 'Hidden' -or '-NonInteractive' -notin $script:captured.arguments) { throw 'ASSERT: hidden driver can prompt' }
            if ((Get-Content -LiteralPath (Join-Path $env:WINSIGHT_LIFECYCLE_HARNESS 'WinSightQualRunner.ps1') -Raw) -notmatch 'driverHeartbeatUtc') { throw 'ASSERT: runner cannot distinguish real child heartbeat' }
            $heartbeat=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-WinSightDriverHeartbeat'},$true)
            if (-not $heartbeat) { throw 'ASSERT: actual driver heartbeat implementation missing' }
            Invoke-Expression $heartbeat.Extent.Text
            function Write-SharedText($Path,$Text) { $script:payload=$Text|ConvertFrom-Json }
            Write-WinSightDriverHeartbeat -Path 'mock' -Phase 'waiting'
            if ($script:payload.processId -ne $PID -or $script:payload.phase -ne 'waiting' -or -not $script:payload.heartbeatUtc) { throw 'ASSERT: heartbeat is not emitted by the child' }
            """);
    }

    [Fact]
    public async Task ResumeNeverInventsCandidateIdentityOrDefaultSwitchConfiguration()
    {
        await Run("""
            $source=Get-Content -LiteralPath $driver -Raw
            $initial=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text.Contains('-not $Resume')},$true)
            if ($initial.ElseClause.Extent.Text -match "SwitchName = 'Default Switch'") { throw 'ASSERT: Resume invents a network configuration' }
            $before=$source.Substring(0,$initial.Extent.StartOffset)
            if ($before -notmatch 'candidate\.json' -or $source -notmatch 'network-state-' -or $source -notmatch 'candidateManifest') { throw 'ASSERT: Resume is not bound to staged candidate identity and original run state' }
            """);
    }

    [Fact]
    public async Task AFailingDiagnosticNeverSkipsRecoveryOrMasksTheOriginalException()
    {
        await Run("""
            $AutomaticCredential=$true;$script:fixtures=0;$script:restores=0
            function Write-HostLog($Message) {throw [IO.IOException]::new('secondary logger failure')}
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            $clause=$ast.Find({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and $n.Parent.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            $injected=[IO.IOException]::new('primary staging failure');$caught=$null
            try {Invoke-Expression ('try {throw $injected} '+$clause.Extent.Text)} catch {$caught=$_}
            if ($script:fixtures -ne 1 -or $script:restores -ne 1) {throw 'ASSERT: diagnostic failure skipped independent recovery'}
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: diagnostic failure masked primary exception'}
            """);
    }

    [Fact]
    public async Task APartialCollectionResumesIdenticalFilesAndRefusesDifferentExistingEvidence()
    {
        await Run("""
            foreach ($name in 'Copy-GuestResults','Get-SharedFileHash') {
                $definition=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
                Invoke-Expression $definition.Extent.Text
            }
            $work=Join-Path ([IO.Path]::GetTempPath()) ('winsight-copy-resume-'+[guid]::NewGuid().ToString('N'))
            $source=Join-Path $work 'source';$dest=Join-Path $work 'dest'
            [void][IO.Directory]::CreateDirectory((Join-Path $source 'sub'));[void][IO.Directory]::CreateDirectory($dest)
            [IO.File]::WriteAllText((Join-Path $source 'a.txt'),'first')
            [IO.File]::WriteAllText((Join-Path $source 'b.txt'),'second')
            [IO.File]::WriteAllText((Join-Path $source 'sub\c.txt'),'third')
            try {
                $refused=@(Copy-GuestResults -From $source -To $dest -MaximumFiles 1)
                if ((Get-ChildItem -LiteralPath $dest -File -Recurse).Count -ne 1 -or $refused.Count -ne 2) {throw 'ASSERT: partial collection fixture failed'}
                try {$refused=@(Copy-GuestResults -From $source -To $dest -Resume)} catch {throw 'ASSERT: identical partial evidence cannot be resumed'}
                if ($refused.Count -ne 0 -or (Get-ChildItem -LiteralPath $dest -File -Recurse).Count -ne 3) {throw 'ASSERT: resumed collection incomplete'}
                $before=[IO.File]::ReadAllText((Join-Path $dest 'a.txt'))
                [IO.File]::WriteAllText((Join-Path $source 'a.txt'),'different guest bytes')
                $rejected=$false
                try {Copy-GuestResults -From $source -To $dest -Resume|Out-Null} catch {$rejected=$true}
                if (-not $rejected -or [IO.File]::ReadAllText((Join-Path $dest 'a.txt')) -ne $before) {throw 'ASSERT: divergent existing evidence was overwritten'}
            }
            finally {
                foreach ($root in $source,$dest) {
                    foreach ($leaf in 'a.txt','b.txt','sub\c.txt') {[IO.File]::Delete((Join-Path $root $leaf))}
                    [IO.Directory]::Delete((Join-Path $root 'sub'));[IO.Directory]::Delete($root)
                }
                [IO.Directory]::Delete($work)
            }
            """);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task APartiallyAcquiredVhdIsReleasedWithoutMaskingThePrimaryFailure(bool cleanupFails)
    {
        await Run($$"""
            $definition=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Mount-WinSightData'},$true)
            Invoke-Expression $definition.Extent.Text
            $script:mounted=0;$script:dismounted=0;$injected=[IO.IOException]::new('primary partition query failure')
            function Mount-VHD($Path,[switch]$Passthru) {$script:mounted++;[pscustomobject]@{DiskNumber=1} }
            function Get-Disk {[pscustomobject]@{Number=1} }
            function Get-Partition($DiskNumber) {throw $injected}
            function Dismount-VHD($Path) {$script:dismounted++;if (${{cleanupFails.ToString().ToLowerInvariant()}}) {throw 'secondary dismount failure'} }
            $caught=$null
            try {Mount-WinSightData 'mock.vhdx'|Out-Null} catch {$caught=$_}
            if ($script:mounted -ne 1 -or $script:dismounted -ne 1) {throw 'ASSERT: partial mount resource leaked'}
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: partial mount cleanup masked original cause'}
            """);
    }

    [Theory]
    [InlineData("harness")]
    [InlineData("bootstrap")]
    [InlineData("not-started")]
    public async Task ResumeRefusesDifferentHarnessOrAnUnstartedCampaign(string mismatch)
    {
        await Run(WaitSetup + $$"""
            $candidateManifest=@('candidate-proof');$harnessManifest=@('harness-proof');$bootstrapSha256='receipt-proof'
            $runId=[guid]::NewGuid().ToString('D')
            $saved=[pscustomobject]@{version=1;candidateCommit=$candidate.commit;candidateManifest=$candidateManifest;harnessManifest=$harnessManifest;bootstrapSha256=$bootstrapSha256;root=$Root;target=$Name;control=$ControlName;checkpoint=$Checkpoint;controlCheckpoint=$ControlCheckpoint;adapters=@();memory=2GB;controlMemory=1GB;automatic=$false;runId=$runId}
            if ('{{mismatch}}' -eq 'harness') {$saved.harnessManifest=@('different-harness')}
            if ('{{mismatch}}' -eq 'bootstrap') {$saved.bootstrapSha256='different-receipt'}
            $statePath='state';$startedPath='started'
            function Get-Content($LiteralPath,[switch]$Raw) {
                if ($LiteralPath -eq $startedPath) {
                    if ('{{mismatch}}' -eq 'not-started') {throw [IO.FileNotFoundException]::new('No staged campaign')}
                    return (@{runId=$runId}|ConvertTo-Json)
                }
                return ($saved|ConvertTo-Json -Depth 6)
            }
            $initial=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Clauses[0].Item1.Extent.Text.Contains('-not $Resume')},$true)
            $refused=$false
            try {Invoke-Expression $initial.ElseClause.Extent.Text.Trim().TrimStart('{').TrimEnd('}')} catch {$refused=$true}
            if (-not $refused) {throw 'ASSERT: Resume accepted changed provenance or an unstarted campaign'}
            if ($script:copies -ne 0 -or $script:restores -ne 0 -or $script:detaches -ne 0) {throw 'ASSERT: Resume identity refusal modified the campaign'}
            """);
    }

    [Theory]
    [InlineData("candidate")]
    [InlineData("run")]
    public async Task StaleGuestResultsCannotBeSealedAsTheCurrentCampaign(string mismatch)
    {
        await Run(WaitSetup + $$"""
            $runState=[pscustomobject]@{runId=[guid]::NewGuid().ToString('D')}
            $target=[pscustomobject]@{candidate=[pscustomobject]@{commit=$candidate.commit;qualificationRunId=$runState.runId} }
            $control=[pscustomobject]@{qualificationRunId=$runState.runId}
            if ('{{mismatch}}' -eq 'candidate') {$target.candidate.commit='ffffffffffffffffffffffffffffffffffffffff'}
            if ('{{mismatch}}' -eq 'run') {$target.candidate.qualificationRunId=[guid]::NewGuid().ToString('D')}
            function Test-Path($LiteralPath) {return $LiteralPath -like '*results.json' -or $LiteralPath -like '*control-result.json'}
            function Get-Content($LiteralPath,[switch]$Raw) {if ($LiteralPath -like '*control-result.json') {return ($control|ConvertTo-Json)};return ($target|ConvertTo-Json -Depth 6)}
            $caught=$null
            try {Invoke-Expression $observationScript} catch {$caught=$_}
            if (-not $caught -or ($script:logs -join ' ').Contains('evidence sealed')) {throw 'ASSERT: stale guest bytes were attributed to the current campaign'}
            if ($script:restores -ne 0) {throw 'ASSERT: stale-result refusal destroyed recoverable evidence'}
            """);
    }

    [Fact]
    public async Task TrayGateRecordsItsActualRouteAndVerifiedExitAfterTryingTheShell()
    {
        await Run("""
            Add-Type -AssemblyName UIAutomationTypes,UIAutomationClient
            Add-Type 'public static class MockUia { public static object RootElement; public static string ControlTypeProperty="type"; public static string ClassNameProperty="class"; public static string ProcessIdProperty="pid"; public static string NameProperty="name"; } public enum MockScope { Children,Descendants }'
            $tree=New-Object PSObject
            $tree|Add-Member ScriptMethod FindAll {param($Scope,$Condition) $script:routes+='shell'; return @()}
            $tree|Add-Member ScriptMethod FindFirst {param($Scope,$Condition) return $this}
            [MockUia]::RootElement=$tree; $UIA=[MockUia]; $Scope=[MockScope]
            function New-Condition($Property,$Value) {return $null}
            function Save-Results {}
            function Start-Sleep {}
            function Get-AttributionSessions {$script:sessionChecks++;return @()}
            function Stop-Process {throw 'ASSERT: forced termination cannot prove tray exit'}
            $guest=Join-Path $env:WINSIGHT_LIFECYCLE_HARNESS 'guest\qualify.ps1'
            $guestAst=[Management.Automation.Language.Parser]::ParseFile($guest,[ref]$null,[ref]$null)
            foreach ($definition in $guestAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {Invoke-Expression $definition.Extent.Text}
            function New-Condition($Property,$Value) {return $null}
            function Save-Results {}
            function Start-Sleep {}
            function Get-AttributionSessions {$script:sessionChecks++;return @()}
            function Stop-Process {throw 'ASSERT: forced termination cannot prove tray exit'}
            $Share=Join-Path ([IO.Path]::GetTempPath()) ('winsight-tray-gate-'+[guid]::NewGuid().ToString('N'));$Evidence=$Share
            [void][IO.Directory]::CreateDirectory($Share)
            $fixture=Join-Path $Share 'operator-automation.ps1'
            [IO.File]::WriteAllText($fixture,'param($Name,$ProcessId) $script:routes+="operator"; $script:operatorPid=$ProcessId; $script:fakeExited=$true')
            $script:routes=@();$script:fakeExited=$false;$script:sessionChecks=0
            $dashboard=[pscustomobject]@{Id=4242;HasExited=$false}
            $dashboard|Add-Member ScriptMethod Refresh {$this.HasExited=$script:fakeExited}
            $Candidate=[pscustomobject]@{};$Results=[ordered]@{gates=[ordered]@{} }
            $source=Get-Content -LiteralPath $guest -Raw
            $start=$source.IndexOf('$trayExited = Invoke-TrayExit')
            $end=$source.IndexOf("`n    'single instance: second launch",$start)
            if ($start -lt 0 -or $end -le $start) {throw 'ASSERT: verified tray gate fragment missing'}
            try {
                Invoke-Gate '21-etw-dashboard-attribution' ([scriptblock]::Create($source.Substring($start,$end-$start)))|Out-Null
                $gate=$Results.gates['21-etw-dashboard-attribution']
                if ($gate.status -cne 'PASS' -or -not $dashboard.HasExited -or $script:sessionChecks -ne 1) {throw 'ASSERT: actual exit and zero-session verification failed'}
                if ($script:routes[0] -ne 'shell' -or $script:operatorPid -ne 4242) {throw 'ASSERT: shell path was skipped or wrong PID fallback'}
                if ($gate.route -cne 'guest-operator' -or $gate.exitVerified -ne $true) {throw 'ASSERT: gate omitted actual route or verified process exit'}
            }
            finally {
                foreach ($leaf in 'operator-automation.ps1','results.json','TRAY-EXIT-REQUIRED.txt') {[IO.File]::Delete((Join-Path $Share $leaf))}
                [IO.Directory]::Delete($Share)
            }
            """);
    }

    [Fact]
    public async Task ResumeCannotForgetAForcedTimeoutAfterCollectionFails()
    {
        await Run(WaitSetup + """
            $timeoutPath=Join-Path ([IO.Path]::GetTempPath()) ('winsight-timeout-'+[guid]::NewGuid().ToString('N')+'.json')
            $TimeoutMinutes=0;$script:stopped=@();$script:firstPass=$true
            function Test-Path($LiteralPath) {return [IO.File]::Exists($LiteralPath)}
            function Get-WinSightVmState($VMName) {if ($VMName -in $script:stopped) {'Off'} else {'Running'} }
            function Stop-VM($Name,[switch]$TurnOff,[switch]$Force) {$script:stopped+=$Name}
            function Get-Content($LiteralPath,[switch]$Raw) {
                if ($LiteralPath -eq $timeoutPath) {return [IO.File]::ReadAllText($timeoutPath)}
                if ($LiteralPath -like '*control-result.json') {return (@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='PASS'}|ConvertTo-Json)}
                return (@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=@{'01-identity-and-protected-root'=@{status='PASS'};'36-ipc-network-logon'=@{status='PASS'};'99-residue'=@{status='PASS'} } }|ConvertTo-Json -Depth 6)
            }
            function Copy-GuestResults($From,$To) {if ($script:firstPass) {throw [IO.IOException]::new('collection interrupted after timeout')} }
            try {
                try {Invoke-Expression $observationScript} catch {}
                if (-not [IO.File]::Exists($timeoutPath)) {throw 'ASSERT: forced timeout has no durable receipt'}
                $script:firstPass=$false;$Resume=$true;$primaryFailure=$null;$safeToRestore=$false
                Invoke-Expression $observationScript
                if (-not $timedOut) {throw 'ASSERT: Resume forgot the previous forced timeout'}
            }
            finally {[IO.File]::Delete($timeoutPath)}
            """);
    }

    [Fact]
    public async Task AnUnavailableSealDiagnosticCannotSkipRestoration()
    {
        await Run(WaitSetup + """
            function Write-HostLog($Message) {if ($Message -like 'evidence sealed*') {throw [IO.IOException]::new('logger unavailable')};$script:logs+=$Message}
            try {Invoke-Expression $observationScript} catch {}
            if ($script:copies -ne 2 -or $script:restores -ne 1) {throw 'ASSERT: completed seal diagnostic skipped restoration'}
            """);
    }

    [Theory]
    [InlineData("expected-switch")]
    [InlineData("")]
    public async Task RestorationChecksTheExactRecordedAdapterState(string expected)
    {
        await Run($$"""
            $Name='target';$ControlName='control';$Checkpoint='S0';$ControlCheckpoint='C0'
            $originalMemory=0;$originalControlMemory=0;$originalAdapters=@([pscustomobject]@{Name='network';SwitchName='{{expected}}'})
            $script:switch='wrong-switch'
            function Restore-VMCheckpoint($VMName,$Name,$Confirm) {}
            function Invoke-WinSightVmRetry([scriptblock]$Action) {& $Action}
            function Get-VMNetworkAdapter($VMName,$Name) {[pscustomobject]@{Name='network';SwitchName=$script:switch} }
            function Connect-VMNetworkAdapter($VMName,$Name,$SwitchName) {$script:switch=$SwitchName}
            function Disconnect-VMNetworkAdapter($VMName,$Name) {$script:switch=''}
            function Remove-VMNetworkAdapter {}
            Restore-BothVms
            if ($script:switch -cne '{{expected}}') {throw 'ASSERT: restored adapter differs from recorded checkpoint configuration'}
            """);
    }


    [Theory]
    [InlineData("target", false)]
    [InlineData("control", false)]
    [InlineData("both", false)]
    [InlineData("both", true)]
    public async Task ClosedCampaignWithMissingResultsIsSealedAndRestored(string missing, bool timeout)
    {
        await Run(WaitSetup + $$"""
            $work=[IO.Path]::Combine([IO.Path]::GetTempPath(), 'winsight-missing-network-'+[guid]::NewGuid().ToString('N'))
            $EvidenceRoot=$work;$runDir=[IO.Path]::Combine($work,$RunName)
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($runDir,'target'))
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($runDir,'control'))
            $targetPath=[IO.Path]::Combine($runDir,'target\results.json');$controlPath=[IO.Path]::Combine($runDir,'control\control-result.json')
            $target=@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=@{'01-identity-and-protected-root'=@{status='PASS'};'36-ipc-network-logon'=@{status='PASS'};'99-residue'=@{status='PASS'} } }
            $control=@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='PASS'}
            if ('{{missing}}' -notin 'target','both') {[IO.File]::WriteAllText($targetPath,($target|ConvertTo-Json -Depth 6))}
            if ('{{missing}}' -notin 'control','both') {[IO.File]::WriteAllText($controlPath,($control|ConvertTo-Json))}
            function Get-Content($LiteralPath,[switch]$Raw) {Microsoft.PowerShell.Management\Get-Content -LiteralPath $LiteralPath -Raw -ErrorAction Stop}
            $timeoutPath=[IO.Path]::Combine($work,'timeout.json')
            if (${{timeout.ToString().ToLowerInvariant()}}) {
                [IO.File]::WriteAllText($timeoutPath,(@{version=1;runId=$runState.runId;reason='forced-timeout'}|ConvertTo-Json))
            }
            function Test-Path($LiteralPath) {return $LiteralPath -ceq $timeoutPath -and [IO.File]::Exists($timeoutPath)}
            $script:seal=0
            function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value) {if ([IO.Path]::GetFileName($LiteralPath) -ceq 'SHA256SUMS.txt') {$script:seal++} }
            try {
                $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
                if ($caught -or $script:copies -ne 2 -or $script:detaches -ne 1 -or $script:restores -ne 1 -or $script:seal -ne 1) {throw 'ASSERT: closed missing-result campaign was not collected, sealed and restored'}
                $receiptPath=[IO.Path]::Combine($runDir,'network-missing-results.json')
                $bytes=[IO.File]::ReadAllBytes($receiptPath);$receipt=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
                if ($receipt.version -ne 1 -or $receipt.runId -cne $runState.runId -or $receipt.candidateCommit -cne $candidate.commit) {throw 'ASSERT: missing receipt is not bound to candidate/run'}
                foreach ($side in 'target','control') {
                    $expected=if ('{{missing}}' -in $side,'both') {'NOT_RUN'} else {'PASS'}
                    if ($receipt.$side.status -cne $expected) {throw 'ASSERT: missing or present side has incorrect qualification status'}
                    if ($expected -ceq 'NOT_RUN' -and $receipt.$side.reason -cne 'result-file-missing') {throw 'ASSERT: missing side lacks explicit reason'}
                }
                if ($receipt.timedOut -ne ${{timeout.ToString().ToLowerInvariant()}}) {throw 'ASSERT: timeout was forgotten in missing receipt'}
                if (Get-NetworkQualificationExitCode -Target $targetResults -Control $controlResults -TimedOut $timedOut -RefusedCount $refused.Count) { }
                else {throw 'ASSERT: a missing-result campaign returned success'}
                $code=Get-NetworkQualificationExitCode -Target $targetResults -Control $controlResults -TimedOut $timedOut -RefusedCount $refused.Count
                if ($code -ne 2) {throw 'ASSERT: missing results require exact exit2'}
                $Resume=$true;$primaryFailure=$null;$safeToRestore=$false
                Invoke-Expression $observationScript
                if ($script:restores -ne 2 -or $script:seal -ne 2 -or [Convert]::ToBase64String([IO.File]::ReadAllBytes($receiptPath)) -cne [Convert]::ToBase64String($bytes)) {throw 'ASSERT: Resume did not reuse byte-identical immutable receipt'}
                if (([IO.Directory]::GetFiles($runDir,'*.tmp')).Count -ne 0) {throw 'ASSERT: owned receipt staging leaked'}
            }
            finally {[IO.Directory]::Delete($work,$true)}
            """);
    }

    [Theory]
    [InlineData("preflight")]
    [InlineData("staging")]
    [InlineData("starting")]
    [InlineData("detaching")]
    [InlineData("restoring")]
    [InlineData("collect-target")]
    [InlineData("collect-control")]
    [InlineData("observing")]
    public async Task SecretFreeNetworkFailuresRetainTheOriginalDiagnostic(string phase)
    {
        await Run($$"""
            $script:logs=@();function Write-HostLog($Message) {$script:logs+=$Message}
            $injected=[IO.IOException]::new('native cause {{phase}}: sharing and volume failure')
            try {throw $injected} catch {Write-SafeFailure '{{phase}}' $_}
            if (-not ($script:logs -join ' ').Contains($injected.Message)) {throw 'ASSERT: non-secret native cause was erased by generic redaction'}
            """);
    }

    [Theory]
    [InlineData("envelope")]
    [InlineData("fixture")]
    public async Task OnlyActualCredentialOperationsRedactSyntheticSecretsAndRecover(string operation)
    {
        await Run($$"""
            $AutomaticCredential=$true;$script:logs=@();$script:restores=0;$script:fixtures=0;$script:secretCalls=0
            function Write-HostLog($Message) {$script:logs+=$Message}
            function Remove-StagedNetworkFixtures {$script:fixtures++}
            function Restore-BothVms {$script:restores++}
            $injected=[IO.IOException]::new('synthetic-credential-payload-never-log');$Envelope='synthetic-credential-payload-never-log';$letter='D'
            function New-NetworkProbeEnvelope {$script:secretCalls++;throw $injected}
            function Write-NetworkProbeFixture($Path,$Envelope) {$script:secretCalls++;throw $injected}
            $staging=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            if (-not $staging.Body.Extent.Text.Contains('New-NetworkProbeEnvelope')) {throw 'ASSERT: credential creation lies outside protected staging catch'}
            $call=$staging.Body.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-NetworkCredentialOperation' -and $n.Extent.Text.Contains('{{(operation == "envelope" ? "New-NetworkProbeEnvelope" : "Write-NetworkProbeFixture")}}')},$true)
            if (-not $call) {throw 'ASSERT: actual secret call site missing'}
            $caught=$null
            try {Invoke-Expression ('try {'+$call.Extent.Text+'} '+$staging.CatchClauses[0].Extent.Text)} catch {$caught=$_}
            if ($script:secretCalls -ne 1 -or $script:fixtures -ne 1 -or $script:restores -ne 1) {throw 'ASSERT: actual secret operation failure skipped independent recovery'}
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: secret boundary changed original exception identity'}
            if (($script:logs -join ' ').Contains($injected.Message) -or -not ($script:logs -join ' ').Contains('HRESULT')) {throw 'ASSERT: actual credential exception leaked or lacks safe diagnostic'}
            """);
    }

    [Theory]
    [InlineData("PASS", 0)]
    [InlineData("FAIL", 1)]
    [InlineData("NOT_RUN", 1)]
    public async Task ControlMustPassForTheNetworkCampaignToPass(string controlStatus, int expected)
    {
        await Run($$"""
            $target=[pscustomobject]@{startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=[pscustomobject]@{'01-identity-and-protected-root'=[pscustomobject]@{status='PASS'};'36-ipc-network-logon'=[pscustomobject]@{status='PASS'};'99-residue'=[pscustomobject]@{status='PASS'} } }
            $control=[pscustomobject]@{startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='{{controlStatus}}'}
            if ((Get-NetworkQualificationExitCode -Target $target -Control $control -TimedOut $false -RefusedCount 0) -ne {{expected}}) {throw 'ASSERT: control failure was ignored'}
            if ((Get-NetworkQualificationExitCode -Target $target -Control $control -TimedOut $true -RefusedCount 0) -ne 1) {throw 'ASSERT: forced-timeout campaign passed'}
            if ((Get-NetworkQualificationExitCode -Target $target -Control $control -TimedOut $false -RefusedCount 1) -ne 1) {throw 'ASSERT: refused collection campaign passed'}
            $source=Microsoft.PowerShell.Management\Get-Content -LiteralPath $driver -Raw
            if ($source -notmatch 'exit \(Get-NetworkQualificationExitCode') {throw 'ASSERT: actual driver exit does not use target/control aggregate'}
            """);
    }


    [Theory]
    [InlineData("stale", true)]
    [InlineData("malformed", true)]
    [InlineData("denied", true)]
    [InlineData("sharing", true)]
    [InlineData("stale", false)]
    [InlineData("malformed", false)]
    [InlineData("denied", false)]
    [InlineData("sharing", false)]
    public async Task MissingCounterpartNeverAuthorizesUncertainPresentResults(string failure, bool presentTarget)
    {
        await Run(WaitSetup + $$"""
            $script:receipt=0;$injected=[IO.IOException]::new('present result unreadable')
            function Get-Content($LiteralPath,[switch]$Raw) {
                $isTarget=$LiteralPath -like '*target\results.json'
                if ($isTarget -ne ${{presentTarget.ToString().ToLowerInvariant()}}) {throw [Management.Automation.ItemNotFoundException]::new('missing counterpart')}
                if ('{{failure}}' -eq 'stale') {
                    if ($isTarget) {return (@{candidate=@{commit='ffffffffffffffffffffffffffffffffffffffff';qualificationRunId=$runState.runId} }|ConvertTo-Json -Depth 6)}
                    return (@{qualificationRunId=[guid]::NewGuid().ToString('D');status='PASS'}|ConvertTo-Json)
                }
                if ('{{failure}}' -eq 'malformed') {return '{broken'}
                if ('{{failure}}' -eq 'denied') {throw [UnauthorizedAccessException]::new('denied present result')}
                throw $injected
            }
            function Write-NetworkMissingReceipt {$script:receipt++}
            $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
            if (-not $caught -or $script:restores -ne 0 -or $script:receipt -ne 0 -or ($script:logs -join ' ').Contains('evidence sealed')) {throw 'ASSERT: uncertain present evidence attributed or restored due to missing counterpart'}
            if (($script:logs -join ' ') -notmatch '-Resume') {throw 'ASSERT: uncertain result lost Resume guidance'}
            """);
    }

    [Theory]
    [InlineData("receipt")]
    [InlineData("seal")]
    public async Task FailedMissingReceiptOrSealPreservesResumeAndDoesNotRestore(string failure)
    {
        await Run(WaitSetup + $$"""
            function Get-Content($LiteralPath,[switch]$Raw) {throw [Management.Automation.ItemNotFoundException]::new('missing guest result')}

            $script:receipts=0;$script:seals=0;$injected=[IO.IOException]::new('injected unique {{failure}} failure')
            function Write-NetworkMissingReceipt {$script:receipts++;if ('{{failure}}' -eq 'receipt') {throw $injected} }
            function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value) {if ($LiteralPath -like '*SHA256SUMS.txt') {$script:seals++;if ('{{failure}}' -eq 'seal') {throw $injected} } }
            $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
            if (-not $caught -or $script:restores -ne 0 -or ($script:logs -join ' ') -notmatch '-Resume') {throw 'ASSERT: failed receipt/seal destroyed resumable evidence'}
            $expectedSeals=if ('{{failure}}' -ceq 'seal') {1} else {0}
            if ($script:receipts -ne 1 -or $script:seals -ne $expectedSeals -or -not [object]::ReferenceEquals($caught.Exception,$injected)) {throw 'ASSERT: receipt/seal failure oracle did not reach actual intended boundary'}
            """);
    }

    [Theory]
    [InlineData("foreign")]
    [InlineData("oversized")]
    [InlineData("sharing")]
    public async Task AForeignMissingReceiptIsPreservedAndCannotAuthorizeRestoration(string kind)
    {
        await Run(WaitSetup + $$"""
            $work=[IO.Path]::Combine([IO.Path]::GetTempPath(),'winsight-receipt-collision-'+[guid]::NewGuid().ToString('N'))
            $EvidenceRoot=$work;$runDir=[IO.Path]::Combine($work,$RunName);[void][IO.Directory]::CreateDirectory($runDir)
            $receiptPath=[IO.Path]::Combine($runDir,'network-missing-results.json');$foreign=if ('{{kind}}' -ceq 'oversized') {'X'*16384} else {'foreign existing receipt preserved'}
            [IO.File]::WriteAllText($receiptPath,$foreign)
            $script:actualReceipt=(Get-Command Write-NetworkMissingReceipt -ErrorAction Stop).ScriptBlock;$script:receiptCalls=0
            function Write-NetworkMissingReceipt($Path,$Receipt) {$script:receiptCalls++;& $script:actualReceipt -Path $Path -Receipt $Receipt}
            $held=if ('{{kind}}' -ceq 'sharing') {[IO.File]::Open($receiptPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)} else {$null}
            function Get-Content($LiteralPath,[switch]$Raw) {throw [Management.Automation.ItemNotFoundException]::new('missing guest result')}
            try {
                $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
                if ($held) {$held.Dispose();$held=$null}
                if (-not $caught -or $script:receiptCalls -ne 1 -or $script:restores -ne 0 -or [IO.File]::ReadAllText($receiptPath) -cne $foreign) {throw 'ASSERT: divergent receipt overwritten or restored'}
                if (([IO.Directory]::GetFiles($runDir,'*.tmp')).Count -ne 0) {throw 'ASSERT: collision leaked owned staging'}
            }
            finally {if ($held) {$held.Dispose()};[IO.Directory]::Delete($work,$true)}
            """);
    }


    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualTrapPreservesNativeStderrAndRedactsOnlyCredentialFailures(bool secret)
    {
        await Run($$"""
            $script:logs=@();function Write-HostLog($Message) {$script:logs+=$Message}
            $operationPhase='preflight';$injected=[IO.IOException]::new('trap-original-native-message-or-synthetic-secret')
            $record=$null
            if (${{secret.ToString().ToLowerInvariant()}}) {
                try {Invoke-NetworkCredentialOperation {throw $injected} } catch {$record=$_}
            }
            else {try {throw $injected} catch {$record=$_} }
            if (-not [object]::ReferenceEquals($record.Exception,$injected)) {throw 'ASSERT: boundary changed primary exception'}
            $trapAst=$ast.Find({param($n) $n -is [Management.Automation.Language.TrapStatementAst]},$true)
            if (-not $trapAst -or -not ($trapAst.Body.Statements|Where-Object {$_ -is [Management.Automation.Language.ExitStatementAst] -and $_.Extent.Text -match '^exit 1$'})) {throw 'ASSERT: actual trap does not fail closed with exit1'}
            $text=($trapAst.Body.Statements|Where-Object {$_ -isnot [Management.Automation.Language.ExitStatementAst]}|ForEach-Object {$_.Extent.Text}) -join "`n"
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error
            try {[Console]::SetError($stderr);$_=$record;. ([scriptblock]::Create($text))}
            finally {[Console]::SetError($originalError)}
            $combined=$stderr.ToString()+($script:logs -join ' ')
            if (${{secret.ToString().ToLowerInvariant()}}) {
                if ($combined.Contains($injected.Message) -or -not $combined.Contains('HRESULT')) {throw 'ASSERT: actual trap leaked credential payload or erased safe diagnostic'}
            }
            elseif (-not $stderr.ToString().Contains($injected.Message) -or -not ($script:logs -join ' ').Contains($injected.Message)) {throw 'ASSERT: actual trap erased native cause from stderr or protected log'}
            """);
    }

    [Theory]
    [InlineData("detaching")]
    [InlineData("restoring")]
    public async Task EachVmRecoveryFailureIsLoggedBeforeItsAggregate(string operation)
    {
        await Run($$"""
            $Name='target';$ControlName='control';$Checkpoint='S0';$ControlCheckpoint='C0';$data='target.vhdx';$controlData='control.vhdx'
            $script:logs=@();$script:calls=@();function Write-HostLog($Message) {$script:logs+=$Message}
            function Remove-WinSightDataDisk($VMName,$Path) {$script:calls+=$VMName;throw [IO.IOException]::new('native detach '+$VMName)}
            function Restore-VMCheckpoint($VMName,$Name,$Confirm) {$script:calls+=$VMName;throw [IO.IOException]::new('native checkpoint '+$VMName)}
            $caught=$null
            try {if ('{{operation}}' -ceq 'detaching') {Remove-DataDisks} else {Restore-BothVms} } catch {$caught=$_}
            $prefix=if ('{{operation}}' -ceq 'detaching') {'native detach '} else {'native checkpoint '}
            if (-not $caught -or ($script:calls -join ',') -cne 'target,control') {throw 'ASSERT: aggregate did not attempt both native recoveries'}
            foreach ($side in 'target','control') {if (-not ($script:logs -join ' ').Contains($prefix+$side)) {throw 'ASSERT: individual original native cause lost before aggregate'} }
            """);
    }


    [Theory]
    [InlineData("missing-status")]
    [InlineData("null-status")]
    [InlineData("array-status")]
    [InlineData("unknown-status")]
    [InlineData("array-root")]
    public async Task PresentControlWithExactIdentityStillRequiresARecognizedSchema(string schema)
    {
        await Run(WaitSetup + $$"""
            $script:receipt=0
            function Get-Content($LiteralPath,[switch]$Raw) {
                if ($LiteralPath -like '*target\results.json') {throw [Management.Automation.ItemNotFoundException]::new('missing target')}
                $control=@{qualificationRunId=$runState.runId}
                if ('{{schema}}' -ceq 'null-status') {$control.status=$null}
                if ('{{schema}}' -ceq 'array-status') {$control.status=@('PASS')}
                if ('{{schema}}' -ceq 'unknown-status') {$control.status='UNVERIFIED'}
                if ('{{schema}}' -ceq 'array-root') {$control.status='PASS';return ('['+($control|ConvertTo-Json)+']')}
                return ($control|ConvertTo-Json)
            }
            function Write-NetworkMissingReceipt {$script:receipt++}
            $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
            if (-not $caught -or $script:restores -ne 0 -or $script:receipt -ne 0 -or ($script:logs -join ' ').Contains('evidence sealed')) {throw 'ASSERT: matching identity authorized an unrecognized control schema'}
            """);
    }

    [Fact]
    public async Task TrapDiagnosticsAreAvailableBeforeTheFirstPreflightOperation()
    {
        await Run("""
            $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-SafeFailure'},$true)
            $firstPreflight=$ast.Find({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Import-Module'},$true)
            if (-not $definition -or $definition.Extent.EndOffset -gt $firstPreflight.Extent.StartOffset) {throw 'ASSERT: native trap logger unavailable during actual early preflight'}
            $trapAst=$ast.Find({param($n) $n -is [Management.Automation.Language.TrapStatementAst]},$true)
            if ($trapAst.Body.Extent.Text -notmatch 'Write-SafeFailure') {throw 'ASSERT: actual early trap omits native cause'}
            """);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task PreflightLogUsesOnlyTheVerifiedRootAndRetainsStderrIfLoggingFails(bool trusted, bool logFails)
    {
        await Run($$"""
            $script:logWrites=0;$trustedHostLog=${{trusted.ToString().ToLowerInvariant()}};$hostLog='protected-host-log'
            function Add-SharedLine($Path,$Line) {$script:logWrites++;if (${{logFails.ToString().ToLowerInvariant()}}) {throw [IO.IOException]::new('logger failed')} }
            $failure=$null;try {throw [IO.IOException]::new('original native preflight cause')} catch {$failure=$_}
            $stderr=[IO.StringWriter]::new();$originalError=[Console]::Error
            try {[Console]::SetError($stderr);Write-SafeFailure 'preflight' $failure}
            finally {[Console]::SetError($originalError)}
            if (-not $stderr.ToString().Contains($failure.Exception.Message)) {throw 'ASSERT: original preflight diagnostic lost when protected root/log unavailable'}
            $expected=if ($trustedHostLog) {1} else {0}
            if ($script:logWrites -ne $expected) {throw 'ASSERT: log touched before protected root verification or valid root not logged'}
            """);
    }


    [Theory]
    [InlineData("FAIL", false, 0, 1)]
    [InlineData("NOT_RUN", false, 0, 1)]
    [InlineData("PASS", true, 0, 1)]
    [InlineData("PASS", false, 1, 1)]
    [InlineData("PASS", false, 0, 0)]
    public async Task ActualNetworkDecisionRejectsFailedControl(string status, bool timeout, int refusedCount, int expected)
    {
        await Run(WaitSetup + $$"""
            $runDir=Join-Path $EvidenceRoot $RunName
            $timedOut=${{timeout.ToString().ToLowerInvariant()}};$refused=@();foreach ($i in 1..{{refusedCount}}) {if ({{refusedCount}} -gt 0) {$refused+='refused'} }
            $targetResults=[pscustomobject]@{candidate=[pscustomobject]@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=[pscustomobject]@{'01-identity-and-protected-root'=[pscustomobject]@{status='PASS'};'36-ipc-network-logon'=[pscustomobject]@{status='PASS'};'99-residue'=[pscustomobject]@{status='PASS'} } }
            $controlResults=[pscustomobject]@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='{{status}}'}
            function Test-Path($LiteralPath) {$true}
            function Get-Content($LiteralPath,[switch]$Raw) {if ($LiteralPath -like '*control-result.json') {return ($controlResults|ConvertTo-Json)};return ($targetResults|ConvertTo-Json -Depth 6)}
            function Write-Host {}
            $text=Microsoft.PowerShell.Management\Get-Content -LiteralPath $driver -Raw
            $start=$text.LastIndexOf('$resultsFile =')
            if ($start -lt 0) {throw 'ASSERT: actual network decision tail missing'}
            $tail=$text.Substring($start);$parsed=[Management.Automation.Language.Parser]::ParseInput($tail,[ref]$null,[ref]$null)
            $exits=@($parsed.FindAll({param($n) $n -is [Management.Automation.Language.ExitStatementAst]},$true)|Sort-Object {$_.Extent.StartOffset} -Descending)
            if (-not $exits.Count) {throw 'ASSERT: actual decision has no exit statements'}
            foreach ($exitAst in $exits) {$at=$exitAst.Extent.StartOffset;$tail=$tail.Substring(0,$at)+'return'+$tail.Substring($at+4)}
            $code=& ([scriptblock]::Create($tail))
            if ($code -isnot [int] -or $code -ne {{expected}}) {throw 'ASSERT: actual driver decision ignored control, timeout or refused evidence'}
            """);
    }

    [Fact]
    public async Task AStopThatLeavesAVmRunningNeverAuthorizesDestructiveCollection()
    {
        await Run(WaitSetup + """
            $TimeoutMinutes=0;$script:stops=0;$script:receipts=0;$script:seals=0
            $timeoutPath=[IO.Path]::Combine([IO.Path]::GetTempPath(),'winsight-stop-postcondition-'+[guid]::NewGuid().ToString('N')+'.json')
            function Get-WinSightVmState($VMName) {'Running'}
            function Stop-VM($Name,[switch]$TurnOff,[switch]$Force) {$script:stops++}
            function Write-NetworkMissingReceipt {$script:receipts++}
            function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value) {if ($LiteralPath -like '*SHA256SUMS.txt') {$script:seals++} }
            try {
                $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
                if (-not $caught -or $script:stops -ne 1 -or $script:detaches -ne 0 -or $script:copies -ne 0 -or $script:receipts -ne 0 -or $script:seals -ne 0 -or $script:restores -ne 0 -or ($script:logs -join ' ') -notmatch '-Resume') {throw 'ASSERT: still-running VM authorized destructive recovery or lost Resume'}
            }
            finally {[IO.File]::Delete($timeoutPath)}
            """);
    }

    private const string WaitSetup = """
        $Name='target';$ControlName='control';$data='target.vhdx';$controlData='control.vhdx'
        $Root='mock';$EvidenceRoot='mock';$RunName='regression-run';$HarnessDir='mock';$CandidateDir='mock';$BootstrapReceipt='mock';$Resume=$false;$AutomaticCredential=$false;$TimeoutMinutes=1
        $candidate=[pscustomobject]@{commit='0123456789abcdef0123456789abcdef01234567'}
        $runState=[pscustomobject]@{runId=[guid]::NewGuid().ToString('D')}
        $script:copies=0;$script:mounts=0;$script:restores=0;$script:detaches=0;$script:fixtureRemovals=0;$script:events=@();$script:logs=@()
        function Get-WinSightVmState($VMName) {'Off'}
        function Invoke-WinSightVmRetry([scriptblock]$Action) {& $Action}
        function Remove-DataDisks {$script:detaches++}
        function Restore-BothVms {$script:restores++}
        function Mount-WinSightData($Disk) {$script:mounts++;'D'}
        function Dismount-WinSightData($Disk) {}
        function Remove-NetworkProbeFixture($Path) {$script:fixtureRemovals++;$script:events+='cleanup'}
        function Copy-GuestResults($From,$To) {$script:copies++;$script:events+='copy'}
        function Test-Path($LiteralPath) {$false}
        function New-Item($ItemType,$Path,[switch]$Force) {}
        function Assert-ProtectedPath($Path,[switch]$Recurse) {}
        function Get-FileManifest($Path) {}
        function Get-Content($LiteralPath,[switch]$Raw) {
            if ($LiteralPath -like '*control-result.json') {return (@{qualificationRunId=$runState.runId;startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');status='PASS'}|ConvertTo-Json)}
            return (@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId};startedUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');finishedUtc=[DateTime]::UtcNow.ToString('o');gates=@{'01-identity-and-protected-root'=@{status='PASS'};'36-ipc-network-logon'=@{status='PASS'};'99-residue'=@{status='PASS'} } }|ConvertTo-Json -Depth 6)
        }
        function Get-ChildItem($LiteralPath,[switch]$Recurse,[switch]$File) {}
        function Copy-Item($LiteralPath,$Destination) {}
        function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value) {}
        # Observe the semantic seal boundary through the same existing checksum/failure counters.
        function Write-WinSightQualificationSeal($RunDir,$SealPath) {Set-Content -LiteralPath ([IO.Path]::Combine($RunDir,'SHA256SUMS.txt'))}
        function Write-HostLog($Message) {$script:logs+=$Message}
        $wait=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('$deadline = $started.AddMinutes')},$true)
        if (-not $wait) {throw 'ASSERT: campaign observation block missing'}
        $failureReturn=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if ($primaryFailure)')},$true)
        $observationScript=$wait.Extent.Text+"`n"+$failureReturn.Extent.Text;
        """;

    private async Task Run(string script, string driverFile = "Invoke-HyperVNetworkLogon.ps1")
    {
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.Environment["PSModulePath"] = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "Modules");
        start.Environment["WINSIGHT_LIFECYCLE_HARNESS"] = Harness;
        start.Environment["WINSIGHT_LIFECYCLE_DRIVER"] = driverFile;
        var command = PowerShellProcessEvidence.Prelude + """
            $ErrorActionPreference='Stop'
            $driver=[IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,$env:WINSIGHT_LIFECYCLE_DRIVER)
            $errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseFile($driver,[ref]$null,[ref]$errors)
            if ($errors.Count) {throw 'Driver parse failed'}
            $moduleAst=[Management.Automation.Language.Parser]::ParseFile(([IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,'WinSightHyperV.psm1')),[ref]$null,[ref]$errors)
            if ($errors.Count) {throw 'Module parse failed'}
            Write-TestPhase 'parsed'
            foreach ($definition in $moduleAst.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {. ([scriptblock]::Create($definition.Extent.Text))}
            foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {. ([scriptblock]::Create($definition.Extent.Text))}
            Write-TestPhase 'definitions-loaded'
            Write-TestPhase 'body-begin'
            """ + "\n" + script + "\nWrite-TestPhase 'body-end'\nexit 0";
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.True(result.ExitCode == 0, $"PowerShell assertion failed: {result.Stdout}\n{result.Stderr}");
    }
}
