using System.Diagnostics;
using System.Text;

using Xunit;

namespace WinSight.Application.Tests;

[Collection(QualificationPowerShellCollection.Name)]
public sealed class NetworkQualificationLifecycleRegressionTests
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
    public async Task StagingPreservesTheOriginalCauseWithoutLoggingArbitrarySecretText()
    {
        await Run("""
            $script:logs=@(); $script:restores=0; $AutomaticCredential=$true
            function Write-HostLog($Message) { $script:logs += $Message }
            function Remove-StagedNetworkFixtures { throw 'secondary cleanup failure' }
            function Restore-BothVms { $script:restores++ }
            $clause=$ast.Find({param($n) $n -is [Management.Automation.Language.CatchClauseAst] -and
                $n.Parent.Body.Extent.Text.Contains('Clear-WinSightDataVolume')},$true)
            if (-not $clause) { throw 'ASSERT: staging catch missing' }
            $injected=[IO.IOException]::new('secret-fixture-value-never-log-me')
            $caught=$null
            try { Invoke-Expression ('try { throw $injected } '+$clause.Extent.Text) } catch { $caught=$_ }
            if (-not [object]::ReferenceEquals($caught.Exception,$injected)) { throw 'ASSERT: original staging cause masked' }
            if ($script:restores -ne 1) { throw 'ASSERT: restoration skipped after cleanup failure' }
            if (-not ($script:logs -join ' ').Contains('IOException') -or ($script:logs -join ' ').Contains('secret-fixture-value-never-log-me')) { throw 'ASSERT: staging diagnostic missing or leaks arbitrary message' }
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
            $Candidate=[pscustomobject]@{};$Results=[ordered]@{gates=[ordered]@{}}
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
            function Get-WinSightVmState($VMName) {if ($VMName -in $script:stopped) {'Off'} else {'Running'}}
            function Stop-VM($Name,[switch]$TurnOff,[switch]$Force) {$script:stopped+=$Name}
            function Get-Content($LiteralPath,[switch]$Raw) {
                if ($LiteralPath -eq $timeoutPath) {return [IO.File]::ReadAllText($timeoutPath)}
                if ($LiteralPath -like '*control-result.json') {return (@{qualificationRunId=$runState.runId}|ConvertTo-Json)}
                return (@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId} }|ConvertTo-Json -Depth 6)
            }
            function Copy-GuestResults($From,$To) {if ($script:firstPass) {throw [IO.IOException]::new('collection interrupted after timeout')}}
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
            if ($LiteralPath -like '*control-result.json') {return (@{qualificationRunId=$runState.runId}|ConvertTo-Json)}
            return (@{candidate=@{commit=$candidate.commit;qualificationRunId=$runState.runId} }|ConvertTo-Json -Depth 6)
        }
        function Get-ChildItem($LiteralPath,[switch]$Recurse,[switch]$File) {}
        function Copy-Item($LiteralPath,$Destination) {}
        function Set-Content($LiteralPath,[Parameter(ValueFromPipeline=$true)]$Value) {}
        function Write-HostLog($Message) {$script:logs+=$Message}
        $wait=$ast.Find({param($n) $n -is [Management.Automation.Language.TryStatementAst] -and $n.Body.Extent.Text.Contains('$deadline = $started.AddMinutes')},$true)
        if (-not $wait) {throw 'ASSERT: campaign observation block missing'}
        $failureReturn=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if ($primaryFailure)')},$true)
        $observationScript=$wait.Extent.Text+"`n"+$failureReturn.Extent.Text;
        """;

    private static async Task Run(string script)
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
        var command = """
            $ErrorActionPreference='Stop'
            $driver=Join-Path $env:WINSIGHT_LIFECYCLE_HARNESS 'Invoke-HyperVNetworkLogon.ps1'
            $errors=$null
            $ast=[Management.Automation.Language.Parser]::ParseFile($driver,[ref]$null,[ref]$errors)
            if ($errors.Count) {throw 'Driver parse failed'}
            $moduleAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:WINSIGHT_LIFECYCLE_HARNESS 'WinSightHyperV.psm1'),[ref]$null,[ref]$errors)
            if ($errors.Count) {throw 'Module parse failed'}
            $heartbeat=$moduleAst.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-WinSightDriverHeartbeat'},$true)
            if ($heartbeat) {Invoke-Expression $heartbeat.Extent.Text}
            foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {Invoke-Expression $definition.Extent.Text}
            """ + "\n" + script + "\nexit 0";
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) })
        {
            start.ArgumentList.Add(argument);
        }
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
        Assert.True(process.ExitCode == 0, $"PowerShell assertion failed: {await stdout}\n{await stderr}");
    }
}
