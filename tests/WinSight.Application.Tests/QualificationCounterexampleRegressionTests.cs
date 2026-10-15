using Xunit;

namespace WinSight.Application.Tests;

public sealed partial class NetworkQualificationLifecycleRegressionTests
{
    [Fact]
    public async Task AtomicQualificationSealerReusesIdenticalBytesAndRefusesForeignSeals()
    {
        await Run(SyntheticTree + """
            function Assert-ProtectedPath {}
            try {
                [IO.File]::WriteAllText([IO.Path]::Combine($to,'synthetic.txt'),'ordinary evidence')
                Write-WinSightQualificationSeal -RunDir $to
                $path=[IO.Path]::Combine($to,'SHA256SUMS.txt');$before=[IO.File]::ReadAllBytes($path)
                Write-WinSightQualificationSeal -RunDir $to
                if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($before)) {throw 'ASSERT: atomic seal changed on identical Resume'}
                [IO.File]::WriteAllText($path,'synthetic foreign checksum preserved')
                $caught=$null;try {Write-WinSightQualificationSeal -RunDir $to} catch {$caught=$_}
                if (-not $caught -or [IO.File]::ReadAllText($path) -cne 'synthetic foreign checksum preserved') {throw 'ASSERT: foreign checksum was overwritten or accepted'}
                if ([IO.Directory]::GetFiles($to,'.campaign-*.tmp').Count -ne 0) {throw 'ASSERT: failed seal publication leaked an owned temporary'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Fact]
    public async Task GuestCollectionNeverReadsThroughACandidateAncestorJunction()
    {
        await Run(SyntheticTree + """
            $external=[IO.Path]::Combine($work,'synthetic-external','guest-results')
            $transport=[IO.Path]::Combine($work,'transport');[void][IO.Directory]::CreateDirectory($external);[void][IO.Directory]::CreateDirectory($transport)
            [IO.File]::WriteAllText([IO.Path]::Combine($external,'synthetic-canary.txt'),'authorized synthetic canary')
            $junction=[IO.Path]::Combine($transport,'candidate')
            [void](New-Item -ItemType Junction -Path $junction -Target ([IO.Path]::GetDirectoryName($external)))
            try {
                $caught=$null;$refused=@()
                try {$refused=@(Copy-GuestResults -From ([IO.Path]::Combine($junction,'guest-results')) -To $to)} catch {$caught=$_}
                if ([IO.File]::Exists([IO.Path]::Combine($to,'synthetic-canary.txt')) -or (-not $caught -and $refused.Count -eq 0)) {throw 'ASSERT: collection followed a guest-controlled ancestor junction outside the transport'}
            }
            finally {
                if (-not ([IO.File]::GetAttributes($junction) -band [IO.FileAttributes]::ReparsePoint)) {throw 'ASSERT: expected owned junction missing during cleanup'}
                [IO.Directory]::Delete($junction)
                Remove-SyntheticTree
            }
            """);
    }

    [Fact]
    public async Task NetworkCampaignExpiredResumeWithoutAForcedTimeoutReceiptCanRecoverButCannotPass()
    {
        await Run(WaitSetup + SyntheticTree + """
            $EvidenceRoot=$work;$runDir=[IO.Path]::Combine($work,$RunName);[void][IO.Directory]::CreateDirectory($runDir)
            $Resume=$true;$TimeoutMinutes=0;$timeoutPath=[IO.Path]::Combine($work,'no-forced-timeout.json')
            $campaignLease=[pscustomobject]@{State=[pscustomobject]@{deadlineUtc=[DateTime]::UtcNow.AddMinutes(-1).ToString('o');stage='starting';timedOut=$false;observationIncomplete=$false}}
            function Set-WinSightCampaignStage($Lease,$Stage,[switch]$ObservationIncomplete,[switch]$TimedOut) {$Lease.State.stage=$Stage;if ($ObservationIncomplete) {$Lease.State.observationIncomplete=$true};if ($TimedOut) {$Lease.State.timedOut=$true}}
            function Copy-Item($LiteralPath,$Destination) {if ($LiteralPath -ceq $timeoutPath -and -not [IO.File]::Exists($LiteralPath)) {throw [IO.FileNotFoundException]::new('No forced-timeout receipt exists')} }
            try {
                $caught=$null;try {Invoke-Expression $observationScript} catch {$caught=$_}
                if ($caught -or $script:copies -ne 2 -or $script:restores -ne 1 -or -not $timedOut) {throw 'ASSERT: expired unobserved campaign cannot recover or was allowed to pass'}
                if ([IO.File]::Exists($timeoutPath)) {throw 'ASSERT: a forced-timeout receipt was fabricated for a guest already Off'}
                $gap=[IO.File]::ReadAllText([IO.Path]::Combine($runDir,'network-observation-gap.json'))|ConvertFrom-Json
                if ($gap.runId -cne $runState.runId -or $gap.status -cne 'NOT_RUN' -or $gap.reason -cne 'deadline-observation-missing') {throw 'ASSERT: observation gap lacks truthful campaign provenance'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Fact]
    public async Task MissingFullReceiptReusesIdenticalBytesAndPreservesForeignEvidence()
    {
        await Run(SyntheticTree + """
            $runDir=$to;$fullResults=$null;$candidate=[pscustomobject]@{commit=('a'*40)};$runState=[pscustomobject]@{runId='607e8783-cd27-42f1-bf50-1206284601e8'}
            function Assert-ProtectedPath {}
            $block=$ast.Find({param($n) $n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if ($null -eq $fullResults)')},$true)
            if (-not $block) {throw 'ASSERT: actual full missing receipt boundary missing'}
            try {
                Invoke-Expression $block.Extent.Text
                $path=[IO.Path]::Combine($runDir,'missing-results.json');$before=[IO.File]::ReadAllText($path)
                Invoke-Expression $block.Extent.Text
                if ([IO.File]::ReadAllText($path) -cne $before) {throw 'ASSERT: identical full receipt changed on Resume'}
                [IO.File]::WriteAllText($path,'synthetic foreign receipt preserved')
                $caught=$null;try {Invoke-Expression $block.Extent.Text} catch {$caught=$_}
                if (-not $caught -or [IO.File]::ReadAllText($path) -cne 'synthetic foreign receipt preserved') {throw 'ASSERT: foreign full receipt was adopted or overwritten'}
            }
            finally {Remove-SyntheticTree}
            """, "Invoke-HyperVQualification.ps1");
    }

    [Theory]
    [InlineData("entry")]
    [InlineData("depth")]
    public async Task CandidateStagingStopsAtAnExplicitEntryOrDepthBound(string kind)
    {
        await Run(SyntheticTree + "$kind='" + kind + "';" + """
            $runner=[Management.Automation.Language.Parser]::ParseFile([IO.Path]::Combine($env:WINSIGHT_LIFECYCLE_HARNESS,'WinSightQualRunner.ps1'),[ref]$null,[ref]$null)
            $method=$runner.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Get-BoundedStagingFiles'},$true)
            if (-not $method) {throw 'ASSERT: bounded staging walker missing'}
            . ([scriptblock]::Create($method.Extent.Text))
            try {
                if ($kind -ceq 'entry') {foreach ($n in 1..2002) {[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($from,('ignored-'+$n)))} }
                else {$path=[IO.Path]::Combine($from,'source','scripts');foreach ($n in 1..18) {$path=[IO.Path]::Combine($path,'d')};[void][IO.Directory]::CreateDirectory($path)}
                $caught=$null;try {Get-BoundedStagingFiles -SourceRoot $from|Out-Null} catch {$caught=$_}
                if (-not $caught -or -not $caught.Exception.Message.Contains($kind+' limit')) {throw 'ASSERT: staging traversal did not stop at its explicit resource bound'}
            }
            finally {Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData("unknown-version")]
    [InlineData("unknown-field")]
    [InlineData("duplicate-member")]
    [InlineData("foreign-root")]
    [InlineData("invalid-deadline")]
    [InlineData("closed-without-seal")]
    [InlineData("idle-with-active-data")]
    [InlineData("oversized")]
    public async Task CampaignOwnershipRejectsCorruptStateWithoutChangingItsBytes(string kind)
    {
        await Run(SyntheticTree + "$kind='" + kind + "';" + """
            function Assert-ProtectedPath {}
            function New-ProtectedDirectory($Path) {[void][IO.Directory]::CreateDirectory($Path)}
            $lease=$null
            try {
                Initialize-WinSightCampaignOwnership -Root $from
                $contract=[ordered]@{version=1;kind='network';runName='synthetic-state';candidateDigest=('a'*64)}
                $lease=Enter-WinSightCampaign -Root $from -Contract $contract
                $state=$lease.State;$lease.Handle.Dispose();$lease=$null
                switch ($kind) {
                    'unknown-version' {$state.version=2}
                    'unknown-field' {$state|Add-Member unexpected $true}
                    'foreign-root' {$state.root='D:\OTHER-SYNTHETIC-ROOT'}
                    'invalid-deadline' {$state.stage='starting';$state.deadlineUtc='not-a-deadline'}
                    'closed-without-seal' {$state.status='Closed';$state.stage='recovered'}
                    'idle-with-active-data' {$state.status='Idle'}
                }
                $text=$state|ConvertTo-Json -Depth 12 -Compress
                if ($kind -ceq 'duplicate-member') {$text=$text.Replace('"version":1','"version":1,"VERSION":1')}
                if ($kind -ceq 'oversized') {$text='X'*8193}
                $path=[IO.Path]::Combine($from,'host-campaign','state.json');[IO.File]::WriteAllText($path,$text,[Text.UTF8Encoding]::new($false))
                $caught=$null;try {$lease=Enter-WinSightCampaign -Root $from -Contract $contract -Resume} catch {$caught=$_}
                if ($lease) {$lease.Handle.Dispose();$lease=$null}
                if (-not $caught -or [IO.File]::ReadAllText($path) -cne $text) {throw 'ASSERT: corrupt state was adopted, changed or did not fail closed'}
            }
            finally {if ($lease) {$lease.Handle.Dispose()};Remove-SyntheticTree}
            """);
    }

    [Theory]
    [InlineData(536870912L)]
    [InlineData(1073741824L)]
    [InlineData(34359738368L)]
    [InlineData(68719476736L)]
    public async Task CheckpointResourceStateRoundTripsAcrossValidPositiveMemorySizes(long bytes)
    {
        await Run(SyntheticTree + "$memory=[long]'" + bytes.ToString(System.Globalization.CultureInfo.InvariantCulture) + "';" + """
            function Assert-ProtectedPath {}
            function New-ProtectedDirectory($Path) {[void][IO.Directory]::CreateDirectory($Path)}
            $lease=$null
            try {
                Initialize-WinSightCampaignOwnership -Root $from
                $contract=[ordered]@{version=1;kind='qualification';runName='memory-state'}
                $lease=Enter-WinSightCampaign -Root $from -Contract $contract
                $lease.State.resources=[pscustomobject]@{memory=$memory}
                Set-WinSightCampaignStage -Lease $lease -Stage starting -TimeoutMinutes 5
                $nonce=$lease.RunId;$lease.Handle.Dispose();$lease=$null
                $lease=Enter-WinSightCampaign -Root $from -Contract $contract -Resume
                if ($lease.RunId -cne $nonce -or $lease.State.resources.memory -ne $memory -or -not $lease.State.deadlineUtc.EndsWith('Z')) {throw 'ASSERT: host-produced checkpoint state could not be resumed exactly'}
            }
            finally {if ($lease) {$lease.Handle.Dispose()};Remove-SyntheticTree}
            """);
    }
}
