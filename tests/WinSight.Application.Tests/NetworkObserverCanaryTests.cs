using Xunit;
using Xunit.Abstractions;

namespace WinSight.Application.Tests;

public sealed class NetworkObserverCanaryTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("winsight-observer-").FullName;
    private static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));

    [Fact]
    public Task UnavailablePreCanaryForbidsReadiness() => Observer("pre-failure");

    [Fact]
    public Task UnavailablePostCanaryForbidsSuccess() => Observer("post-failure");

    [Fact]
    public Task StoppedScmForbidsReadiness() => Observer("bad-before");

    [Theory]
    [InlineData("success")]
    [InlineData("bad-after")]
    [InlineData("wrong-completion")]
    [InlineData("no-completion")]
    public Task ObserverRetainsIdentityAndFreshnessChecks(string scenario) => Observer(scenario);

    private Task Observer(string scenario) => Run(scenario, """
        $path=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_ROOT,'scripts','Test-IpcNetworkObserver.ps1')
        $ast=Parse-Script $path
        Load-Functions $ast
        $tries=@($ast.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $_.Finally.Extent.Text.Contains('$identity.Dispose()')})
        if ($tries.Count -ne 1) {throw 'SETUP: unique observer identity try missing'}
        $statements=@($tries[0].Body.Statements)
        $anchors=@($statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -eq 'resolvedServicePath'})
        if ($anchors.Count -ne 1) {throw 'SETUP: observer core anchor missing'}
        $source=$ast.Extent.Text
        $core=$source.Substring($anchors[0].Extent.StartOffset,$statements[-1].Extent.EndOffset-$anchors[0].Extent.StartOffset)
        if (-not $core.Contains("Result = 'READY'") -or -not $core.Contains("Result = 'PASS'")) {throw 'SETUP: source verdicts omitted'}
        $ServicePath='D:\fixture\service.exe';$CliPath='D:\fixture\winsight.exe'
        $ObservationId=[guid]::NewGuid().ToString('N')
        $ReadyPath=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_FOLDER,'ready.json')
        $CompletionSignalPath=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_FOLDER,'complete.json')
        $ResultPath=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_FOLDER,'result.json')
        $TimeoutSeconds=10
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'no-completion') {$TimeoutSeconds=-1}
        $completionId=$ObservationId
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'wrong-completion') {$completionId=[guid]::NewGuid().ToString('N')}
        if ($env:WINSIGHT_OBSERVER_SCENARIO -ne 'no-completion') {
            [IO.File]::WriteAllText($CompletionSignalPath,([ordered]@{SchemaVersion=1;ObservationId=$completionId;Stage='COMPLETE';Utc=[DateTime]::UtcNow.ToString('O')}|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
        }
        $script:writes=@();$script:events=@();$script:canaries=0;$script:scm=0
        function Resolve-Path($LiteralPath) {
            if ($LiteralPath -cne $ServicePath -and $LiteralPath -cne $CliPath) {throw 'SETUP: unexpected selected path'}
            [pscustomobject]@{Path=$LiteralPath}
        }
        function Get-CimInstance($ClassName,$Filter,$ErrorAction) {
            $script:scm++;$script:events+='SCM'
            $state='Running';$pidValue=42
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'bad-before' -and $script:scm -eq 1) {$state='Stopped'}
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'bad-after' -and $script:scm -eq 2) {$pidValue=43}
            [pscustomobject]@{State=$state;ProcessId=$pidValue;PathName=('"{0}" run' -f $ServicePath)}
        }
        # Present on the old baseline too: missing-command errors cannot supply RED.
        function Invoke-ReadOnlyIpcProbe($CliPath) {
            if ($CliPath -cne 'D:\fixture\winsight.exe') {throw 'ASSERT: selected CLI changed'}
            $script:canaries++;$script:events+='CANARY'
            if (($env:WINSIGHT_OBSERVER_SCENARIO -eq 'pre-failure' -and $script:canaries -eq 1) -or
                ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'post-failure' -and $script:canaries -eq 2)) {throw 'CANARY_UNAVAILABLE'}
        }
        function Write-JsonEvidence($Value,$Path) {
            $script:writes+=($Value|ConvertTo-Json -Depth 4 -Compress|ConvertFrom-Json)
            $script:events+=[string]$Value.Result
        }
        $failure=$null
        try {. ([scriptblock]::Create($core))} catch {$failure=$_}
        $readyCount=@($script:writes|Where-Object {$_.Result -eq 'READY'}).Count
        $passCount=@($script:writes|Where-Object {$_.Result -eq 'PASS'}).Count
        switch ($env:WINSIGHT_OBSERVER_SCENARIO) {
            'pre-failure' {
                if ($readyCount -ne 0 -or $passCount -ne 0) {throw 'ASSERT: unavailable pre-canary published READY/PASS'}
                if ($script:canaries -ne 1 -or $failure.Exception.Message -notmatch 'CANARY_UNAVAILABLE') {throw 'ASSERT: pre-canary failure not preserved'}
            }
            'post-failure' {
                if ($passCount -ne 0) {throw 'ASSERT: unavailable post-canary published PASS'}
                if ($readyCount -ne 1 -or $script:canaries -ne 2 -or $failure.Exception.Message -notmatch 'CANARY_UNAVAILABLE') {throw 'ASSERT: post-canary failure not preserved'}
            }
            'success' {
                if ($failure) {throw $failure}
                if ($readyCount -ne 1 -or $passCount -ne 1 -or $script:canaries -ne 2) {throw 'ASSERT: two positive observations missing'}
                if (($script:events -join ',') -cne 'SCM,CANARY,READY,SCM,CANARY,PASS') {throw 'ASSERT: observation order changed'}
                foreach($receipt in $script:writes) {if ($receipt.ObservationId -cne $ObservationId -or $receipt.SchemaVersion -ne 1) {throw 'ASSERT: unbound evidence'}}
            }
            'bad-before' {
                Assert-ExpectedFailure $failure 'WinSightFirewall is not running before the Network-logon probe.'
                if ($readyCount -ne 0 -or $passCount -ne 0 -or $script:canaries -ne 0) {throw 'ASSERT: bad SCM before accepted'}
            }
            'bad-after' {
                Assert-ExpectedFailure $failure 'The denied Network-logon attempt did not preserve the exact running service instance.'
                if ($readyCount -ne 1 -or $passCount -ne 0 -or $script:canaries -ne 1) {throw 'ASSERT: changed SCM after accepted'}
            }
            default {
                $expected=if($env:WINSIGHT_OBSERVER_SCENARIO -eq 'wrong-completion') {'Network observer receipt rejected.'} else {'Timed out waiting for the Network-logon probe completion signal.'}
                Assert-ExpectedFailure $failure $expected
                if ($readyCount -ne 1 -or $passCount -ne 0) {throw 'ASSERT: completion failure accepted'}
            }
        }
        """);

    [Theory]
    [InlineData("success")]
    [InlineData("unavailable")]
    [InlineData("bad-exit")]
    [InlineData("stderr")]
    [InlineData("extra-line")]
    [InlineData("malformed")]
    [InlineData("oversized")]
    [InlineData("timeout")]
    public Task CanaryRequiresTheExactReadOnlyRecord(string scenario) => Run(scenario, """
        $ast=Parse-Script ([IO.Path]::Combine($env:WINSIGHT_OBSERVER_ROOT,'scripts','Test-IpcNetworkObserver.ps1'))
        Load-Functions $ast
        if (-not (Get-Command Invoke-ReadOnlyIpcProbe -ErrorAction SilentlyContinue)) {throw 'SETUP: additive canary API absent'}
        $script:launches=0
        function Invoke-IpcProbeProcess($CliPath) {
            $script:launches++
            if ($CliPath -cne 'D:\fixture\winsight.exe') {throw 'ASSERT: selected CLI changed'}
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'timeout') {throw [TimeoutException]::new('fixture timeout')}
            $value=[pscustomobject]@{ExitCode=0;Stdout="[IPC_READONLY] schema=1 command=GetStatus serviceAvailable=true mutation=none`r`n";Stderr=''}
            switch($env:WINSIGHT_OBSERVER_SCENARIO) {
                'unavailable' {$value.Stdout=$value.Stdout.Replace('true','false');$value.ExitCode=11}
                'bad-exit' {$value.ExitCode=11}
                'stderr' {$value.Stderr='fixture error'}
                'extra-line' {$value.Stdout+="extra`n"}
                'malformed' {$value.Stdout='{}'}
                'oversized' {$value.Stdout='x'*1025}
            }
            $value
        }
        $failure=$null
        try {Invoke-ReadOnlyIpcProbe -CliPath 'D:\fixture\winsight.exe'} catch {$failure=$_}
        if ($script:launches -ne 1) {throw 'ASSERT: canary retried or never launched'}
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'success') {if ($failure) {throw $failure}}
        else {
            $expected=if($env:WINSIGHT_OBSERVER_SCENARIO -eq 'timeout') {'fixture timeout'} else {'Read-only IPC canary failed.'}
            Assert-ExpectedFailure $failure $expected
        }
        """);

    [Theory]
    [InlineData("valid")]
    [InlineData("array")]
    [InlineData("duplicate")]
    [InlineData("wrong-id")]
    [InlineData("unknown-schema")]
    [InlineData("unknown-field")]
    [InlineData("partial")]
    [InlineData("oversized")]
    [InlineData("invalid-utf8")]
    public Task ReceiptReaderRejectsForeignOrMalformedBytes(string scenario) => Run(scenario, """
        $ast=Parse-Script ([IO.Path]::Combine($env:WINSIGHT_OBSERVER_ROOT,'scripts','Test-IpcNetworkObserver.ps1'))
        Load-Functions $ast
        if (-not (Get-Command Read-NetworkObservation -ErrorAction SilentlyContinue)) {throw 'SETUP: additive receipt API absent'}
        $id=[guid]::NewGuid().ToString('N')
        $value=[ordered]@{SchemaVersion=1;ObservationId=$id;Stage='COMPLETE';Utc=[DateTime]::UtcNow.ToString('O')}
        switch($env:WINSIGHT_OBSERVER_SCENARIO) {
            'wrong-id' {$value.ObservationId=[guid]::NewGuid().ToString('N')}
            'unknown-schema' {$value.SchemaVersion=2}
            'unknown-field' {$value.Foreign='value'}
            'partial' {$value.Remove('Utc')}
        }
        $raw=$value|ConvertTo-Json -Compress
        switch($env:WINSIGHT_OBSERVER_SCENARIO) {
            'array' {$raw='['+$raw+']'}
            'duplicate' {$raw=$raw.Replace('"SchemaVersion":1','"SchemaVersion":1,"SchemaVersion":1')}
            'oversized' {$raw='x'*4097}
        }
        $path=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_FOLDER,'receipt.json')
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'invalid-utf8') {[IO.File]::WriteAllBytes($path,[byte[]]@(255,255))}
        else {[IO.File]::WriteAllText($path,$raw,[Text.UTF8Encoding]::new($false))}
        $failure=$null
        try {$receipt=Read-NetworkObservation -Path $path -ObservationId $id -Stage 'COMPLETE'} catch {$failure=$_}
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'valid') {
            if ($failure) {throw $failure}
            if ($receipt.ObservationId -cne $id -or $receipt.Stage -cne 'COMPLETE') {throw 'ASSERT: receipt changed'}
        } else {Assert-ExpectedFailure $failure 'Network observer receipt rejected.'}
        """);

    [Fact]
    public Task ReceiptPublicationNeverReplacesExistingEvidence() => Run("immutable", """
        $ast=Parse-Script ([IO.Path]::Combine($env:WINSIGHT_OBSERVER_ROOT,'scripts','Test-IpcNetworkObserver.ps1'))
        Load-Functions $ast
        $path=[IO.Path]::Combine($env:WINSIGHT_OBSERVER_FOLDER,'immutable.json')
        $value=[ordered]@{SchemaVersion=1;ObservationId=[guid]::NewGuid().ToString('N');Stage='COMPLETE';Utc=[DateTime]::UtcNow.ToString('O')}
        Write-JsonEvidence $value $path
        $before=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
        $value.ObservationId=[guid]::NewGuid().ToString('N')
        $failure=$null
        try {Write-JsonEvidence $value $path} catch {$failure=$_}
        if (-not $failure) {throw 'ASSERT: existing evidence overwritten'}
        if ($failure.Exception.Message -match 'SETUP:|not recognized|parameter cannot') {throw $failure}
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne $before) {throw 'ASSERT: original evidence changed'}
        if (@([IO.Directory]::GetFiles($env:WINSIGHT_OBSERVER_FOLDER)).Count -ne 1) {throw 'ASSERT: unpublished temporary evidence leaked'}
        """);

    [Theory]
    [InlineData("success")]
    [InlineData("stale-ready")]
    [InlineData("stale-result")]
    [InlineData("failed")]
    [InlineData("stopped")]
    [InlineData("running")]
    [InlineData("missing-remote-token")]
    public Task GuestRequiresFreshCompletedObserver(string scenario) => Run(scenario, GuestScript);

    private const string GuestScript = """
        $ast=Parse-Script ([IO.Path]::Combine($env:WINSIGHT_OBSERVER_ROOT,'scripts','validation','hyperv','guest','qualify.ps1'))
        Load-Functions $ast
        $gates=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Gate' -and $n.CommandElements[1].Extent.Text -eq "'36-ipc-network-logon'"},$true))
        if ($gates.Count -ne 1) {throw 'SETUP: network gate missing'}
        $blocks=@($gates[0].CommandElements|Where-Object {$_ -is [Management.Automation.Language.ScriptBlockExpressionAst]})
        $tries=@($blocks[0].ScriptBlock.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.TryStatementAst] -and $null -ne $_.Finally})
        if ($tries.Count -ne 1) {throw 'SETUP: network staging try missing'}
        $statements=@($tries[0].Body.Statements)
        $anchors=@($statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -eq 'ready'})
        if ($anchors.Count -ne 1) {throw 'SETUP: guest ready anchor missing'}
        # Include every preceding assignment from observationId onwards when introduced.
        $start=$anchors[0].Extent.StartOffset
        $nonce=@($statements|Where-Object {$_ -is [Management.Automation.Language.AssignmentStatementAst] -and $_.Left -is [Management.Automation.Language.VariableExpressionAst] -and $_.Left.VariablePath.UserPath -eq 'observationId'})
        if ($nonce.Count -gt 1) {throw 'SETUP: ambiguous observation nonce'}
        if ($nonce.Count -eq 1) {$start=$nonce[0].Extent.StartOffset}
        $core=$ast.Extent.Text.Substring($start,$statements[-1].Extent.EndOffset-$start)
        if (-not $core.Contains('S-1-5-2=true') -or -not $core.Contains('serviceAvailable=false')) {throw 'SETUP: final predicates omitted'}
        $Evidence=$env:WINSIGHT_OBSERVER_FOLDER;$Source=$env:WINSIGHT_OBSERVER_ROOT
        $script:PackageRoot=$Evidence;$script:Service='D:\fixture\service.exe';$script:Cli='D:\fixture\winsight.exe'
        $net=[pscustomobject]@{targetAddress='127.0.0.1';httpPort=12345};$state=@{}
        $script:starts=0;$script:job=$null;$script:completionPath=$null;$script:expectedId=$null
        $network='Result: 7 checks, 0 failure(s). S-1-5-2=true S-1-5-4=false serviceAvailable=false outcome=ServiceUnavailable mutation=none'
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'missing-remote-token') {$network=$network.Replace('mutation=none','')}
        $script:networkBytes=[Text.Encoding]::UTF8.GetBytes($network)
        function Assert-CandidateFiles {}
        function Start-Job($ScriptBlock,$ArgumentList) {
            # The nonce must come from the ACTUAL guest Start-Job arguments, never test preseed.
            $id=@($ArgumentList|Where-Object {$_ -is [string] -and $_ -cmatch '^[a-f0-9]{32}$'})
            $script:expectedId=if ($id.Count -eq 1) {[string]$id[0]} else {'old-baseline'}
            $paths=@($ArgumentList|Where-Object {$_ -is [string] -and $_.StartsWith($Evidence,[StringComparison]::OrdinalIgnoreCase) -and $_ -notlike '*.ps1'})
            if ($paths.Count -ne 3) {throw 'SETUP: observer receipt arguments missing'}
            $script:completionPath=$paths[1]
            $readyId=$script:expectedId;$resultId=$script:expectedId
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'stale-ready') {$readyId=[guid]::NewGuid().ToString('N')}
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'stale-result') {$resultId=[guid]::NewGuid().ToString('N')}
            $command='"D:\fixture\service.exe" run'
            $readyValue=[ordered]@{SchemaVersion=1;ObservationId=$readyId;Stage='READY';Result='READY';Checks='3/5';ProcessId=42;PathName=$command;PreCanary='PASS';Utc=[DateTime]::UtcNow.ToString('O')}
            $resultValue=[ordered]@{SchemaVersion=1;ObservationId=$resultId;Stage='PASS';Result='PASS';Checks='5/5';BeforeProcessId=42;AfterProcessId=42;PathName=$command;PreCanary='PASS';PostCanary='PASS';Utc=[DateTime]::UtcNow.ToString('O')}
            if ($script:expectedId -eq 'old-baseline') {$readyValue.Checks='2/3';$resultValue.Checks='3/3'}
            [IO.File]::WriteAllText($paths[0],($readyValue|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($paths[2],($resultValue|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
            $jobState=switch($env:WINSIGHT_OBSERVER_SCENARIO) {'failed' {'Failed'} 'stopped' {'Stopped'} 'running' {'Running'} default {'Completed'}}
            $script:job=[pscustomobject]@{State=$jobState};$script:job
        }
        function Wait-Job {param([Parameter(ValueFromPipeline=$true)]$InputObject,$Timeout) process {if ($Timeout -ne 330) {throw 'ASSERT: observer watchdog changed'};$InputObject}}
        function Receive-Job {param([Parameter(ValueFromPipeline=$true)]$InputObject) process {'fixture observer output'}}
        function New-Object($TypeName,$ArgumentList) {
            if ($TypeName -eq 'Net.HttpListener') {
                $listener=[pscustomobject]@{Prefixes=[Collections.Generic.List[string]]::new()}
                $listener|Add-Member ScriptMethod Start {$script:starts++}
                $listener|Add-Member ScriptMethod Stop {}
                $listener|Add-Member ScriptMethod GetContextAsync {
                    $response=[pscustomobject]@{ContentType='';StatusCode=200;OutputStream=[IO.MemoryStream]::new()}
                    $response|Add-Member ScriptMethod Close {$this.OutputStream.Dispose()}
                    $context=[pscustomobject]@{Request=[pscustomobject]@{Url=[uri]'http://127.0.0.1/done';InputStream=[IO.MemoryStream]::new($script:networkBytes)};Response=$response}
                    $completion=[Threading.Tasks.TaskCompletionSource[object]]::new()
                    $completion.SetResult($context)
                    $completion.Task
                }
                return $listener
            }
            if ($TypeName -eq 'IO.StreamReader') {return [IO.StreamReader]::new($ArgumentList[0],$ArgumentList[1])}
            throw 'SETUP: unexpected constructor'
        }
        $failure=$null;$actual=@()
        try {$actual=@(. ([scriptblock]::Create($core)))} catch {$failure=$_}
        if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'success') {
            if ($failure) {throw $failure}
            if ($script:expectedId -cnotmatch '^[a-f0-9]{32}$' -or $script:starts -ne 1 -or ($actual -join '') -notmatch 'combined 12/12') {throw 'ASSERT: fresh positive guest proof missing'}
            $signal=Get-Content -LiteralPath $script:completionPath -Raw|ConvertFrom-Json
            if ($signal.ObservationId -cne $script:expectedId -or $signal.Stage -cne 'COMPLETE') {throw 'ASSERT: completion not bound'}
        } else {
            $expected=switch($env:WINSIGHT_OBSERVER_SCENARIO) {
                'stale-ready' {'Network observer receipt rejected.'}
                'stale-result' {'Network observer receipt rejected.'}
                'missing-remote-token' {'Network Logon evidence is missing: mutation=none'}
                default {'Target observer did not complete successfully.'}
            }
            Assert-ExpectedFailure $failure $expected
            if ($env:WINSIGHT_OBSERVER_SCENARIO -eq 'stale-ready' -and $script:starts -ne 0) {throw 'ASSERT: listener started before readiness validation'}
        }
        """;

    private async Task Run(string scenario, string body)
    {
        var start = PowerShellProcessEvidence.StartInfo();
        start.Environment["WINSIGHT_OBSERVER_ROOT"] = Root;
        start.Environment["WINSIGHT_OBSERVER_FOLDER"] = _folder;
        start.Environment["WINSIGHT_OBSERVER_SCENARIO"] = scenario;
        var setup = """
            $ErrorActionPreference='Stop';Set-StrictMode -Version Latest
            function Parse-Script($Path) {
                $errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$null,[ref]$errors)
                if ($errors.Count) {throw 'SETUP: source parse failed'}
                return $tree
            }
            function Assert-ExpectedFailure($Failure,[string]$Expected) {
                if (-not $Failure) {throw 'ASSERT: expected refusal absent'}
                if ($Failure.Exception.Message -cne $Expected) {throw $Failure}
            }
            function Load-Functions($Tree) {
                foreach($definition in $Tree.EndBlock.Statements|Where-Object {$_ -is [Management.Automation.Language.FunctionDefinitionAst]}) {
                    $text=$definition.Extent.Text
                    $prefix=[regex]::Match($text,'^(?i:function)\s+')
                    if (-not $prefix.Success -or $definition.Name.Contains(':')) {throw 'SETUP: unsupported helper declaration'}
                    # Only the declaration scope changes; signature parameters and body bytes stay exact.
                    . ([scriptblock]::Create($text.Insert($prefix.Length,'script:')))
                }
            }
            $loaderErrors=$null
            $loaderAst=[Management.Automation.Language.Parser]::ParseInput('function Test-Signature($Value) {$Value}; function Test-Body {param($Value) $Value}',[ref]$null,[ref]$loaderErrors)
            if ($loaderErrors.Count) {throw 'SETUP: loader control parse failed'}
            Load-Functions $loaderAst
            if ((Test-Signature -Value 'signature') -cne 'signature' -or (Test-Body -Value 'body') -cne 'body') {throw 'SETUP: helper parameters lost'}
            Write-TestPhase 'body-begin'
            """;
        PowerShellProcessEvidence.EncodedCommand(start, PowerShellProcessEvidence.Prelude + setup + "\n" + body
            + PowerShellProcessEvidence.BodyEnd + "\nexit 0");
        var result = await PowerShellProcessEvidence.Run(start, TimeSpan.FromSeconds(30), output.WriteLine);
        Assert.True(result.ExitCode == 0, $"PowerShell assertion failed: {result.Stdout}\n{result.Stderr}");
    }

    public void Dispose() => Directory.Delete(_folder, recursive: true);
}
