<#
.SYNOPSIS
    Runs the WFP runtime validation protocol on an isolated VM.

.DESCRIPTION
    The real VM protocol and both contract modes execute Invoke-WfpValidationWorkflow.
    Contract modes inject deterministic operations and never invoke SCM, WFP, DACL,
    a service binary, the network, or staging filesystem effects.
#>
[CmdletBinding()]
param(
    [string]$ServicePath,
    [switch]$SkipEnforcement,
    [switch]$ContractSelfTest,
    [switch]$ContractNegativeControl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

class NativeResult {
    [string]$Output
    [int]$ExitCode
    NativeResult([string]$output, [int]$exitCode) { $this.Output = $output; $this.ExitCode = $exitCode }
}

class PreconditionsResult {
    [bool]$Elevated
    [bool]$CandidateAndToolsExist
    PreconditionsResult([bool]$elevated, [bool]$candidateAndToolsExist) {
        $this.Elevated = $elevated; $this.CandidateAndToolsExist = $candidateAndToolsExist
    }
}

class StageResult {
    [bool]$Success
    [string]$Directory
    [string]$SentinelPath
    StageResult([bool]$success, [string]$directory, [string]$sentinelPath) {
        $this.Success = $success; $this.Directory = $directory; $this.SentinelPath = $sentinelPath
    }
}

class BaselineResult {
    [NativeResult]$Target
    [NativeResult]$Control
    BaselineResult([NativeResult]$target, [NativeResult]$control) {
        $this.Target = $target; $this.Control = $control
    }
}

class WorkflowResult {
    [int]$Checks
    [int]$Failures
    [bool]$Stopped
    [string]$Reason
    [int]$ExitCode
    WorkflowResult([int]$checks, [int]$failures, [bool]$stopped, [string]$reason) {
        $this.Checks = $checks; $this.Failures = $failures; $this.Stopped = $stopped; $this.Reason = $reason
        $this.ExitCode = [int](($failures -gt 0) -or $stopped)
    }
}

class StrictCaptureResult {
    [bool]$Valid
    [object]$Value
    [string]$Reason
    StrictCaptureResult([bool]$valid, [object]$value, [string]$reason) {
        $this.Valid = $valid; $this.Value = $value; $this.Reason = $reason
    }
}

class ServiceObservation {
    [bool]$Found
    [string]$State
    [string]$PathName
    ServiceObservation([bool]$found, [string]$state, [string]$pathName) {
        $this.Found = $found; $this.State = $state; $this.PathName = $pathName
    }
}

class HostCall {
    [string]$Kind
    [string]$Path
    [string[]]$Arguments
    HostCall([string]$kind, [string]$path, [string[]]$arguments) {
        $this.Kind = $kind; $this.Path = $path; $this.Arguments = $arguments
    }
}

class HostExpectation {
    [HostCall]$Call
    [object[]]$Results
    HostExpectation([HostCall]$call, [object[]]$results) {
        $this.Call = $call; $this.Results = $results
    }
}

$script:PathDenialCodes = @(
    '[FW_INSTALL_PATH_INVALID]', '[FW_INSTALL_PATH_OUTSIDE_MACHINE_DATA]',
    '[FW_INSTALL_PATH_MISSING_COMPONENT]', '[FW_INSTALL_PATH_REPARSE_POINT]',
    '[FW_INSTALL_PATH_UNTRUSTED_OWNER]', '[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]',
    '[FW_INSTALL_PATH_IDENTITY_CHANGED]', '[FW_INSTALL_PATH_INSPECTION_FAILED]'
)
$script:WfpAbsent = 'WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.'
$script:WfpArmed = 'WinSight WFP provider: present, sublayer: present, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.'

function Invoke-StrictCapture {
    param(
        [scriptblock]$Operation,
        [type]$ExpectedType,
        [ValidateSet(0, 1)][int]$ExpectedCount,
        [object[]]$Arguments = @()
    )
    try { [object[]]$items = @(& $Operation @Arguments) }
    catch { return [StrictCaptureResult]::new($false, $null, 'operation-threw') }
    if ($items.Count -ne $ExpectedCount) {
        return [StrictCaptureResult]::new($false, $null, ('cardinality-{0}' -f $items.Count))
    }
    if ($ExpectedCount -eq 1 -and ($null -eq $items[0] -or $items[0].GetType() -ne $ExpectedType)) {
        return [StrictCaptureResult]::new($false, $null, 'unexpected-type')
    }
    return [StrictCaptureResult]::new($true, $(if ($ExpectedCount -eq 1) { $items[0] } else { $null }), '')
}

function Invoke-BoundedPoll {
    param([scriptblock]$Probe, [scriptblock]$Sleeper, [ValidateRange(1, 100)][int]$MaxAttempts)
    for ($attempt = 0; $attempt -lt $MaxAttempts; $attempt++) {
        $probeCapture = Invoke-StrictCapture $Probe ([bool]) 1
        if (-not $probeCapture.Valid) { return $false }
        if ([bool]$probeCapture.Value) { return $true }
        if ($attempt -lt ($MaxAttempts - 1)) {
            $sleepCapture = Invoke-StrictCapture $Sleeper $null 0
            if (-not $sleepCapture.Valid) { return $false }
        }
    }
    return $false
}

function Invoke-Native([string]$exe, [string[]]$nativeArguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = (& $exe @nativeArguments 2>&1 | ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
            } | Out-String)
        return [NativeResult]::new($output, [int]$LASTEXITCODE)
    }
    finally { $ErrorActionPreference = $previous }
}

function Write-NativeResult([NativeResult]$result, [string]$exe, [string[]]$arguments) {
    Write-Host ('  > {0} {1} (exit {2})' -f (Split-Path -Leaf $exe), ($arguments -join ' '), $result.ExitCode)
    if ($result.Output.Length -eq 0) { Write-Host '    <no output>' }
    else { foreach ($line in ($result.Output.TrimEnd("`r", "`n") -split "`r?`n")) { Write-Host "    $line" } }
    return [NativeResult]::new($result.Output, $result.ExitCode)
}

function Test-NativeSuccess([NativeResult]$result) { return $result.ExitCode -eq 0 }
function Test-EnforcementStatus([NativeResult]$result, [string]$expectedMode) {
    return $result.ExitCode -eq 0 -and
        $result.Output.TrimEnd("`r", "`n") -ceq
        ('Persisted desired enforcement mode: {0}. Effective runtime state: unknown (query the authenticated running service).' -f $expectedMode)
}
function Test-WfpSelfTestResult([NativeResult]$result) {
    if ($result.ExitCode -ne 0) { return $false }
    return [regex]::IsMatch(
        $result.Output.TrimEnd("`r", "`n"),
        '^WFP engine opened\. Existing filters visible: (?:0|[1-9][0-9]*)\. Read-only: no filter, provider or sublayer was added or changed\.$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}
function Test-BlockedStatus([NativeResult]$result) {
    return $result.ExitCode -eq 0 -and $result.Output.TrimEnd("`r", "`n") -ceq '[FW_APP_BLOCKED]'
}
function Test-WfpState([NativeResult]$result, [string]$provider, [string]$sublayer, [string]$permit) {
    if ($result.ExitCode -ne 0) { return $false }
    $match = [regex]::Match($result.Output,
        '^\s*WinSight WFP provider: (?<provider>present|absent), sublayer: (?<sublayer>present|absent), permit-filter: (?<permit>present|absent)\. Per-app blocks are queried with wfp-block-status <path>\.\s*$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    return $match.Success -and $match.Groups['provider'].Value -ceq $provider -and
        $match.Groups['sublayer'].Value -ceq $sublayer -and $match.Groups['permit'].Value -ceq $permit
}
function Test-ServiceBinding([string]$pathName, [string]$canonicalServicePath) {
    return -not [string]::IsNullOrWhiteSpace($pathName) -and $pathName -ceq ('"{0}" run' -f $canonicalServicePath)
}
function Test-PathTrustRefusal([NativeResult]$result) {
    $output = $result.Output.TrimEnd("`r", "`n")
    return $result.ExitCode -eq 1 -and $script:PathDenialCodes -ccontains $output
}
function Test-DirectMutationRefusal([NativeResult]$result) {
    return $result.ExitCode -eq 1 -and $result.Output.TrimEnd("`r", "`n") -ceq '[FW_DIRECT_MUTATION_DISABLED]'
}
function Test-WebSuccess([NativeResult]$result) { return $result.ExitCode -eq 0 -and $result.Output.TrimEnd("`r", "`n") -ceq '200' }
function Test-WebBlocked([NativeResult]$result) { return $result.ExitCode -ne 0 -and $result.Output.TrimEnd("`r", "`n") -ceq '000' }

function Invoke-WfpValidationWorkflow($Operations, [switch]$SkipEnforcement) {
    $state = [pscustomobject]@{ Checks = 0; Failures = 0; Stopped = $false; Reason = '' }
    $stage = $null

    function Emit([string]$message) {
        $capture = Invoke-StrictCapture $Operations.Output $null 0 @($message)
        return [bool]$capture.Valid
    }
    function Check-Step([string]$name, [bool]$passed, [string]$expectation) {
        $state.Checks++
        if (-not $passed) { $state.Failures++ }
        $message = if ($passed) { '  [PASS] {0}' -f $name } else { '  [FAIL] {0}: {1}' -f $name, $expectation }
        if (-not (Emit $message)) { $state.Failures++; return $false }
        return $passed
    }
    function Capture-Decision([scriptblock]$operation, [type]$expectedType, [object[]]$arguments = @()) {
        return Invoke-StrictCapture $operation $expectedType 1 $arguments
    }
    function Invoke-Effect([scriptblock]$operation, [object[]]$arguments = @()) {
        $capture = Invoke-StrictCapture $operation $null 0 $arguments
        return [bool]$capture.Valid
    }
    function Stop-Workflow([string]$reason) {
        if ($null -ne $stage -and -not [string]::IsNullOrWhiteSpace($stage.Directory)) {
            if (-not (Invoke-Effect $Operations.RemoveStage @($stage))) { $state.Failures++ }
            $stage = $null
        }
        $state.Stopped = $true; $state.Reason = $reason
        if (-not (Emit ('STOP: {0}' -f $reason))) { $state.Failures++ }
        return [WorkflowResult]::new($state.Checks, $state.Failures, $true, $reason)
    }
    function Cleanup-Service {
        $stopCapture = Capture-Decision $Operations.Stop ([NativeResult])
        $stopOk = $stopCapture.Valid -and (Test-NativeSuccess ([NativeResult]$stopCapture.Value))
        if (-not (Check-Step 'service stop succeeds' $stopOk 'absolute System32 sc.exe stop exits 0')) {
            return Stop-Workflow 'service stop failed; restore the clean VM snapshot.'
        }
        $stoppedCapture = Capture-Decision $Operations.PollStopped ([bool])
        $stopped = $stoppedCapture.Valid -and [bool]$stoppedCapture.Value
        if (-not (Check-Step 'service reaches stopped state before uninstall' $stopped 'bounded locale-invariant stopped poll')) {
            return Stop-Workflow 'service did not stop; do not uninstall and restore the clean VM snapshot.'
        }
        $uninstallCapture = Capture-Decision $Operations.Uninstall ([NativeResult])
        $uninstallOk = $uninstallCapture.Valid -and (Test-NativeSuccess ([NativeResult]$uninstallCapture.Value))
        if (-not (Check-Step 'candidate uninstall succeeds' $uninstallOk 'uninstall exits 0')) {
            return Stop-Workflow 'candidate uninstall failed; restore the clean VM snapshot.'
        }
        $absentCapture = Capture-Decision $Operations.PollAbsent ([bool])
        $absent = $absentCapture.Valid -and [bool]$absentCapture.Value
        if (-not (Check-Step 'uninstall leaves no service' $absent 'bounded absolute sc.exe query reaches 1060')) {
            return Stop-Workflow 'service deletion did not complete; restore the clean VM snapshot.'
        }
        return $null
    }

    if (-not (Emit '== WFP validation protocol ==')) {
        return [WorkflowResult]::new(0, 1, $true, 'output operation violated the zero-output contract')
    }
    $preCapture = Capture-Decision $Operations.Preconditions ([PreconditionsResult])
    $elevated = $preCapture.Valid -and ([PreconditionsResult]$preCapture.Value).Elevated
    if (-not (Check-Step 'console is elevated' $elevated 'an elevated VM console')) { return Stop-Workflow 'preconditions failed before touching SCM or WFP.' }
    $tools = $preCapture.Valid -and ([PreconditionsResult]$preCapture.Value).CandidateAndToolsExist
    if (-not (Check-Step 'candidate and protected tools exist' $tools 'candidate plus absolute System32 sc, curl and PowerShell paths')) { return Stop-Workflow 'preconditions failed before touching SCM or WFP.' }

    $stageCapture = Capture-Decision $Operations.Stage ([StageResult])
    if ($stageCapture.Valid) { $stage = [StageResult]$stageCapture.Value }
    $stageOk = $stageCapture.Valid -and $stage.Success -and -not [string]::IsNullOrWhiteSpace($stage.Directory) -and -not [string]::IsNullOrWhiteSpace($stage.SentinelPath)
    if (-not (Check-Step 'user-writable sentinel is staged as data' $stageOk 'one sentinel file, never a staged service or DLL')) { return Stop-Workflow 'mandatory path-trust sentinel staging failed.' }

    $cleanCapture = Capture-Decision $Operations.CleanSnapshot ([bool])
    $clean = $cleanCapture.Valid -and [bool]$cleanCapture.Value
    if (-not (Check-Step 'clean snapshot has no WinSight service' $clean 'absolute sc.exe query returns 1060 before install')) { return Stop-Workflow 'service already exists or SCM query failed before candidate installation.' }
    $installCapture = Capture-Decision $Operations.Install ([NativeResult])
    $installed = $installCapture.Valid -and (Test-NativeSuccess ([NativeResult]$installCapture.Value))
    if (-not (Check-Step 'candidate install succeeds' $installed 'install exits 0')) { return Stop-Workflow 'candidate install failed.' }
    $bindingCapture = Capture-Decision $Operations.Binding ([bool])
    $binding = $bindingCapture.Valid -and [bool]$bindingCapture.Value
    if (-not (Check-Step 'SCM binds the canonical candidate and run verb' $binding 'exact case-sensitive quoted candidate plus run')) { return Stop-Workflow 'SCM registration does not bind the requested candidate exactly.' }
    $startCapture = Capture-Decision $Operations.Start ([NativeResult])
    $runningCapture = Capture-Decision $Operations.PollRunning ([bool])
    $running = $startCapture.Valid -and $runningCapture.Valid -and
        (Test-NativeSuccess ([NativeResult]$startCapture.Value)) -and [bool]$runningCapture.Value
    if (-not (Check-Step 'service starts and reaches Running' $running 'start exits 0 and bounded CIM polling reaches Running')) { return Stop-Workflow 'service is not running; do not arm enforcement and restore the clean VM snapshot.' }
    $auditCapture = Capture-Decision $Operations.Audit ([NativeResult])
    $audit = $auditCapture.Valid -and (Test-EnforcementStatus ([NativeResult]$auditCapture.Value) 'AuditOnly')
    if (-not (Check-Step 'starts in audit-only' $audit 'AuditOnly with exit 0 on a fresh install')) { return Stop-Workflow 'pre-arm audit verification failed; do not arm enforcement.' }
    $pathCapture = Capture-Decision $Operations.PathProbe ([NativeResult]) @($stage)
    $pathRefused = $pathCapture.Valid -and (Test-PathTrustRefusal ([NativeResult]$pathCapture.Value))
    if (-not (Check-Step 'protected candidate refuses the sentinel path' $pathRefused 'install-path-trust-check returns one typed denial and exit 1')) { return Stop-Workflow 'path-trust probe failed; do not arm enforcement.' }
    if (-not (Invoke-Effect $Operations.RemoveStage @($stage))) { $state.Failures++; return Stop-Workflow 'stage cleanup violated the zero-output contract.' }
    $stage = $null

    $selfCapture = Capture-Decision $Operations.SelfTest ([NativeResult])
    $selfTest = $selfCapture.Valid -and (Test-WfpSelfTestResult ([NativeResult]$selfCapture.Value))
    if (-not (Check-Step 'WFP engine opens' $selfTest 'the exact fixed read-only engine result with a nonnegative invariant filter count and exit 0')) { return Stop-Workflow 'WFP read-only precheck failed; do not arm enforcement.' }
    $beforeCapture = Capture-Decision $Operations.WfpBefore ([NativeResult])
    $beforeEmpty = $beforeCapture.Valid -and (Test-WfpState ([NativeResult]$beforeCapture.Value) 'absent' 'absent' 'absent')
    if (-not (Check-Step 'no WFP state before arming' $beforeEmpty 'provider, sublayer and permit-filter exactly absent')) { return Stop-Workflow 'pre-arm WFP state is not empty; do not arm enforcement.' }
    $directCapture = Capture-Decision $Operations.DirectRefusal ([NativeResult])
    $afterDirectCapture = Capture-Decision $Operations.WfpAfterDirect ([NativeResult])
    $directClosed = $directCapture.Valid -and $afterDirectCapture.Valid -and
        (Test-DirectMutationRefusal ([NativeResult]$directCapture.Value)) -and
        (Test-WfpState ([NativeResult]$afterDirectCapture.Value) 'absent' 'absent' 'absent')
    if (-not (Check-Step 'direct mutation is refused without changing WFP' $directClosed 'exact refusal/exit 1 followed immediately by exact empty WFP state')) { return Stop-Workflow 'direct mutation refusal or post-state check failed; do not arm enforcement.' }

    if ($SkipEnforcement) {
        $cleanup = Cleanup-Service
        if ($null -ne $cleanup) { return $cleanup }
        return [WorkflowResult]::new($state.Checks, $state.Failures, $false, 'skip-enforcement cleanup complete')
    }

    $baselineCapture = Capture-Decision $Operations.Baseline ([BaselineResult])
    $baseline = $baselineCapture.Valid -and
        (Test-WebSuccess ([BaselineResult]$baselineCapture.Value).Target) -and
        (Test-WebSuccess ([BaselineResult]$baselineCapture.Value).Control)
    if (-not (Check-Step 'target and control reach the network before blocking' $baseline 'curl and PowerShell HTTP clients both return 200/exit 0')) { return Stop-Workflow 'baseline failed; do not arm enforcement and restore the clean VM snapshot.' }
    if (-not (Invoke-Effect $Operations.PromptArm)) { $state.Failures++; return Stop-Workflow 'arm prompt violated the zero-output contract.' }

    $enforcedCapture = Capture-Decision $Operations.Enforced ([NativeResult])
    Check-Step 'enforcement is persisted' ($enforcedCapture.Valid -and (Test-EnforcementStatus ([NativeResult]$enforcedCapture.Value) 'Enforcement')) 'exact Enforcement status with unknown runtime suffix and exit 0' | Out-Null
    $armedCapture = Capture-Decision $Operations.WfpArmed ([NativeResult])
    Check-Step 'WFP state is exactly armed' ($armedCapture.Valid -and (Test-WfpState ([NativeResult]$armedCapture.Value) 'present' 'present' 'absent')) 'provider and sublayer present; permit-filter absent' | Out-Null
    $blockCapture = Capture-Decision $Operations.BlockStatus ([NativeResult])
    $blockStatus = $blockCapture.Valid -and (Test-BlockedStatus ([NativeResult]$blockCapture.Value))
    Check-Step 'the System32 curl target reads as blocked' $blockStatus 'FW_APP_BLOCKED and exit 0' | Out-Null
    $blockedCapture = Capture-Decision $Operations.Blocked ([NativeResult])
    Check-Step 'blocked System32 curl cannot reach the network' ($blockedCapture.Valid -and (Test-WebBlocked ([NativeResult]$blockedCapture.Value)) ) 'http 000 and non-zero curl exit' | Out-Null
    $unblockedCapture = Capture-Decision $Operations.Unblocked ([NativeResult])
    Check-Step 'PowerShell HTTP control still reaches the network' ($unblockedCapture.Valid -and (Test-WebSuccess ([NativeResult]$unblockedCapture.Value))) 'http 200 and exit 0 from absolute System32 PowerShell' | Out-Null

    if (-not (Invoke-Effect $Operations.PromptRollback)) { $state.Failures++; return Stop-Workflow 'rollback prompt violated the zero-output contract.' }
    $rollbackAuditCapture = Capture-Decision $Operations.RollbackAudit ([NativeResult])
    $rollbackWfpCapture = Capture-Decision $Operations.RollbackWfp ([NativeResult])
    $restoredCapture = Capture-Decision $Operations.Restored ([BaselineResult])
    $rollbackAudit = Check-Step 'back to audit-only' ($rollbackAuditCapture.Valid -and (Test-EnforcementStatus ([NativeResult]$rollbackAuditCapture.Value) 'AuditOnly')) 'exact AuditOnly status with unknown runtime suffix and exit 0'
    $rollbackWfp = Check-Step 'all WFP state is removed' ($rollbackWfpCapture.Valid -and (Test-WfpState ([NativeResult]$rollbackWfpCapture.Value) 'absent' 'absent' 'absent')) 'provider, sublayer and permit-filter exactly absent'
    $restored = Check-Step 'target and control connectivity are restored' ($restoredCapture.Valid -and
        (Test-WebSuccess ([BaselineResult]$restoredCapture.Value).Target) -and
        (Test-WebSuccess ([BaselineResult]$restoredCapture.Value).Control)) 'both fixed HTTP clients return 200/exit 0'
    if (-not ($rollbackAudit -and $rollbackWfp -and $restored)) { return Stop-Workflow 'rollback proof failed; do not uninstall and restore the clean VM snapshot.' }

    $cleanup = Cleanup-Service
    if ($null -ne $cleanup) { return $cleanup }
    return [WorkflowResult]::new($state.Checks, $state.Failures, $false, 'full validation cleanup complete')
}

function Test-HostCall([HostCall]$actual, [HostCall]$expected) {
    if ($actual.Kind -cne $expected.Kind -or $actual.Path -cne $expected.Path -or
        $actual.Arguments.Count -ne $expected.Arguments.Count) { return $false }
    for ($index = 0; $index -lt $actual.Arguments.Count; $index++) {
        if ($actual.Arguments[$index] -cne $expected.Arguments[$index]) { return $false }
    }
    return $true
}

function New-RealHostEffects {
    $invoke = {
        param([HostCall]$call)
        switch ($call.Kind) {
            'Native' { return Write-NativeResult (Invoke-Native $call.Path $call.Arguments) $call.Path $call.Arguments }
            'ObserveService' {
                try {
                    $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $call.Path) -ErrorAction Stop
                    if ($null -eq $service) { return [ServiceObservation]::new($false, '', '') }
                    return [ServiceObservation]::new($true, [string]$service.State, [string]$service.PathName)
                }
                catch { return [ServiceObservation]::new($false, '', '') }
            }
            'FileExists' { return [bool](Test-Path -LiteralPath $call.Path -PathType Leaf) }
            'CreateDirectory' { New-Item -ItemType Directory -Path $call.Path -ErrorAction Stop | Out-Null; return }
            'CreateFile' { New-Item -ItemType File -Path $call.Path -ErrorAction Stop | Out-Null; return }
            'RemoveDirectory' { Remove-Item -LiteralPath $call.Path -Recurse -Force -ErrorAction SilentlyContinue; return }
            'IsElevated' {
                return [bool](([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator))
            }
            'NewToken' { return [guid]::NewGuid().ToString('N') }
            'Sleep' { Start-Sleep -Milliseconds ([int]$call.Arguments[0]); return }
            'Prompt' { Read-Host $call.Path | Out-Null; return }
            'Output' { Write-Host $call.Path; return }
            default { throw ('Unknown host effect: {0}' -f $call.Kind) }
        }
    }
    return [pscustomobject]@{
        Invoke = $invoke
        WindowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
        UserProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    }
}

function New-ScriptedHostEffects([HostExpectation[]]$expectations, [string]$windowsRoot = 'C:\Windows', [string]$userProfile = 'C:\Users\tester') {
    $queue = New-Object System.Collections.Queue
    foreach ($expectation in $expectations) { $queue.Enqueue($expectation) }
    $state = [pscustomobject]@{ Mismatch = ''; Calls = (New-Object System.Collections.ArrayList) }
    $testHostCall = ${function:Test-HostCall}
    $invoke = {
        param([HostCall]$call)
        [void]$state.Calls.Add($call)
        if ($queue.Count -eq 0) { $state.Mismatch = 'unexpected-call'; throw $state.Mismatch }
        $expected = [HostExpectation]$queue.Dequeue()
        if (-not (& $testHostCall $call $expected.Call)) {
            $state.Mismatch = 'expected {0}:{1} [{2}], got {3}:{4} [{5}]' -f
                $expected.Call.Kind, $expected.Call.Path, ($expected.Call.Arguments -join '|'),
                $call.Kind, $call.Path, ($call.Arguments -join '|')
            throw $state.Mismatch
        }
        foreach ($result in $expected.Results) { Write-Output -NoEnumerate $result }
    }.GetNewClosure()
    return [pscustomobject]@{
        Invoke = $invoke; WindowsRoot = $windowsRoot; UserProfile = $userProfile
        Queue = $queue; State = $state
    }
}

function New-ValidationAdapter($HostEffects, [string]$candidateServicePath) {
    # GetNewClosure() captures variables, never functions. Under `-File` the script is the top-level
    # scope and a closure can still resolve script functions; invoked with `&` from an existing
    # session the script gets a child scope and every such call throws "is not recognized". Capturing
    # the function as a scriptblock local makes the closure carry it either way.
    $strictCapture = ${function:Invoke-StrictCapture}
    $testServiceBinding = ${function:Test-ServiceBinding}
    $canonicalPath = [IO.Path]::GetFullPath($candidateServicePath)
    $scPath = Join-Path $HostEffects.WindowsRoot 'System32\sc.exe'
    $targetPath = Join-Path $HostEffects.WindowsRoot 'System32\curl.exe'
    $controlPath = Join-Path $HostEffects.WindowsRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $serviceName = 'WinSightFirewall'
    $httpArguments = @('-NoProfile', '-NonInteractive', '-Command',
        "try { `$r = Invoke-WebRequest -UseBasicParsing -Uri 'https://example.com' -TimeoutSec 20; [Console]::Out.Write([int]`$r.StatusCode); exit 0 } catch { [Console]::Out.Write('000'); exit 2 }")
    $curlArguments = @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '20', 'https://example.com')
    $hostDecision = {
        param([string]$kind, [string]$path, [string[]]$arguments, [type]$expectedType)
        $call = [HostCall]::new($kind, $path, $arguments)
        $capture = & $strictCapture $HostEffects.Invoke $expectedType 1 @($call)
        if (-not $capture.Valid) { throw ('Host decision contract failed: {0}' -f $capture.Reason) }
        return $capture.Value
    }.GetNewClosure()
    $hostEffect = {
        param([string]$kind, [string]$path, [string[]]$arguments)
        $call = [HostCall]::new($kind, $path, $arguments)
        $capture = & $strictCapture $HostEffects.Invoke $null 0 @($call)
        if (-not $capture.Valid) { throw ('Host effect contract failed: {0}' -f $capture.Reason) }
    }.GetNewClosure()
    $observe = { return (& $hostDecision 'ObserveService' $serviceName @() ([ServiceObservation])) }.GetNewClosure()
    $pollLifecycle = {
        param([string]$mode, [string]$wanted)
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            $matched = if ($mode -ceq 'State') {
                $observation = [ServiceObservation](& $hostDecision 'ObserveService' $serviceName @() ([ServiceObservation]))
                $observation.Found -and $observation.State -ceq $wanted
            }
            else {
                $query = [NativeResult](& $hostDecision 'Native' $scPath @('query', $serviceName) ([NativeResult]))
                $query.ExitCode -eq 1060
            }
            if ($matched) { return $true }
            if ($attempt -lt 9) { & $hostEffect 'Sleep' '' @('500') }
        }
        return $false
    }.GetNewClosure()
    $native = {
        param([string]$path, [string[]]$arguments)
        return [NativeResult](& $hostDecision 'Native' $path $arguments ([NativeResult]))
    }.GetNewClosure()
    $targetWeb = { return (& $native $targetPath $curlArguments) }.GetNewClosure()
    $controlWeb = { return (& $native $controlPath $httpArguments) }.GetNewClosure()
    return [pscustomobject]@{
        ScPath = $scPath; TargetPath = $targetPath; ControlPath = $controlPath; ServiceName = $serviceName
        Output = { param($message); & $hostEffect 'Output' ([string]$message) @() }.GetNewClosure()
        Preconditions = {
            $elevated = [bool](& $hostDecision 'IsElevated' '' @() ([bool]))
            $candidate = [bool](& $hostDecision 'FileExists' $canonicalPath @() ([bool]))
            $sc = [bool](& $hostDecision 'FileExists' $scPath @() ([bool]))
            $target = [bool](& $hostDecision 'FileExists' $targetPath @() ([bool]))
            $control = [bool](& $hostDecision 'FileExists' $controlPath @() ([bool]))
            return [PreconditionsResult]::new($elevated, ($candidate -and $sc -and $target -and $control))
        }.GetNewClosure()
        Stage = {
            $directory = ''
            try {
                $token = [string](& $hostDecision 'NewToken' '' @() ([string]))
                $directory = Join-Path $HostEffects.UserProfile ('Desktop\winsight-path-trust-' + $token)
                & $hostEffect 'CreateDirectory' $directory @()
                $sentinel = Join-Path $directory 'user-writable-sentinel.exe'
                & $hostEffect 'CreateFile' $sentinel @()
                $exists = [bool](& $hostDecision 'FileExists' $sentinel @() ([bool]))
                return [StageResult]::new($exists, $directory, $sentinel)
            }
            catch {
                if (-not [string]::IsNullOrWhiteSpace($directory)) {
                    try { & $hostEffect 'RemoveDirectory' $directory @() } catch { }
                }
                return [StageResult]::new($false, '', '')
            }
        }.GetNewClosure()
        CleanSnapshot = { $query = & $native $scPath @('query', $serviceName); return [bool]($query.ExitCode -eq 1060) }.GetNewClosure()
        Install = { return (& $native $canonicalPath @('install')) }.GetNewClosure()
        Binding = { $observation = [ServiceObservation](& $observe); return [bool]($observation.Found -and (& $testServiceBinding $observation.PathName $canonicalPath)) }.GetNewClosure()
        Start = { return (& $native $scPath @('start', $serviceName)) }.GetNewClosure()
        PollRunning = { return [bool](& $pollLifecycle 'State' 'Running') }.GetNewClosure()
        Audit = { return (& $native $canonicalPath @('enforce-status')) }.GetNewClosure()
        PathProbe = { param([StageResult]$stage); return (& $native $canonicalPath @('install-path-trust-check', $stage.SentinelPath)) }.GetNewClosure()
        RemoveStage = { param([StageResult]$stage); & $hostEffect 'RemoveDirectory' $stage.Directory @() }.GetNewClosure()
        SelfTest = { return (& $native $canonicalPath @('wfp-selftest')) }.GetNewClosure()
        WfpBefore = { return (& $native $canonicalPath @('wfp-status')) }.GetNewClosure()
        DirectRefusal = { return (& $native $canonicalPath @('wfp-block-add', $targetPath)) }.GetNewClosure()
        WfpAfterDirect = { return (& $native $canonicalPath @('wfp-status')) }.GetNewClosure()
        Baseline = { return [BaselineResult]::new((& $targetWeb), (& $controlWeb)) }.GetNewClosure()
        PromptArm = { & $hostEffect 'Prompt' ('ACTION REQUIRED -- block {0} and enable enforcement, then press Enter' -f $targetPath) @() }.GetNewClosure()
        Enforced = { return (& $native $canonicalPath @('enforce-status')) }.GetNewClosure()
        WfpArmed = { return (& $native $canonicalPath @('wfp-status')) }.GetNewClosure()
        BlockStatus = { return (& $native $canonicalPath @('wfp-block-status', $targetPath)) }.GetNewClosure()
        Blocked = { return (& $targetWeb) }.GetNewClosure()
        Unblocked = { return (& $controlWeb) }.GetNewClosure()
        PromptRollback = { & $hostEffect 'Prompt' 'ACTION REQUIRED -- dashboard: Emergency disable, then press Enter' @() }.GetNewClosure()
        RollbackAudit = { return (& $native $canonicalPath @('enforce-status')) }.GetNewClosure()
        RollbackWfp = { return (& $native $canonicalPath @('wfp-status')) }.GetNewClosure()
        Restored = { return [BaselineResult]::new((& $targetWeb), (& $controlWeb)) }.GetNewClosure()
        Stop = { return (& $native $scPath @('stop', $serviceName)) }.GetNewClosure()
        PollStopped = { return [bool](& $pollLifecycle 'State' 'Stopped') }.GetNewClosure()
        Uninstall = { return (& $native $canonicalPath @('uninstall')) }.GetNewClosure()
        PollAbsent = { return [bool](& $pollLifecycle 'Absent' '') }.GetNewClosure()
    }
}

function Add-HostExpectation(
    [System.Collections.ArrayList]$list,
    [string]$kind,
    [string]$path,
    [string[]]$arguments,
    [object[]]$results) {
    [void]$list.Add([HostExpectation]::new([HostCall]::new($kind, $path, $arguments), $results))
}

function Add-OutputExpectation([System.Collections.ArrayList]$list, [string]$message) {
    Add-HostExpectation $list 'Output' $message @() @()
}

function New-ScriptedPaths {
    $windowsRoot = 'C:\Windows'
    $userProfile = 'C:\Users\tester'
    $candidate = 'C:\protected\winsight-firewall-service.exe'
    $sc = Join-Path $windowsRoot 'System32\sc.exe'
    $target = Join-Path $windowsRoot 'System32\curl.exe'
    $control = Join-Path $windowsRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $directory = Join-Path $userProfile 'Desktop\winsight-path-trust-closedtoken'
    $sentinel = Join-Path $directory 'user-writable-sentinel.exe'
    $httpArguments = @('-NoProfile', '-NonInteractive', '-Command',
        'try { $r = Invoke-WebRequest -UseBasicParsing -Uri ''https://example.com'' -TimeoutSec 20; [Console]::Out.Write([int]$r.StatusCode); exit 0 } catch { [Console]::Out.Write(''000''); exit 2 }')
    $curlArguments = @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '20', 'https://example.com')
    return [pscustomobject]@{
        WindowsRoot = $windowsRoot; UserProfile = $userProfile; Candidate = $candidate
        Sc = $sc; Target = $target; Control = $control; Directory = $directory; Sentinel = $sentinel
        HttpArguments = $httpArguments; CurlArguments = $curlArguments; Service = 'WinSightFirewall'
    }
}

function Add-ServicePollExpectations(
    [System.Collections.ArrayList]$list,
    $paths,
    [string[]]$states) {
    for ($index = 0; $index -lt $states.Count; $index++) {
        Add-HostExpectation $list 'ObserveService' $paths.Service @() @(
            [ServiceObservation]::new($true, $states[$index], ('"{0}" run' -f $paths.Candidate)))
        if ($index -lt ($states.Count - 1)) {
            Add-HostExpectation $list 'Sleep' '' @('500') @()
        }
    }
}

function Add-AbsentPollExpectations(
    [System.Collections.ArrayList]$list,
    $paths,
    [int[]]$exitCodes) {
    for ($index = 0; $index -lt $exitCodes.Count; $index++) {
        Add-HostExpectation $list 'Native' $paths.Sc @('query', $paths.Service) @(
            [NativeResult]::new('', $exitCodes[$index]))
        if ($index -lt ($exitCodes.Count - 1)) {
            Add-HostExpectation $list 'Sleep' '' @('500') @()
        }
    }
}

function New-ScriptedPlan(
    [bool]$full,
    [string[]]$runningStates = @('Running'),
    [string[]]$stoppedStates = @('Stopped'),
    [int[]]$absentExitCodes = @(1060)) {
    $paths = New-ScriptedPaths
    $list = New-Object System.Collections.ArrayList
    $audit = 'Persisted desired enforcement mode: AuditOnly. Effective runtime state: unknown (query the authenticated running service).'
    $enforced = 'Persisted desired enforcement mode: Enforcement. Effective runtime state: unknown (query the authenticated running service).'
    $selfTest = 'WFP engine opened. Existing filters visible: 42. Read-only: no filter, provider or sublayer was added or changed.'
    $wfpAbsent = [NativeResult]::new($script:WfpAbsent, 0)
    $wfpArmed = [NativeResult]::new($script:WfpArmed, 0)

    Add-OutputExpectation $list '== WFP validation protocol =='
    Add-HostExpectation $list 'IsElevated' '' @() @($true)
    foreach ($path in @($paths.Candidate, $paths.Sc, $paths.Target, $paths.Control)) {
        Add-HostExpectation $list 'FileExists' $path @() @($true)
    }
    Add-OutputExpectation $list '  [PASS] console is elevated'
    Add-OutputExpectation $list '  [PASS] candidate and protected tools exist'
    Add-HostExpectation $list 'NewToken' '' @() @('closedtoken')
    Add-HostExpectation $list 'CreateDirectory' $paths.Directory @() @()
    Add-HostExpectation $list 'CreateFile' $paths.Sentinel @() @()
    Add-HostExpectation $list 'FileExists' $paths.Sentinel @() @($true)
    Add-OutputExpectation $list '  [PASS] user-writable sentinel is staged as data'
    Add-HostExpectation $list 'Native' $paths.Sc @('query', $paths.Service) @([NativeResult]::new('', 1060))
    Add-OutputExpectation $list '  [PASS] clean snapshot has no WinSight service'
    Add-HostExpectation $list 'Native' $paths.Candidate @('install') @([NativeResult]::new('ok', 0))
    Add-OutputExpectation $list '  [PASS] candidate install succeeds'
    Add-HostExpectation $list 'ObserveService' $paths.Service @() @(
        [ServiceObservation]::new($true, 'Stopped', ('"{0}" run' -f $paths.Candidate)))
    Add-OutputExpectation $list '  [PASS] SCM binds the canonical candidate and run verb'
    Add-HostExpectation $list 'Native' $paths.Sc @('start', $paths.Service) @([NativeResult]::new('ok', 0))
    Add-ServicePollExpectations $list $paths $runningStates
    if ($runningStates[$runningStates.Count - 1] -cne 'Running') {
        Add-OutputExpectation $list '  [FAIL] service starts and reaches Running: start exits 0 and bounded CIM polling reaches Running'
        Add-HostExpectation $list 'RemoveDirectory' $paths.Directory @() @()
        Add-OutputExpectation $list 'STOP: service is not running; do not arm enforcement and restore the clean VM snapshot.'
        return [pscustomobject]@{ Expectations = @($list); Paths = $paths; Full = $full; Success = $false; Checks = 7 }
    }
    Add-OutputExpectation $list '  [PASS] service starts and reaches Running'
    Add-HostExpectation $list 'Native' $paths.Candidate @('enforce-status') @([NativeResult]::new($audit, 0))
    Add-OutputExpectation $list '  [PASS] starts in audit-only'
    Add-HostExpectation $list 'Native' $paths.Candidate @('install-path-trust-check', $paths.Sentinel) @(
        [NativeResult]::new('[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]', 1))
    Add-OutputExpectation $list '  [PASS] protected candidate refuses the sentinel path'
    Add-HostExpectation $list 'RemoveDirectory' $paths.Directory @() @()
    Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-selftest') @([NativeResult]::new($selfTest, 0))
    Add-OutputExpectation $list '  [PASS] WFP engine opens'
    Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-status') @($wfpAbsent)
    Add-OutputExpectation $list '  [PASS] no WFP state before arming'
    Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-block-add', $paths.Target) @(
        [NativeResult]::new('[FW_DIRECT_MUTATION_DISABLED]', 1))
    Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-status') @($wfpAbsent)
    Add-OutputExpectation $list '  [PASS] direct mutation is refused without changing WFP'

    if ($full) {
        Add-HostExpectation $list 'Native' $paths.Target $paths.CurlArguments @([NativeResult]::new('200', 0))
        Add-HostExpectation $list 'Native' $paths.Control $paths.HttpArguments @([NativeResult]::new('200', 0))
        Add-OutputExpectation $list '  [PASS] target and control reach the network before blocking'
        Add-HostExpectation $list 'Prompt' ('ACTION REQUIRED -- block {0} and enable enforcement, then press Enter' -f $paths.Target) @() @()
        Add-HostExpectation $list 'Native' $paths.Candidate @('enforce-status') @([NativeResult]::new($enforced, 0))
        Add-OutputExpectation $list '  [PASS] enforcement is persisted'
        Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-status') @($wfpArmed)
        Add-OutputExpectation $list '  [PASS] WFP state is exactly armed'
        Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-block-status', $paths.Target) @([NativeResult]::new('[FW_APP_BLOCKED]', 0))
        Add-OutputExpectation $list '  [PASS] the System32 curl target reads as blocked'
        Add-HostExpectation $list 'Native' $paths.Target $paths.CurlArguments @([NativeResult]::new('000', 2))
        Add-OutputExpectation $list '  [PASS] blocked System32 curl cannot reach the network'
        Add-HostExpectation $list 'Native' $paths.Control $paths.HttpArguments @([NativeResult]::new('200', 0))
        Add-OutputExpectation $list '  [PASS] PowerShell HTTP control still reaches the network'
        Add-HostExpectation $list 'Prompt' 'ACTION REQUIRED -- dashboard: Emergency disable, then press Enter' @() @()
        Add-HostExpectation $list 'Native' $paths.Candidate @('enforce-status') @([NativeResult]::new($audit, 0))
        Add-HostExpectation $list 'Native' $paths.Candidate @('wfp-status') @($wfpAbsent)
        Add-HostExpectation $list 'Native' $paths.Target $paths.CurlArguments @([NativeResult]::new('200', 0))
        Add-HostExpectation $list 'Native' $paths.Control $paths.HttpArguments @([NativeResult]::new('200', 0))
        Add-OutputExpectation $list '  [PASS] back to audit-only'
        Add-OutputExpectation $list '  [PASS] all WFP state is removed'
        Add-OutputExpectation $list '  [PASS] target and control connectivity are restored'
    }

    Add-HostExpectation $list 'Native' $paths.Sc @('stop', $paths.Service) @([NativeResult]::new('ok', 0))
    Add-OutputExpectation $list '  [PASS] service stop succeeds'
    Add-ServicePollExpectations $list $paths $stoppedStates
    if ($stoppedStates[$stoppedStates.Count - 1] -cne 'Stopped') {
        Add-OutputExpectation $list '  [FAIL] service reaches stopped state before uninstall: bounded locale-invariant stopped poll'
        Add-OutputExpectation $list 'STOP: service did not stop; do not uninstall and restore the clean VM snapshot.'
        return [pscustomobject]@{ Expectations = @($list); Paths = $paths; Full = $full; Success = $false; Checks = $(if ($full) { 23 } else { 14 }) }
    }
    Add-OutputExpectation $list '  [PASS] service reaches stopped state before uninstall'
    Add-HostExpectation $list 'Native' $paths.Candidate @('uninstall') @([NativeResult]::new('ok', 0))
    Add-OutputExpectation $list '  [PASS] candidate uninstall succeeds'
    Add-AbsentPollExpectations $list $paths $absentExitCodes
    if ($absentExitCodes[$absentExitCodes.Count - 1] -ne 1060) {
        Add-OutputExpectation $list '  [FAIL] uninstall leaves no service: bounded absolute sc.exe query reaches 1060'
        Add-OutputExpectation $list 'STOP: service deletion did not complete; restore the clean VM snapshot.'
        return [pscustomobject]@{ Expectations = @($list); Paths = $paths; Full = $full; Success = $false; Checks = $(if ($full) { 25 } else { 16 }) }
    }
    Add-OutputExpectation $list '  [PASS] uninstall leaves no service'
    return [pscustomobject]@{ Expectations = @($list); Paths = $paths; Full = $full; Success = $true; Checks = $(if ($full) { 25 } else { 16 }) }
}

function Invoke-ScriptedPlan($plan, [switch]$QuietFailure) {
    $effects = New-ScriptedHostEffects $plan.Expectations
    $adapter = New-ValidationAdapter $effects $plan.Paths.Candidate
    $runWorkflow = ${function:Invoke-WfpValidationWorkflow}
    $invoke = { return & $runWorkflow $adapter -SkipEnforcement:(-not $plan.Full) }.GetNewClosure()
    $capture = Invoke-StrictCapture $invoke ([WorkflowResult]) 1
    $result = if ($capture.Valid) { [WorkflowResult]$capture.Value } else { $null }
    $ok = $capture.Valid -and
        (($result.ExitCode -eq 0) -eq $plan.Success) -and
        $result.Checks -eq $plan.Checks -and
        $effects.Queue.Count -eq 0 -and [string]::IsNullOrEmpty($effects.State.Mismatch)
    if ($ok -and $plan.PSObject.Properties.Name -contains 'ExpectedStopped') {
        $ok = $result.Stopped -eq $plan.ExpectedStopped
    }
    if ($ok -and $plan.PSObject.Properties.Name -contains 'ExpectedFailures') {
        $ok = $result.Failures -eq $plan.ExpectedFailures
    }
    if (-not $ok -and -not $QuietFailure) {
        Write-Host ('    scripted mismatch: remaining={0}; host={1}' -f
            $effects.Queue.Count, $effects.State.Mismatch)
    }
    return [bool]$ok
}

function Copy-Expectations([HostExpectation[]]$expectations) {
    $copy = New-Object System.Collections.ArrayList
    foreach ($expectation in $expectations) {
        $call = [HostCall]::new($expectation.Call.Kind, $expectation.Call.Path, @($expectation.Call.Arguments))
        [void]$copy.Add([HostExpectation]::new($call, @($expectation.Results)))
    }
    return @($copy)
}

function New-WfpStateResult(
    [ValidateSet('present', 'absent')][string]$provider,
    [ValidateSet('present', 'absent')][string]$sublayer,
    [ValidateSet('present', 'absent')][string]$permit,
    [int]$exitCode = 0) {
    return [NativeResult]::new(
        ('WinSight WFP provider: {0}, sublayer: {1}, permit-filter: {2}. Per-app blocks are queried with wfp-block-status <path>.' -f
            $provider, $sublayer, $permit),
        $exitCode)
}

function Find-HostExpectationIndex(
    $plan,
    [string]$kind,
    [string]$path = '*',
    [string]$firstArgument = '*',
    [int]$occurrence = 0) {
    $matched = 0
    for ($index = 0; $index -lt $plan.Expectations.Count; $index++) {
        $call = $plan.Expectations[$index].Call
        $pathMatches = $path -ceq '*' -or $call.Path -ceq $path
        $argumentMatches = $firstArgument -ceq '*' -or
            ($call.Arguments.Count -gt 0 -and $call.Arguments[0] -ceq $firstArgument)
        if ($call.Kind -ceq $kind -and $pathMatches -and $argumentMatches) {
            if ($matched -eq $occurrence) { return $index }
            $matched++
        }
    }
    throw ('Missing scripted expectation {0}:{1}:{2} occurrence {3}' -f
        $kind, $path, $firstArgument, $occurrence)
}

function Set-ScriptedPlanTail(
    $plan,
    [int]$throughIndex,
    [HostExpectation[]]$tail,
    [int]$checks,
    [bool]$success,
    [bool]$stopped,
    [int]$failures) {
    $updated = New-Object System.Collections.ArrayList
    for ($index = 0; $index -le $throughIndex; $index++) {
        [void]$updated.Add($plan.Expectations[$index])
    }
    foreach ($expectation in $tail) { [void]$updated.Add($expectation) }
    $plan.Expectations = @($updated)
    $plan.Checks = $checks
    $plan.Success = $success
    $plan | Add-Member -NotePropertyName ExpectedStopped -NotePropertyValue $stopped -Force
    $plan | Add-Member -NotePropertyName ExpectedFailures -NotePropertyValue $failures -Force
}

function Set-ScriptedPlanOutcome(
    $plan,
    [bool]$success,
    [bool]$stopped,
    [int]$failures) {
    $plan.Success = $success
    $plan | Add-Member -NotePropertyName ExpectedStopped -NotePropertyValue $stopped -Force
    $plan | Add-Member -NotePropertyName ExpectedFailures -NotePropertyValue $failures -Force
}

function Invoke-ContractSelfTest([bool]$negativeControl) {
    $script:ContractChecks = 0; $script:ContractFailures = 0
    function Contract([string]$name, [scriptblock]$test) {
        $script:ContractChecks++
        $capture = Invoke-StrictCapture $test ([bool]) 1
        $passed = $capture.Valid -and [bool]$capture.Value
        if ($passed) { Write-Host ('  [PASS] {0}' -f $name) }
        else { $script:ContractFailures++; Write-Host ('  [FAIL] {0} ({1})' -f $name, $capture.Reason) }
    }

    Contract 'skip traverses production adapter primitive calls with 16 checks' {
        $plan = New-ScriptedPlan $false
        if ($negativeControl) {
            $plan.Expectations = Copy-Expectations $plan.Expectations
            $stopped = Find-HostExpectationIndex $plan 'ObserveService' $plan.Paths.Service '*' 2
            $plan.Expectations[$stopped].Results = @(
                [ServiceObservation]::new($true, 'Running', ('"{0}" run' -f $plan.Paths.Candidate)))
        }
        return Invoke-ScriptedPlan $plan
    }
    Contract 'full traverses production adapter target control prompts with 25 checks' {
        return Invoke-ScriptedPlan (New-ScriptedPlan $true)
    }
    Contract 'Running poll pins delayed and exact ten-attempt timeout' {
        return [bool]((Invoke-ScriptedPlan (New-ScriptedPlan $false @('StartPending','StartPending','Running'))) -and
            (Invoke-ScriptedPlan (New-ScriptedPlan $false (@('StartPending') * 10))))
    }
    Contract 'Stopped poll pins delayed timeout and uninstall ordering' {
        return [bool]((Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') @('StopPending','StopPending','Stopped'))) -and
            (Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') (@('StopPending') * 10))))
    }
    Contract 'Absent poll accepts exact 1060 with delayed and timeout sequences' {
        return [bool]((Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') @('Stopped') @(0,0,1060))) -and
            (Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') @('Stopped') (@(0) * 10))))
    }
    Contract 'delayed primitive queues reject constant Stopped and Absent implementations' {
        return [bool]((Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') @('StopPending','Stopped'))) -and
            (Invoke-ScriptedPlan (New-ScriptedPlan $false @('Running') @('Stopped') @(0,1060))))
    }
    Contract 'changed poll attempt count cannot drain closed queue' {
        $plan = New-ScriptedPlan $false (@('StartPending') * 10)
        $plan.Expectations = Copy-Expectations $plan.Expectations
        $lastObservation = -1
        for ($index = 0; $index -lt $plan.Expectations.Count; $index++) {
            if ($plan.Expectations[$index].Call.Kind -ceq 'ObserveService') {
                $lastObservation = $index
            }
        }
        $shortened = New-Object System.Collections.ArrayList
        for ($index = 0; $index -lt $plan.Expectations.Count; $index++) {
            if ($index -ne $lastObservation) {
                [void]$shortened.Add($plan.Expectations[$index])
            }
        }
        $plan.Expectations = @($shortened)
        return [bool](-not (Invoke-ScriptedPlan $plan -QuietFailure))
    }
    Contract 'absolute executable argument service and order mutations fail' {
        $plans = @()
        foreach ($kind in @('BareTool','ChangedArgument','ChangedService','ChangedOrder')) {
            $plan = New-ScriptedPlan $false
            $plan.Expectations = Copy-Expectations $plan.Expectations
            if ($kind -ceq 'BareTool') {
                ($plan.Expectations | Where-Object { $_.Call.Kind -ceq 'Native' -and $_.Call.Path -ceq $plan.Paths.Sc } | Select-Object -First 1).Call.Path = 'sc.exe'
            }
            elseif ($kind -ceq 'ChangedArgument') {
                ($plan.Expectations | Where-Object { $_.Call.Kind -ceq 'Native' -and $_.Call.Arguments[0] -ceq 'start' } | Select-Object -First 1).Call.Arguments[0] = 'start-mutated'
            }
            elseif ($kind -ceq 'ChangedService') {
                ($plan.Expectations | Where-Object { $_.Call.Kind -ceq 'ObserveService' } | Select-Object -First 1).Call.Path = 'OtherService'
            }
            else {
                $first = $plan.Expectations[0]; $plan.Expectations[0] = $plan.Expectations[1]; $plan.Expectations[1] = $first
            }
            $plans += $plan
        }
        foreach ($plan in $plans) { if (Invoke-ScriptedPlan $plan -QuietFailure) { return $false } }
        return $true
    }
    Contract 'real native effect normalizes stdout and stderr as refusal data' {
        $shell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $native = [HostCall]::new('Native', $shell, @(
            '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::Out.WriteLine(''NATIVE-NORMALIZED-MARKER''); [Console]::Error.WriteLine(''NATIVE-REFUSAL-DATA''); exit 7'))
        $capture = Invoke-StrictCapture (New-RealHostEffects).Invoke ([NativeResult]) 1 @($native)
        $passed = $capture.Valid -and ([NativeResult]$capture.Value).ExitCode -eq 7 -and
            ([NativeResult]$capture.Value).Output.Contains('NATIVE-NORMALIZED-MARKER') -and
            ([NativeResult]$capture.Value).Output.Contains('NATIVE-REFUSAL-DATA')
        if ($passed) { Write-Host 'NATIVE-NORMALIZED-MARKER' }
        return [bool]$passed
    }
    Contract 'scripted host exposes elementary effects and no business polls' {
        $effects = New-ScriptedHostEffects @()
        $names = @($effects.PSObject.Properties.Name)
        return [bool](($names -join '|') -ceq 'Invoke|WindowsRoot|UserProfile|Queue|State' -and
            -not ($names -contains 'PollRunning') -and -not ($names -contains 'PollStopped') -and -not ($names -contains 'PollAbsent'))
    }
    Contract 'strict capture rejects cardinality type and decorated results' {
        return [bool](-not (Invoke-StrictCapture { } ([bool]) 1).Valid -and
            -not (Invoke-StrictCapture { $true; $false } ([bool]) 1).Valid -and
            -not (Invoke-StrictCapture { 'true' } ([bool]) 1).Valid -and
            -not (Invoke-StrictCapture { 'diagnostic'; $false } ([bool]) 1).Valid)
    }
    Contract 'bounded poll primitive pins probe and sleep cardinality' {
        $state = [pscustomobject]@{ Probes = 0; Sleeps = 0 }
        $probe = { $state.Probes++; return [bool]($state.Probes -eq 3) }.GetNewClosure()
        $sleep = { $state.Sleeps++ }.GetNewClosure()
        $delayed = Invoke-BoundedPoll $probe $sleep 5
        $timeoutState = [pscustomobject]@{ Probes = 0; Sleeps = 0 }
        $timeoutProbe = { $timeoutState.Probes++; return $false }.GetNewClosure()
        $timeoutSleep = { $timeoutState.Sleeps++ }.GetNewClosure()
        $timeout = Invoke-BoundedPoll $timeoutProbe $timeoutSleep 4
        return [bool]($delayed -and $state.Probes -eq 3 -and $state.Sleeps -eq 2 -and
            -not $timeout -and $timeoutState.Probes -eq 4 -and $timeoutState.Sleeps -eq 3)
    }
    Contract 'WFP state helper exhaustively distinguishes absent and armed tuples' {
        foreach ($provider in @('absent', 'present')) {
            foreach ($sublayer in @('absent', 'present')) {
                foreach ($permit in @('absent', 'present')) {
                    $result = New-WfpStateResult $provider $sublayer $permit
                    $isAbsent = Test-WfpState $result 'absent' 'absent' 'absent'
                    $isArmed = Test-WfpState $result 'present' 'present' 'absent'
                    if ($isAbsent -ne ($provider -ceq 'absent' -and $sublayer -ceq 'absent' -and $permit -ceq 'absent')) {
                        return $false
                    }
                    if ($isArmed -ne ($provider -ceq 'present' -and $sublayer -ceq 'present' -and $permit -ceq 'absent')) {
                        return $false
                    }
                }
            }
        }
        return [bool](-not (Test-WfpState (New-WfpStateResult 'absent' 'absent' 'absent' 1) 'absent' 'absent' 'absent') -and
            -not (Test-WfpState ([NativeResult]::new(('prefix ' + $script:WfpAbsent), 0)) 'absent' 'absent' 'absent'))
    }
    Contract 'path denial helper accepts only eight exact codes at exit one' {
        foreach ($code in $script:PathDenialCodes) {
            if (-not (Test-PathTrustRefusal ([NativeResult]::new($code, 1)))) { return $false }
            if (Test-PathTrustRefusal ([NativeResult]::new(('prefix ' + $code), 1))) { return $false }
            if (Test-PathTrustRefusal ([NativeResult]::new(($code + "`nextra"), 1))) { return $false }
            if (Test-PathTrustRefusal ([NativeResult]::new($code, 0))) { return $false }
        }
        return $true
    }
    Contract 'web helpers pin 200 and 000 across zero and nonzero exits' {
        foreach ($output in @('200', '000')) {
            foreach ($exitCode in @(0, 2)) {
                $result = [NativeResult]::new($output, $exitCode)
                $success = Test-WebSuccess $result
                $blocked = Test-WebBlocked $result
                if ($success -ne ($output -ceq '200' -and $exitCode -eq 0)) { return $false }
                if ($blocked -ne ($output -ceq '000' -and $exitCode -ne 0)) { return $false }
            }
        }
        return $true
    }
    Contract 'direct refusal helper rejects decoration multiline and wrong exit' {
        $code = '[FW_DIRECT_MUTATION_DISABLED]'
        return [bool]((Test-DirectMutationRefusal ([NativeResult]::new($code, 1))) -and
            -not (Test-DirectMutationRefusal ([NativeResult]::new(('prefix ' + $code), 1))) -and
            -not (Test-DirectMutationRefusal ([NativeResult]::new(($code + "`nextra"), 1))) -and
            -not (Test-DirectMutationRefusal ([NativeResult]::new($code, 0))))
    }
    Contract 'SCM binding helper rejects unquoted missing wrong verb path and case' {
        $path = 'C:\Program Files\WinSight\winsight-firewall-service.exe'
        $otherPath = 'C:\Program Files\WinSight\other-firewall-service.exe'
        return [bool]((Test-ServiceBinding ('"{0}" run' -f $path) $path) -and
            -not (Test-ServiceBinding ('{0} run' -f $path) $path) -and
            -not (Test-ServiceBinding '' $path) -and
            -not (Test-ServiceBinding ('"{0}"' -f $path) $path) -and
            -not (Test-ServiceBinding ('"{0}" start' -f $path) $path) -and
            -not (Test-ServiceBinding ('"{0}" run' -f $otherPath) $path) -and
            -not (Test-ServiceBinding ('"{0}" run' -f $path.ToUpperInvariant()) $path) -and
            -not (Test-ServiceBinding ('"{0}" RUN' -f $path) $path))
    }
    Contract 'other exact helper predicates remain fail closed' {
        $path = 'C:\Program Files\WinSight\winsight-firewall-service.exe'
        $audit = 'Persisted desired enforcement mode: AuditOnly. Effective runtime state: unknown (query the authenticated running service).'
        $self = 'WFP engine opened. Existing filters visible: 0. Read-only: no filter, provider or sublayer was added or changed.'
        return [bool]((Test-ServiceBinding ('"{0}" run' -f $path) $path) -and
            -not (Test-ServiceBinding ('"{0}" RUN' -f $path) $path) -and
            (Test-EnforcementStatus ([NativeResult]::new($audit,0)) 'AuditOnly') -and
            -not (Test-EnforcementStatus ([NativeResult]::new('Persisted desired enforcement mode: AuditOnly',0)) 'AuditOnly') -and
            (Test-WfpSelfTestResult ([NativeResult]::new($self,0))) -and
            -not (Test-WfpSelfTestResult ([NativeResult]::new(('prefix ' + $self),0))) -and
            (Test-BlockedStatus ([NativeResult]::new('[FW_APP_BLOCKED]',0))) -and
            -not (Test-BlockedStatus ([NativeResult]::new('prefix [FW_APP_BLOCKED]',0))) -and
            (Test-DirectMutationRefusal ([NativeResult]::new('[FW_DIRECT_MUTATION_DISABLED]',1))) -and
            -not (Test-DirectMutationRefusal ([NativeResult]::new('prefix [FW_DIRECT_MUTATION_DISABLED]',1))) -and
            (Test-WebSuccess ([NativeResult]::new('200',0))) -and
            -not (Test-WebSuccess ([NativeResult]::new('200',1))))
    }
    Contract 'pre-arm primitive WFP observations stop before prompt or service cleanup' {
        $plans = New-Object System.Collections.ArrayList
        foreach ($state in @(
                @('present', 'present', 'absent'),
                @('absent', 'present', 'absent'))) {
            $plan = New-ScriptedPlan $true
            $plan.Expectations = Copy-Expectations $plan.Expectations
            $index = Find-HostExpectationIndex $plan 'Native' $plan.Paths.Candidate 'wfp-status' 0
            $plan.Expectations[$index].Results = @(
                (New-WfpStateResult $state[0] $state[1] $state[2]))
            $tail = New-Object System.Collections.ArrayList
            Add-OutputExpectation $tail '  [FAIL] no WFP state before arming: provider, sublayer and permit-filter exactly absent'
            Add-OutputExpectation $tail 'STOP: pre-arm WFP state is not empty; do not arm enforcement.'
            Set-ScriptedPlanTail $plan $index @($tail) 11 $false $true 1
            [void]$plans.Add($plan)
        }

        $directPlan = New-ScriptedPlan $true
        $directPlan.Expectations = Copy-Expectations $directPlan.Expectations
        $afterDirect = Find-HostExpectationIndex $directPlan 'Native' $directPlan.Paths.Candidate 'wfp-status' 1
        $directPlan.Expectations[$afterDirect].Results = @(
            (New-WfpStateResult 'present' 'present' 'absent'))
        $directTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $directTail '  [FAIL] direct mutation is refused without changing WFP: exact refusal/exit 1 followed immediately by exact empty WFP state'
        Add-OutputExpectation $directTail 'STOP: direct mutation refusal or post-state check failed; do not arm enforcement.'
        Set-ScriptedPlanTail $directPlan $afterDirect @($directTail) 12 $false $true 1
        [void]$plans.Add($directPlan)

        foreach ($plan in $plans) {
            if (-not (Invoke-ScriptedPlan $plan)) { return $false }
        }
        return $true
    }
    Contract 'rollback failures emit all restored checks then stop before uninstall' {
        $plans = New-Object System.Collections.ArrayList

        $wfpPlan = New-ScriptedPlan $true
        $wfpPlan.Expectations = Copy-Expectations $wfpPlan.Expectations
        $rollbackWfp = Find-HostExpectationIndex $wfpPlan 'Native' $wfpPlan.Paths.Candidate 'wfp-status' 3
        $wfpPlan.Expectations[$rollbackWfp].Results = @(
            (New-WfpStateResult 'present' 'present' 'absent'))
        $restoredControl = Find-HostExpectationIndex $wfpPlan 'Native' $wfpPlan.Paths.Control '*' 2
        $wfpTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $wfpTail '  [PASS] back to audit-only'
        Add-OutputExpectation $wfpTail '  [FAIL] all WFP state is removed: provider, sublayer and permit-filter exactly absent'
        Add-OutputExpectation $wfpTail '  [PASS] target and control connectivity are restored'
        Add-OutputExpectation $wfpTail 'STOP: rollback proof failed; do not uninstall and restore the clean VM snapshot.'
        Set-ScriptedPlanTail $wfpPlan $restoredControl @($wfpTail) 21 $false $true 1
        [void]$plans.Add($wfpPlan)

        $connectivityPlan = New-ScriptedPlan $true
        $connectivityPlan.Expectations = Copy-Expectations $connectivityPlan.Expectations
        $restoredTarget = Find-HostExpectationIndex $connectivityPlan 'Native' $connectivityPlan.Paths.Target '*' 2
        $connectivityPlan.Expectations[$restoredTarget].Results = @([NativeResult]::new('000', 2))
        $restoredControl = Find-HostExpectationIndex $connectivityPlan 'Native' $connectivityPlan.Paths.Control '*' 2
        $connectivityTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $connectivityTail '  [PASS] back to audit-only'
        Add-OutputExpectation $connectivityTail '  [PASS] all WFP state is removed'
        Add-OutputExpectation $connectivityTail '  [FAIL] target and control connectivity are restored: both fixed HTTP clients return 200/exit 0'
        Add-OutputExpectation $connectivityTail 'STOP: rollback proof failed; do not uninstall and restore the clean VM snapshot.'
        Set-ScriptedPlanTail $connectivityPlan $restoredControl @($connectivityTail) 21 $false $true 1
        [void]$plans.Add($connectivityPlan)

        foreach ($plan in $plans) {
            if (-not (Invoke-ScriptedPlan $plan)) { return $false }
        }
        return $true
    }
    Contract 'post-arm observation failure still rolls back and completes cleanup nonzero' {
        $plan = New-ScriptedPlan $true
        $plan.Expectations = Copy-Expectations $plan.Expectations
        $armed = Find-HostExpectationIndex $plan 'Native' $plan.Paths.Candidate 'wfp-status' 2
        $plan.Expectations[$armed].Results = @(
            (New-WfpStateResult 'absent' 'absent' 'absent'))
        $plan.Expectations[$armed + 1].Call.Path =
            '  [FAIL] WFP state is exactly armed: provider and sublayer present; permit-filter absent'
        Set-ScriptedPlanOutcome $plan $false $false 1
        return Invoke-ScriptedPlan $plan
    }
    Contract 'stage binding native prompt and effect pollution fail closed through adapter' {
        $plans = New-Object System.Collections.ArrayList

        $stagePlan = New-ScriptedPlan $false
        $stagePlan.Expectations = Copy-Expectations $stagePlan.Expectations
        $stageToken = Find-HostExpectationIndex $stagePlan 'NewToken'
        $stagePlan.Expectations[$stageToken].Results = @('closedtoken', 'pollution')
        $stageTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $stageTail '  [FAIL] user-writable sentinel is staged as data: one sentinel file, never a staged service or DLL'
        Add-OutputExpectation $stageTail 'STOP: mandatory path-trust sentinel staging failed.'
        Set-ScriptedPlanTail $stagePlan $stageToken @($stageTail) 3 $false $true 1
        [void]$plans.Add($stagePlan)

        $bindingPlan = New-ScriptedPlan $false
        $bindingPlan.Expectations = Copy-Expectations $bindingPlan.Expectations
        $binding = Find-HostExpectationIndex $bindingPlan 'ObserveService' $bindingPlan.Paths.Service '*' 0
        $bindingPlan.Expectations[$binding].Results = @(
            [ServiceObservation]::new($true, 'Stopped', ('"{0}" RUN' -f $bindingPlan.Paths.Candidate)))
        $bindingTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $bindingTail '  [FAIL] SCM binds the canonical candidate and run verb: exact case-sensitive quoted candidate plus run'
        Add-HostExpectation $bindingTail 'RemoveDirectory' $bindingPlan.Paths.Directory @() @()
        Add-OutputExpectation $bindingTail 'STOP: SCM registration does not bind the requested candidate exactly.'
        Set-ScriptedPlanTail $bindingPlan $binding @($bindingTail) 6 $false $true 1
        [void]$plans.Add($bindingPlan)

        $nativePlan = New-ScriptedPlan $false
        $nativePlan.Expectations = Copy-Expectations $nativePlan.Expectations
        $install = Find-HostExpectationIndex $nativePlan 'Native' $nativePlan.Paths.Candidate 'install'
        $nativePlan.Expectations[$install].Results = @(
            [NativeResult]::new('ok', 0),
            [NativeResult]::new('pollution', 0))
        $nativeTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $nativeTail '  [FAIL] candidate install succeeds: install exits 0'
        Add-HostExpectation $nativeTail 'RemoveDirectory' $nativePlan.Paths.Directory @() @()
        Add-OutputExpectation $nativeTail 'STOP: candidate install failed.'
        Set-ScriptedPlanTail $nativePlan $install @($nativeTail) 5 $false $true 1
        [void]$plans.Add($nativePlan)

        $promptPlan = New-ScriptedPlan $true
        $promptPlan.Expectations = Copy-Expectations $promptPlan.Expectations
        $prompt = Find-HostExpectationIndex $promptPlan 'Prompt' '*' '*' 0
        $promptPlan.Expectations[$prompt].Results = @('pollution')
        $promptTail = New-Object System.Collections.ArrayList
        Add-OutputExpectation $promptTail 'STOP: arm prompt violated the zero-output contract.'
        Set-ScriptedPlanTail $promptPlan $prompt @($promptTail) 13 $false $true 1
        [void]$plans.Add($promptPlan)

        $effectPlan = New-ScriptedPlan $false
        $effectPlan.Expectations = Copy-Expectations $effectPlan.Expectations
        $removeStage = Find-HostExpectationIndex $effectPlan 'RemoveDirectory' $effectPlan.Paths.Directory '*' 0
        $effectPlan.Expectations[$removeStage].Results = @('pollution')
        $effectTail = New-Object System.Collections.ArrayList
        Add-HostExpectation $effectTail 'RemoveDirectory' $effectPlan.Paths.Directory @() @()
        Add-OutputExpectation $effectTail 'STOP: stage cleanup violated the zero-output contract.'
        Set-ScriptedPlanTail $effectPlan $removeStage @($effectTail) 9 $false $true 1
        [void]$plans.Add($effectPlan)

        foreach ($plan in $plans) {
            if (-not (Invoke-ScriptedPlan $plan)) { return $false }
        }
        return $true
    }
    Contract 'adapter pins sentinel as data and absolute target control calls' {
        $plan = New-ScriptedPlan $true
        $nativeCalls = @($plan.Expectations | Where-Object { $_.Call.Kind -ceq 'Native' })
        return [bool](@($nativeCalls | Where-Object { $_.Call.Arguments[0] -ceq 'install-path-trust-check' }).Count -eq 1 -and
            @($nativeCalls | Where-Object { $_.Call.Path -ceq $plan.Paths.Sentinel }).Count -eq 0 -and
            @($nativeCalls | Where-Object { $_.Call.Path -ceq $plan.Paths.Target }).Count -eq 3 -and
            @($nativeCalls | Where-Object { $_.Call.Path -ceq $plan.Paths.Control }).Count -eq 3)
    }
    Contract 'workflow returns one typed result and queue drains' {
        $plan = New-ScriptedPlan $false
        $effects = New-ScriptedHostEffects $plan.Expectations
        $adapter = New-ValidationAdapter $effects $plan.Paths.Candidate
        $capture = Invoke-StrictCapture { return Invoke-WfpValidationWorkflow $adapter -SkipEnforcement } ([WorkflowResult]) 1
        return [bool]($capture.Valid -and $effects.Queue.Count -eq 0 -and [string]::IsNullOrEmpty($effects.State.Mismatch))
    }

    $expectedChecks = 24
    if ($script:ContractChecks -ne $expectedChecks) {
        $script:ContractFailures++; Write-Host ('  [FAIL] mandatory contract count expected {0}, ran {1}' -f $expectedChecks, $script:ContractChecks)
    }
    if ($script:ContractFailures -eq 0) { Write-Host ('[CONTRACT-SELFTEST PASS] {0} checks' -f $script:ContractChecks); return 0 }
    Write-Host ('[CONTRACT-SELFTEST FAIL] {0} checks, {1} failures' -f $script:ContractChecks, $script:ContractFailures); return 1
}
if ($ContractNegativeControl -and -not $ContractSelfTest) { throw '-ContractNegativeControl requires -ContractSelfTest.' }
if ($ContractSelfTest) {
    $capture = Invoke-StrictCapture { return Invoke-ContractSelfTest ([bool]$ContractNegativeControl) } ([int]) 1
    if (-not $capture.Valid) { Write-Host '[CONTRACT-SELFTEST FAIL] invalid self-test result contract'; exit 1 }
    exit ([int]$capture.Value)
}
if ([string]::IsNullOrWhiteSpace($ServicePath)) { throw '-ServicePath is required unless -ContractSelfTest is specified.' }

$workflow = Invoke-StrictCapture {
    return Invoke-WfpValidationWorkflow (New-ValidationAdapter (New-RealHostEffects) $ServicePath) -SkipEnforcement:$SkipEnforcement
} ([WorkflowResult]) 1
if (-not $workflow.Valid) { Write-Host 'STOP: workflow result contract was violated.'; exit 1 }
$result = [WorkflowResult]$workflow.Value
Write-Host ('Result: {0} checks, {1} failure(s). {2}' -f $result.Checks, $result.Failures, $result.Reason)
exit $result.ExitCode
