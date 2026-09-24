# WinSight v0.13.0 candidate qualification - runs INSIDE WinSight-Qualification-Fresh, elevated, as the
# auto-logged-on WinSightAdmin, started by the bootstrap logon task. Unattended: every gate records
# PASS / FAIL / NOT_RUN into guest-results\results.json on the shared folder (outside the snapshot),
# with its evidence file next to it. Never reports PASS for a step it did not execute.
#
# Scope: identity + protected root, Authenticode/PE, CLI contract, installer lifecycle, MCP, read-only
# scanners, MSIX package evidence, operator-confirmed responses (process verbs, holders, Guardian
# Block/Restore/Allow/Revoke through the real alert window), Explorer signature verb + window,
# dashboard languages, all-users uninstall with service (WS-63), upgrade from the published release,
# Cloud Files placeholders (WS-40), ETW recovery, pre-opened write attribution (WS-60),
# WFP contract/pre-arm/full, trust, local IPC, final residue.
# Network Logon (36) needs the control VM and a disposable password typed by the operator: it runs only
# when Invoke-HyperVNetworkLogon.ps1 stages network.json, and is recorded NOT_RUN otherwise.

$ErrorActionPreference = 'Continue'
$Share = Split-Path -Parent $MyInvocation.MyCommand.Path
$Evidence = Join-Path $Share 'guest-results'
New-Item -ItemType Directory -Force $Evidence | Out-Null
Start-Transcript -Path (Join-Path $Evidence 'transcript.txt') -Force | Out-Null

# A stray click in the console enters QuickEdit selection and freezes the run until a key is pressed.
Add-Type -Name Con -Namespace W -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int h);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint m);
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint m);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern void mouse_event(uint f, uint x, uint y, uint d, System.IntPtr e);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint f);
'@
$stdin = [W.Con]::GetStdHandle(-10); $mode = 0
if ([W.Con]::GetConsoleMode($stdin, [ref]$mode)) { [void][W.Con]::SetConsoleMode($stdin, (($mode -band (-bnot 0x40)) -bor 0x80)) }
[void][W.Con]::SetProcessDPIAware()
# An idle guest turns its display off after about ten minutes; WPF then stops presenting on the virtual
# adapter and UI Automation calls into the dashboard block until the display wakes (gate 12 stalled 55
# minutes on 2026-09-22). Keep display and system awake while this script runs; no setting is changed.
[void][W.Con]::SetThreadExecutionState([uint32]2147483651)  # ES_CONTINUOUS | ES_DISPLAY_REQUIRED | ES_SYSTEM_REQUIRED
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$NativePowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
$CurlExe = Join-Path $env:SystemRoot 'System32\curl.exe'
$Candidate = Get-Content (Join-Path $Share 'candidate.json') -Raw | ConvertFrom-Json
$Version = $Candidate.version
$Root = 'C:\Program Files\WinSight-Qualification'
$Artifacts = Join-Path $Root 'artifacts'
$Payload = Join-Path $Root 'payload'
$Source = Join-Path $Root 'source'
$ProbeValue = 'WinSightQualificationProbe'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

$Results = [ordered]@{
    candidate = $Candidate
    startedUtc = (Get-Date).ToUniversalTime().ToString('o')
    computer = $env:COMPUTERNAME
    user = "$env:USERDOMAIN\$env:USERNAME"
    os = (Get-CimInstance Win32_OperatingSystem | ForEach-Object { "$($_.Caption) $($_.Version) build $($_.BuildNumber)" })
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    gates = [ordered]@{}
    finishedUtc = $null
}
function Save-Results { $Results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $Evidence 'results.json') -Encoding UTF8 }

function Invoke-Gate([string]$Name, [scriptblock]$Body) {
    # A re-run lists the gates it repeats in candidate.json; staging (01) always runs.
    if ($Candidate.PSObject.Properties['gates'] -and $Name -notlike '01-*' -and $Candidate.gates -notcontains $Name) { return }
    "===== GATE $Name  $(Get-Date -Format o) ====="
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $status = 'PASS'
    try {
        $detail = (& $Body | Out-String).Trim()
    }
    catch {
        $message = $_.Exception.Message
        $status = if ($message -like 'NOT_RUN:*') { 'NOT_RUN' } else { 'FAIL' }
        $detail = "$message`n$($_.InvocationInfo.PositionMessage)"
    }
    if ($detail.Length -gt 4000) { $detail = $detail.Substring($detail.Length - 4000) }
    $Results.gates[$Name] = [ordered]@{ status = $status; seconds = [math]::Round($watch.Elapsed.TotalSeconds, 1); detail = $detail }
    "----- $Name -> $status"
    Save-Results
}

function Get-Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

# Every executable and script the run starts is re-hashed against the manifest bound at staging.
$script:Manifest = @{}
function Assert-CandidateFiles {
    foreach ($entry in $script:Manifest.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Key) -or (Get-Sha256 $entry.Key) -ne $entry.Value) {
            throw "Candidate file changed or missing: $($entry.Key)"
        }
    }
}

function Invoke-Logged([string]$LogName, [string]$File, [string[]]$Arguments) {
    Assert-CandidateFiles
    $log = Join-Path $Evidence $LogName
    & $File @Arguments *> $log
    $code = $LASTEXITCODE
    Add-Content -LiteralPath $log -Value "exit=$code"
    return $code
}

function Invoke-Script([string]$LogName, [string]$ScriptPath, [string[]]$Arguments) {
    Invoke-Logged $LogName $NativePowerShell (@('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $Arguments)
}

function Tail([string]$LogName, [int]$Lines = 6) { (Get-Content (Join-Path $Evidence $LogName) -Tail $Lines) -join "`n" }

function Invoke-Cli([string[]]$Arguments) {
    Assert-CandidateFiles
    $output = & $script:Cli @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $output }
}

function Invoke-CliJson([string[]]$Arguments) {
    $run = Invoke-Cli ($Arguments + '--json')
    try { $json = $run.Output | ConvertFrom-Json } catch { throw "Not JSON from winsight $($Arguments -join ' '): exit=$($run.Exit) $($run.Output)" }
    if ($json.schemaVersion -ne 1) { throw "Unexpected envelope from winsight $($Arguments -join ' ')" }
    return [pscustomobject]@{ Exit = $run.Exit; Report = $json.reports[0] }
}

# The dashboard normally runs as the signed-in user, not elevated: start it through a one-shot
# Limited-run-level task so HKCU, the journals and the windows are exactly an operator's.
function Start-Unelevated([string]$File, [string]$Arguments) {
    Assert-CandidateFiles
    $name = 'WinSightQualLimited-' + [guid]::NewGuid().ToString('N')
    $action = if ($Arguments) { New-ScheduledTaskAction -Execute $File -Argument $Arguments } else { New-ScheduledTaskAction -Execute $File }
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    $before = Get-Date
    Start-ScheduledTask -TaskName $name
    $leaf = [IO.Path]::GetFileNameWithoutExtension($File)
    # A single-file executable unpacks on its first run, which takes far longer on a cold VM disk
    # than any fixed short wait would allow.
    $deadline = (Get-Date).AddSeconds(180)
    do {
        $process = Get-Process -Name $leaf -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -ge $before.AddSeconds(-2) -and $_.Path -eq $File } | Select-Object -First 1
        if ($process) { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    $script:LimitedTasks += $name
    if (-not $process) {
        $info = Get-ScheduledTaskInfo -TaskName $name -ErrorAction SilentlyContinue
        throw "Unelevated $leaf did not start (task lastResult=$($info.LastTaskResult) lastRun=$($info.LastRunTime))."
    }
    return $process
}
$script:LimitedTasks = @()

# --- UI Automation -------------------------------------------------------------------------------
$UIA = [System.Windows.Automation.AutomationElement]
$Scope = [System.Windows.Automation.TreeScope]
function New-Condition($Property, $Value) { New-Object System.Windows.Automation.PropertyCondition($Property, $Value) }

function Find-ProcessWindowWith([int]$ProcessId, [string]$AutomationId, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $windows = $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $ProcessId))
        foreach ($window in $windows) {
            if ($window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $AutomationId))) { return $window }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $null
}

# A burst of arrivals is announced as one balloon, by design, so the planted item must arrive alone.
# The dashboard's own alert journal says when the machine last announced anything.
function Wait-GuardianQuiet([int]$QuietSeconds = 150, [int]$TimeoutSeconds = 1200) {
    $journal = Join-Path (Join-Path $env:LOCALAPPDATA 'WinSight') 'alerts.log'
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $last = if (Test-Path $journal) { (Get-Item $journal).LastWriteTime } else { [DateTime]::MinValue }
        if (((Get-Date) - $last).TotalSeconds -gt $QuietSeconds) { return $true }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Find-AlertWindowFor([int]$ProcessId, [string]$ButtonId, [string]$Pattern, [int]$TimeoutSeconds) {
    # A real machine raises its own arrivals (an Edge updater writes a Run value of its own), so the
    # window this gate acts on is the one naming the planted item, never simply the first one open.
    # Every candidate is recorded, so a miss says which windows were open and what they named.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $seen = @{}
    do {
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $ProcessId))) {
            if (-not $window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $ButtonId))) { continue }
            $parts = foreach ($id in 'ItemText', 'LocationText', 'ProgramText') {
                $element = $window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $id))
                if ($element) { $element.Current.Name } else { '' }
            }
            $text = ($parts -join ' | ')
            if (-not $seen.ContainsKey($text)) {
                $seen[$text] = $true
                Add-Content -LiteralPath (Join-Path $Evidence 'alert-windows-seen.txt') `
                    -Value "$(Get-Date -Format o) [$ButtonId] $text"
            }
            if ($text -match $Pattern) { return $window }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $null
}

# Alert windows are capped at three per item set: an unrelated arrival left open would keep the
# planted one from ever opening its own window.
function Close-OtherAlertWindows([int]$ProcessId, [string]$KeepPattern) {
    foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $ProcessId))) {
        $later = $window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty 'LaterButton'))
        if (-not $later) { continue }
        $item = $window.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty 'ItemText'))
        if ($item -and $item.Current.Name -match $KeepPattern) { continue }
        try { $later.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() } catch { }
    }
}

function Find-ById($Parent, [string]$AutomationId) {
    $element = $Parent.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $AutomationId))
    if (-not $element) { throw "UI element '$AutomationId' not found." }
    return $element
}

function Invoke-UiButton($Parent, [string]$AutomationId) {
    $button = Find-ById $Parent $AutomationId
    if (-not $button.Current.IsEnabled) { throw "Button '$AutomationId' is disabled." }
    $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}

function Wait-UiText($Parent, [string]$AutomationId, [string]$Pattern, [int]$TimeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $element = $Parent.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty $AutomationId))
        if ($element) {
            $text = $element.Current.Name
            $valuePattern = $null
            if ($element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$valuePattern)) { $text = $valuePattern.Current.Value }
            if ($text -match $Pattern) { return $text }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "UI text '$AutomationId' never matched '$Pattern' (last: '$text')."
}

function Close-UiWindow($Window) {
    $Window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
}

function Click-At([int]$X, [int]$Y, [switch]$Right) {
    [void][W.Con]::SetCursorPos($X, $Y)
    Start-Sleep -Milliseconds 200
    if ($Right) { [W.Con]::mouse_event(0x0008, 0, 0, 0, [IntPtr]::Zero); [W.Con]::mouse_event(0x0010, 0, 0, 0, [IntPtr]::Zero) }
    else { [W.Con]::mouse_event(0x0002, 0, 0, 0, [IntPtr]::Zero); [W.Con]::mouse_event(0x0004, 0, 0, 0, [IntPtr]::Zero) }
}

function Get-Center($Element) {
    $r = $Element.Current.BoundingRectangle
    return @([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2))
}

# Exits one dashboard through its notification-area icon: right-click -> Exit. Returns $false when the
# icon or the menu cannot be driven, so the caller records NOT_RUN instead of substituting a kill.
function Invoke-TrayExit([int[]]$DashboardIds) {
    $buttons = New-Condition $UIA::ControlTypeProperty ([System.Windows.Automation.ControlType]::Button)
    $icon = $null
    foreach ($attempt in 1..2) {
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, [System.Windows.Automation.Condition]::TrueCondition)) {
            $class = $window.Current.ClassName
            if ($class -notin @('Shell_TrayWnd', 'TopLevelWindowForOverflowXamlIsland', 'NotifyIconOverflowWindow')) { continue }
            $icon = @($window.FindAll($Scope::Descendants, $buttons)) | Where-Object { $_.Current.Name -like 'WinSight*' } | Select-Object -First 1
            if ($icon) { break }
        }
        if ($icon -or $attempt -eq 2) { break }
        $taskbar = $UIA::RootElement.FindFirst($Scope::Children, (New-Condition $UIA::ClassNameProperty 'Shell_TrayWnd'))
        $chevron = @($taskbar.FindAll($Scope::Descendants, $buttons)) | Where-Object { $_.Current.Name -match 'hidden|cach|ocult' } | Select-Object -First 1
        if (-not $chevron) { break }
        $xy = Get-Center $chevron; Click-At $xy[0] $xy[1]
        Start-Sleep -Seconds 2
    }
    if (-not $icon) {
        # Record what the notification area exposes, so a failure names the missing element.
        $script:TrayDiagnostic = @($UIA::RootElement.FindAll($Scope::Children, [System.Windows.Automation.Condition]::TrueCondition) |
            Where-Object { $_.Current.ClassName -match 'Shell_TrayWnd|Overflow' } |
            ForEach-Object { $_.FindAll($Scope::Descendants, $buttons) } | ForEach-Object { "$($_.Current.ClassName)|$($_.Current.Name)" }) -join '; '
        return $false
    }
    $xy = Get-Center $icon; Click-At $xy[0] $xy[1] -Right
    $deadline = (Get-Date).AddSeconds(10)
    do {
        foreach ($id in $DashboardIds) {
            foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $id))) {
                $exit = $window.FindFirst($Scope::Descendants, (New-Condition $UIA::NameProperty 'Exit'))
                if ($exit) {
                    $invoke = $null
                    if ($exit.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$invoke)) { $invoke.Invoke() }
                    else { $xy = Get-Center $exit; Click-At $xy[0] $xy[1] }
                    return $true
                }
            }
        }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Test-AllThreadsSuspended([int]$ProcessId) {
    foreach ($thread in (Get-Process -Id $ProcessId).Threads) {
        # WaitReason throws for a thread that is not waiting, so test the state first.
        if ($thread.ThreadState -ne 'Wait' -or $thread.WaitReason -ne 'Suspended') { return $false }
    }
    return $true
}

# Asks for one operator action through the shared folder and waits for the same folder to confirm it.
function Request-OperatorAction([string]$Name, [string]$Instruction, [int]$TimeoutMinutes = 20) {
    $request = Join-Path $Evidence "OPERATOR-ACTION-$Name.txt"
    $done = Join-Path $Evidence "OPERATOR-DONE-$Name.txt"
    Remove-Item -LiteralPath $done -Force -ErrorAction SilentlyContinue
    $Instruction | Set-Content -LiteralPath $request
    # A host-provided operator, when present, performs the decision through the real controls and says
    # so in operator-automation.txt; without it, a human does and confirms through the shared folder.
    $automation = Join-Path $Share 'operator-automation.ps1'
    if (Test-Path -LiteralPath $automation) {
        try { . $automation -Name $Name }
        catch { throw "NOT_RUN: the operator automation for '$Name' failed: $($_.Exception.Message)" }
        "performed by operator-automation.ps1 at $(Get-Date -Format o)" | Set-Content -LiteralPath $done
    }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    while (-not (Test-Path -LiteralPath $done)) {
        if ((Get-Date) -gt $deadline) { throw "NOT_RUN: the operator action '$Name' was not carried out within $TimeoutMinutes minutes." }
        Start-Sleep -Seconds 5
    }
    Remove-Item -LiteralPath $request -Force -ErrorAction SilentlyContinue
    "operator action $Name confirmed"
}

function Confirm-Dialog([int]$ProcessId, [int]$TimeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $ProcessId))) {
            $yes = @($window.FindAll($Scope::Descendants,
                (New-Condition $UIA::ControlTypeProperty ([System.Windows.Automation.ControlType]::Button)))) |
                Where-Object { $_.Current.Name -match '^(Yes|Oui|S..|Si)$' } | Select-Object -First 1
            if ($yes) {
                $yes.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
                return
            }
        }
        Start-Sleep -Milliseconds 400
    } while ((Get-Date) -lt $deadline)
    throw 'No confirmation dialog appeared.'
}

function Wait-Service([string]$State, [int]$ExcludePid = 0) {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
        if ($svc -and $svc.State -eq $State -and ($State -ne 'Running' -or ($svc.ProcessId -gt 0 -and $svc.ProcessId -ne $ExcludePid))) { return $svc }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Service did not reach $State."
}

function Remove-ServiceIfPresent {
    $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
    if (-not $svc) { return }
    & $ScExe stop WinSightFirewall *> $null
    Start-Sleep -Seconds 3
    if ($script:Service) { & $script:Service uninstall *> $null }
}

function Assert-AuditOnlyEmpty {
    Assert-CandidateFiles
    $mode = @(& $script:Service enforce-status); $modeExit = $LASTEXITCODE
    $wfp = @(& $script:Service wfp-status); $wfpExit = $LASTEXITCODE
    $ipc = @(& $script:Cli firewall-ipc-selftest); $ipcExit = $LASTEXITCODE
    if ($modeExit -ne 0 -or ($mode -join "`n") -notmatch 'mode: AuditOnly\.' -or $wfpExit -ne 0 -or
        ($wfp -join "`n") -notmatch 'provider: absent, sublayer: absent, permit-filter: absent' -or
        $ipcExit -ne 0 -or ($ipc -join "`n") -notmatch 'serviceAvailable=true') {
        throw "AuditOnly/WFP/IPC state invalid: mode=[$($mode -join ' ')] wfp=[$($wfp -join ' ')] ipc=[$($ipc -join ' ')]"
    }
    "AuditOnly, empty WFP state, IPC available"
}

# ================================================================================================
Invoke-Gate '01-identity-and-protected-root' {
    if (-not $Results.elevated) { throw 'The run is not elevated.' }
    foreach ($directory in $Artifacts, $Payload, $Source) {
        if (Test-Path $directory) { Remove-Item -Recurse -Force $directory }
        New-Item -ItemType Directory -Force $directory | Out-Null
    }
    foreach ($artifact in $Candidate.artifacts.PSObject.Properties) {
        $shared = Join-Path $Share $artifact.Name
        if ((Get-Sha256 $shared) -ne $artifact.Value) { throw "Shared artifact hash mismatch: $($artifact.Name)" }
        Copy-Item -LiteralPath $shared -Destination $Artifacts
        $protected = Join-Path $Artifacts $artifact.Name
        if ((Get-Sha256 $protected) -ne $artifact.Value) { throw "Protected artifact hash mismatch: $($artifact.Name)" }
        $script:Manifest[$protected] = $artifact.Value
    }
    foreach ($file in $Candidate.source.PSObject.Properties) {
        $destination = Join-Path $Source $file.Name
        New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
        Copy-Item -LiteralPath (Join-Path $Share "source\$($file.Name)") -Destination $destination
        if ((Get-Sha256 $destination) -ne $file.Value) { throw "Source hash mismatch: $($file.Name)" }
        $script:Manifest[$destination] = $file.Value
    }
    $zip = Get-ChildItem $Artifacts -Filter '*.zip' | Select-Object -First 1
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $Payload -Force
    Get-ChildItem $Payload -Recurse -File | Where-Object { $_.Extension -in '.exe', '.ps1', '.psm1', '.dll' } |
        ForEach-Object { $script:Manifest[$_.FullName] = Get-Sha256 $_.FullName }
    $script:Cli = (Get-ChildItem $Payload -Recurse -Filter 'winsight.exe' | Select-Object -First 1).FullName
    $script:Dashboard = (Get-ChildItem $Payload -Recurse -Filter 'winsight-dashboard.exe' | Select-Object -First 1).FullName
    $script:Service = (Get-ChildItem $Payload -Recurse -Filter 'winsight-firewall-service.exe' | Select-Object -First 1).FullName
    $script:Installer = (Get-ChildItem $Artifacts -Filter '*-setup.exe' | Select-Object -First 1).FullName
    $script:PackageRoot = Split-Path -Parent $script:Cli
    if (-not ($script:Cli -and $script:Dashboard -and $script:Service -and $script:Installer)) { throw 'Candidate executables are missing.' }
    function Resolve-ValidationScript([string]$Name) {
        $packaged = Join-Path $script:PackageRoot $Name
        if (Test-Path $packaged) { return $packaged }
        return (Join-Path $Source "scripts\$Name")
    }
    $script:WfpScript = Resolve-ValidationScript 'Test-WfpValidation.ps1'
    $script:TrustScript = Resolve-ValidationScript 'Test-TrustBoundary.ps1'
    $script:IpcScript = Resolve-ValidationScript 'Test-IpcBoundary.ps1'
    Assert-CandidateFiles
    $script:Manifest.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Value)  $($_.Key)" } |
        Set-Content (Join-Path $Evidence 'protected-manifest.txt')
    "commit=$($Candidate.commit) run=$($Candidate.runId) files=$($script:Manifest.Count) packageRoot=$script:PackageRoot"
    "wfp=$script:WfpScript trust=$script:TrustScript ipc=$script:IpcScript"
}

if (-not $script:Cli) {
    $Results.finishedUtc = (Get-Date).ToUniversalTime().ToString('o'); Save-Results; Stop-Transcript | Out-Null; return
}

Invoke-Gate '02-authenticode-and-architecture' {
    $lines = foreach ($path in @($script:Installer, $script:Cli, $script:Dashboard, $script:Service)) {
        Assert-CandidateFiles
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if ($sig.Status -ne 'NotSigned' -or $null -ne $sig.SignerCertificate -or $null -ne $sig.TimeStamperCertificate) {
            throw "Unexpected signature state: $path status=$($sig.Status)"
        }
        "$path status=$($sig.Status) signer=<none> timestamp=<none>"
    }
    $lines | Set-Content (Join-Path $Evidence 'unsigned-signature-status.txt')
    foreach ($path in @($script:Cli, $script:Dashboard, $script:Service)) {
        $code = Invoke-Script "pe-$([IO.Path]::GetFileNameWithoutExtension($path)).txt" (Join-Path $Source 'scripts\Test-PeArchitecture.ps1') @('-Path', $path, '-Architecture', 'x64')
        if ($code -ne 0) { throw "PE architecture check failed for $path" }
    }
    $lines
    'PE architecture x64 for the three executables'
}

Invoke-Gate '03-cli-contract' {
    $versionRun = Invoke-Cli @('--version')
    if ($versionRun.Exit -ne 0 -or $versionRun.Output -notmatch [regex]::Escape($Version)) { throw "Version mismatch: $($versionRun.Output)" }
    $integrity = Invoke-CliJson @('integrity')
    if ($integrity.Exit -notin 0, 1) { throw "Unexpected integrity exit $($integrity.Exit)" }
    if ($integrity.Report.tool -cne 'integrity' -or $null -eq $integrity.Report.items -or
        $null -eq $integrity.Report.notableCount -or $null -eq $integrity.Report.unverifiedCount) { throw 'Integrity JSON contract invalid.' }
    $help = Invoke-Cli @('--help')
    foreach ($verb in 'sign', 'holders', 'actions', 'rules', 'restore', 'revoke', 'suspend') {
        if ($help.Output -notmatch "\b$verb\b") { throw "Help does not document '$verb'." }
    }
    "version: $($versionRun.Output.Trim())"
    "integrity exit=$($integrity.Exit) notable=$($integrity.Report.notableCount)"
}

Invoke-Gate '04-installer-lifecycle' {
    $code = Invoke-Script 'installer-lifecycle.txt' (Join-Path $Source 'scripts\Test-Installer.ps1') @('-InstallerPath', $script:Installer, '-Version', $Version, '-Architecture', 'x64')
    if ($code -ne 0) { throw "Installer lifecycle failed (exit $code): $(Tail 'installer-lifecycle.txt' 15)" }
    Tail 'installer-lifecycle.txt'
}

Invoke-Gate '05-mcp-read-only' {
    $code = Invoke-Script 'mcp-server.txt' (Join-Path $Source 'scripts\Test-McpServer.ps1') @('-ServerPath', $script:Cli, '-Version', $Version)
    if ($code -ne 0) { throw "MCP server check failed (exit $code): $(Tail 'mcp-server.txt' 15)" }
    Tail 'mcp-server.txt'
}

Invoke-Gate '06-read-only-scanners' {
    $rows = foreach ($tool in 'persistence', 'av', 'net', 'dns', 'processes', 'modules', 'extensions', 'certs', 'hosts', 'input', 'drivers', 'integrity', 'hijack', 'presence', 'actions', 'rules', 'alerts') {
        $run = Invoke-CliJson @($tool)
        if ($run.Exit -notin 0, 1) { throw "winsight $tool exited $($run.Exit)" }
        if ([string]::IsNullOrWhiteSpace($run.Report.tool) -or $null -eq $run.Report.items) { throw "winsight $tool report contract invalid" }
        "$tool exit=$($run.Exit) items=$(@($run.Report.items).Count) :: $($run.Report.summary)"
    }
    $unsigned = Invoke-CliJson @('persistence', '--unsigned')
    $nonMicrosoft = Invoke-CliJson @('persistence', '--nonmicrosoft')
    if ($unsigned.Exit -notin 0, 1 -or $nonMicrosoft.Exit -notin 0, 1) { throw 'View filters failed.' }
    $rows
    "persistence --unsigned items=$(@($unsigned.Report.items).Count); --nonmicrosoft items=$(@($nonMicrosoft.Report.items).Count)"
}

Invoke-Gate '07-msix-package-evidence' {
    $member = Get-AppxPackage -Name Microsoft.Paint | ForEach-Object { Get-ChildItem $_.InstallLocation -Recurse -Depth 2 -Filter *.exe } |
        Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -eq 'NotSigned' } | Select-Object -First 1
    if ($null -eq $member) { throw 'NOT_RUN: no Store package member without its own signature on this guest.' }
    $sign = Invoke-CliJson @('sign', $member.FullName)
    $fields = $sign.Report.items[0].fields
    if ($fields.state -ne 'SignedTrusted' -or $fields.signer -notmatch 'MSIX package' -or $fields.signer -notmatch 'content verified') {
        throw "Store member not verified through its package: state=$($fields.state) signer=$($fields.signer)"
    }
    $copy = Join-Path $env:TEMP 'winsight-msix-copy.exe'
    Copy-Item $member.FullName $copy -Force
    $bytes = [IO.File]::ReadAllBytes($copy); $bytes[4096] = $bytes[4096] -bxor 0xFF; [IO.File]::WriteAllBytes($copy, $bytes)
    $loose = Invoke-CliJson @('sign', $copy)
    Remove-Item $copy -Force
    if ($loose.Report.items[0].fields.state -eq 'SignedTrusted') { throw 'A copy outside its package was trusted.' }
    "$($member.FullName): $($fields.state) / $($fields.signer)"
    "altered copy outside the package: $($loose.Report.items[0].fields.state)"
}

Invoke-Gate '08-process-response-verbs' {
    $start = (Get-Date).ToUniversalTime()
    $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\PING.EXE') -ArgumentList '-n', '900', '127.0.0.1' -WindowStyle Hidden -PassThru
    try {
        Start-Sleep -Seconds 1
        $childPid = [string]$child.Id
        $refused = Invoke-Cli @('suspend', $childPid)
        if ($refused.Exit -ne 2) { throw "suspend without --confirm exited $($refused.Exit)" }
        $suspend = Invoke-Cli @('suspend', $childPid, '--confirm')
        if ($suspend.Exit -ne 0) { throw "suspend failed: $($suspend.Output)" }
        if (-not (Test-AllThreadsSuspended $child.Id)) { throw 'Not every thread is suspended.' }
        $resume = Invoke-Cli @('resume', $childPid, '--confirm')
        if ($resume.Exit -ne 0) { throw "resume failed: $($resume.Output)" }
        Start-Sleep -Milliseconds 500
        if (Test-AllThreadsSuspended $child.Id) { throw 'Threads are still suspended after resume.' }
        $protected = Invoke-Cli @('terminate', '4', '--confirm')
        if ($protected.Exit -ne 1 -or $protected.Output -notmatch 'TargetProtected') { throw "pid 4 was not refused: exit=$($protected.Exit) $($protected.Output)" }
        $terminate = Invoke-Cli @('terminate', $childPid, '--confirm')
        if ($terminate.Exit -ne 0 -or -not $child.WaitForExit(10000)) { throw "terminate failed: $($terminate.Output)" }
    }
    finally {
        if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    }
    $actions = Invoke-CliJson @('actions')
    $mine = @($actions.Report.items | ForEach-Object { $_.fields } | Where-Object {
        [DateTime]::Parse($_.time).ToUniversalTime() -ge $start.AddSeconds(-2) -and $_.target -match 'PING' -and $_.outcome -eq 'Succeeded' })
    foreach ($kind in 'SuspendProcess', 'ResumeProcess', 'TerminateProcess') {
        if (-not ($mine | Where-Object action -eq $kind)) { throw "Journal lacks $kind for the child." }
    }
    "suspend/resume/terminate on pid $($child.Id) journalled; refusal without --confirm exit 2; pid 4 TargetProtected"
}

Invoke-Gate '09-holders' {
    $path = Join-Path $env:TEMP 'winsight-held.dat'
    $stream = [IO.File]::Open($path, 'Create', 'ReadWrite', 'ReadWrite')
    try {
        $holders = Invoke-CliJson @('holders', $path)
        if (-not (@($holders.Report.items) | Where-Object { $_.fields.kind -eq 'fileHolder' -and $_.fields.pid -eq [string]$PID })) {
            throw "This run ($PID) was not named as the holder: $($holders.Report.summary)"
        }
        $remote = Invoke-CliJson @('holders', '\\server\share\decoy.docx')
        if ($remote.Report.items[0].fields.kind -ne 'holderTarget') { throw 'A non-local target was not refused.' }
    }
    finally { $stream.Dispose(); Remove-Item $path -Force -ErrorAction SilentlyContinue }
    "holders named pid $PID; UNC target refused"
}

Invoke-Gate '10-signature-verb-and-window' {
    $verbKey = 'HKCU:\Software\Classes\*\shell\WinSight.Signature\command'
    $register = Invoke-Cli @('register-signature-verb')
    if ($register.Exit -ne 0) { throw "register failed: $($register.Output)" }
    $again = Invoke-Cli @('register-signature-verb')
    if ($again.Exit -ne 0 -or $again.Output -notmatch 'already registered') { throw "register is not idempotent: $($again.Output)" }
    $command = (Get-ItemProperty -LiteralPath $verbKey).'(default)'
    $target = Join-Path $env:SystemRoot 'System32\notepad.exe'
    if ($command -notmatch '^"(?<exe>[^"]+)" --signature "%1"$') { throw "Unexpected verb command: $command" }
    $verbExe = $Matches.exe
    if ($verbExe -ne $script:Dashboard) { throw "Verb runs $verbExe, not the candidate dashboard." }
    $process = Start-Unelevated $verbExe "--signature `"$target`""
    try {
        $window = Find-ProcessWindowWith $process.Id 'Sha256Box' 60
        if (-not $window) { throw 'Signature window did not open.' }
        $sha = Wait-UiText $window 'Sha256Box' '^[0-9A-Fa-f]{64}$' 60
        if ($sha -ne (Get-Sha256 $target)) { throw "Window SHA-256 $sha differs from Get-FileHash." }
        $state = Wait-UiText $window 'StateText' '.+'
        $signer = Wait-UiText $window 'SignerText' 'Microsoft'
        if ($UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $process.Id)).Count -ne 1) { throw 'Signature mode opened more than one window.' }
        Invoke-UiButton $window 'CloseButton'
        if (-not $process.WaitForExit(15000)) { throw 'The process did not exit when the signature window closed.' }
    }
    finally { if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force } }
    $unregister = Invoke-Cli @('unregister-signature-verb')
    if ($unregister.Exit -ne 0 -or (Test-Path -LiteralPath 'HKCU:\Software\Classes\*\shell\WinSight.Signature')) { throw 'Verb not removed.' }
    "verb registered (idempotent) and removed; window for notepad.exe: $state / $signer; SHA-256 matches; exit on close"
}

$script:GuardianDashboard = $null
Invoke-Gate '11-guardian-block-and-restore' {
    Remove-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue
    $baseline = Join-Path $env:LOCALAPPDATA 'WinSight\guardian-baseline.tsv'
    $launched = Get-Date
    $script:GuardianDashboard = Start-Unelevated $script:Dashboard '--language en'
    $deadline = (Get-Date).AddMinutes(10)
    while (-not ((Test-Path $baseline) -and (Get-Item $baseline).LastWriteTime -ge $launched)) {
        if ((Get-Date) -gt $deadline) { throw 'Guardian never saved its baseline.' }
        $script:GuardianDashboard.Refresh(); if ($script:GuardianDashboard.HasExited) { throw 'Dashboard exited during startup.' }
        Start-Sleep -Seconds 2
    }
    Start-Sleep -Seconds 10
    $probeTarget = Join-Path $env:SystemRoot 'System32\notepad.exe'
    New-ItemProperty -Path $RunKey -Name $ProbeValue -Value "`"$probeTarget`"" -PropertyType String -Force | Out-Null
    $alert = $null
    foreach ($attempt in 1..3) {
        Close-OtherAlertWindows $script:GuardianDashboard.Id $ProbeValue
        # A scoped re-scan verifies signatures across the changed surface: on a cold VM that is minutes,
        # not seconds, so give the first arrival a wide window before assuming a burst swallowed it.
        $alert = Find-AlertWindowFor $script:GuardianDashboard.Id 'BlockButton' "$ProbeValue|notepad" 420
        if ($alert) { break }
        # A burst (a real arrival of the machine's own at the same moment) keeps the coalesced
        # balloon instead of a window: re-plant so the item arrives alone.
        Remove-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 30
        [void](Wait-GuardianQuiet)
        New-ItemProperty -Path $RunKey -Name $ProbeValue -Value "`"$probeTarget`"" -PropertyType String -Force | Out-Null
    }
    if (-not $alert) {
        # Say which half failed: Guardian never recorded the arrival, or recorded it without a window.
        $journal = (Invoke-CliJson @('alerts')).Report | ConvertTo-Json -Depth 6
        $journal | Set-Content (Join-Path $Evidence 'gate11-alerts.json')
        $windows = @($UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $script:GuardianDashboard.Id)) |
            ForEach-Object { "'$($_.Current.Name)' visible=$(-not $_.Current.IsOffscreen)" }) -join '; '
        $script:GuardianDashboard.Refresh()
        $recorded = $journal -match $ProbeValue
        # 1. Does the one-shot scanner see the planted value at all?
        $scanSees = ((Invoke-CliJson @('persistence')).Report | ConvertTo-Json -Depth 6) -match $ProbeValue
        # 2. What does the dashboard itself say about Guardian (health / diagnostics text)?
        $guardianText = @()
        foreach ($window in $UIA::RootElement.FindAll($Scope::Children, (New-Condition $UIA::ProcessIdProperty $script:GuardianDashboard.Id))) {
            $guardianText += @($window.FindAll($Scope::Descendants, [System.Windows.Automation.Condition]::TrueCondition) |
                ForEach-Object { $_.Current.Name; $_.Current.HelpText } | Where-Object { $_ -match 'Guardian|armed|surveill|protect' })
        }
        $guardianText | Set-Content (Join-Path $Evidence 'gate11-guardian-ui.txt')
        # 3. Does a fresh launch report the arrival from the persisted baseline? That separates a broken
        #    change signal (reported on relaunch) from a broken reconciliation (never reported).
        Stop-Process -Id $script:GuardianDashboard.Id -Force
        Start-Sleep -Seconds 3
        $relaunched = Get-Date
        $script:GuardianDashboard = Start-Unelevated $script:Dashboard '--language en'
        $relaunchWindow = Find-ProcessWindowWith $script:GuardianDashboard.Id 'BlockButton' 360
        $relaunchJournal = ((Invoke-CliJson @('alerts')).Report | ConvertTo-Json -Depth 6) -match $ProbeValue
        if ($relaunchWindow) { Invoke-UiButton $relaunchWindow 'LaterButton' }
        throw ("No alert window for the planted Run value after 6 min: journalled=$recorded scannerSees=$scanSees " +
            "relaunchWindow=$([bool]$relaunchWindow) relaunchJournalled=$relaunchJournal windows=[$windows] " +
            "guardianUi=[$(($guardianText | Select-Object -Unique) -join ' / ')]")
    }
    $item = (Wait-UiText $alert 'ItemText' '.+') + ' | ' + (Wait-UiText $alert 'ProgramText' '.+')
    if ((Find-ById $alert 'LaterButton').Current.IsKeyboardFocusable -eq $false) { throw 'Decide later is not focusable.' }
    Invoke-UiButton $alert 'BlockButton'
    $status = Wait-UiText $alert 'StatusText' 'winsight restore [0-9a-f-]{36} --confirm'
    $blockId = [regex]::Match($status, '[0-9a-f]{8}-[0-9a-f-]{27}').Value
    if ((Get-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue)) { throw 'Block did not remove the value.' }
    Invoke-UiButton $alert 'LaterButton'
    $refused = Invoke-Cli @('restore', $blockId)
    if ($refused.Exit -ne 2) { throw "restore without --confirm exited $($refused.Exit)" }
    $restore = Invoke-Cli @('restore', $blockId, '--confirm')
    if ($restore.Exit -ne 0) { throw "restore failed: $($restore.Output)" }
    $value = (Get-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue).$ProbeValue
    if ($value -ne "`"$probeTarget`"") { throw "Restored value differs: '$value'" }
    $journal = Invoke-CliJson @('actions')
    $block = @($journal.Report.items | ForEach-Object { $_.fields } | Where-Object { $_.actionId -eq $blockId })
    if ($block.Count -ne 1 -or $block[0].action -ne 'QuarantinePersistence' -or -not $block[0].undoneBy) { throw 'The block is not journalled as undone.' }
    $script:BlockId = $blockId
    "alert for '$item'; Block $blockId removed the value; restore without --confirm refused; restore put the exact value back; journal marks the block undone"
}

Invoke-Gate '12-guardian-allow-silence-revoke' {
    if (-not $script:BlockId) { throw 'NOT_RUN: depends on gate 11.' }
    # The restore in gate 11 is itself a new arrival: the operator decides it again, this time Allow.
    Close-OtherAlertWindows $script:GuardianDashboard.Id $ProbeValue
    $alert = Find-AlertWindowFor $script:GuardianDashboard.Id 'AllowButton' "$ProbeValue|notepad" 360
    if (-not $alert) { throw 'No alert window for the restored value.' }
    Invoke-UiButton $alert 'AllowButton'
    $status = Wait-UiText $alert 'StatusText' 'winsight revoke [0-9a-f-]{36} --confirm'
    $ruleId = [regex]::Match($status, '[0-9a-f]{8}-[0-9a-f-]{27}').Value
    Invoke-UiButton $alert 'LaterButton'
    $rules = Invoke-CliJson @('rules')
    if (-not (@($rules.Report.items) | Where-Object { $_.fields.ruleId -eq $ruleId -and $_.fields.decision -eq 'Allow' })) { throw "Rule $ruleId not listed." }

    # A re-arrival of an allowed item is not announced, but it is recorded naming the rule.
    Remove-ItemProperty -Path $RunKey -Name $ProbeValue
    Start-Sleep -Seconds 15
    New-ItemProperty -Path $RunKey -Name $ProbeValue -Value "`"$(Join-Path $env:SystemRoot 'System32\notepad.exe')`"" -PropertyType String -Force | Out-Null
    if (Find-AlertWindowFor $script:GuardianDashboard.Id 'AllowButton' $ProbeValue 45) { throw 'An allowed item raised an alert window.' }
    $alerts = Invoke-CliJson @('alerts')
    if (($alerts.Report | ConvertTo-Json -Depth 6) -notmatch "not announced: allowed by rule $ruleId") { throw 'The silenced arrival is not recorded with its rule.' }

    $refused = Invoke-Cli @('revoke', $ruleId)
    if ($refused.Exit -ne 2) { throw "revoke without --confirm exited $($refused.Exit)" }
    $revoke = Invoke-Cli @('revoke', $ruleId, '--confirm')
    if ($revoke.Exit -ne 0) { throw "revoke failed: $($revoke.Output)" }
    $rules = Invoke-CliJson @('rules')
    if (@($rules.Report.items) | Where-Object { $_.fields.ruleId -eq $ruleId }) { throw 'Revoked rule still listed.' }
    $again = Invoke-Cli @('revoke', $ruleId, '--confirm')
    if ($again.Exit -ne 1) { throw "A second revoke exited $($again.Exit)" }
    "Allow $ruleId listed; re-arrival silent and recorded as not announced; revoke refused without --confirm, then removed the rule; repeat revoke is notable"
}

Invoke-Gate '13-guardian-cleanup' {
    Remove-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue
    if ($script:GuardianDashboard -and -not $script:GuardianDashboard.HasExited) {
        if (-not (Invoke-TrayExit @($script:GuardianDashboard.Id)) -or -not $script:GuardianDashboard.WaitForExit(20000)) {
            Stop-Process -Id $script:GuardianDashboard.Id -Force -ErrorAction SilentlyContinue
            'tray Exit could not be driven for the unelevated dashboard; stopped it (not an ETW gate)'
        } else { 'unelevated dashboard exited through tray Exit' }
    }
    if (Get-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue) { throw 'Probe value remains.' }
    'probe value absent'
}

Invoke-Gate '14-dashboard-languages-smoke' {
    foreach ($language in 'en', 'fr', 'es') {
        Assert-CandidateFiles
        $smoke = Start-Process -FilePath $script:Dashboard -ArgumentList '--smoke-test', '--language', $language -PassThru -Wait
        if ($smoke.ExitCode -ne 0) { throw "Smoke test ($language) exited $($smoke.ExitCode)" }
        "smoke $language exit 0"
    }
}

# --- ETW recovery (section 6) ---------------------------------------------------------------------
Import-Module (Join-Path $Source 'scripts\WinSightEtwValidation.psm1') -Force
$EtwGateStart = Get-Date

Invoke-Gate '15-installer-all-users-service' {
    # WS-63: the all-users uninstall removes the service registered from it, and only that one.
    # RA-05: when it cannot, the uninstall stops with nothing removed, then completes.
    Remove-ServiceIfPresent
    $code = Invoke-Script 'installer-all-users-service.txt' (Join-Path $Source 'scripts\Test-InstallerServiceUninstall.ps1') @('-InstallerPath', $script:Installer, '-Version', $Version, '-ForeignServicePath', $script:Service)
    if ($code -ne 0) { throw "All-users uninstall with service failed (exit $code): $(Tail 'installer-all-users-service.txt' 15)" }
    & $ScExe query WinSightFirewall *> $null
    if ($LASTEXITCODE -ne 1060) { throw 'A firewall service is left after the all-users uninstall.' }
    $text = Get-Content (Join-Path $Evidence 'installer-all-users-service.txt') -Raw
    if ($text -notmatch 'PASS own-service' -or $text -notmatch 'PASS blocked-service' -or $text -notmatch 'PASS foreign-service') { throw "Not every case passed: $(Tail 'installer-all-users-service.txt' 10)" }
    Tail 'installer-all-users-service.txt' 5
}

Invoke-Gate '16-installer-upgrade' {
    if (-not $Candidate.PSObject.Properties['previous']) { throw 'NOT_RUN: no previous release staged in candidate.json.' }
    $previous = Join-Path $Artifacts $Candidate.previous.file
    Copy-Item -LiteralPath (Join-Path $Share "previous\$($Candidate.previous.file)") -Destination $previous -Force
    if ((Get-Sha256 $previous) -ne $Candidate.previous.sha256) { throw 'Previous release installer hash mismatch.' }
    $script:Manifest[$previous] = $Candidate.previous.sha256
    $code = Invoke-Script 'installer-upgrade.txt' (Join-Path $Source 'scripts\Test-InstallerUpgrade.ps1') @('-PreviousInstallerPath', $previous, '-PreviousVersion', $Candidate.previous.version, '-InstallerPath', $script:Installer, '-Version', $Version)
    if ($code -ne 0) { throw "Upgrade from $($Candidate.previous.version) failed (exit $code): $(Tail 'installer-upgrade.txt' 15)" }
    "previous: $($Candidate.previous.file) ($($Candidate.previous.commit))"
    Tail 'installer-upgrade.txt' 3
}

Invoke-Gate '17-cloud-files' {
    # WS-40: OneDrive's placeholders, through a disposable Cloud Files sync root.
    $evidenceFile = Join-Path $Evidence 'cloud-files.json'
    $code = Invoke-Script 'cloud-files.txt' (Join-Path $Source 'scripts\Measure-CloudFilesAccess.ps1') @('-CliPath', $script:Cli, '-EvidencePath', $evidenceFile)
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $evidenceFile)) { throw "Cloud Files probe failed (exit $code): $(Tail 'cloud-files.txt' 15)" }
    $cases = (Get-Content -LiteralPath $evidenceFile -Raw | ConvertFrom-Json).cases
    $lines = @(Get-Content (Join-Path $Evidence 'cloud-files.txt') | Where-Object { $_ -match 'readable=' })
    $unreadable = @('control', 'plain-in-sync-root', 'hydrated-placeholder', 'hydrated-in-directory-placeholder' | Where-Object { -not $cases.$_.sha256Matches })
    $fetching = @($cases.PSObject.Properties | Where-Object { $_.Value.fetchRequestsDuringRead -gt 0 } | ForEach-Object Name)
    # A cloud-only file is unreadable, and must be so at once rather than after a download times out.
    $slow = @($cases.PSObject.Properties | Where-Object { [int64]$_.Value.milliseconds -gt 30000 } | ForEach-Object Name)
    if ($unreadable.Count -gt 0 -or $fetching.Count -gt 0 -or $slow.Count -gt 0) {
        throw "WS-40: unreadable [$($unreadable -join ', ')], download requested by [$($fetching -join ', ')], over 30 s [$($slow -join ', ')]`n$($lines -join "`n")"
    }
    # RA-02: the persistence scan (the scanner Guardian re-runs) over a Run value naming the cloud-only
    # file: it must list the entry and finish without asking the provider for the data.
    $scan = (Get-Content -LiteralPath $evidenceFile -Raw | ConvertFrom-Json).persistence
    $scanLine = @(Get-Content (Join-Path $Evidence 'cloud-files.txt') | Where-Object { $_ -match '^persistence scan:' })
    if ($null -eq $scan -or -not $scan.entryFound -or [int]$scan.fetchRequestsDuringScan -ne 0 -or "$($scan.exit)" -eq 'timeout') {
        throw "RA-02: the persistence scan of a cloud-only image failed its bound: $($scanLine -join ' ')"
    }
    $lines + $scanLine
}

Invoke-Gate '18-interpreter-triage' {
    # WS-74: the genuine powershell.exe handed an encoded command from a Run value is flagged. Before the
    # fix the compiled-in name read "PowerShell.EXE.MUI" - the name of its language file, in no rule's
    # table - and the entry passed as an ordinary Microsoft-signed one.
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $name = 'WinSightInterpreterProbe'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    Set-ItemProperty -LiteralPath $runKey -Name $name -Value "`"$powershell`" -NoProfile -enc SQBFAFgA"
    try {
        $json = & $script:Cli persistence --flagged --json 2>$null | Out-String
        $json | Set-Content (Join-Path $Evidence 'interpreter-triage.json')
        $item = @(($json | ConvertFrom-Json).reports[0].items | Where-Object { $_.fields.name -eq $name })
        if ($item.Count -ne 1) { throw 'WS-74: the encoded PowerShell Run value is not among the flagged entries.' }
        if ("$($item[0].fields.commandLineConcern)" -ne 'EncodedCommand') { throw "WS-74: flagged for '$($item[0].fields.commandLineConcern)', not EncodedCommand." }
        "flagged: $($item[0].title), concern $($item[0].fields.commandLineConcern), signature $($item[0].fields.signature)"
    }
    finally { Remove-ItemProperty -LiteralPath $runKey -Name $name -ErrorAction SilentlyContinue }
}

Invoke-Gate '20-etw-clean-before' {
    $before = @(Get-WinSightEtwSessionNames)
    $before | Set-Content (Join-Path $Evidence 'etw-before.txt')
    if ($before.Count -ne 0) { throw "ETW snapshot is not clean: $($before -join ', ')" }
    'no WinSight ETW session'
}

Invoke-Gate '21-etw-dashboard-attribution' {
    # The dashboard is single-instance per user and session (WS-31): a second launch raises the first
    # and exits, so two dashboards of this account never coexist. Live-session preservation is proven
    # against the other Attribution owner, the elevated `attribution --watch` CLI watcher.
    function Get-AttributionSession([Diagnostics.Process]$Process) {
        $Process.Refresh()
        if ($Process.HasExited) { throw "Process $($Process.Id) stopped." }
        Get-WinSightEtwSessionForProcess -Family Attribution -ProcessId $Process.Id
    }
    function Get-AttributionSessions { @(Get-WinSightEtwSessionNames | Where-Object { $_ -cmatch '^WinSight-Attribution' }) }
    function Send-ConsoleCtrlC([int]$ProcessId) {
        $ctrlC = @"
Add-Type -Namespace K -Name C -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool AttachConsole(uint p); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool FreeConsole(); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr h, bool a); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);'
[void][K.C]::FreeConsole()
if (-not [K.C]::AttachConsole($ProcessId)) { exit 3 }
[void][K.C]::SetConsoleCtrlHandler([IntPtr]::Zero, `$true)
if (-not [K.C]::GenerateConsoleCtrlEvent(0, 0)) { exit 4 }
Start-Sleep -Milliseconds 500
exit 0
"@
        $helper = Start-Process -FilePath $NativePowerShell -ArgumentList '-NoProfile', '-EncodedCommand', ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ctrlC))) -WindowStyle Hidden -PassThru -Wait
        return $helper.ExitCode
    }

    $first = $null; $second = $null; $watcher = $null; $dashboard = $null
    try {
    Assert-CandidateFiles; $first = Start-Process -FilePath $script:Dashboard -ArgumentList '--language', 'en' -PassThru
    Start-Sleep -Seconds 20
    $sessionFirst = Get-AttributionSession $first

    Assert-CandidateFiles; $second = Start-Process -FilePath $script:Dashboard -ArgumentList '--language', 'en' -PassThru
    if (-not $second.WaitForExit(120000) -or $second.ExitCode -ne 0) { throw 'A second dashboard launch did not hand over and exit 0.' }
    # @() keeps a single session an array: a function returning one element hands back the string itself,
    # and indexing a string yields its first character (run 4 compared "W" with the session name).
    $sessions = @(Get-AttributionSessions)
    if ($sessions.Count -ne 1 -or $sessions[0] -cne $sessionFirst) { throw "Single instance violated: $($sessions -join ', ')" }

    Assert-CandidateFiles; $watcher = Start-Process -FilePath $script:Cli -ArgumentList 'attribution', '--watch' -PassThru
    Start-Sleep -Seconds 10
    $watcherSession = Get-AttributionSession $watcher

    $main = Find-ProcessWindowWith $first.Id 'LanguagePicker' 30
    if (-not $main) { throw 'Main window of the dashboard not found.' }
    Close-UiWindow $main
    Start-Sleep -Seconds 3
    $first.Refresh(); if ($first.HasExited) { throw 'X exited the dashboard instead of hiding it.' }
    if ((Get-WinSightEtwSessionNames) -notcontains $sessionFirst) { throw 'Tray session is missing after X.' }
    Stop-Process -InputObject $first -Force
    Start-Sleep -Seconds 2
    if ((Get-WinSightEtwSessionNames) -notcontains $sessionFirst) { throw 'The kill did not leave the expected orphan: inconclusive.' }

    Assert-CandidateFiles; $dashboard = Start-Process -FilePath $script:Dashboard -ArgumentList '--language', 'en' -PassThru
    Start-Sleep -Seconds 20
    [void](Get-AttributionSession $dashboard)
    $watcher.Refresh()
    if ($watcher.HasExited -or (Get-WinSightEtwSessionNames) -contains $sessionFirst -or
        (Get-WinSightEtwSessionNames) -notcontains $watcherSession) {
        throw 'Orphan recovery or live-session preservation failed.'
    }
    foreach ($cycle in 1..2) {
        $victimSession = Get-AttributionSession $dashboard
        Stop-Process -InputObject $dashboard -Force
        Start-Sleep -Seconds 2
        if ((Get-WinSightEtwSessionNames) -notcontains $victimSession) { throw "Cycle ${cycle}: no orphan after kill." }
        Assert-CandidateFiles; $dashboard = Start-Process -FilePath $script:Dashboard -ArgumentList '--language', 'en' -PassThru
        Start-Sleep -Seconds 20
        [void](Get-AttributionSession $dashboard)
        if ((Get-WinSightEtwSessionNames) -contains $victimSession) { throw "Cycle ${cycle}: orphan not reclaimed." }
        if ((Get-WinSightEtwSessionNames) -notcontains $watcherSession) { throw "Cycle ${cycle}: the live watcher session was stopped." }
        $count = (Get-AttributionSessions).Count
        if ($count -gt 2) { throw "Cycle ${cycle}: $count Attribution sessions for 2 live owners." }
    }

    # The watcher leaves on a real console interrupt, exit 0, taking its session with it.
    $helperExit = Send-ConsoleCtrlC $watcher.Id
    if ($helperExit -ne 0) { Stop-Process -InputObject $watcher -Force; throw "NOT_RUN: Ctrl+C could not be delivered to the watcher (helper exit $helperExit); single instance, orphan recovery and preservation PASSED." }
    if (-not $watcher.WaitForExit(30000)) { Stop-Process -InputObject $watcher -Force; throw 'The watcher did not exit within 30 seconds after Ctrl+C.' }
    if ($watcher.ExitCode -ne 0) { throw "Unexpected watcher exit: $($watcher.ExitCode)." }
    Start-Sleep -Seconds 2
    if ((Get-WinSightEtwSessionNames) -contains $watcherSession) { throw 'Graceful watcher shutdown left its ETW session behind.' }

    # The dashboard leaves through its tray Exit command. Windows 11 exposes no notification-area
    # button to UI Automation, so when the automated path cannot drive it the gate waits for a human
    # (or a screen-driving operator) to right-click the WinSight icon and choose Exit.
    $trayExited = Invoke-TrayExit @($dashboard.Id)
    $waitDeadline = (Get-Date).AddMinutes(10)
    $trayMarker = Join-Path $Evidence 'TRAY-EXIT-REQUIRED.txt'
    if (-not $trayExited) {
        "waiting until $($waitDeadline.ToString('o')) for the WinSight tray icon to be exited" | Set-Content -LiteralPath $trayMarker
    }
    $automation = Join-Path $Share 'operator-automation.ps1'
    if (-not $trayExited -and (Test-Path -LiteralPath $automation)) {
        try { . $automation -Name 'TRAYEXIT' -ProcessId $dashboard.Id }
        catch { Add-Content -LiteralPath (Join-Path $Evidence 'operator-automation.txt') -Value "$(Get-Date -Format o) [TRAYEXIT] failed: $($_.Exception.Message)" }
    }
    while ((Get-Date) -lt $waitDeadline) {
        $dashboard.Refresh()
        if ($dashboard.HasExited) { break }
        Start-Sleep -Seconds 5
    }
    Remove-Item -LiteralPath $trayMarker -Force -ErrorAction SilentlyContinue
    $dashboard.Refresh()
    if (-not $dashboard.HasExited) {
        Stop-Process -InputObject $dashboard -Force
        Start-Sleep -Seconds 2
        # Test cleanup, not product evidence: stop the orphan the forced stop left so later gates start clean.
        $logman = Get-WinSightSystemLogmanPath
        Get-AttributionSessions | ForEach-Object { & $logman stop $_ -ets *> $null }
        throw "NOT_RUN: single instance, orphan recovery, live-watcher preservation and watcher Ctrl+C PASSED, but tray Exit could not be driven; the dashboard was stopped. Tray buttons seen: $script:TrayDiagnostic"
    }
    Start-Sleep -Seconds 2
    if ((Get-AttributionSessions).Count -ne 0) { throw 'Attribution sessions remain after tray Exit.' }
    'single instance: second launch handed over (exit 0, no session); X hides; kill leaves orphan; relaunch reclaims it and preserves the live watcher session; two kill cycles never exceed 2 owners; watcher Ctrl+C exit 0 without residue; dashboard exited through tray Exit with zero sessions'
    }
    finally {
        # A failed gate must not leave a dashboard, a watcher or a session behind for the next gates.
        foreach ($p in @($first, $second, $watcher, $dashboard)) { if ($p -and -not $p.HasExited) { Stop-Process -InputObject $p -Force -ErrorAction SilentlyContinue } }
        Start-Sleep -Seconds 2
        $logman = Get-WinSightSystemLogmanPath
        Get-WinSightEtwSessionNames | Where-Object { $_ -cmatch '^WinSight-Attribution' } | ForEach-Object { & $logman stop $_ -ets *> $null }
    }
}

Invoke-Gate '22-etw-dns' {
    Assert-CandidateFiles
    $dnsOne = Start-Process -FilePath $script:Cli -ArgumentList 'dns', '--watch' -PassThru
    Start-Sleep -Seconds 10
    $dnsOne.Refresh(); if ($dnsOne.HasExited) { throw "The original DNS watcher exited with $($dnsOne.ExitCode)." }
    $dnsSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsOne.Id
    Stop-Process -InputObject $dnsOne -Force
    if ((Get-WinSightEtwSessionNames) -notcontains $dnsSession) { throw 'Expected DNS orphan is missing.' }
    Assert-CandidateFiles
    $dnsTwo = Start-Process -FilePath $script:Cli -ArgumentList 'dns', '--watch' -PassThru
    Start-Sleep -Seconds 10
    $dnsTwo.Refresh(); if ($dnsTwo.HasExited) { throw "The restarted DNS watcher exited with $($dnsTwo.ExitCode)." }
    $dnsTwoSession = Get-WinSightEtwSessionForProcess -Family DNS -ProcessId $dnsTwo.Id
    if ((Get-WinSightEtwSessionNames) -contains $dnsSession) { throw 'The previous DNS orphan remains after the replacement started.' }
    # Ctrl+C from a helper that attaches to the watcher's console: a real console interrupt, not a kill.
    $ctrlC = @"
Add-Type -Namespace K -Name C -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool AttachConsole(uint p); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool FreeConsole(); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr h, bool a); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);'
[void][K.C]::FreeConsole()
if (-not [K.C]::AttachConsole($($dnsTwo.Id))) { exit 3 }
[void][K.C]::SetConsoleCtrlHandler([IntPtr]::Zero, `$true)
if (-not [K.C]::GenerateConsoleCtrlEvent(0, 0)) { exit 4 }
Start-Sleep -Milliseconds 500
exit 0
"@
    $helper = Start-Process -FilePath $NativePowerShell -ArgumentList '-NoProfile', '-EncodedCommand', ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ctrlC))) -WindowStyle Hidden -PassThru -Wait
    if ($helper.ExitCode -ne 0) { Stop-Process -InputObject $dnsTwo -Force; throw "NOT_RUN: Ctrl+C could not be delivered (helper exit $($helper.ExitCode)); DNS orphan/replacement PASSED." }
    if (-not $dnsTwo.WaitForExit(30000)) { Stop-Process -InputObject $dnsTwo -Force; throw 'dnsTwo did not exit within 30 seconds after Ctrl+C.' }
    if ($dnsTwo.ExitCode -ne 0) { throw "Unexpected dnsTwo exit: $($dnsTwo.ExitCode)." }
    Start-Sleep -Seconds 2
    if ((Get-WinSightEtwSessionNames) -contains $dnsTwoSession) { throw 'Graceful DNS shutdown left its ETW session behind.' }
    'DNS kill leaves orphan; replacement reclaims it; Ctrl+C exits 0 and removes its session'
}

Invoke-Gate '23-etw-outbound-service' {
    try {
        Assert-CandidateFiles
        & $script:Service install *> (Join-Path $Evidence 'outbound-install.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Install service failed.' }
        & $ScExe start WinSightFirewall | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Start service failed.' }
        $svc = Wait-Service 'Running'
        Assert-AuditOnlyEmpty | Out-Null
        $svcNow = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
        if ($svcNow.State -ne 'Running' -or $svcNow.ProcessId -ne $svc.ProcessId) { throw 'The SCM service PID changed before rebinding.' }
        $serviceProcess = Get-Process -Id ([int]$svcNow.ProcessId) -ErrorAction Stop
        $canonicalServicePath = (Resolve-Path -LiteralPath $script:Service).Path
        if ((Resolve-Path -LiteralPath $serviceProcess.Path).Path -cne $canonicalServicePath) { throw 'PID SCM does not point at the candidate.' }
        $oldOutbound = Get-WinSightEtwSessionForProcess -Family Outbound -ProcessId $serviceProcess.Id
        $svcKill = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
        if ($svcKill.ProcessId -ne $serviceProcess.Id -or
            (Resolve-Path -LiteralPath (Get-Process -Id $serviceProcess.Id -ErrorAction Stop).Path).Path -cne $canonicalServicePath) { throw 'PID/path changed before kill.' }
        Stop-Process -InputObject $serviceProcess -Force
        [void](Wait-Service 'Stopped')
        if ((Get-WinSightEtwSessionNames) -notcontains $oldOutbound) { throw 'Expected outbound orphan is missing: inconclusive.' }
        # Do not start it: the SCM recovery action (first restart after 5 s) brings it back, and that is
        # part of what this gate proves. An explicit start raced it and failed with 1056 whenever the
        # rehash in between took longer than 5 s (run 3, 2026-09-22).
        $deadline = (Get-Date).AddSeconds(90)
        do {
            $svcNew = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
            if ($svcNew.State -eq 'Running' -and $svcNew.ProcessId -gt 0 -and $svcNew.ProcessId -ne $serviceProcess.Id) { break }
            Start-Sleep -Milliseconds 250
        } while ((Get-Date) -lt $deadline)
        if ($svcNew.State -ne 'Running' -or $svcNew.ProcessId -eq $serviceProcess.Id) { throw 'The SCM recovery action did not restart the service under a new PID.' }
        Assert-CandidateFiles
        if ((Resolve-Path -LiteralPath (Get-Process -Id ([int]$svcNew.ProcessId) -ErrorAction Stop).Path).Path -cne $canonicalServicePath) { throw 'The restarted service is not the candidate.' }
        Start-Sleep -Seconds 10
        [void](Get-WinSightEtwSessionForProcess -Family Outbound -ProcessId ([int]$svcNew.ProcessId))
        if ((Get-WinSightEtwSessionNames) -contains $oldOutbound) { throw 'Outbound orphan survived the restart.' }
        Assert-AuditOnlyEmpty | Out-Null
        $http = & $CurlExe -s -o NUL -w '%{http_code}' --max-time 20 https://example.com
        if ($LASTEXITCODE -ne 0 -or $http -ne '200') { throw "Connectivity after restart: curl exit=$LASTEXITCODE http=$http" }
        & $ScExe stop WinSightFirewall | Out-Null
        [void](Wait-Service 'Stopped')
        Assert-CandidateFiles
        & $script:Service uninstall *> (Join-Path $Evidence 'outbound-uninstall.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Uninstall service failed.' }
        & $ScExe query WinSightFirewall *> $null
        if ($LASTEXITCODE -ne 1060) { throw "SCM 1060 absence not proven (exit $LASTEXITCODE)." }
        Start-Sleep -Seconds 3
        if (@(Get-WinSightEtwSessionNames | Where-Object { $_ -cmatch '^WinSight-Outbound-(v2-)?' }).Count -ne 0) { throw 'Unexpected persistent outbound session.' }
        "old pid $($serviceProcess.Id) killed -> orphan; restart pid $($svcNew.ProcessId) reclaimed it; AuditOnly/empty WFP/IPC; curl 200; uninstall SCM 1060"
    }
    finally { Remove-ServiceIfPresent }
}

Invoke-Gate '25-etw-preopened-write' {
    # WS-60 measurement: the session enables FileIOInit only, so a write through a handle opened before
    # the session exists may carry no file name. A fresh open during the session is the control.
    $startup = [Environment]::GetFolderPath('Startup')
    $id = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $early = Join-Path $startup "ws60-preopened-$id.lnk"
    $late = Join-Path $startup "ws60-fresh-$id.lnk"
    $go = Join-Path $env:TEMP "ws60-go-$id.signal"
    $output = Join-Path $Evidence 'attribution-preopened.txt'
    $writer = @"
`$stream = [IO.File]::Open('$early', 'Create', 'Write', 'ReadWrite')
`$deadline = (Get-Date).AddMinutes(3)
while (-not (Test-Path '$go') -and (Get-Date) -lt `$deadline) { Start-Sleep -Milliseconds 200 }
`$bytes = New-Object byte[] 4096
for (`$i = 0; `$i -lt 5; `$i++) { `$stream.Write(`$bytes, 0, `$bytes.Length); `$stream.Flush(`$true); Start-Sleep -Milliseconds 300 }
`$stream.Dispose()
"@
    $writerProcess = Start-Process -FilePath $NativePowerShell -ArgumentList '-NoProfile', '-EncodedCommand', ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($writer))) -WindowStyle Hidden -PassThru
    $watch = $null
    try {
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath $early) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
        if (-not (Test-Path -LiteralPath $early)) { throw 'The pre-opening writer did not create its file.' }
        Start-Sleep -Seconds 1
        Assert-CandidateFiles
        # cmd owns the console, so the watcher's output can go to a file and Ctrl+C still reaches it.
        $watch = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList '/s', '/c', "`"`"$script:Cli`" attribution --watch > `"$output`" 2>&1`"" -PassThru
        $deadline = (Get-Date).AddSeconds(90)
        while ((Get-Date) -lt $deadline -and -not ((Test-Path -LiteralPath $output) -and (Get-Content -LiteralPath $output -Raw) -match 'Watching registry writes')) { Start-Sleep -Milliseconds 500 }
        if (-not ((Test-Path -LiteralPath $output) -and (Get-Content -LiteralPath $output -Raw) -match 'Watching registry writes')) { throw "The attribution watch did not start: $(Get-Content -LiteralPath $output -Raw -ErrorAction SilentlyContinue)" }
        Start-Sleep -Seconds 5
        Set-Content -LiteralPath $go -Value 'go'
        [IO.File]::WriteAllBytes($late, (New-Object byte[] 4096))
        if (-not $writerProcess.WaitForExit(60000)) { throw 'The pre-opened writer did not finish.' }
        Start-Sleep -Seconds 5
        $ctrlC = @"
Add-Type -Namespace K -Name C -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool AttachConsole(uint p); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool FreeConsole(); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool SetConsoleCtrlHandler(System.IntPtr h, bool a); [System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g);'
[void][K.C]::FreeConsole()
if (-not [K.C]::AttachConsole($($watch.Id))) { exit 3 }
[void][K.C]::SetConsoleCtrlHandler([IntPtr]::Zero, `$true)
if (-not [K.C]::GenerateConsoleCtrlEvent(0, 0)) { exit 4 }
Start-Sleep -Milliseconds 500
exit 0
"@
        $helper = Start-Process -FilePath $NativePowerShell -ArgumentList '-NoProfile', '-EncodedCommand', ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ctrlC))) -WindowStyle Hidden -PassThru -Wait
        if ($helper.ExitCode -ne 0 -or -not $watch.WaitForExit(30000)) { throw "The watch did not stop on Ctrl+C (helper exit $($helper.ExitCode))." }
        Start-Sleep -Seconds 2
        $text = Get-Content -LiteralPath $output -Raw
        $summary = @($text -split "`r?`n" | Where-Object { $_ -match 'ws60-|attributed \d+' })
        $ours = @($PID, $writerProcess.Id)
        $fresh = @($summary | Where-Object { $_ -match [regex]::Escape("ws60-fresh-$id") -and $_ -match "\(pid $PID\)" })
        $preopened = @($summary | Where-Object { $_ -match [regex]::Escape("ws60-preopened-$id") -and $_ -match "\(pid $($writerProcess.Id)\)" })
        # Anyone else named for these two files only opened them (the shell, Defender): never an author.
        $strangers = @($summary | Where-Object { $_ -match 'ws60-' -and $_ -match '\(pid (\d+)\)' -and $ours -notcontains [int]$Matches[1] })
        if ($fresh.Count -eq 0) { throw "Control failed: the fresh write was not attributed to its writer (pid $PID).`n$($summary -join "`n")" }
        if ($strangers.Count -gt 0) { throw "Processes that only opened the files were attributed as writers:`n$($strangers -join "`n")" }
        "fresh write attributed to its writer (pid $PID); no opener attributed"
        if ($preopened.Count -gt 0) { "pre-opened handle: attributed to its writer (pid $($writerProcess.Id))" }
        else { "pre-opened handle: NOT attributed to its writer (pid $($writerProcess.Id)) - WS-60, documented limit" }
        $summary
    }
    finally {
        if ($watch -and -not $watch.HasExited) { Stop-Process -Id $watch.Id -Force -ErrorAction SilentlyContinue; Get-Process -Name winsight -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
        if (-not $writerProcess.HasExited) { Stop-Process -Id $writerProcess.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $early, $late, $go -Force -ErrorAction SilentlyContinue
        $left = @(Get-WinSightEtwSessionNames)
        if ($left.Count -gt 0) { "ETW sessions after the gate: $($left -join ', ')" }
    }
}

Invoke-Gate '24-etw-final' {
    Assert-WinSightEtwSessionsAbsent
    $crashes = @(Get-WinSightRuntimeCrashEvents -StartTime $EtwGateStart)
    if ($crashes.Count -ne 0) { throw "WinSight .NET Runtime crash during the ETW gate: $($crashes.Count)" }
    'no WinSight ETW session; no .NET Runtime crash'
}

# --- WFP, trust, IPC (section 7) -----------------------------------------------------------------
Invoke-Gate '30-wfp-contract-selftest' {
    $code = Invoke-Script 'wfp-contract.txt' $script:WfpScript @('-ContractSelfTest')
    if ($code -ne 0) { throw "Contract self-test exit ${code}: $(Tail 'wfp-contract.txt' 10)" }
    Tail 'wfp-contract.txt' 4
}

Invoke-Gate '31-wfp-negative-control' {
    $code = Invoke-Script 'wfp-negative-control.txt' $script:WfpScript @('-ContractSelfTest', '-ContractNegativeControl')
    if ($code -ne 1) { throw "Negative control exit $code (expected 1): $(Tail 'wfp-negative-control.txt' 10)" }
    Tail 'wfp-negative-control.txt' 4
}

Invoke-Gate '32-wfp-prearm' {
    try {
        $code = Invoke-Script 'wfp-prearm.txt' $script:WfpScript @('-ServicePath', $script:Service, '-SkipEnforcement')
        if ($code -ne 0) { throw "Pre-arm exit ${code}: $(Tail 'wfp-prearm.txt' 15)" }
        Tail 'wfp-prearm.txt' 4
    }
    finally { Remove-ServiceIfPresent }
}

# The full WFP gate is the one the protocol keeps interactive: the operator must block an app and arm
# enforcement from the dashboard, then disable it, while the script watches WFP and the network from
# outside. This drives that operator through UI Automation - the real buttons, the real confirmation
# dialogs - and answers each prompt only once the dashboard reports the action done.
# The full WFP gate is the one the protocol keeps interactive: an operator must block an app and arm
# enforcement from the dashboard, then disable it, while the workflow watches WFP and the network from
# outside. This drives that operator through UI Automation - the real buttons, the real confirmation
# dialogs - and answers each prompt only once the dashboard has carried the action out.
Invoke-Gate '33-wfp-full' {
    $log = Join-Path $Evidence 'wfp-full.txt'
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
    $dashboard = $null
    $process = $null
    $main = $null
    # The workflow keeps the file open for writing, so it can only be read in full sharing mode.
    function Read-Log {
        try {
            $stream = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try { return (New-Object IO.StreamReader($stream)).ReadToEnd() } finally { $stream.Dispose() }
        }
        catch { return '' }
    }
    function Wait-LogMarker([string]$Marker, [int]$TimeoutSeconds) {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            if ((Read-Log) -match [regex]::Escape($Marker)) { return $true }
            Start-Sleep -Seconds 2
        } while ((Get-Date) -lt $deadline -and -not $process.HasExited)
        return $false
    }
    function Invoke-FirewallAction([string]$ButtonId) {
        # Re-read the service state first: the workflow stops and restarts the service underneath, and
        # a stale panel would offer a button the service can no longer honour.
        Invoke-UiButton $main 'ScanButton'
        Start-Sleep -Seconds 12
        Invoke-UiButton $main $ButtonId
    }
    try {
        Assert-CandidateFiles
        $psi = [Diagnostics.ProcessStartInfo]::new($env:ComSpec,
            "/c `"`"$NativePowerShell`" -NoProfile -ExecutionPolicy Bypass -File `"$script:WfpScript`" -ServicePath `"$script:Service`" > `"$log`" 2>&1`"")
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($psi)

        # Only once the service is installed and running does the dashboard have a firewall to control.
        if (-not (Wait-LogMarker '[PASS] starts in audit-only' 420)) { throw "The service never reached audit-only: $(Tail 'wfp-full.txt' 10)" }
        Assert-CandidateFiles
        # Elevated: the service refuses to arm enforcement for a dashboard that is not.
        $dashboard = Start-Process -FilePath $script:Dashboard -ArgumentList '--language', 'en' -PassThru
        $main = Find-ProcessWindowWith $dashboard.Id 'ToolPicker' 240
        if (-not $main) { throw 'The dashboard main window did not open.' }
        $picker = Find-ById $main 'ToolPicker'
        $tool = @($picker.FindAll($Scope::Descendants, [System.Windows.Automation.Condition]::TrueCondition)) |
            Where-Object { $_.Current.Name -match 'Outbound Firewall' } | Select-Object -First 1
        if (-not $tool) { throw 'The outbound-firewall tool is not listed.' }
        $tool.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern).Select()
        Start-Sleep -Seconds 2
        Invoke-UiButton $main 'ScanButton'
        $deadline = (Get-Date).AddSeconds(180)
        do {
            $panel = $main.FindFirst($Scope::Descendants, (New-Condition $UIA::AutomationIdProperty 'FirewallEnableEnforcementButton'))
            if ($panel -and $panel.Current.IsEnabled) { break }
            Start-Sleep -Seconds 3
        } while ((Get-Date) -lt $deadline)
        if (-not ($panel -and $panel.Current.IsEnabled)) { throw 'The firewall controls never became usable.' }

        if (-not (Wait-LogMarker '[PASS] target and control reach the network before blocking' 900)) {
            throw "The workflow never reached the arm prompt: $(Tail 'wfp-full.txt' 10)"
        }
        # The two decisions this gate exists for are the operator's, and Windows offers no reliable
        # automation for a file picker plus a modal confirmation. The run asks for them by file and
        # waits for the same file to say they are done, so what is measured is the product's behaviour
        # under a real operator, not an automation trick.
        Request-OperatorAction 'ARM' "In the WinSight dashboard (Outbound Firewall): Block an app... -> $CurlExe -> Open, then Enable enforcement -> Yes."
        Invoke-UiButton $main 'ScanButton'
        Start-Sleep -Seconds 10
        $process.StandardInput.WriteLine()

        if (-not (Wait-LogMarker '[PASS] restart restores scoped enforcement and control connectivity' 1200)) {
            throw "The workflow never reached the rollback prompt: $(Tail 'wfp-full.txt' 12)"
        }
        Request-OperatorAction 'ROLLBACK' 'In the WinSight dashboard (Outbound Firewall): Emergency disable -> Yes.'
        Invoke-UiButton $main 'ScanButton'
        Start-Sleep -Seconds 10
        $process.StandardInput.WriteLine()

        if (-not $process.WaitForExit(300000)) { $process.Kill(); throw "The WFP workflow did not finish: $(Tail 'wfp-full.txt' 12)" }
        Add-Content -LiteralPath $log -Value "exit=$($process.ExitCode)"
        if ($process.ExitCode -ne 0) { throw "Full WFP exit $($process.ExitCode): $(Tail 'wfp-full.txt' 20)" }
        Tail 'wfp-full.txt' 4
    }
    finally {
        if ($dashboard -and -not $dashboard.HasExited) { Stop-Process -Id $dashboard.Id -Force -ErrorAction SilentlyContinue }
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-ServiceIfPresent
        # Test teardown, not product evidence: stopping the dashboard by force is what leaves an ETW
        # orphan (section 6 proves the product reclaims one), and the residue gate must not read this
        # harness's own kill as a leak.
        Start-Sleep -Seconds 3
        $logman = Get-WinSightSystemLogmanPath
        Get-WinSightEtwSessionNames | ForEach-Object { & $logman stop $_ -ets *> $null }
    }
}

Invoke-Gate '34-trust-boundary' {
    # The kit asks for a dedicated standard account; creating one is out of this run's remit, so the
    # built-in Guest - a real, non-administrator local principal - is the foreign owner.
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
    if (-not $guest) { throw 'NOT_RUN: no built-in Guest principal to use as foreign owner.' }
    try {
        $code = Invoke-Script 'trust-boundary.txt' $script:TrustScript @('-ServicePath', $script:Service, '-HostileAccount', $guest.Name)
        if ($code -ne 0) { throw "Trust exit ${code}: $(Tail 'trust-boundary.txt' 20)" }
        if ((Get-Content (Join-Path $Evidence 'trust-boundary.txt') -Raw) -match '\[SKIP\]') { throw 'Trust run skipped a case.' }
        "HostileAccount=$($guest.Name) (built-in, non-administrator)"
        Tail 'trust-boundary.txt' 4
    }
    finally { Remove-ServiceIfPresent }
}

Invoke-Gate '35-ipc-local' {
    try {
        Assert-CandidateFiles
        & $script:Service install *> (Join-Path $Evidence 'ipc-install.txt')
        if ($LASTEXITCODE -ne 0) { throw 'IPC install failed.' }
        & $ScExe start WinSightFirewall | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'IPC start failed.' }
        [void](Wait-Service 'Running')
        Assert-AuditOnlyEmpty | Out-Null
        $code = Invoke-Script 'ipc-local.txt' $script:IpcScript @('-CliPath', $script:Cli, '-ServicePath', $script:Service)
        if ($code -ne 0) { throw "IPC exit ${code}: $(Tail 'ipc-local.txt' 15)" }
        if ((Get-Content (Join-Path $Evidence 'ipc-local.txt') -Raw) -match 'ReadableMutateSkipped') { throw 'ReadableMutateSkipped is not a PASS.' }
        Tail 'ipc-local.txt' 4
    }
    finally {
        & $ScExe stop WinSightFirewall *> $null
        Start-Sleep -Seconds 3
        Remove-ServiceIfPresent
    }
}

Invoke-Gate '36-ipc-network-logon' {
    # Kit section 7, "Network Logon": a standard account logs on over the network from a second machine
    # (the control VM on a private Hyper-V switch). The operator types the disposable password in the
    # Windows credential dialog here and again on the control VM; this script never sees it in clear.
    $networkFile = Join-Path $Share 'network.json'
    if (-not (Test-Path -LiteralPath $networkFile)) {
        throw 'NOT_RUN: needs the control VM on the private switch (Invoke-HyperVNetworkLogon.ps1 stages network.json) and a disposable password typed by the operator.'
    }
    $net = Get-Content -LiteralPath $networkFile -Raw | ConvertFrom-Json
    $user = 'WinSightNetworkProbe'
    $state = @{}
    try {
        # 1. The service, running from the protected package.
        Remove-ServiceIfPresent
        Assert-CandidateFiles
        & $script:Service install *> (Join-Path $Evidence 'network-service-install.txt')
        if ($LASTEXITCODE -ne 0) { throw "Service install failed: $(Tail 'network-service-install.txt')" }
        $deadline = (Get-Date).AddSeconds(60)
        do {
            $svc = Get-CimInstance Win32_Service -Filter "Name='WinSightFirewall'"
            if ($svc.State -ne 'Running') { Start-Service WinSightFirewall -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
        } while ($svc.State -ne 'Running' -and (Get-Date) -lt $deadline)
        if ($svc.State -ne 'Running') { throw 'The service is not running.' }

        # 2. The private address, on the adapter the host created with a known MAC.
        $mac = ($net.targetMac -replace '[-:]', '').ToUpperInvariant()
        $adapter = Get-NetAdapter | Where-Object { ($_.MacAddress -replace '-', '') -eq $mac } | Select-Object -First 1
        if (-not $adapter) { throw "No adapter with MAC $mac." }
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $net.targetAddress -PrefixLength $net.prefixLength | Out-Null
        $deadline = (Get-Date).AddSeconds(90)
        while (-not (Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        $state.Interface = $adapter.ifIndex
        $state.Category = (Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex).NetworkCategory
        Set-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -NetworkCategory Private

        # 3. The standard account: Users and Remote Management Users only.
        $credential = Get-Credential -UserName $user -Message "WinSight gate 36 (TARGET): choose a disposable password for the local account $user. Type the same one on the control VM."
        if ($null -eq $credential -or $credential.Password.Length -eq 0) { throw 'NOT_RUN: no disposable password was provided on the target.' }
        New-LocalUser -Name $user -Password $credential.Password -Description 'WinSight Network Logon probe (disposable)' | Out-Null
        $state.User = $true
        Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-580').Name -Member $user

        # 4. WinRM over HTTPS with Basic, exactly as the kit does it (no Enable-PSRemoting).
        $winRm = Get-Service WinRM
        $state.WinRmStart = $winRm.StartType
        $state.WinRmRunning = $winRm.Status -eq 'Running'
        $tokenFilterPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ($null -ne (Get-ItemProperty -LiteralPath $tokenFilterPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue)) {
            throw 'LocalAccountTokenFilterPolicy already exists; this VM is not a clean qualification baseline.'
        }
        Set-Service WinRM -StartupType Manual
        Start-Service WinRM
        if ($null -ne (Get-ItemProperty -LiteralPath $tokenFilterPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue)) {
            throw 'Starting WinRM unexpectedly created LocalAccountTokenFilterPolicy.'
        }
        $rootSddlPath = 'WSMan:\localhost\Service\RootSDDL'
        $state.RootSddl = [string](Get-Item -LiteralPath $rootSddlPath).Value
        if ($state.RootSddl -notmatch [regex]::Escape('(A;;GR;;;RM)')) {
            if ($state.RootSddl -notmatch 'S:') { throw 'Unexpected RootSDDL: SACL is missing.' }
            Set-Item -LiteralPath $rootSddlPath -Value ($state.RootSddl -replace 'S:', '(A;;GR;;;RM)S:') -Force
        }
        $state.Basic = [bool](Get-Item 'WSMan:\localhost\Service\Auth\Basic').Value
        $certificate = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject "CN=$env:COMPUTERNAME" `
            -TextExtension @("2.5.29.17={text}IPAddress=$($net.targetAddress)&DNS=$env:COMPUTERNAME") `
            -CertStoreLocation 'Cert:\LocalMachine\My' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(1)
        $state.Thumbprint = $certificate.Thumbprint
        $certificateFile = Join-Path $Evidence 'winrm-network-probe.cer'
        Export-Certificate -Cert $certificate -FilePath $certificateFile -Force | Out-Null
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } `
            -ValueSet @{ Hostname = $env:COMPUTERNAME; CertificateThumbprint = $certificate.Thumbprint } | Out-Null
        $state.Listener = $true
        Set-Item 'WSMan:\localhost\Service\Auth\Basic' -Value $true -Force
        New-NetFirewallRule -DisplayName 'WinSight qualification WinRM HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 `
            -LocalAddress $net.targetAddress -RemoteAddress $net.controlAddress -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName 'WinSight qualification rendezvous' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $net.httpPort `
            -LocalAddress $net.targetAddress -RemoteAddress $net.controlAddress -Profile Any | Out-Null
        $state.Rules = $true
        Restart-Service WinRM -Force

        # 5. Arm the observer before the control is allowed to connect.
        $ready = Join-Path $Evidence 'network-observer-ready.json'
        $complete = Join-Path $Evidence 'network-probe-complete.signal'
        $observed = Join-Path $Evidence 'network-observer-result.json'
        Remove-Item $ready, $complete, $observed -Force -ErrorAction SilentlyContinue
        Assert-CandidateFiles
        # The packaged copy when the ZIP carries it, the commit's otherwise (as gate 01 resolves the others).
        $observerScript = Join-Path $script:PackageRoot 'Test-IpcNetworkObserver.ps1'
        if (-not (Test-Path -LiteralPath $observerScript)) { $observerScript = Join-Path $Source 'scripts\Test-IpcNetworkObserver.ps1' }
        $observer = Start-Job -ScriptBlock { param($Script, $Service, $Ready, $Complete, $Result) & $Script -ServicePath $Service -ReadyPath $Ready -CompletionSignalPath $Complete -ResultPath $Result -TimeoutSeconds 1800 } `
            -ArgumentList $observerScript, $script:Service, $ready, $complete, $observed
        $deadline = (Get-Date).AddSeconds(60)
        while (-not (Test-Path $ready) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (-not (Test-Path $ready)) { throw "The network observer did not arm: $($observer | Receive-Job 2>&1 | Out-String)" }

        # 6. Rendezvous over the private switch: the public certificate and the package path out, the
        #    control's result in. Nothing secret crosses it.
        $listener = New-Object Net.HttpListener
        $listener.Prefixes.Add("http://$($net.targetAddress):$($net.httpPort)/")
        $listener.Start()
        $state.Listener2 = $listener
        $networkText = $null
        $deadline = (Get-Date).AddMinutes(60)
        while ($null -eq $networkText -and (Get-Date) -lt $deadline) {
            $pending = $listener.GetContextAsync()
            while (-not $pending.Wait(1000)) { if ((Get-Date) -ge $deadline) { break } }
            if (-not $pending.IsCompleted) { break }
            $context = $pending.Result
            $body = [byte[]]@()
            switch ($context.Request.Url.AbsolutePath) {
                '/cert' { $body = [IO.File]::ReadAllBytes($certificateFile) }
                '/package-root' { $body = [Text.Encoding]::UTF8.GetBytes($script:PackageRoot) }
                '/done' {
                    $reader = New-Object IO.StreamReader($context.Request.InputStream, [Text.Encoding]::UTF8)
                    $networkText = $reader.ReadToEnd()
                    $body = [Text.Encoding]::UTF8.GetBytes('received')
                }
                default { $context.Response.StatusCode = 404 }
            }
            $context.Response.ContentType = 'text/plain; charset=utf-8'
            $context.Response.OutputStream.Write($body, 0, $body.Length)
            $context.Response.Close()
        }
        [DateTime]::UtcNow.ToString('O') | Set-Content -LiteralPath $complete
        if ($null -eq $networkText) { throw 'NOT_RUN: the control VM never reported (60 minutes); the observer and cleanup ran.' }
        $networkText | Set-Content (Join-Path $Evidence 'ipc-network-logon.txt')

        # 7. Both evidence sets, each attributed to its own token.
        $observer | Wait-Job -Timeout 330 | Out-Null
        $observerOutput = $observer | Receive-Job 2>&1 | Out-String
        $observerOutput | Set-Content (Join-Path $Evidence 'network-observer.txt')
        if (-not (Test-Path $observed)) { throw "Target observer produced no result: $observerOutput" }
        $observerEvidence = Get-Content -LiteralPath $observed -Raw | ConvertFrom-Json
        if ($observerEvidence.Result -ne 'PASS' -or $observerEvidence.Checks -ne '3/3') { throw "Target observer 3/3 failed: $observerOutput" }
        if ($networkText -notmatch [regex]::Escape('Result: 7 checks, 0 failure(s).')) { throw "Network Logon 7/7 failed:`n$networkText" }
        foreach ($required in 'S-1-5-2=true', 'S-1-5-4=false', 'serviceAvailable=false', 'outcome=ServiceUnavailable', 'mutation=none') {
            if ($networkText -notmatch [regex]::Escape($required)) { throw "Network Logon evidence is missing: $required" }
        }
        'network logon 7/7 from the control VM; target observer 3/3; combined 10/10'
    }
    finally {
        if ($state.Listener2) { try { $state.Listener2.Stop() } catch { } }
        if ($observer) { Stop-Job $observer -ErrorAction SilentlyContinue; Remove-Job $observer -Force -ErrorAction SilentlyContinue }
        if ($state.Listener) { Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } -ErrorAction SilentlyContinue }
        if ($state.ContainsKey('Basic')) { Set-Item 'WSMan:\localhost\Service\Auth\Basic' -Value $state.Basic -Force -ErrorAction SilentlyContinue }
        if ($state.RootSddl) { Set-Item -LiteralPath 'WSMan:\localhost\Service\RootSDDL' -Value $state.RootSddl -Force -ErrorAction SilentlyContinue }
        if ($state.Rules) { Remove-NetFirewallRule -DisplayName 'WinSight qualification WinRM HTTPS', 'WinSight qualification rendezvous' -ErrorAction SilentlyContinue }
        if ($state.Thumbprint) { Remove-Item -LiteralPath "Cert:\LocalMachine\My\$($state.Thumbprint)" -Force -ErrorAction SilentlyContinue }
        if ($state.User) { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue }
        if ($state.Interface -and $state.Category) { Set-NetConnectionProfile -InterfaceIndex $state.Interface -NetworkCategory $state.Category -ErrorAction SilentlyContinue }
        if ($state.ContainsKey('WinRmStart')) {
            Restart-Service WinRM -Force -ErrorAction SilentlyContinue
            if (-not $state.WinRmRunning) { Stop-Service WinRM -Force -ErrorAction SilentlyContinue }
            Set-Service WinRM -StartupType $state.WinRmStart -ErrorAction SilentlyContinue
        }
        if ($null -ne (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue)) {
            'CLEANUP WARNING: LocalAccountTokenFilterPolicy exists'
        }
        Remove-ServiceIfPresent
    }
}

Invoke-Gate '99-residue' {
    & $ScExe query WinSightFirewall *> $null
    if ($LASTEXITCODE -ne 1060) { throw "Service still registered (sc exit $LASTEXITCODE)." }
    $sessions = @(Get-WinSightEtwSessionNames)
    if ($sessions.Count -ne 0) { throw "ETW sessions remain: $($sessions -join ', ')" }
    if (Get-ItemProperty -Path $RunKey -Name $ProbeValue -ErrorAction SilentlyContinue) { throw 'Probe value remains.' }
    if (Test-Path -LiteralPath 'HKCU:\Software\Classes\*\shell\WinSight.Signature') { throw 'Signature verb remains.' }
    $alive = @(Get-Process -Name 'winsight', 'winsight-dashboard', 'winsight-firewall-service' -ErrorAction SilentlyContinue)
    if ($alive.Count -ne 0) { throw "WinSight processes remain: $($alive.Id -join ', ')" }
    foreach ($task in $script:LimitedTasks) { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue }
    'no service, ETW session, probe value, verb or process left'
}

$Results.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
Save-Results
Stop-Transcript | Out-Null
