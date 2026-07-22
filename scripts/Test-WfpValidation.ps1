<#
.SYNOPSIS
    Runs the WFP runtime validation protocol on a VM and prints a pass/fail transcript.

.DESCRIPTION
    CI cannot cover the part of the firewall that actually filters traffic: it reaches WFP through
    P/Invoke into fwpuclnt.dll, and a hosted runner is no place to cut network traffic and watch what
    breaks. docs/ARM64_VALIDATION.md describes that protocol in prose. This script *executes* it, so
    the result is a transcript with verdicts rather than an account of what somebody remembers doing.

    That distinction is the point. A validation nobody can replay is indistinguishable from one that
    was never run, six months later — and the three defects fixed in #61, #62 and #63 were all
    invisible to the unit suite and only appeared against a real machine.

    Everything here is read-only or reversible, and the arming step is deliberately NOT automated:
    mutating WFP requires authenticated IPC by design, so the script pauses and tells you exactly
    what to do in the dashboard, then verifies the result.

.PARAMETER ServicePath
    Full path to a deployed winsight-firewall-service.exe, in a trusted location.

.PARAMETER SkipEnforcement
    Run only the read-only half: preconditions, service lifecycle, path trust and the WFP probe.
    Nothing is armed and no traffic is cut. Safe on a working machine.

.EXAMPLE
    ./scripts/Test-WfpValidation.ps1 -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
    ./scripts/Test-WfpValidation.ps1 -ServicePath ... -SkipEnforcement
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServicePath,

    [switch]$SkipEnforcement
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Failures = 0
$script:Checks = 0

function Section($name) { Write-Output ""; Write-Output "== $name ==" }

function Check($name, [scriptblock]$test, $expectation) {
    $script:Checks++
    try {
        $result = & $test
    }
    catch {
        $result = $false
        $expectation = "$expectation (threw: $($_.Exception.GetType().Name))"
    }
    if ($result) {
        "  [PASS] {0}" -f $name | Write-Output
    }
    else {
        $script:Failures++
        "  [FAIL] {0}`n         expected: {1}" -f $name, $expectation | Write-Output
    }
}

# Raw output is kept for every probe: a summary loses the FWP_E_* codes that carry the signal.
function Run($exe, [string[]]$serviceArgs) {
    $output = & $exe @serviceArgs 2>&1 | Out-String
    "  > $(Split-Path -Leaf $exe) $($serviceArgs -join ' ')" | Write-Output
    ($output.TrimEnd() -split "`n" | ForEach-Object { "    $_" }) | Write-Output
    return $output
}

Section "Preconditions"

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Check "console is elevated" { $elevated } "an elevated console; the service installs to a trusted path and arming is gated on elevation"
Check "service binary exists" { Test-Path $ServicePath } "a deployed winsight-firewall-service.exe at -ServicePath"

if (-not $elevated -or -not (Test-Path $ServicePath)) {
    Write-Output ""
    Write-Output "Preconditions failed; stopping before touching anything."
    exit 1
}

Write-Output ""
Write-Output "  NOTE: take a VM snapshot before continuing. Enforcement really does cut traffic for"
Write-Output "        one process. Everything is reversible, but a snapshot means never having to"
Write-Output "        trust that."

Section "Service lifecycle"

$null = Run $ServicePath @("install")
Start-Sleep -Seconds 1
sc.exe start WinSightFirewall | Out-Null
Start-Sleep -Seconds 5
$query = sc.exe query WinSightFirewall | Out-String
Check "service reaches RUNNING" { $query -match "RUNNING" } "STATE : 4 RUNNING from sc.exe query"

$enforce = Run $ServicePath @("enforce-status")
Check "starts in audit-only" { $enforce -match "AuditOnly" } "persisted desired AuditOnly on a fresh install"

Section "Path trust boundary"

# The service must refuse to install from a location an unprivileged user can write, or the trusted
# path is a convention rather than a boundary.
$untrusted = Join-Path $env:USERPROFILE "Desktop\winsight-untrusted-probe"
New-Item -ItemType Directory -Force -Path $untrusted | Out-Null
Copy-Item (Join-Path (Split-Path $ServicePath) "*") $untrusted -Recurse -Force -ErrorAction SilentlyContinue
$untrustedExe = Join-Path $untrusted (Split-Path -Leaf $ServicePath)
if (Test-Path $untrustedExe) {
    $refusal = & $untrustedExe install 2>&1 | Out-String
    $refusalCode = $LASTEXITCODE
    "  > install from a user-writable path" | Write-Output
    ($refusal.TrimEnd() -split "`n" | ForEach-Object { "    $_" }) | Write-Output
    Check "install refused from a user-writable path" `
        { $refusalCode -ne 0 -and $refusal -match "FW_INSTALL_FAILED|Writable|UntrustedOwner|OutsideProgramData" } `
        "[FW_INSTALL_FAILED] and a non-zero exit; the trust codes are UntrustedOwner, WritableByUnprivilegedPrincipal, OutsideProgramData, ReparsePoint, IdentityChanged"
}
Remove-Item $untrusted -Recurse -Force -ErrorAction SilentlyContinue

Section "WFP engine, read-only"

$selfTest = Run $ServicePath @("wfp-selftest")
Check "WFP engine opens" { $selfTest -notmatch "FWP_E_" -and $selfTest -match "\d" } `
    "an engine session and a filter count, with no FWP_E_* error. THIS IS THE INTEROP SIGNAL: if it fails here, stop and report it — that result is worth more than the rest of the protocol."

$wfpStatus = Run $ServicePath @("wfp-status")
Check "no WFP state before arming" { $wfpStatus -match "absent" } "provider: absent, sublayer: absent on an unarmed machine"

Check "direct WFP mutation is refused" `
    { (& $ServicePath wfp-block-add "C:\Windows\System32\curl.exe" 2>&1 | Out-String) -match "DIRECT_MUTATION_DISABLED|disabled" } `
    "[FW_DIRECT_MUTATION_DISABLED]; policy mutation must go through authenticated IPC, never the command line"

if ($SkipEnforcement) {
    Section "Result"
    "  {0} checks, {1} failure(s). Enforcement half skipped (-SkipEnforcement)." -f $script:Checks, $script:Failures | Write-Output
    exit ([int]($script:Failures -gt 0))
}

Section "Enforcement — manual gate"

# curl, never ping: ping sends ICMP through the IP Helper service, so an app-id filter never matches
# it and the test would be measuring nothing.
$target = "C:\curltest\curl.exe"
New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
Copy-Item "C:\Windows\System32\curl.exe" $target -Force

$before = & $target -s -o NUL -w "%{http_code}" --max-time 15 https://example.com 2>&1
Check "target reaches the network before blocking" { "$before" -eq "200" } "http 200 from the unblocked copy; without this the blocked result proves nothing"

Write-Output ""
Write-Output "  ACTION REQUIRED — this cannot be automated by design."
Write-Output "  Mutating policy requires authenticated IPC, so do this in an ELEVATED dashboard:"
Write-Output "    1. Outbound firewall -> Start analysis"
Write-Output "    2. Block an app...   -> $target"
Write-Output "    3. Enable enforcement -> confirm"
Write-Output ""
Read-Host "  Press Enter once enforcement is enabled"

$armed = Run $ServicePath @("enforce-status")
Check "enforcement is persisted" { $armed -match "Enforcement" } "persisted desired Enforcement"

$wfpArmed = Run $ServicePath @("wfp-status")
Check "WFP provider and sublayer exist" { $wfpArmed -match "present" } "provider: present, sublayer: present"

$blockStatus = Run $ServicePath @("wfp-block-status", $target)
Check "the target reads as blocked" { $blockStatus -match "FW_APP_BLOCKED" } "[FW_APP_BLOCKED]"

$blocked = & $target -s -o NUL -w "%{http_code}" --max-time 20 https://example.com 2>&1
Check "blocked app cannot reach the network" { "$blocked" -ne "200" } "anything but 200 (x64 yields http 000, exit 2)"

# The unblocked leg matters as much as the blocked one: if both fail, the filter is not app-scoped
# and that is a bug, not a success.
$unblocked = & "C:\Windows\System32\curl.exe" -s -o NUL -w "%{http_code}" --max-time 20 https://example.com 2>&1
Check "an unblocked copy still reaches the network" { "$unblocked" -eq "200" } `
    "http 200 from C:\Windows\System32\curl.exe. If this also fails the block is machine-wide, not per-app — a defect, however good the blocked leg looks."

Section "Rollback"

Write-Output "  ACTION REQUIRED: dashboard -> Emergency disable"
Read-Host "  Press Enter once emergency disable has completed"

$disarmed = Run $ServicePath @("enforce-status")
Check "back to audit-only" { $disarmed -match "AuditOnly" } "persisted desired AuditOnly"

$wfpClean = Run $ServicePath @("wfp-status")
Check "all WFP state removed" { $wfpClean -match "absent" } "provider: absent, sublayer: absent — a leftover provider is enforcement state nothing owns"

$restored = & $target -s -o NUL -w "%{http_code}" --max-time 20 https://example.com 2>&1
Check "the target reaches the network again" { "$restored" -eq "200" } "http 200 once enforcement is lifted"

Section "Clean up"

sc.exe stop WinSightFirewall | Out-Null
Start-Sleep -Seconds 2
$null = Run $ServicePath @("uninstall")
sc.exe query WinSightFirewall 2>&1 | Out-Null
Check "uninstall leaves no service" { $LASTEXITCODE -eq 1060 } "sc.exe query returns 1060 (service absent)"
Remove-Item (Split-Path $target) -Recurse -Force -ErrorAction SilentlyContinue

Section "Result"
"  {0} checks, {1} failure(s)." -f $script:Checks, $script:Failures | Write-Output
Write-Output "  Paste this whole transcript into the validation issue. Raw codes matter more than a summary."
Write-Output "  Then restore the VM snapshot."
exit ([int]($script:Failures -gt 0))
