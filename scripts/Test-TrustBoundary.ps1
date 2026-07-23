<#
.SYNOPSIS
    Adversarial validation of service-path trust: hostile filesystem states and a rename-aside race.

.DESCRIPTION
    CI cannot build hostile ACLs, foreign owners, reparse points or a live swap race, so this is a
    VM-only gate. It drives the protected candidate's read-only `install-path-trust-check` verb, which
    shares the inspect-and-revalidate primitive Install uses but can never reach SCM or WFP. Nothing
    here installs, starts or stops a service, and nothing touches the Windows Filtering Platform.

    Every expectation below is a code that was measured, not assumed. Two of them are worth stating
    because they look like bugs and are not:

      * A System32 executable is REFUSED with UNTRUSTED_OWNER. TrustedInstaller is accepted as an
        owner for parent directories but not for the leaf binary, which must be owned by SYSTEM or
        Administrators. That is the policy, deliberately.
      * A junction resolves to its target, so a junction inside a user-writable tree reports
        WRITABLE_BY_UNPRIVILEGED rather than REPARSE_POINT. Only a reparse point whose resolved chain
        is otherwise trusted can surface REPARSE_POINT, which is why that case needs a protected root.

    Uses no closures on purpose. GetNewClosure() captures variables but not functions, so a closure
    calling a script function dies when the script is invoked with `&` instead of `-File`. That defect
    killed the WFP protocol on a real VM while every local gate was green.

.EXAMPLE
    ./Test-TrustBoundary.ps1 -ServicePath 'C:\Program Files\WinSight-VM\winsight-firewall-service.exe'
#>
[CmdletBinding()]
param(
    # The protected candidate. Its own path is the trusted baseline.
    [Parameter(Mandatory = $true)]
    [string]$ServicePath,

    # A protected, non-user-writable directory this script may create and delete inside.
    [string]$ScratchRoot = 'C:\Program Files\WinSight-TrustBoundary',

    # How many times the planted file is probed while being swapped underneath.
    [int]$RaceIterations = 40,

    # A local standard (non-administrator) account used as the hostile owner. Optional: the
    # foreign-owner case is skipped, and reported as skipped, when it is absent.
    [string]$HostileAccount
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:Checks = 0
$script:Failures = 0
$script:Created = New-Object System.Collections.ArrayList

$DenialCodes = @(
    '[FW_INSTALL_PATH_INVALID]',
    '[FW_INSTALL_PATH_OUTSIDE_MACHINE_DATA]',
    '[FW_INSTALL_PATH_MISSING_COMPONENT]',
    '[FW_INSTALL_PATH_REPARSE_POINT]',
    '[FW_INSTALL_PATH_UNTRUSTED_OWNER]',
    '[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]',
    '[FW_INSTALL_PATH_IDENTITY_CHANGED]',
    '[FW_INSTALL_PATH_INSPECTION_FAILED]'
)
$TrustedCode = '[FW_INSTALL_PATH_TRUSTED]'

function Write-Check([string]$name, [bool]$ok, [string]$expectation, [string]$observed) {
    $script:Checks++
    if ($ok) {
        Write-Host ('  [PASS] {0}' -f $name)
    }
    else {
        $script:Failures++
        Write-Host ('  [FAIL] {0}: expected {1}, observed {2}' -f $name, $expectation, $observed)
    }
}

function Invoke-Probe([string]$candidate, [string]$target) {
    # The probe is read-only. Native stderr is captured, not treated as a terminating error - that
    # mistake killed an earlier WFP revision. But the refusal is a single [FW_...] token, and PS 5.1
    # decorates native stderr merged with 2>&1 ("<exe> : ...", "Au caractere ... + $raw = ..."). That
    # decoration is not part of the verdict, so extract the token instead of string-comparing the
    # whole capture. A real VM run failed five checks on that decoration while the service was correct.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $candidate install-path-trust-check $target 2>&1
        $code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $previous }
    $text = ($raw | Out-String)
    $token = [regex]::Match($text, '\[FW_[A-Z_]+\]').Value
    return [pscustomobject]@{ Code = $token; Raw = $text.Trim(); ExitCode = $code }
}

function Test-ExactCode([string]$name, [string]$candidate, [string]$target, [string]$expected, [int]$expectedExit) {
    $r = Invoke-Probe $candidate $target
    $ok = ($r.Code -ceq $expected) -and ($r.ExitCode -eq $expectedExit)
    Write-Check $name $ok ('{0} and exit {1}' -f $expected, $expectedExit) ('"{0}" and exit {1}' -f $r.Code, $r.ExitCode)
    return $r
}

function Test-AnyDenial([string]$name, [string]$candidate, [string]$target) {
    # Not a loose predicate: this excludes trusted, empty output, a crash, an untyped message and
    # exit 0. It records which typed code fired so the record can be tightened to it afterwards.
    $r = Invoke-Probe $candidate $target
    $ok = ($DenialCodes -ccontains $r.Code) -and ($r.ExitCode -eq 1)
    Write-Check $name $ok 'one typed denial code and exit 1' ('"{0}" and exit {1}' -f $r.Code, $r.ExitCode)
    if ($ok) { Write-Host ('         code: {0}' -f $r.Code) }
    return $r
}

function New-TrackedDirectory([string]$path) {
    New-Item -ItemType Directory -Force $path | Out-Null
    [void]$script:Created.Add($path)
}

function Remove-Tracked {
    for ($i = $script:Created.Count - 1; $i -ge 0; $i--) {
        $p = $script:Created[$i]
        if (Test-Path -LiteralPath $p) {
            # rmdir handles junctions without following them into the target.
            cmd /c ('rmdir /s /q "{0}" 2>nul' -f $p) | Out-Null
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Write-Host '== service-path trust boundary =='

$elevated = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Check 'console is elevated' $elevated 'an elevated VM console' $elevated
if (-not $elevated) {
    Write-Host 'STOP: hostile states need an elevated console to build a protected root.'
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

$candidate = [IO.Path]::GetFullPath($ServicePath)
Write-Check 'candidate exists' (Test-Path -LiteralPath $candidate) 'an existing protected candidate' $candidate
if ($script:Failures -gt 0) {
    Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
    exit 1
}

try {
    # 1. Baseline. If the protected candidate itself is not trusted, every refusal below is
    #    meaningless because the probe would be refusing everything.
    Test-ExactCode 'the protected candidate is trusted' $candidate $candidate $TrustedCode 0 | Out-Null

    # 2. A user-writable leaf. Measured.
    $userRoot = Join-Path $env:TEMP ('winsight-trust-' + [guid]::NewGuid().ToString('N'))
    New-TrackedDirectory $userRoot
    $writable = Join-Path $userRoot 'planted.exe'
    Copy-Item -LiteralPath $candidate -Destination $writable -Force
    Test-ExactCode 'a user-writable leaf is refused' $candidate $writable `
        '[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]' 1 | Out-Null

    # 3. A missing directory component. Measured.
    Test-ExactCode 'a missing path component is refused' $candidate (Join-Path $userRoot 'absent\x.exe') `
        '[FW_INSTALL_PATH_MISSING_COMPONENT]' 1 | Out-Null

    # 4. A TrustedInstaller-owned leaf. Measured, and correct by policy: TrustedInstaller is a
    #    trusted owner for parent directories only, never for the binary itself.
    Test-ExactCode 'a TrustedInstaller-owned leaf is refused' $candidate `
        (Join-Path $env:SystemRoot 'System32\curl.exe') '[FW_INSTALL_PATH_UNTRUSTED_OWNER]' 1 | Out-Null

    # 5. A protected root, so the remaining hostile states are not masked by writability.
    New-TrackedDirectory $ScratchRoot
    $protectedLeaf = Join-Path $ScratchRoot 'candidate-copy.exe'
    Copy-Item -LiteralPath $candidate -Destination $protectedLeaf -Force
    Test-ExactCode 'a copy in a protected root is trusted' $candidate $protectedLeaf $TrustedCode 0 | Out-Null

    # 6. A reparse point inside the protected root pointing at the user-writable tree. Measured on a
    #    real VM as REPARSE_POINT, so it is now asserted exactly. On a machine whose %TEMP% is itself
    #    inside a user-writable tree, the junction leaf can instead resolve to WRITABLE_BY_UNPRIVILEGED
    #    before reparse detection fires; both are refusals, but the VM measurement was REPARSE_POINT.
    $junction = Join-Path $ScratchRoot 'junction'
    cmd /c ('mklink /J "{0}" "{1}"' -f $junction, $userRoot) | Out-Null
    [void]$script:Created.Add($junction)
    Test-ExactCode 'a reparse point in a protected root is refused' $candidate `
        (Join-Path $junction 'planted.exe') '[FW_INSTALL_PATH_REPARSE_POINT]' 1 | Out-Null

    # 7. A leaf inside the protected root owned by an unprivileged account.
    if ([string]::IsNullOrWhiteSpace($HostileAccount)) {
        Write-Host '  [SKIP] a foreign-owned leaf is refused: pass -HostileAccount <standard user> to run it'
    }
    else {
        $foreign = Join-Path $ScratchRoot 'foreign-owned.exe'
        Copy-Item -LiteralPath $candidate -Destination $foreign -Force
        & (Join-Path $env:SystemRoot 'System32\icacls.exe') $foreign /setowner $HostileAccount | Out-Null
        Test-AnyDenial 'a foreign-owned leaf in a protected root is refused' $candidate $foreign | Out-Null
    }

    # 8. The race. One honest file in the protected root, whose ACL is flipped between "an unprivileged
    #    principal can write" and "protected" on every iteration, with a probe in each state. This is
    #    the property that matters: the trusted verdict must track the real security state and never
    #    lag into a stale TRUSTED while the file is writable. An earlier version copied user-writable
    #    *content* into the protected root and was surprised the *path* read trusted - the path model
    #    evaluates the path's ACLs, not where the bytes came from, so that test proved nothing.
    #
    #    BUILTIN\Users is the well-known SID S-1-5-32-545, so this needs no separate account and is
    #    locale-independent. icacls resolves absolutely from System32.
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $usersSid = '*S-1-5-32-545'
    $racePath = Join-Path $ScratchRoot 'race-target.exe'
    Copy-Item -LiteralPath $candidate -Destination $racePath -Force
    $writableTrusted = 0
    $protectedTrusted = 0
    $writableCodes = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $RaceIterations; $i++) {
        # Grant an unprivileged principal write, then probe: must never read trusted.
        & $icacls $racePath /grant ('{0}:(W)' -f $usersSid) | Out-Null
        $hostile = Invoke-Probe $candidate $racePath
        [void]$writableCodes.Add($hostile.Code)
        if ($hostile.Code -ceq $TrustedCode) { $writableTrusted++ }
        # Revoke it, then probe: must read trusted again, so the loop is not merely refusing
        # everything for some unrelated reason.
        & $icacls $racePath /remove:g $usersSid | Out-Null
        $honest = Invoke-Probe $candidate $racePath
        if ($honest.Code -ceq $TrustedCode) { $protectedTrusted++ }
    }
    Write-Check ('the user-writable leaf is never trusted across {0} ACL flips' -f $RaceIterations) `
        ($writableTrusted -eq 0) 'zero trusted observations while user-writable' ('{0} trusted' -f $writableTrusted)
    Write-Check ('the protected leaf still reads trusted across {0} ACL flips' -f $RaceIterations) `
        ($protectedTrusted -eq $RaceIterations) `
        ('{0} trusted observations' -f $RaceIterations) ('{0} trusted' -f $protectedTrusted)
    $distinct = ($writableCodes | Sort-Object -Unique) -join ', '
    Write-Host ('         user-writable codes observed: {0}' -f $distinct)
}
finally {
    Remove-Tracked
}

$leftovers = @($script:Created | Where-Object { Test-Path -LiteralPath $_ })
Write-Check 'every hostile artefact is removed' ($leftovers.Count -eq 0) 'no leftover path' ($leftovers -join ', ')

Write-Host ('Result: {0} checks, {1} failure(s).' -f $script:Checks, $script:Failures)
if ($script:Failures -gt 0) { exit 1 }
exit 0
