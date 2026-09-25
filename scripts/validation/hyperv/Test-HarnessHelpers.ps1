# Run UNELEVATED, under Windows PowerShell 5.1 (what the runner uses). Self-checks of the harness
# helpers that need no privilege: the git blob id binding, and the refusals that keep the elevated
# scripts out of links and out of user-owned folders. Prints PASS / FAIL, exits 1 on any FAIL.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force
$repository = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$failures = 0
function Report([bool]$Passed, [string]$Check) {
    $script:failures += [int](-not $Passed)
    '{0} {1}' -f $(if ($Passed) { 'PASS' } else { 'FAIL' }), $Check
}
function Throws([scriptblock]$Block, [string]$Pattern) {
    try { & $Block; return $false } catch { return $_.Exception.Message -match $Pattern }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('winsight-harness-selftest-' + [Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $work)
$source = Join-Path $work 'source'
$outside = Join-Path $work 'outside'
$link = Join-Path $source 'link'
try {
    # The blob id computed from the bytes is the one git has for the committed file.
    $tracked = 'LICENSE'
    $expected = (& git -C $repository rev-parse "HEAD:$tracked").Trim()
    $dirty = & git -C $repository status --porcelain -- $tracked
    Report ((-not $dirty) -and (Get-GitBlobId (Join-Path $repository $tracked)) -eq $expected) 'Get-GitBlobId equals git rev-parse HEAD:<path>'

    [void](New-Item -ItemType Directory -Path $source, $outside, (Join-Path $source 'sub'))
    Set-Content -LiteralPath (Join-Path $source 'sub\result.txt') -Value 'guest result'
    Set-Content -LiteralPath (Join-Path $outside 'host-secret.txt') -Value 'must not be collected'
    # A junction needs no privilege: exactly what a guest, or a user, can plant.
    & cmd.exe /c mklink /J "$link" "$outside" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not create the test junction' }

    $collected = Join-Path $work 'collected'
    [void](New-Item -ItemType Directory -Path $collected)
    $refused = @(Copy-GuestResults -From $source -To $collected)
    Report ((Test-Path -LiteralPath (Join-Path $collected 'sub\result.txt')) -and
        -not (Test-Path -LiteralPath (Join-Path $collected 'link')) -and
        ($refused -contains 'link (reparse point)')) 'Copy-GuestResults copies files and refuses a junction without entering it'

    Report (Throws { Assert-NoReparseBetween -Root $source -Path (Join-Path $link 'host-secret.txt') } 'Reparse point') 'Assert-NoReparseBetween refuses a junction on the way'
    $staging = Join-Path $work 'staging'
    [void](New-Item -ItemType Directory -Path $staging)
    Report (Throws { Copy-ListedFile -SourceRoot $source -Relative 'link\host-secret.txt' -DestinationRoot $staging } 'Reparse point') 'Copy-ListedFile refuses a file behind a junction'
    Report (Throws { Copy-ListedFile -SourceRoot $source -Relative '..\outside\host-secret.txt' -DestinationRoot $staging } 'Invalid relative path') 'Copy-ListedFile refuses a path that climbs out'
    Copy-ListedFile -SourceRoot $source -Relative 'sub\result.txt' -DestinationRoot $staging
    Report (Test-Path -LiteralPath (Join-Path $staging 'sub\result.txt')) 'Copy-ListedFile copies a listed ordinary file'
    Report (Throws { Assert-ProtectedPath -Path $source } 'Not owned by Administrators|Writable by|renamed|Children of') 'Assert-ProtectedPath refuses a folder an ordinary user owns'
    # The folders above a protected one count: here the user's own profile, which the user can rename.
    Report (Throws { Assert-ProtectedAncestors -Path $source } 'Not owned by Administrators|renamed|Children of') 'Assert-ProtectedAncestors refuses a path under folders an ordinary user controls'
    Report (-not (Throws { Assert-ProtectedAncestors -Path (Join-Path $env:SystemRoot 'System32') } '.')) 'Assert-ProtectedAncestors accepts a path whose parents only administrators can replace'
    # An inheritable entry can hold only the generic bit (GENERIC_ALL), which no specific right matches.
    $generic = [pscustomobject]@{ FileSystemRights = [Enum]::ToObject([System.Security.AccessControl.FileSystemRights], 0x10000000) }
    $module = Get-Module WinSightHyperV
    Report (& $module { param($Rule) Test-Grants $Rule $script:WriteRights } $generic) 'a GENERIC_ALL inheritable entry counts as a write grant'
    Report (Throws { Assert-ProtectedPath -Path $source -Recurse } 'Reparse point|Not owned|Writable by|renamed|Children of') 'Assert-ProtectedPath -Recurse refuses a tree holding a junction'

    # Hyper-V grants its worker process capability on the disks of the VMs it runs. The check trusts
    # that one capability in the VM storage and nowhere else, and still refuses any other.
    $worker = 'S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704'
    $trusts = {
        param($Sid, [switch]$VirtualMachines)
        try { [bool](& $module { param($s, $v) Test-TrustedWriter $s -VirtualMachines:$v } $Sid $VirtualMachines.IsPresent) } catch { $null }
    }
    Report ((& $trusts $worker -VirtualMachines) -eq $true -and (& $trusts $worker) -eq $false) 'the Hyper-V worker capability is trusted in the VM storage only'
    Report ((& $trusts 'S-1-15-3-1' -VirtualMachines) -eq $false) 'another capability is not trusted, even in the VM storage'
    Report ((& $trusts 'S-1-5-83-1-1111-2222-3333-4444') -eq $true -and (& $trusts 'S-1-5-11' -VirtualMachines) -eq $false) 'the per-VM identity is trusted, Authenticated Users are not'
    Report ((& $module { $script:VmWorkerProcessCapability }) -eq $worker) 'the module names the vmWorkerProcess capability SID'
}
finally {
    # The junction first, by itself: deleting the tree with it in place is how a recursive delete
    # reaches the folder it points to.
    if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link, $false) }
    if (Test-Path -LiteralPath (Join-Path $outside 'host-secret.txt')) { } else { $failures++; 'FAIL the junction target was touched' }
    [IO.Directory]::Delete($work, $true)
}
if ($failures -gt 0) { "$failures check(s) failed."; exit 1 }
'All checks passed.'
exit 0
