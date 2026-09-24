#Requires -RunAsAdministrator
# HOST, elevated, once (and again after any change to the VMs): makes the Hyper-V qualification VM
# storage administrators-only, then seals the SHA-256 of every disk in it.
#
# RA-01. The VMs were built under <vol>\, where Authenticated Users have Modify by inheritance, so any
# local user could have replaced the disks the evidence came from. This removes that inheritance and
# leaves SYSTEM, Administrators and the Hyper-V worker identities (Virtual Machines, S-1-5-83-0, and
# the per-VM S-1-5-83-1-* grants Hyper-V adds itself). It cannot tell whether a disk was altered
# before today: the sealed hashes let later runs prove it has not changed since, and rebuilding the
# VM into protected storage is what removes the earlier doubt.
[CmdletBinding()]
param(
    [string]$VmRoot = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification'),
    [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'WinSight-Qualification'),
    [string[]]$VmNames = @('WinSight-Qualification-HV', 'WinSight-Control-HV')
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force

foreach ($vm in $VmNames) {
    $found = Get-VM -Name $vm -ErrorAction SilentlyContinue
    if ($found -and $found.State -ne 'Off') { throw "VM $vm is $($found.State); turn it off first." }
}
$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
if ([IO.File]::GetAttributes($VmRoot) -band [IO.FileAttributes]::ReparsePoint) { throw "$VmRoot is a reparse point." }

# Owners first: a file created by an ordinary account keeps that account as its owner, and an owner
# can always rewrite the DACL.
$pending = New-Object System.Collections.Generic.Stack[string]
$pending.Push([IO.Path]::GetFullPath($VmRoot))
$items = New-Object System.Collections.Generic.List[string]
$items.Add([IO.Path]::GetFullPath($VmRoot))
while ($pending.Count -gt 0) {
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
        $attributes = [IO.File]::GetAttributes($entry)
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point in the VM storage: $entry" }
        $items.Add($entry)
        if ($attributes -band [IO.FileAttributes]::Directory) { $pending.Push($entry) }
    }
}
foreach ($item in $items) {
    $owner = (Get-Acl -LiteralPath $item).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin 'S-1-5-18', 'S-1-5-32-544') {
        & $icacls $item /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not take ownership of $item (icacls exit $LASTEXITCODE)." }
        Write-Host "owner reset to Administrators: $item"
    }
}

# Then the DACL of the root, which every item inherits from once the inheritance from <vol>\ is cut.
& $icacls $VmRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-83-0:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not set the DACL of $VmRoot (icacls exit $LASTEXITCODE)." }
# An explicit grant on an item survives that; it must be gone too, or the storage is still writable.
Assert-ProtectedPath -Path $VmRoot -Recurse -AllowVirtualMachines
Write-Host "$VmRoot is administrators-only."

New-ProtectedDirectory -Path $Root -UsersRead
New-ProtectedDirectory -Path (Join-Path $Root 'sealed') -UsersRead
$record = Join-Path $Root ("sealed\vm-storage-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$lines = @("# $VmRoot protected $([DateTime]::UtcNow.ToString('o'))")
foreach ($disk in $items | Where-Object { $_ -match '\.(a?vhdx?|vmgs|vmrs|vmcx)$' } | Sort-Object) {
    $lines += '{0}  {1}' -f (Get-FileHash -LiteralPath $disk -Algorithm SHA256).Hash, $disk.Substring($VmRoot.TrimEnd('\').Length + 1)
}
$lines | Set-Content -LiteralPath $record
Write-Host "Disk hashes sealed in $record"
