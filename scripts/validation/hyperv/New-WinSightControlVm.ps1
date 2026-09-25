#Requires -RunAsAdministrator
# HOST, elevated, once: the second machine of gate 36 (IPC by network logon, kit section 7).
#
# - A Private Hyper-V switch, WinSight-Qual-Private: the two VMs see each other and nothing else, not
#   even the host.
# - WinSight-Control-HV, a Generation 2 VM on a differencing disk whose parent is the qualification
#   VM's settled base disk (os.vhdx). That parent is already read-only (the qualification VM writes to
#   its checkpoint chain), so both VMs share it without touching it. Same image, same auto-logon, same
#   WINSIGHTQ logon task: the control runs whatever its own data disk tells it to.
# - Its own data disk (control-data.vhdx, label WINSIGHTQ), attached only for a run.
# - A first boot in 'settle' mode, then the clean checkpoint C0-control.
#
# No guest account is created here, no password is handled, and the development workstation's own
# network, WinRM and certificate configuration are not touched.
#
# RA-01: run by WinSightQualRunner.ps1 from its protected copy; the VM storage must already be
# administrators-only (Protect-WinSightVmStorage.ps1).
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HarnessDir,
    [Parameter(Mandatory)][string]$EvidenceRoot,
    # Default locations, resolved below, are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root,
    [string]$TargetName = 'WinSight-Qualification-HV',
    [string]$Name = 'WinSight-Control-HV',
    [string]$Switch = 'WinSight-Qual-Private',
    [string]$Checkpoint = 'C0-control',
    [int64]$MemoryBytes = 3GB,
    [int]$SettleTimeoutMinutes = 45
)

# Resolved here rather than as parameter defaults: Windows PowerShell 5.1 leaves $PSScriptRoot
# empty in the defaults of an advanced script started with -File.
if (-not $Root) { $Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification') }

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $HarnessDir 'WinSightHyperV.psm1') -Force
Set-AdministratorsDefaultOwner
Assert-ProtectedPath -Path $Root -Recurse -AllowVirtualMachines

$base = Join-Path $Root 'os.vhdx'
$disk = Join-Path $Root 'control.vhdx'
$data = Join-Path $Root 'control-data.vhdx'

if ((Get-VM -Name $Name -ErrorAction SilentlyContinue) -and (Get-VMCheckpoint -VMName $Name -Name $Checkpoint -ErrorAction SilentlyContinue)) {
    Write-Host "Already ready: VM $Name has its clean checkpoint $Checkpoint."
    return
}
if (-not (Test-Path -LiteralPath $base)) { throw "Missing $base (the qualification VM's base disk)." }
$chain = @(Get-VMHardDiskDrive -VMName $TargetName | ForEach-Object { $_.Path })
if ($chain -contains $base) {
    throw "$TargetName writes to $base directly (no checkpoint); a second VM must not share it. Take its clean checkpoint first."
}

if (-not (Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $Switch -SwitchType Private | Out-Null
    Write-Host "Private switch $Switch created."
}

if (-not (Test-Path -LiteralPath $disk)) {
    New-VHD -Path $disk -ParentPath $base -Differencing | Out-Null
    Write-Host "Differencing disk $disk (parent $base) created."
}
if (-not (Test-Path -LiteralPath $data)) {
    New-VHD -Path $data -SizeBytes 4GB -Dynamic | Out-Null
    $mounted = Mount-VHD -Path $data -Passthru | Get-Disk
    Initialize-Disk -Number $mounted.Number -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $mounted.Number -UseMaximumSize -AssignDriveLetter
    Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'WINSIGHTQ' -Confirm:$false | Out-Null
    Dismount-VHD -Path $data
}
$letter = Mount-WinSightData $data
try {
    Clear-WinSightDataVolume $letter
    Copy-Item -LiteralPath (Join-Path $HarnessDir 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1"
    'settle' | Set-Content -LiteralPath "${letter}:\mode.txt"
}
finally { Dismount-WinSightData $data }

$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
if (-not $vm) {
    New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryBytes -VHDPath $disk -Path $Root | Out-Null
    Write-Host "VM $Name created."
}
elseif ($vm.State -ne 'Off') { throw "VM $Name is $($vm.State); turn it off and run this again." }
Set-VMProcessor -VMName $Name -Count 2
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false -StartupBytes $MemoryBytes
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStopAction TurnOff
Get-VMNetworkAdapter -VMName $Name | Remove-VMNetworkAdapter
Add-VMNetworkAdapter -VMName $Name -Name 'WinSightPrivate' -SwitchName $Switch -StaticMacAddress '00155D5AFA20'
Get-VMHardDiskDrive -VMName $Name | Where-Object Path -eq $data | Remove-VMHardDiskDrive
Add-VMHardDiskDrive -VMName $Name -Path $data

Write-Host "First boot of $Name (settles, then shuts itself down; up to $SettleTimeoutMinutes minutes)..."
Start-VM -Name $Name
$started = Get-Date
while ((Get-WinSightVmState $Name) -ne 'Off' -and (Get-Date) -lt $started.AddMinutes($SettleTimeoutMinutes)) {
    Start-Sleep -Seconds 30
    Write-Host ("  running {0:N0} min" -f ((Get-Date) - $started).TotalMinutes)
}
if ((Get-WinSightVmState $Name) -ne 'Off') {
    throw "$Name did not shut itself down within $SettleTimeoutMinutes minutes. Open it with vmconnect to see its screen, turn it off, and run this again."
}
Get-VMHardDiskDrive -VMName $Name | Where-Object Path -eq $data | Remove-VMHardDiskDrive
Checkpoint-VM -Name $Name -SnapshotName $Checkpoint
Write-Host "Ready: $Name, clean checkpoint $Checkpoint, private switch $Switch."
Add-Content -LiteralPath (Join-Path $EvidenceRoot 'host-operations.txt') -Value "$(Get-Date -Format o) [control] $Name ready, checkpoint $Checkpoint"
Write-Host 'Next: queue a network request for the runner.'
