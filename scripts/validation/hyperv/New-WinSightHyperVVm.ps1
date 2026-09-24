#Requires -RunAsAdministrator
# HOST, elevated, once: builds the Hyper-V qualification VM from the disk exported from VirtualBox
# (os.vhd, the prepared clean baseline) and takes its clean checkpoint.
#
# - Generation 2 (the VirtualBox guest is EFI with Secure Boot), 4 vCPU, fixed memory, Default Switch.
# - A separate data disk (data.vhdx, NTFS, label WINSIGHTQ) carries the candidate in and the evidence
#   out. It is attached only for a run and never belongs to a checkpoint, so restoring the clean
#   checkpoint never touches the evidence, and the host reads it while the VM is off: no guest
#   account, no password, no network share.
# - First boot lets Windows settle on the new hardware; the guest's WINSIGHTQ logon task finds
#   mode.txt = settle, waits five minutes and shuts down. The clean checkpoint is taken after that.
#
# Resumable: run it again after a failure and it continues from what already exists. Nothing here
# depends on the display language of Windows (component names are localized; none is used).
#
# Kept for the record of how the VM was built (from a disk exported from VirtualBox). RA-01: the VM
# storage must be administrators-only before the runner will use it - run Protect-WinSightVmStorage.ps1
# afterwards. A VM whose disks sat in a folder any user could modify is only as trustworthy as that
# folder was; rebuilding it into a protected folder is what removes the doubt.
[CmdletBinding()]
param(
    # Default locations are at the root of the volume this script runs from; pass a path to use another.
    [string]$Root = (Join-Path ([IO.Path]::GetPathRoot($PSScriptRoot)) 'Hyper-V\WinSight-Qualification'),
    [string]$Name = 'WinSight-Qualification-HV',
    [string]$Checkpoint = 'S0-hyperv-autorun',
    [int64]$MemoryBytes = 6GB,
    [int]$SettleTimeoutMinutes = 45
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V
Import-Module (Join-Path $PSScriptRoot 'WinSightHyperV.psm1') -Force

$osVhd = Join-Path $Root 'os.vhd'
$osVhdx = Join-Path $Root 'os.vhdx'
$data = Join-Path $Root 'data.vhdx'

$vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
if ($vm -and (Get-VMCheckpoint -VMName $Name -Name $Checkpoint -ErrorAction SilentlyContinue)) {
    Write-Host "Already ready: VM $Name has its clean checkpoint $Checkpoint. Nothing to do."
    return
}
if ($vm -and $vm.State -ne 'Off') { throw "VM $Name is $($vm.State); turn it off (Stop-VM -Name $Name -TurnOff) and run this again." }

# --- Disks ------------------------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $osVhdx)) {
    if (-not (Test-Path -LiteralPath $osVhd)) { throw "Missing $osVhd (exported from VirtualBox)." }
    Write-Host 'Converting os.vhd to os.vhdx...'
    Convert-VHD -Path $osVhd -DestinationPath $osVhdx -VHDType Dynamic
}
if ($vm) { Get-VMHardDiskDrive -VMName $Name | Where-Object Path -eq $data | Remove-VMHardDiskDrive }
if (-not (Test-Path -LiteralPath $data)) {
    Write-Host 'Creating the WINSIGHTQ data disk...'
    New-VHD -Path $data -SizeBytes 40GB -Dynamic | Out-Null
    $disk = Mount-VHD -Path $data -Passthru | Get-Disk
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'WINSIGHTQ' -Confirm:$false | Out-Null
    Dismount-VHD -Path $data
}

# First-boot content: settle mode only.
$letter = Mount-WinSightData $data
try {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'guest\run-guest-checks.ps1') -Destination "${letter}:\run-guest-checks.ps1" -Force
    'settle' | Set-Content -LiteralPath "${letter}:\mode.txt"
}
finally { Dismount-WinSightData $data }

# --- VM ---------------------------------------------------------------------------------------------
if (-not $vm) {
    $switch = Get-VMSwitch -Name 'Default Switch' -ErrorAction Stop
    New-VM -Name $Name -Generation 2 -MemoryStartupBytes $MemoryBytes -VHDPath $osVhdx -SwitchName $switch.Name -Path $Root | Out-Null
    Write-Host "VM $Name created."
}
else { Write-Host "VM $Name already exists; completing its configuration." }
Set-VMProcessor -VMName $Name -Count 4
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false -StartupBytes $MemoryBytes
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
Set-VM -Name $Name -AutomaticCheckpointsEnabled $false -CheckpointType Standard -AutomaticStopAction TurnOff
Add-VMHardDiskDrive -VMName $Name -Path $data

# --- First boot -------------------------------------------------------------------------------------
$freeBytes = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
if ($freeBytes -lt $MemoryBytes + 512MB) {
    Write-Warning ("Only {0:N1} GB of RAM free for a {1:N1} GB VM. Close memory-heavy applications (browsers, VirtualBox) or run this again with -MemoryBytes 4GB." -f ($freeBytes / 1GB), ($MemoryBytes / 1GB))
}
Write-Host "First boot of $Name (Windows settles on the new hardware, then shuts itself down; up to $SettleTimeoutMinutes minutes)..."
Start-VM -Name $Name
$started = Get-Date
$deadline = $started.AddMinutes($SettleTimeoutMinutes)
while ((Get-WinSightVmState $Name) -ne 'Off' -and (Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 30
    Write-Host ("  running {0:N0} min" -f ((Get-Date) - $started).TotalMinutes)
}
if ((Get-WinSightVmState $Name) -ne 'Off') {
    throw "The guest did not shut itself down within $SettleTimeoutMinutes minutes. Open it in Hyper-V Manager (vmconnect) to see its screen, then turn it off and run this again."
}

Get-VMHardDiskDrive -VMName $Name | Where-Object Path -eq $data | Remove-VMHardDiskDrive
Checkpoint-VM -Name $Name -SnapshotName $Checkpoint
Write-Host "Ready: VM $Name, clean checkpoint $Checkpoint, data disk $data (detached)."
Write-Host "Next: & '$(Join-Path $PSScriptRoot 'Protect-WinSightVmStorage.ps1')', then start WinSightQualRunner.ps1 (README.md)."
