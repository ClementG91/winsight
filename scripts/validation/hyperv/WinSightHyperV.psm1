# Shared helpers for the Hyper-V qualification scripts (HOST, elevated), Windows PowerShell 5.1.
#
# RA-01. The first harness kept its scripts, the staged candidate, the VM disks and the evidence under
# <vol>\, where Authenticated Users have Modify by inheritance, and its elevated runner wrote and deleted
# there. Anything that runs elevated here therefore follows three rules:
#   - it writes only inside a directory it created itself with an administrators-only DACL, or one
#     that Assert-ProtectedPath has just verified;
#   - it reads from user-writable places only an explicit list of files, refusing reparse points;
#   - it never deletes recursively (Windows PowerShell 5.1 Remove-Item -Recurse follows junctions).

$script:Administrators = 'S-1-5-32-544'
$script:LocalSystem = 'S-1-5-18'
$script:AuthenticatedUsers = 'S-1-5-11'
$script:VirtualMachines = 'S-1-5-83-0'
$script:WriteRights = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'

function New-DirectorySecurity([bool]$UsersRead, [bool]$VirtualMachinesFull = $false) {
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $grants = @(@($script:LocalSystem, 'FullControl'), @($script:Administrators, 'FullControl'))
    if ($UsersRead) { $grants += , @($script:AuthenticatedUsers, 'ReadAndExecute') }
    if ($VirtualMachinesFull) { $grants += , @($script:VirtualMachines, 'FullControl') }
    foreach ($grant in $grants) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier $grant[0]
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $grant[1], $inherit, $none, 'Allow')))
    }
    $security.SetOwner((New-Object System.Security.Principal.SecurityIdentifier $script:Administrators))
    return $security
}

# Throws unless $Path is an ordinary directory or file owned by Administrators or SYSTEM that no other
# principal may write, change or delete - except the Hyper-V worker group where -AllowVirtualMachines
# says so. -Recurse applies the same test to everything below, which also rules out a reparse point
# planted anywhere in the tree.
function Assert-ProtectedPath {
    param([Parameter(Mandatory)][string]$Path, [switch]$Recurse, [switch]$AllowVirtualMachines)
    $items = New-Object System.Collections.Generic.List[string]
    $items.Add([IO.Path]::GetFullPath($Path))
    if ($Recurse -and ([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::Directory)) {
        # By hand, one level at a time: Windows PowerShell 5.1 Get-ChildItem -Recurse follows junctions,
        # and a cyclic one would never end. A reparse point is refused, never entered.
        $pending = New-Object System.Collections.Generic.Stack[string]
        $pending.Push($items[0])
        while ($pending.Count -gt 0) {
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
                $attributes = [IO.File]::GetAttributes($entry)
                if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point under a protected path: $entry" }
                $items.Add($entry)
                if ($attributes -band [IO.FileAttributes]::Directory) { $pending.Push($entry) }
            }
        }
    }
    $allowed = @($script:LocalSystem, $script:Administrators)
    if ($AllowVirtualMachines) { $allowed += $script:VirtualMachines }
    foreach ($item in $items) {
        if ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $item" }
        $acl = Get-Acl -LiteralPath $item
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $script:LocalSystem, $script:Administrators) { throw "Not owned by Administrators or SYSTEM ($owner): $item" }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            # S-1-5-83-1-*: the per-VM identity Hyper-V grants on the disks of the VM it runs.
            if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $script:WriteRights) -and
                $sid -notin $allowed -and $sid -notlike 'S-1-5-83-1-*') {
                throw "Writable by $sid ($($rule.FileSystemRights)): $item"
            }
        }
    }
}

# Creates $Path with an administrators-only DACL in one call, so there is no moment at which it
# inherits the parent's permissions; an existing directory must already pass Assert-ProtectedPath.
function New-ProtectedDirectory {
    param([Parameter(Mandatory)][string]$Path, [switch]$UsersRead, [switch]$VirtualMachinesFull)
    if (Test-Path -LiteralPath $Path) {
        Assert-ProtectedPath -Path $Path -AllowVirtualMachines:$VirtualMachinesFull
        return
    }
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { throw "Parent does not exist: $parent" }
    [void][System.IO.Directory]::CreateDirectory($Path, (New-DirectorySecurity -UsersRead $UsersRead.IsPresent -VirtualMachinesFull $VirtualMachinesFull.IsPresent))
    # CreateDirectory returns an existing directory untouched: whoever created it in between wins
    # nothing, because it must now pass the same test.
    Assert-ProtectedPath -Path $Path -AllowVirtualMachines:$VirtualMachinesFull
}

# Throws when $Path, or any directory between $Root and it, is a reparse point.
function Assert-NoReparseBetween([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Path) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $current = [IO.Path]::GetFullPath($Path)
    if (-not $current.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase) -and $current -ne $rootFull) { throw "Outside $rootFull`: $current" }
    while ($current.Length -ge $rootFull.Length) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $current" }
        if ($current -eq $rootFull) { break }
        $current = Split-Path -Parent $current
    }
}

# Copies one file named in advance from a possibly user-writable tree into a protected one. The source
# must be an ordinary file of bounded size with no reparse point on its way from $SourceRoot; the
# destination directory must be protected already.
function Copy-ListedFile {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Relative,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [int64]$MaximumBytes = 2GB
    )
    if ($Relative -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::IsPathRooted($Relative)) { throw "Invalid relative path: $Relative" }
    $source = Join-Path $SourceRoot $Relative
    Assert-NoReparseBetween -Root $SourceRoot -Path $source
    $item = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Expected a file: $source" }
    if ($item.Length -gt $MaximumBytes) { throw "Too large ($($item.Length) bytes): $source" }
    $destination = Join-Path $DestinationRoot $Relative
    $directory = Split-Path -Parent $destination
    $relativeDirectory = Split-Path -Parent $Relative
    if ($relativeDirectory) {
        $built = $DestinationRoot
        foreach ($part in ($relativeDirectory -split '[\\/]')) {
            $built = Join-Path $built $part
            if (-not (Test-Path -LiteralPath $built)) { [void](New-Item -ItemType Directory -Path $built) }
        }
    }
    Assert-NoReparseBetween -Root $DestinationRoot -Path $directory
    if (Test-Path -LiteralPath $destination) { throw "Already staged: $destination" }
    $reader = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $writer = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $reader.CopyTo($writer) } finally { $writer.Dispose() }
    }
    finally { $reader.Dispose() }
}

# The git blob id of a file's bytes: what `git rev-parse <commit>:<path>` prints for the same content,
# so a copy can be bound to a reviewed commit without running git elevated.
function Get-GitBlobId([Parameter(Mandatory)][string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $header = [Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
    $sha1 = [Security.Cryptography.SHA1]::Create()
    try {
        [void]$sha1.TransformBlock($header, 0, $header.Length, $null, 0)
        [void]$sha1.TransformFinalBlock($bytes, 0, $bytes.Length)
        return ([BitConverter]::ToString($sha1.Hash) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha1.Dispose() }
}

# "SHA256  gitblob  relative" for every file under $Root, sorted: what a verifier compares.
function Get-FileManifest([Parameter(Mandatory)][string]$Root) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
        '{0}  {1}  {2}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash, (Get-GitBlobId $_.FullName), $_.FullName.Substring($rootFull.Length + 1)
    }
}

# Mounts the WINSIGHTQ data disk on the host and returns its drive letter.
function Mount-WinSightData([Parameter(Mandatory)][string]$Path) {
    $disk = Mount-VHD -Path $Path -Passthru | Get-Disk
    $partition = Get-Partition -DiskNumber $disk.Number | Where-Object Type -eq 'Basic' | Select-Object -First 1
    if (-not $partition) { Dismount-VHD -Path $Path; throw "No data partition on $Path." }
    if (-not $partition.DriveLetter) {
        $partition | Add-PartitionAccessPath -AssignDriveLetter
        $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber
    }
    $volume = Get-Volume -Partition $partition
    if ($volume.FileSystemLabel -ne 'WINSIGHTQ') { Dismount-VHD -Path $Path; throw "Unexpected volume label '$($volume.FileSystemLabel)' on $Path." }
    return [string]$partition.DriveLetter
}

function Dismount-WinSightData([Parameter(Mandatory)][string]$Path) {
    Dismount-VHD -Path $Path
}

# Empties a mounted WINSIGHTQ volume by formatting it. What is on it was written by the guest, which
# runs the candidate as an administrator: deleting it file by file would walk links the guest planted,
# and Windows PowerShell 5.1 would follow a junction out of the volume and into the host.
function Clear-WinSightDataVolume([Parameter(Mandatory)][string]$Letter) {
    $volume = Get-Volume -DriveLetter $Letter
    if ($volume.FileSystemLabel -ne 'WINSIGHTQ') { throw "Refusing to format ${Letter}: (label '$($volume.FileSystemLabel)')." }
    Format-Volume -DriveLetter $Letter -FileSystem NTFS -NewFileSystemLabel 'WINSIGHTQ' -Confirm:$false -Force | Out-Null
}

# Copies what the guest left in $From into $To (a protected directory this run created): ordinary files
# only, never through a reparse point, within a bound. What is refused is listed, not followed.
function Copy-GuestResults {
    param([Parameter(Mandatory)][string]$From, [Parameter(Mandatory)][string]$To,
        [int]$MaximumFiles = 20000, [int64]$MaximumBytes = 4GB)
    $refused = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $From)) { return @() }
    if ([IO.File]::GetAttributes($From) -band [IO.FileAttributes]::ReparsePoint) { return @("$From (reparse point)") }
    $fromFull = [IO.Path]::GetFullPath($From).TrimEnd('\')
    $files = 0
    $bytes = [int64]0
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($fromFull)
    while ($pending.Count -gt 0) {
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($pending.Pop())) {
            $relative = $entry.Substring($fromFull.Length + 1)
            $attributes = [IO.File]::GetAttributes($entry)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) { $refused.Add("$relative (reparse point)"); continue }
            $destination = Join-Path $To $relative
            if ($attributes -band [IO.FileAttributes]::Directory) {
                [void](New-Item -ItemType Directory -Path $destination)
                $pending.Push($entry)
                continue
            }
            $length = (New-Object IO.FileInfo $entry).Length
            if (++$files -gt $MaximumFiles -or ($bytes += $length) -gt $MaximumBytes) { $refused.Add("$relative (over the collection bound)"); continue }
            [IO.File]::Copy($entry, $destination, $false)
        }
    }
    return $refused.ToArray()
}

function Get-WinSightVmState([Parameter(Mandatory)][string]$Name) {
    (Get-VM -Name $Name -ErrorAction Stop).State.ToString()
}

Export-ModuleMember -Function Assert-ProtectedPath, New-ProtectedDirectory, Assert-NoReparseBetween, Copy-ListedFile,
    Get-GitBlobId, Get-FileManifest, Mount-WinSightData, Dismount-WinSightData, Clear-WinSightDataVolume,
    Copy-GuestResults, Get-WinSightVmState
