# Shared helpers for the Hyper-V qualification scripts (HOST, elevated), Windows PowerShell 5.1.
#
# RA-01. The first harness kept its scripts, the staged candidate, the VM disks and the evidence at the
# root of a data volume, where Authenticated Users have Modify by inheritance, and its elevated runner
# wrote and deleted there. Anything that runs elevated here therefore follows three rules:
#   - it writes only inside a directory it created itself with an administrators-only DACL, or one
#     that Assert-ProtectedPath has just verified;
#   - it reads from user-writable places only an explicit list of files, refusing reparse points;
#   - it never deletes recursively (Windows PowerShell 5.1 Remove-Item -Recurse follows junctions).

$script:Administrators = 'S-1-5-32-544'
$script:LocalSystem = 'S-1-5-18'
# The Windows servicing identity that owns the system folders, more privileged than Administrators.
$script:TrustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:AuthenticatedUsers = 'S-1-5-11'
$script:VirtualMachines = 'S-1-5-83-0'
# CREATOR OWNER: a placeholder that stands, on each new child, for whoever created it.
$script:CreatorOwner = 'S-1-3-0'
# The capability Hyper-V gives its worker process (vmWorkerProcess: S-1-15-3-1024 and the SHA-256 of
# the upper-case name), which it grants on the disks of the VMs it runs, next to the per-VM identity
# (measured on Windows 11 26200: Write on the control VM's data disk). A capability counts only for an
# AppContainer token, and only in the second of its two access checks, after the one on the token's
# user and groups: it never lets a local user write.
$script:VmWorkerProcessCapability = 'S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704'
$script:WriteRights = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteExtendedAttributes, WriteAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
# What lets someone rename or re-permission a directory, and what lets them delete its children.
$script:ReplaceRights = [System.Security.AccessControl.FileSystemRights]'Delete, ChangePermissions, TakeOwnership'
$script:DeleteChildRights = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
# GENERIC_ALL and GENERIC_WRITE, as inheritable entries carry them before they are mapped.
$script:GenericWrite = 0x50000000L

# Whether an access rule grants any of $Rights, counting the generic bits an inheritable entry holds.
function Test-Grants($Rule, [System.Security.AccessControl.FileSystemRights]$Rights) {
    $raw = [int64]$Rule.FileSystemRights -band 0xFFFFFFFFL
    return (($raw -band [int64]$Rights) -ne 0) -or (($raw -band $script:GenericWrite) -ne 0)
}

# Throws unless nobody but an administrator can rename, replace or re-permission a directory between
# the drive root and $Path. Otherwise a protected tree can be swapped for another under the same
# path between two checks - a whole VM storage folder, for instance. A directory can be renamed by
# whoever has DELETE on it or FILE_DELETE_CHILD on its parent, and re-permissioned by its owner or
# whoever has WRITE_DAC or WRITE_OWNER; only entries that apply to the directory itself count.
function Assert-ProtectedAncestors([Parameter(Mandatory)][string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $driveRoot = [IO.Path]::GetPathRoot($full).TrimEnd('\')
    $allowed = @($script:LocalSystem, $script:Administrators, $script:TrustedInstaller)
    $parent = [IO.Path]::GetDirectoryName($full)
    while ($parent) {
        $acl = Get-Acl -LiteralPath $parent
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            $sid = $rule.IdentityReference.Value
            if ($sid -in $allowed) { continue }
            if (Test-Grants $rule $script:DeleteChildRights) { throw "Children of $parent can be deleted or renamed by $sid." }
            if ($parent.TrimEnd('\') -ne $driveRoot -and (Test-Grants $rule $script:ReplaceRights)) { throw "$parent can be renamed or re-permissioned by $sid." }
        }
        if ($parent.TrimEnd('\') -eq $driveRoot) { break }
        if ([IO.File]::GetAttributes($parent) -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $parent" }
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $allowed) { throw "Not owned by Administrators, SYSTEM or TrustedInstaller ($owner): $parent" }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
}

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

# Whether a write grant to $Sid leaves a path protected: SYSTEM, Administrators, the per-VM identity
# Hyper-V grants on the disks of the VM it runs (S-1-5-83-1-*), and CREATOR OWNER, which grants nothing
# itself: on each new child it stands for whoever created it, who needed a create right that only a
# trusted writer can hold here (every other writer is refused). CREATOR GROUP is not trusted: it stands
# for the creator's primary group, an ordinary group. In the VM storage only, also the Virtual Machines
# group and the Hyper-V worker capability.
function Test-TrustedWriter([string]$Sid, [switch]$VirtualMachines) {
    $trusted = @($script:LocalSystem, $script:Administrators, $script:CreatorOwner)
    if ($VirtualMachines) { $trusted += $script:VirtualMachines, $script:VmWorkerProcessCapability }
    return ($Sid -in $trusted) -or ($Sid -like 'S-1-5-83-1-*')
}

# Throws unless $Path is an ordinary directory or file owned by Administrators or SYSTEM that no other
# principal may write, change or delete - except the Hyper-V worker identities where
# -AllowVirtualMachines says so. -Recurse applies the same test to everything below, which also rules
# out a reparse point planted anywhere in the tree. Every refusal is listed, not just the first, so one
# run shows all there is to fix.
function Assert-ProtectedPath {
    param([Parameter(Mandatory)][string]$Path, [switch]$Recurse, [switch]$AllowVirtualMachines, [switch]$AdministratorsOnly)
    # A protected folder under a parent anyone can rename is not protected: the parent goes, and
    # another folder takes its path.
    Assert-ProtectedAncestors -Path $Path
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
    $refusals = @(Get-ProtectionRefusals -Items $items -AllowVirtualMachines:$AllowVirtualMachines)
    if ($AdministratorsOnly) { $refusals += @(Get-ProtectionRefusals -Items $items -AdministratorsOnly) }
    if ($refusals.Count -gt 0) { throw ($refusals -join [Environment]::NewLine) }
}

# Whether $Sid may own something protected: SYSTEM or Administrators; in the VM storage only, also the
# per-VM identity (S-1-5-83-1-*), which owns the differencing disk Hyper-V creates when it restores a
# checkpoint and which already has every right on its own VM's disks.
function Test-TrustedOwner([string]$Sid, [switch]$VirtualMachines) {
    return ($Sid -in $script:LocalSystem, $script:Administrators) -or ($VirtualMachines -and $Sid -like 'S-1-5-83-1-*')
}

# One line per reason $Items are not protected: an owner Test-TrustedOwner does not trust, a write
# grant to a principal Test-TrustedWriter does not trust. A reparse point is refused at once.
function Get-ProtectionRefusals([string[]]$Items, [switch]$AllowVirtualMachines, [switch]$AdministratorsOnly) {
    foreach ($item in $Items) {
        if ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $item" }
        $acl = Get-Acl -LiteralPath $item
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if (-not (Test-TrustedOwner $owner -VirtualMachines:$AllowVirtualMachines)) { "Not owned by Administrators or SYSTEM ($owner): $item" }
        if ($AdministratorsOnly -and $owner -notin $script:LocalSystem,$script:Administrators) { "Private campaign path has a non-administrative owner: $item" }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $rule.IdentityReference.Value
            if ($AdministratorsOnly -and $rule.AccessControlType -eq 'Allow' -and (Test-Grants $rule $script:WriteRights) -and $sid -notin $script:LocalSystem,$script:Administrators) { "Private campaign path is writable outside Administrators/SYSTEM: $item" }
            # Entries that only children inherit count too: they would make the next file written here
            # writable.
            if ($rule.AccessControlType -eq 'Allow' -and (Test-Grants $rule $script:WriteRights) -and
                -not (Test-TrustedWriter $sid -VirtualMachines:$AllowVirtualMachines)) {
                "Writable by $sid ($($rule.FileSystemRights), $($rule.InheritanceFlags), $($rule.PropagationFlags)): $item"
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

# Retain every source ancestor before reading a user-writable candidate. No managed pathname IO
# precedes the native no-follow walk. Inline C#5 keeps this within the authenticated PS5 bundle.
function Initialize-WinSightSourceAccess {
    if ('WinSightHarness.StagingSourceContext' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace WinSightHarness {
    // Synchronous ownership: dispose file leases before their enclosing source context.
    public sealed class StagingSourceContext : IDisposable {
        private readonly List<SafeFileHandle> ancestors = new List<SafeFileHandle>();
        private bool disposed;
        public string Root { get; private set; }

        public static string NormalizeRelative(string relative) {
            if (String.IsNullOrEmpty(relative) || relative.Length > 2048 || Path.IsPathRooted(relative))
                throw new IOException("Invalid relative path: " + relative);
            string[] parts = relative.Replace('/', '\\').Split('\\');
            if (parts.Length > 128) throw new IOException("Invalid relative path: excessive components.");
            foreach (string part in parts) {
                if (part.Length == 0 || part.Length > 255 || part == "." || part == ".." ||
                    part.TrimEnd('.', ' ') != part || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                    Regex.IsMatch(part, @"^(CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\.|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    throw new IOException("Invalid relative path: " + relative);
            }
            return String.Join("\\", parts);
        }

        public static string NormalizeRoot(string root) {
            if (String.IsNullOrEmpty(root) || root.Length > 2048 || !Regex.IsMatch(root, @"^[A-Za-z]:[\\/]"))
                throw new IOException("Source root must be an absolute ordinary local drive path.");
            string full = root.Replace('/', '\\');
            if (full.Length > 3) {
                string tail = full.Substring(3);
                if (tail.EndsWith("\\", StringComparison.Ordinal)) tail = tail.Substring(0, tail.Length - 1);
                if (tail.Length == 0) throw new IOException("Source root must be an ordinary local drive path.");
                full = full.Substring(0, 3) + NormalizeRelative(tail);
            }
            return Path.GetFullPath(full);
        }

        public StagingSourceContext(string root) {
            Root = NormalizeRoot(root);
            try {
                StringBuilder mapping = new StringBuilder(32768);
                if (QueryDosDeviceW(Root.Substring(0, 2), mapping, mapping.Capacity) == 0)
                    throw NativeError("Query local source volume", Marshal.GetLastWin32Error());
                string volume = mapping.ToString();
                if (!Regex.IsMatch(volume, @"^\\Device\\HarddiskVolume[0-9]+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    throw new IOException("Source root must resolve to a physical local drive volume; aliases and network devices are refused.");
                SafeFileHandle parent = Open(null, volume + "\\", true);
                ancestors.Add(parent);
                if (Root.Length > 3) {
                    foreach (string part in Root.Substring(3).Split('\\')) {
                        parent = Open(parent, part, true);
                        ancestors.Add(parent);
                    }
                }
            }
            catch { Dispose(); throw; }
        }

        public StagingSourceLease OpenFile(string relative, long maximumBytes) {
            if (disposed) throw new ObjectDisposedException("StagingSourceContext");
            if (maximumBytes < 0 || maximumBytes > 2147483648L) throw new ArgumentOutOfRangeException("maximumBytes");
            string normalized = NormalizeRelative(relative);
            string[] parts = normalized.Split('\\');
            List<SafeFileHandle> parents = new List<SafeFileHandle>();
            SafeFileHandle file = null;
            FileStream stream = null;
            try {
                SafeFileHandle parent = ancestors[ancestors.Count - 1];
                for (int i = 0; i < parts.Length - 1; i++) {
                    parent = Open(parent, parts[i], true);
                    parents.Add(parent);
                }
                file = Open(parent, parts[parts.Length - 1], false);
                stream = new FileStream(file, FileAccess.Read, 65536, false);
                file = null; // stream now owns the SafeFileHandle
                long length = stream.Length;
                if (length > maximumBytes) throw new IOException("Too large: opened source exceeds its byte limit.");
                StagingSourceLease lease = new StagingSourceLease(stream, parents, length);
                stream = null;
                return lease;
            }
            catch {
                if (stream != null) stream.Dispose();
                if (file != null) file.Dispose();
                for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose();
                throw;
            }
        }

        public void Dispose() {
            if (disposed) return;
            disposed = true;
            for (int i = ancestors.Count - 1; i >= 0; i--) ancestors[i].Dispose();
        }

        // NtCreateFile RootDirectory is a retained filesystem directory, not a DOS path.
        // https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntcreatefile
        // https://learn.microsoft.com/windows/win32/api/ntdef/ns-ntdef-_object_attributes
        private static SafeFileHandle Open(SafeFileHandle parent, string name, bool directory) {
            bool reference = false;
            IntPtr buffer = IntPtr.Zero, namePointer = IntPtr.Zero;
            SafeFileHandle handle = null;
            try {
                if (parent != null) parent.DangerousAddRef(ref reference);
                buffer = Marshal.StringToHGlobalUni(name);
                UnicodeString unicode = new UnicodeString {
                    Length = checked((ushort)(name.Length * 2)),
                    MaximumLength = checked((ushort)((name.Length + 1) * 2)), Buffer = buffer
                };
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(unicode, namePointer, false);
                ObjectAttributes attributes = new ObjectAttributes {
                    Length = Marshal.SizeOf(typeof(ObjectAttributes)),
                    RootDirectory = parent == null ? IntPtr.Zero : parent.DangerousGetHandle(),
                    ObjectName = namePointer, Attributes = 0x40 | 0x1000 // CASE_INSENSITIVE | DONT_REPARSE
                };
                IoStatusBlock io;
                int status = NtCreateFile(out handle, directory ? 0x1000A0U : 0x100081U,
                    ref attributes, out io, IntPtr.Zero, 0, directory ? 3U : 1U, 1,
                    0x200020U | (directory ? 1U : 0x40U), IntPtr.Zero, 0);
                if (status < 0 || handle == null || handle.IsInvalid) {
                    if (unchecked((uint)status) == 0xC000050BU) throw new IOException("Reparse point refused in source path.");
                    throw NativeError("Open source component", status < 0 ? unchecked((int)RtlNtStatusToDosError(status)) : 6);
                }
                ByHandleFileInformation info;
                if (!GetFileInformationByHandle(handle, out info)) throw NativeError("Inspect acquired source", Marshal.GetLastWin32Error());
                if ((info.FileAttributes & 0x400) != 0) throw new IOException("Reparse point refused in source path.");
                if (((info.FileAttributes & 0x10) != 0) != directory) throw new IOException("Source component has an unexpected file type.");
                if (!directory && info.NumberOfLinks != 1) throw new IOException("Source hardlink refused; expected a single-link ordinary file.");
                SafeFileHandle result = handle;
                handle = null;
                return result;
            }
            finally {
                if (handle != null) handle.Dispose();
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if (reference) parent.DangerousRelease();
            }
        }

        private static IOException NativeError(string operation, int error) {
            return new IOException(operation + " failed (Win32 " + error + ").", new Win32Exception(error));
        }
        [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] private struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [StructLayout(LayoutKind.Sequential)] private struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
        [StructLayout(LayoutKind.Sequential)] private struct ByHandleFileInformation {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime;
            public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint QueryDosDeviceW(string device, StringBuilder target, int length);
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int NtCreateFile(out SafeFileHandle file, uint access, ref ObjectAttributes attributes, out IoStatusBlock io,
            IntPtr allocation, uint fileAttributes, uint sharing, uint disposition, uint options, IntPtr ea, uint eaLength);
        [DllImport("ntdll.dll", ExactSpelling = true)] private static extern uint RtlNtStatusToDosError(int status);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle file, out ByHandleFileInformation info);
    }

    public sealed class StagingSourceLease : IDisposable {
        private readonly List<SafeFileHandle> parents;
        public FileStream Stream { get; private set; }
        public long Length { get; private set; }
        internal StagingSourceLease(FileStream stream, List<SafeFileHandle> retainedParents, long length) { Stream = stream; parents = retainedParents; Length = length; }
        public void CopyExactlyTo(Stream destination) {
            if (Stream == null) throw new ObjectDisposedException("StagingSourceLease");
            long remaining = Length;
            byte[] buffer = new byte[65536];
            while (remaining > 0) {
                int read = Stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (read == 0) throw new IOException("Acquired source ended before its captured length.");
                destination.Write(buffer, 0, read);
                remaining -= read;
            }
            if (Stream.ReadByte() != -1) throw new IOException("Acquired source grew beyond its captured length.");
        }
        public void Dispose() {
            if (Stream == null) return;
            try { Stream.Dispose(); }
            finally { Stream = null; for (int i = parents.Count - 1; i >= 0; i--) parents[i].Dispose(); }
        }
    }
}
'@
}

function New-WinSightSourceContext([Parameter(Mandatory)][string]$SourceRoot) {
    Initialize-WinSightSourceAccess
    return [WinSightHarness.StagingSourceContext]::new($SourceRoot)
}

# Copies acquired bytes only; the caller owns/protects the destination root. A shared context pins
# the source namespace throughout a complete stage, while each file lease pins its subdirectories.
function Copy-ListedFile {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Relative,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [int64]$MaximumBytes = 2GB,
        $SourceContext
    )
    Initialize-WinSightSourceAccess
    $Relative = [WinSightHarness.StagingSourceContext]::NormalizeRelative($Relative)
    $ownedContext = $null; $lease = $null
    try {
    if ($null -eq $SourceContext) { $ownedContext = New-WinSightSourceContext -SourceRoot $SourceRoot; $SourceContext = $ownedContext }
    if ($SourceContext -isnot [WinSightHarness.StagingSourceContext] -or
        $SourceContext.Root -ine [WinSightHarness.StagingSourceContext]::NormalizeRoot($SourceRoot)) { throw 'Source context does not match its declared root.' }
    $lease = $SourceContext.OpenFile($Relative, $MaximumBytes)
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
    $writer = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $lease.CopyExactlyTo($writer); $writer.Flush($true) } finally { $writer.Dispose() }
    }
    finally { try { if ($lease) { $lease.Dispose() } } finally { if ($ownedContext) { $ownedContext.Dispose() } } }
}

# The git blob id of a file's bytes: what `git rev-parse <commit>:<path>` prints for the same content,
# so a copy can be bound to a reviewed commit without running git elevated.
# SHA-256 of a file another process may hold open, as the Hyper-V management service holds the
# configuration of its VMs even while they are off: read through every sharing mode, so an existing
# writer does not make the open fail. $null when the holder allows no sharing or has locked what is
# read, for the caller to name the file rather than guess; any other failure throws.
function Get-SharedFileHash([Parameter(Mandatory)][string]$Path) {
    $stream = $null
    try {
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]'ReadWrite, Delete'))
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '') } finally { $sha.Dispose() }
    }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        # ERROR_SHARING_VIOLATION (32) or ERROR_LOCK_VIOLATION (33).
        if ($inner -is [System.IO.IOException] -and ($inner.HResult -band 0xFFFF) -in 32, 33) { return $null }
        throw
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

# On client Windows an elevated process creates files owned by the operator's own account (the
# "Object creator" default), and an owner may always re-permission: any process running as the
# operator could then change a protected copy or the sealed evidence. Every elevated script calls
# Set-AdministratorsDefaultOwner before it creates anything, so what it and the processes it starts
# create is owned by Administrators. Windows allows that default owner only to an elevated token.
function Set-DefaultOwner([Parameter(Mandatory)][string]$Sid) {
    if (-not ('WinSightHarness.TokenOwner' -as [type])) {
        Add-Type -Namespace WinSightHarness -Name TokenOwner -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
private static extern System.IntPtr GetCurrentProcess();
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
private static extern bool OpenProcessToken(System.IntPtr process, uint access, out System.IntPtr token);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
private static extern bool SetTokenInformation(System.IntPtr token, int informationClass, ref System.IntPtr owner, int length);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
private static extern bool CloseHandle(System.IntPtr handle);
// TOKEN_OWNER holds a single pointer to the owner SID; 4 is TokenOwner, 0x80 TOKEN_ADJUST_DEFAULT.
public static int Set(byte[] sid) {
    System.Runtime.InteropServices.GCHandle pinned = System.Runtime.InteropServices.GCHandle.Alloc(sid, System.Runtime.InteropServices.GCHandleType.Pinned);
    System.IntPtr token = System.IntPtr.Zero;
    try {
        if (!OpenProcessToken(GetCurrentProcess(), 0x80, out token)) { return System.Runtime.InteropServices.Marshal.GetLastWin32Error(); }
        System.IntPtr owner = pinned.AddrOfPinnedObject();
        if (!SetTokenInformation(token, 4, ref owner, System.IntPtr.Size)) { return System.Runtime.InteropServices.Marshal.GetLastWin32Error(); }
        return 0;
    }
    finally {
        if (token != System.IntPtr.Zero) { CloseHandle(token); }
        pinned.Free();
    }
}
'@
    }
    $identifier = New-Object System.Security.Principal.SecurityIdentifier $Sid
    $bytes = New-Object byte[] $identifier.BinaryLength
    $identifier.GetBinaryForm($bytes, 0)
    $code = [WinSightHarness.TokenOwner]::Set($bytes)
    if ($code -ne 0) { throw "$Sid could not be made the default owner of new files (Win32 error $code)." }
}

function Set-AdministratorsDefaultOwner { Set-DefaultOwner -Sid $script:Administrators }

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
    $mounted = $false
    try {
    $vhd = Mount-VHD -Path $Path -Passthru
    $mounted = $true
    $disk = $vhd | Get-Disk
    $partition = Get-Partition -DiskNumber $disk.Number | Where-Object Type -eq 'Basic' | Select-Object -First 1
    if (-not $partition) { throw 'No data partition on the qualification disk.' }
    if (-not $partition.DriveLetter) {
        $partition | Add-PartitionAccessPath -AssignDriveLetter
        $partition = Get-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber
    }
    $volume = Get-Volume -Partition $partition
    if ($volume.FileSystemLabel -ne 'WINSIGHTQ') { throw 'Unexpected qualification data volume label.' }
    return [string]$partition.DriveLetter
    }
    catch {
        $failure = $_
        if ($mounted) { try { Dismount-VHD -Path $Path } catch { Write-WinSightDiagnostic ('Partial data-disk mount cleanup failed; original error retained: ' + $_.Exception.Message) } }
        throw $failure
    }
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
        [ValidateRange(1,20000)][int]$MaximumFiles = 20000, [int64]$MaximumBytes = 4GB,
        [ValidateRange(1,40000)][int]$MaximumEntries = 40000, [ValidateRange(1,64)][int]$MaximumDepth = 64,
        [switch]$Resume)
    if ($MaximumBytes -lt 1 -or $MaximumBytes -gt 4GB) { throw 'Invalid collection byte limit.' }
    $refused = New-Object Collections.Generic.List[string]
    # The guest controls the entire offline volume, including candidate's ancestors. Inspect
    # from its volume root BEFORE resolving/reading a descendant through a junction or mount point.
    $fromFull = [IO.Path]::GetFullPath($From).TrimEnd('\')
    $volumeRoot = [IO.Path]::GetPathRoot($fromFull)
    $current = $volumeRoot
    if ([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) { return @('Guest result volume root is a reparse point.') }
    foreach ($part in $fromFull.Substring($volumeRoot.Length).Split('\')) {
        if (-not $part) { continue }
        $current = [IO.Path]::Combine($current,$part)
        try { $attributes = [IO.File]::GetAttributes($current) }
        catch [IO.FileNotFoundException] { return @() }
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return @('Guest result ancestry is a reparse point; no descendant read.') }
        if (-not ($attributes -band [IO.FileAttributes]::Directory)) { throw 'Guest result ancestry is not an ordinary directory.' }
    }
    $attributes = [IO.File]::GetAttributes($From)
    if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return @('Guest result root is a reparse point.') }
    if (-not ($attributes -band [IO.FileAttributes]::Directory)) { throw 'Guest result root is not an ordinary directory.' }
    $fromFull = [IO.Path]::GetFullPath($From).TrimEnd('\')
    $files = 0; $bytes = [int64]0; $examined = 0; $stopped = $false
    $pending = New-Object Collections.Stack
    $pending.Push([pscustomobject]@{ path = $fromFull; depth = 0 })
    while ($pending.Count -gt 0 -and -not $stopped) {
        $directory = $pending.Pop()
        $iterator = [IO.Directory]::EnumerateFileSystemEntries($directory.path).GetEnumerator()
        try {
            while ($iterator.MoveNext()) {
                if ($examined -ge $MaximumEntries -or $refused.Count -ge 128) {
                    $refused.Add('Collection limit reached; remaining entries were not examined.'); $stopped = $true; break
                }
                $examined++
                $entry = $iterator.Current
                $relative = $entry.Substring($fromFull.Length + 1)
                $display = if ($relative.Length -gt 512) { $relative.Substring(0,512) + '...' } else { $relative }
                $attributes = [IO.File]::GetAttributes($entry)
                if ($attributes -band [IO.FileAttributes]::ReparsePoint) { $refused.Add("$display (reparse point)"); continue }
                $destination = Join-Path $To $relative
                if ($attributes -band [IO.FileAttributes]::Directory) {
                    if ($directory.depth -ge $MaximumDepth) { $refused.Add("$display (directory depth limit)"); continue }
                    if ($Resume -and (Test-Path -LiteralPath $destination)) {
                        $existing = [IO.File]::GetAttributes($destination)
                        if (-not ($existing -band [IO.FileAttributes]::Directory) -or ($existing -band [IO.FileAttributes]::ReparsePoint)) { throw 'Existing collection directory is not an ordinary directory.' }
                    }
                    else { [void](New-Item -ItemType Directory -Path $destination) }
                    $pending.Push([pscustomobject]@{ path = $entry; depth = $directory.depth + 1 })
                    continue
                }
                $reader = [IO.File]::Open($entry,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                try {
                    $length = $reader.Length
                    if ($files -ge $MaximumFiles -or $length -gt ($MaximumBytes - $bytes)) {
                        $refused.Add("$display (over the collection file/byte limit)"); $refused.Add('Collection limit reached; remaining entries were not examined.'); $stopped = $true; break
                    }
                    $files++; $bytes += $length
                    if ($Resume -and (Test-Path -LiteralPath $destination)) {
                        $existing = [IO.File]::GetAttributes($destination)
                        if ($existing -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Existing collection file is not an ordinary file.' }
                        $sha = [Security.Cryptography.SHA256]::Create()
                        try { $sourceHash = [Convert]::ToBase64String($sha.ComputeHash($reader)) } finally { $sha.Dispose() }
                        $destinationHash = Get-SharedFileHash -Path $destination
                        $sourceHex = [BitConverter]::ToString([Convert]::FromBase64String($sourceHash)).Replace('-','')
                        if ((New-Object IO.FileInfo $destination).Length -ne $length -or -not $destinationHash -or $sourceHex -cne $destinationHash) { throw 'Existing collection evidence differs; preserve it and use an isolated collection attempt.' }
                    }
                    else {
                        $writer = [IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
                        try { $reader.CopyTo($writer); $writer.Flush($true) } finally { $writer.Dispose() }
                    }
                }
                finally { $reader.Dispose() }
            }
        }
        finally { $iterator.Dispose() }
    }
    return $refused.ToArray()
}

# Diagnostics never become control flow, even when both the disk and stderr fail.
function Write-WinSightDiagnostic([string]$Message) {
    try { [Console]::Error.WriteLine($Message) } catch { }
}

function Write-WinSightDriverHeartbeat([AllowEmptyString()][string]$Path, [ValidateSet('initializing','staging','starting','observing','waiting','collecting','restoring','finished')][string]$Phase) {
    if (-not $Path) { return }
    try { Write-SharedText -Path $Path -Text ([ordered]@{ processId = $PID; heartbeatUtc = [DateTime]::UtcNow.ToString('o'); phase = $Phase } | ConvertTo-Json -Compress) }
    catch { Write-WinSightDiagnostic 'Driver heartbeat unavailable; recovery continues and runner status reports missing or stale child progress.' }
}

function Read-WinSightDriverHeartbeat([string]$Path, [int]$ExpectedProcessId) {
    try {
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($file.Length -gt 4096 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $null }
        $value = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($value.processId -ne $ExpectedProcessId -or $value.phase -notin 'initializing','staging','starting','observing','waiting','collecting','restoring','finished') { return $null }
        $utc = [DateTime]::Parse($value.heartbeatUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $seconds = ([DateTime]::UtcNow - $utc).TotalSeconds
        if ($seconds -lt -30) { return $null }
        return [pscustomobject]@{ processId = $value.processId; heartbeatUtc = $utc.ToString('o'); phase = $value.phase; ageSeconds = [math]::Max(0, [math]::Round($seconds, 1)) }
    }
    catch { return $null }
}

function Get-WinSightVmState([Parameter(Mandatory)][string]$Name) {
    (Get-VM -Name $Name -ErrorAction Stop).State.ToString()
}

# Detaches the data disk $Path from $VMName once the VM is really off. Returns the state the VM was
# found in when it had to be turned off first, and nothing otherwise. Hyper-V refused the detach a second
# after a guest had shut itself down ("the operation cannot be performed while the object is in its
# current state"), so it is retried; and a VM found running again after its run - whoever started it -
# is turned off, since a guest started again can only overwrite the results this disk carries.
function Remove-WinSightDataDisk([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Path, [int]$Attempts = 30) {
    $found = $null
    for ($attempt = 1; ; $attempt++) {
        # The queries are retried too: this runs right after a checkpoint restore, while Hyper-V can
        # answer "object not found" for a moment (see Invoke-WinSightVmRetry).
        try {
            $state = Get-WinSightVmState $VMName
            if ($state -ne 'Off') {
                if (-not $found) { $found = $state }
                Stop-VM -Name $VMName -TurnOff -Force
                if ((Get-WinSightVmState $VMName) -ne 'Off') { throw 'VM stop was not confirmed; data-disk access refused.' }
            }
            $drives = @(Get-VMHardDiskDrive -VMName $VMName | Where-Object Path -eq $Path)
            if ($drives.Count -eq 0) { return $found }
            $drives | Remove-VMHardDiskDrive -ErrorAction Stop
            return $found
        }
        catch {
            if ($attempt -ge $Attempts) { throw }
            Start-Sleep -Seconds 10
        }
    }
}

# Runs $Action until it succeeds, for up to $Seconds, then fails with its last error. Right after
# Restore-VMCheckpoint, Hyper-V rebuilds the VM's objects and a query of the VM can fail for a moment
# ("the object was not found; it may have been deleted"): seen after a network run whose evidence was
# already sealed.
function Invoke-WinSightVmRetry([scriptblock]$Action, [int]$Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        try { return & $Action }
        catch {
            if ((Get-Date) -ge $deadline) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

# Writes a file that people may be reading while the harness runs: the runner's log, status and
# processed list, the host operations log. Windows PowerShell 5.1 Add-Content and Set-Content fail
# while any other process holds the file open for reading, even one that shares writing (measured):
# an operator following the log stopped the runner. The file is opened with read and write sharing,
# and a sharing violation from another writer is retried for five seconds. UTF-8, no BOM.
function Write-SharedText([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text, [switch]$Append) {
    $mode = if ($Append) { [IO.FileMode]::Append } else { [IO.FileMode]::Create }
    $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($Text)
    for ($attempt = 1; ; $attempt++) {
        try {
            $stream = New-Object IO.FileStream($Path, $mode, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
            return
        }
        catch {
            if ($attempt -ge 20) { throw }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Add-SharedLine([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Line) {
    Write-SharedText -Path $Path -Text ($Line + "`r`n") -Append
}

# Refuses a run whose VMs the host cannot hold: $Bytes is what they need, margin included, compared with
# the memory Windows can hand out now (free and standby pages). Hyper-V gives a VM all its memory at
# start and fails the start otherwise.
function Assert-WinSightHostMemory([int64]$Bytes, [string]$Advice) {
    $available = [int64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
    if ($available -lt $Bytes) {
        throw ("This run needs {0:N1} GB of memory and the host has {1:N1} GB available: {2}" -f ($Bytes / 1GB), ($available / 1GB), $Advice)
    }
}

function Assert-WinSightJsonMembers([string]$Raw) {
    # PS5 ConvertFrom-Json keeps the last physical member. Inspect the Framework JSON reader's
    # uncollapsed object members first, including decoded escaped names, with bounded depth/size.
    Add-Type -AssemblyName System.Runtime.Serialization
    $quotas = New-Object Xml.XmlDictionaryReaderQuotas
    $quotas.MaxDepth = 64
    $quotas.MaxStringContentLength = 16MB
    $quotas.MaxNameTableCharCount = 16MB
    $quotas.MaxArrayLength = 16MB
    $bytes = [Text.Encoding]::UTF8.GetBytes($Raw)
    if ($bytes.Length -gt 16MB) { throw 'Collected network result exceeds its UTF8 byte bound; campaign preserved.' }
    $reader = [Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes, $quotas)
    $frames = New-Object Collections.Stack
    try {
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if ($frames.Count -gt 0 -and $frames.Peek().kind -ceq 'object') {
                    # Escaped/non-XML names use the item attribute; ordinary LocalName is already
                    # the original JSON name. XmlConvert.DecodeName would corrupt literal _xNNNN_.
                    $key = $reader.GetAttribute('item')
                    if ($null -eq $key) { $key = $reader.LocalName }
                    if (-not $frames.Peek().keys.Add($key)) { throw 'Collected network result has duplicate decoded object members; campaign preserved.' }
                }
                if (-not $reader.IsEmptyElement) {
                    $keys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    if ($null -ne $reader.GetAttribute('__type')) { [void]$keys.Add('__type') }
                    $frames.Push([pscustomobject]@{ kind = $reader.GetAttribute('type'); keys = $keys })
                }
            }
            elseif ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) { [void]$frames.Pop() }
        }
    }
    finally { $reader.Dispose() }
}

# Shared completion rules consume the exact guest-produced UTC strings under Windows PS5.
function Test-WinSightCompletion($Result) {
    if ($null -eq $Result -or $Result.startedUtc -isnot [string] -or $Result.finishedUtc -isnot [string]) { return $false }
    if ($Result.startedUtc -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$' -or
        $Result.finishedUtc -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$') { return $false }
    $start = [DateTimeOffset]::MinValue; $finish = [DateTimeOffset]::MinValue
    $style = [Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [DateTimeOffset]::TryParse($Result.startedUtc,[Globalization.CultureInfo]::InvariantCulture,$style,[ref]$start) -or
        -not [DateTimeOffset]::TryParse($Result.finishedUtc,[Globalization.CultureInfo]::InvariantCulture,$style,[ref]$finish)) { return $false }
    return $finish -ge $start
}

function Get-WinSightQualificationStatus($Result, [string[]]$ExpectedGates) {
    if ($null -eq $Result -or $Result.gates -isnot [pscustomobject]) { return 'NOT_RUN' }
    $incomplete = -not (Test-WinSightCompletion $Result)
    foreach ($name in $ExpectedGates) {
        $gate = $Result.gates.PSObject.Properties[$name]
        if ($gate -and $gate.Name -cne $name) { $incomplete = $true; continue }
        if ($null -eq $gate -or $gate.Value -isnot [pscustomobject]) { $incomplete = $true; continue }
        if ($gate.Value.status -is [string] -and $gate.Value.status -ceq 'FAIL') { return 'FAIL' }
        if ($gate.Value.status -isnot [string] -or $gate.Value.status -cne 'PASS') { $incomplete = $true }
    }
    foreach ($entry in $Result.gates.PSObject.Properties) { if ($entry.Value -isnot [pscustomobject] -or $entry.Value.status -isnot [string] -or $entry.Value.status -cnotin 'PASS','FAIL','NOT_RUN') { $incomplete = $true } }
    if ($ExpectedGates.Count -eq 0 -or $incomplete) { return 'NOT_RUN' }
    return 'PASS'
}

function Get-WinSightQualificationExitCode($Result, [string]$Commit, [string]$RunId, [string[]]$ExpectedGates, [bool]$TimedOut, [int]$RefusedCount) {
    if ($null -eq $Result) { return 2 }
    if ($Result.candidate -isnot [pscustomobject] -or $Result.candidate.commit -isnot [string] -or
        $Result.candidate.commit -cne $Commit -or $Result.candidate.qualificationRunId -isnot [string] -or
        $Result.candidate.qualificationRunId -cne $RunId -or $TimedOut -or $RefusedCount -ne 0 -or
        (Get-WinSightQualificationStatus $Result $ExpectedGates) -cne 'PASS') { return 1 }
    return 0
}

function Get-WinSightTextDigest([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

# Callers hold the exclusive campaign lease for every read/replace. Existing unknown state is never
# overwritten. A private CreateNew temporary is flushed, then published atomically on the same volume.
function Write-WinSightAtomicText([string]$Path, [string]$Text, [switch]$Replace, [int]$MaximumBytes = 8192) {
    $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($Text)
    if ($bytes.Length -gt $MaximumBytes) { throw 'Campaign publication exceeds its byte bound.' }
    $temp = [IO.Path]::Combine([IO.Path]::GetDirectoryName($Path),('.campaign-'+[guid]::NewGuid().ToString('N')+'.tmp'))
    $owned = $false; $stream = $null
    try {
        $stream = [IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
        $owned = $true
        $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true); $stream.Dispose(); $stream = $null
        if ($Replace) { [IO.File]::Replace($temp,$Path,[NullString]::Value) } else { [IO.File]::Move($temp,$Path) }
        $owned = $false
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($owned) { try { [IO.File]::Delete($temp) } catch { Write-WinSightDiagnostic 'Owned campaign publication temporary could not be removed.' } }
    }
}

function Write-WinSightImmutableText([string]$Path, [string]$Text, [int]$MaximumBytes = 8192) {
    try { $existing = Read-WinSightBoundedText -Path $Path -MaximumBytes $MaximumBytes }
    catch [IO.FileNotFoundException] {
        try { Write-WinSightAtomicText -Path $Path -Text $Text -MaximumBytes $MaximumBytes; return }
        catch [IO.IOException] { $existing = Read-WinSightBoundedText -Path $Path -MaximumBytes $MaximumBytes }
    }
    if ($existing -cne $Text) { throw 'Existing immutable receipt differs; preserve it and the Active campaign.' }
}

function Read-WinSightBoundedText([string]$Path, [int]$MaximumBytes = 8192) {
    $attributes = [IO.File]::GetAttributes($Path)
    if ($attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Campaign metadata is not an ordinary file.' }
    Assert-ProtectedPath -Path $Path -AdministratorsOnly
    $stream = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $MaximumBytes) { throw 'Campaign metadata exceeds its byte bound or is empty.' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) { $read = $stream.Read($bytes,$offset,$bytes.Length-$offset); if ($read -eq 0) { throw 'Campaign metadata ended unexpectedly.' }; $offset += $read }
        return [Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    }
    finally { $stream.Dispose() }
}

function Read-WinSightCampaignState([string]$Root) {
    $path = [IO.Path]::Combine($Root,'host-campaign','state.json')
    $raw = Read-WinSightBoundedText $path
    Assert-WinSightJsonMembers $raw
    if (-not $raw.TrimStart().StartsWith('{')) { throw 'Campaign state root is unrecognized.' }
    $value = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($value -isnot [pscustomobject] -or $value.version -isnot [int] -or $value.version -ne 1 -or
        $value.root -cne [IO.Path]::GetFullPath($Root).TrimEnd('\').ToUpperInvariant() -or
        $value.status -cnotin 'Idle','Active','Closed') { throw 'Unknown or foreign campaign state; owner recovery is required.' }
    $keys = @('version','root','status','runId','contract','contractDigest','stage','deadlineUtc','timedOut','observationIncomplete','sealDigest','resources')
    foreach ($property in $value.PSObject.Properties) { if ($property.Name -cnotin $keys) { throw 'Unknown campaign state field; owner recovery is required.' } }
    if ($value.status -ceq 'Idle' -and @($value.PSObject.Properties).Count -ne 3) { throw 'Idle campaign state contains unexpected lifecycle data.' }
    if ($value.status -ceq 'Closed' -and ($value.sealDigest -isnot [string] -or $value.sealDigest -cnotmatch '^[0-9a-f]{64}$' -or $value.stage -cne 'recovered')) { throw 'Closed campaign lacks its recognized recovery seal.' }
    if ($value.status -cne 'Idle') {
        if (@($value.PSObject.Properties).Count -ne $keys.Count) { throw 'Campaign lifecycle state is incomplete.' }
        if ($null -ne $value.deadlineUtc) {
            $parsedDeadline = [DateTime]::MinValue
            if ($value.deadlineUtc -isnot [string] -or $value.deadlineUtc -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z$' -or -not [DateTime]::TryParseExact($value.deadlineUtc,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$parsedDeadline)) { throw 'Campaign deadline is unrecognized.' }
        }
        elseif ($value.status -ceq 'Active' -and $value.stage -cne 'staging' -and $value.contract.kind -cin 'qualification','network') { throw 'Started campaign has no original deadline.' }
        if ($null -ne $value.resources -and ($value.resources -isnot [pscustomobject] -or @($value.resources.PSObject.Properties).Count -ne 1 -or ($value.resources.memory -isnot [long] -and $value.resources.memory -isnot [int]) -or $value.resources.memory -le 0)) { throw 'Campaign resource baseline is unrecognized.' }

        if ($value.runId -isnot [string] -or $value.runId -cnotmatch '^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$' -or
            $value.contract -isnot [pscustomobject] -or $value.contractDigest -isnot [string] -or
            $value.contractDigest -cne (Get-WinSightTextDigest ($value.contract|ConvertTo-Json -Depth 12 -Compress)) -or
            $value.stage -cnotin 'staging','starting','collecting','recovered' -or
            $value.timedOut -isnot [bool] -or $value.observationIncomplete -isnot [bool]) { throw 'Campaign state identity or lifecycle is unrecognized.' }
    }
    return $value
}

function Open-WinSightCampaignLease([string]$Root) {
    $directory = [IO.Path]::Combine([IO.Path]::GetFullPath($Root),'host-campaign')
    # Never create or adopt ownership implicitly. Only the reviewed explicit owner initializer may.
    Assert-ProtectedPath -Path $directory -AdministratorsOnly
    $marker = [IO.Path]::Combine($directory,'initialized.txt')
    if ((Read-WinSightBoundedText $marker) -cne 'WinSight campaign ownership v1') { throw 'Campaign ownership marker is unknown.' }
    $path = [IO.Path]::Combine($directory,'campaign.lock')
    try {
        $attr = [IO.File]::GetAttributes($path)
        if ($attr -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Campaign lease is not an ordinary file.' }
        Assert-ProtectedPath -Path $path -AdministratorsOnly
    }
    catch [IO.FileNotFoundException] { }
    return [IO.FileStream]::new($path,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}

function Initialize-WinSightCampaignOwnership([string]$Root, [string[]]$VmNames = @()) {
    Assert-ProtectedPath -Path $Root -AllowVirtualMachines
    $directory = [IO.Path]::Combine([IO.Path]::GetFullPath($Root),'host-campaign')
    New-ProtectedDirectory -Path $directory
    Assert-ProtectedPath -Path $directory -AdministratorsOnly
    $lockPath = [IO.Path]::Combine($directory,'campaign.lock')
    try {
        $lockAttributes = [IO.File]::GetAttributes($lockPath)
        if ($lockAttributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Existing initializer lease is not an ordinary file.' }
        Assert-ProtectedPath -Path $lockPath -AdministratorsOnly
    }
    catch [IO.FileNotFoundException] { }
    $handle = [IO.FileStream]::new($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        foreach ($existing in 'state.json','migration.txt','initialized.txt') {
            try { [void][IO.File]::GetAttributes([IO.Path]::Combine($directory,$existing)); throw 'Ownership or partial migration already exists; explicit owner recovery is required.' }
            catch [IO.FileNotFoundException] { }
        }
        # The CreateNew marker precedes all migration. A crash leaves an explicit partial setup,
        # never permission to silently adopt disks or reset an existing Active/corrupt campaign.
        Write-WinSightAtomicText -Path ([IO.Path]::Combine($directory,'initialized.txt')) -Text 'WinSight campaign ownership v1'
        foreach ($name in $VmNames) { $vm = Get-VM -Name $name -ErrorAction SilentlyContinue; if ($vm -and $vm.State.ToString() -cne 'Off') { throw 'VMs must be Off for explicit campaign initialization.' } }
        $backup = [IO.Path]::Combine($directory,('legacy-'+[guid]::NewGuid().ToString('N')))
        $receipts = New-Object Collections.Generic.List[string]
        foreach ($leaf in 'data.vhdx','control-data.vhdx') {
            $source = [IO.Path]::Combine($Root,$leaf)
            try { $attr = [IO.File]::GetAttributes($source) } catch [IO.FileNotFoundException] { continue }
            if ($VmNames.Count -eq 0 -or ($attr -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) { throw 'Legacy transports require explicit VM identities and ordinary files.' }
            New-ProtectedDirectory -Path $backup
            # The source handle excludes writes/deletion for the entire cold copy and source hash.
            $reader = [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try {
                $destination = [IO.Path]::Combine($backup,$leaf)
                $writer = [IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                try {
                    $reader.CopyTo($writer); $writer.Flush($true); $reader.Position = 0; $writer.Position = 0
                    $sha = [Security.Cryptography.SHA256]::Create()
                    try { $original = [Convert]::ToBase64String($sha.ComputeHash($reader)); $copied = [Convert]::ToBase64String($sha.ComputeHash($writer)) } finally { $sha.Dispose() }
                    if ($reader.Length -ne $writer.Length -or $original -cne $copied) { throw 'Cold transport backup did not verify; originals preserved.' }
                    $receipts.Add(($leaf+' '+$reader.Length+' '+[BitConverter]::ToString([Convert]::FromBase64String($original)).Replace('-','')))
                }
                finally { $writer.Dispose() }
            }
            finally { $reader.Dispose() }
        }
        foreach ($name in $VmNames) { $vm = Get-VM -Name $name -ErrorAction SilentlyContinue; if ($vm -and $vm.State.ToString() -cne 'Off') { throw 'A VM changed state during campaign initialization; originals and backups preserved.' } }
        Write-WinSightAtomicText -Path ([IO.Path]::Combine($directory,'migration.txt')) -Text ($receipts -join "`n")
        $state = [ordered]@{version=1;root=[IO.Path]::GetFullPath($Root).TrimEnd('\').ToUpperInvariant();status='Idle'}
        Write-WinSightAtomicText -Path ([IO.Path]::Combine($directory,'state.json')) -Text ($state|ConvertTo-Json -Compress)
    }
    finally { $handle.Dispose() }
}

function Enter-WinSightCampaign([string]$Root, $Contract, [switch]$Resume) {
    $handle = Open-WinSightCampaignLease $Root
    try {
        $state = Read-WinSightCampaignState $Root
        $text = $Contract | ConvertTo-Json -Depth 12 -Compress
        $digest = Get-WinSightTextDigest $text
        if ($state.status -ceq 'Active') {
            if (-not $Resume -or $state.contractDigest -cne $digest) { throw 'A campaign still owns these transports; preserve it and use its exact Resume contract.' }
        }
        elseif ($Resume) { throw 'No Active campaign matches Resume; never invent a run identity.' }
        else {
            $state = [pscustomobject][ordered]@{version=1;root=[IO.Path]::GetFullPath($Root).TrimEnd('\').ToUpperInvariant();status='Active';runId=[guid]::NewGuid().ToString('D');contract=($text|ConvertFrom-Json);contractDigest=$digest;stage='staging';deadlineUtc=$null;timedOut=$false;observationIncomplete=$false;sealDigest=$null;resources=$null}
            Write-WinSightAtomicText -Path ([IO.Path]::Combine($Root,'host-campaign','state.json')) -Text ($state|ConvertTo-Json -Depth 12 -Compress) -Replace
        }
        return [pscustomobject]@{Handle=$handle;Root=$Root;RunId=$state.runId;State=$state}
    }
    catch { $handle.Dispose(); throw }
}

function Set-WinSightCampaignStage($Lease, [ValidateSet('staging','starting','collecting','recovered')][string]$Stage, [int]$TimeoutMinutes = 0, [switch]$TimedOut, [switch]$ObservationIncomplete) {
    if (-not $Lease -or -not $Lease.Handle.CanWrite -or $Lease.State.status -cne 'Active') { throw 'Campaign transition requires its live exclusive lease.' }
    if ($Stage -ceq 'starting' -and -not $Lease.State.deadlineUtc) {
        if ($TimeoutMinutes -le 0) { throw 'Campaign start requires its original positive time budget.' }
        $Lease.State.deadlineUtc = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes).ToString('o')
    }
    $Lease.State.stage = $Stage
    if ($TimedOut) { $Lease.State.timedOut = $true }
    if ($ObservationIncomplete) { $Lease.State.observationIncomplete = $true }
    Write-WinSightAtomicText -Path ([IO.Path]::Combine($Lease.Root,'host-campaign','state.json')) -Text ($Lease.State|ConvertTo-Json -Depth 12 -Compress) -Replace
}

function Get-WinSightCampaignContext([string]$Root, [switch]$RequireIdle, [switch]$Hold) {
    $handle = Open-WinSightCampaignLease $Root
    $transferred = $false
    try {
        $state = Read-WinSightCampaignState $Root
        if ($RequireIdle -and $state.status -ceq 'Active') { throw 'A campaign owns the common transport root; staging or maintenance refused.' }
        if ($Hold) { $transferred = $true; return [pscustomobject]@{Handle=$handle;State=$state} }
        return $state
    }
    finally { if (-not $transferred) { $handle.Dispose() } }
}

function Close-WinSightCampaign($Lease, [string]$SealPath) {
    # The driver must prove collection, cleanup and VM/resource recovery before calling this boundary.
    if (-not $Lease -or -not $Lease.Handle.CanWrite -or $Lease.State.status -cne 'Active') { throw 'Campaign close requires its exclusive active lease.' }
    $attributes = [IO.File]::GetAttributes($SealPath)
    if ($attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Campaign seal is not an ordinary file.' }
    Assert-ProtectedPath -Path $SealPath -AdministratorsOnly
    $stream = [IO.File]::Open($SealPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        if ($stream.Length -gt 16MB) { throw 'Campaign seal exceeds its byte bound.' }
        $stream.Flush($true)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $digest = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
    $Lease.State.status = 'Closed'; $Lease.State.stage = 'recovered'; $Lease.State.sealDigest = $digest
    Write-WinSightAtomicText -Path ([IO.Path]::Combine($Lease.Root,'host-campaign','state.json')) -Text ($Lease.State|ConvertTo-Json -Depth 12 -Compress) -Replace
    $Lease.Handle.Dispose()
}

function Write-WinSightQualificationSeal([string]$RunDir, [string]$SealPath) {
    $expected = [IO.Path]::Combine([IO.Path]::GetFullPath($RunDir),'SHA256SUMS.txt')
    if ($SealPath -and -not [string]::Equals([IO.Path]::GetFullPath($SealPath),$expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Qualification seal must use the fixed run checksum path.' }
    $lines = @(Get-ChildItem -LiteralPath $RunDir -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName |
        ForEach-Object { "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)  $($_.FullName.Substring($RunDir.Length + 1))" })
    $path = [IO.Path]::Combine($RunDir,'SHA256SUMS.txt'); $text = $lines -join "`r`n"
    try { $existing = Read-WinSightBoundedText -Path $path -MaximumBytes 16MB }
    catch [IO.FileNotFoundException] { Write-WinSightAtomicText -Path $path -Text $text -MaximumBytes 16MB; return }
    if ($existing -cne $text) { throw 'Existing qualification seal differs; evidence and active ownership preserved.' }
}

function Read-WinSightQualificationResult([string]$Path, [string]$Commit, [string]$RunId) {
    try {
        $entry = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $entry.Length -gt 16MB) { throw 'Collected result is not an ordinary bounded file.' }
    }
    catch [Management.Automation.ItemNotFoundException] { }
    try { $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
    catch [Management.Automation.ItemNotFoundException] { return $null }
    if ($raw -isnot [string] -or $raw.Length -gt 16MB -or -not $raw.TrimStart().StartsWith('{')) { throw 'Collected result root is unrecognized.' }
    Assert-WinSightJsonMembers $raw
    $value = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($value -isnot [pscustomobject] -or $value.candidate -isnot [pscustomobject] -or
        $value.candidate.commit -isnot [string] -or $value.candidate.commit -cne $Commit -or
        $value.candidate.qualificationRunId -isnot [string] -or $value.candidate.qualificationRunId -cne $RunId -or
        $value.gates -isnot [pscustomobject]) { throw 'Collected result does not identify this candidate/run; evidence preserved without attribution.' }
    foreach ($gate in $value.gates.PSObject.Properties) {
        if ($gate.Value -isnot [pscustomobject] -or $gate.Value.status -isnot [string] -or $gate.Value.status -cnotin 'PASS','FAIL','NOT_RUN') { throw 'Collected gate status is unrecognized; campaign preserved.' }
    }
    return $value
}

function Confirm-WinSightQualificationSeal([string]$RunDir) {
    $path = [IO.Path]::Combine($RunDir,'SHA256SUMS.txt')
    $attributes = [IO.File]::GetAttributes($path)
    if ($attributes -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint)) { throw 'Qualification seal is not an ordinary file.' }
    Assert-ProtectedPath -Path $path -AdministratorsOnly
    $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try { if ($stream.Length -gt 16MB) { throw 'Qualification seal exceeds its byte bound.' }; $stream.Flush($true) }
    finally { $stream.Dispose() }
}

Export-ModuleMember -Function Set-AdministratorsDefaultOwner, Assert-ProtectedPath, Assert-ProtectedAncestors, New-ProtectedDirectory, Assert-NoReparseBetween, Copy-ListedFile,
    Get-GitBlobId, Get-FileManifest, Get-SharedFileHash, Mount-WinSightData, Dismount-WinSightData, Clear-WinSightDataVolume,
    Copy-GuestResults, Get-WinSightVmState, Remove-WinSightDataDisk, Assert-WinSightHostMemory, Write-SharedText, Add-SharedLine,
    Invoke-WinSightVmRetry, Write-WinSightDriverHeartbeat, Read-WinSightDriverHeartbeat,
    Test-WinSightCompletion, Get-WinSightQualificationStatus, Get-WinSightQualificationExitCode, Get-WinSightTextDigest, Write-WinSightAtomicText, Read-WinSightBoundedText, Assert-WinSightJsonMembers, Read-WinSightQualificationResult, Initialize-WinSightCampaignOwnership, Enter-WinSightCampaign, Set-WinSightCampaignStage, Get-WinSightCampaignContext, Close-WinSightCampaign, Write-WinSightQualificationSeal, Write-WinSightDiagnostic, Confirm-WinSightQualificationSeal, Write-WinSightImmutableText, New-WinSightSourceContext
