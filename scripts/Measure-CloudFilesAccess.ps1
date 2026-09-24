[CmdletBinding()]
param(
    # The winsight.exe under test.
    [Parameter(Mandatory)]
    [string]$CliPath,

    # Where the JSON evidence is written.
    [Parameter(Mandatory)]
    [string]$EvidencePath
)

# WS-40. OneDrive's Known Folder Move puts Documents, Desktop and Pictures under a Cloud Files sync
# root, where every file is a placeholder carrying a cloud reparse tag. WinSight's automatic reads
# refuse any reparse point (AutomaticFileAccess). Nothing had measured whether that refusal also
# turns away OneDrive's ordinary, fully hydrated files, and whether a read of a cloud-only file
# makes Windows download it.
#
# This registers a throw-away sync root with the documented Cloud Files API (no OneDrive, no account),
# creates the placeholder shapes OneDrive does - hydrated and dehydrated files, a directory placeholder
# - connects a provider that only counts download (FETCH_DATA) requests, and asks winsight.exe to
# hash each file. It registers a sync root for the current user: run it in the disposable VM.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class CloudFilesProbe
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SyncRegistration
    {
        public uint StructSize;
        public string ProviderName;
        public string ProviderVersion;
        public IntPtr SyncRootIdentity;
        public uint SyncRootIdentityLength;
        public IntPtr FileIdentity;
        public uint FileIdentityLength;
        public Guid ProviderId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SyncPolicies
    {
        public uint StructSize;
        public ushort HydrationPrimary;
        public ushort HydrationModifier;
        public ushort PopulationPrimary;
        public ushort PopulationModifier;
        public uint InSync;
        public uint HardLink;
        public uint PlaceholderManagement;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CallbackRegistration
    {
        public int Type;
        public IntPtr Callback;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FindData
    {
        public uint FileAttributes;
        public long CreationTime;
        public long LastAccessTime;
        public long LastWriteTime;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint Reserved0;
        public uint Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateFileName;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void Callback(IntPtr info, IntPtr parameters);

    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    public static extern int CfRegisterSyncRoot(string path, ref SyncRegistration registration, ref SyncPolicies policies, uint flags);
    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    public static extern int CfUnregisterSyncRoot(string path);
    [DllImport("cldapi.dll", CharSet = CharSet.Unicode)]
    public static extern int CfConnectSyncRoot(string path, [In] CallbackRegistration[] table, IntPtr context, uint flags, out long connectionKey);
    [DllImport("cldapi.dll")]
    public static extern int CfDisconnectSyncRoot(long connectionKey);
    [DllImport("cldapi.dll")]
    public static extern int CfConvertToPlaceholder(SafeFileHandle handle, IntPtr identity, uint identityLength, uint flags, out long usn, IntPtr overlapped);
    [DllImport("cldapi.dll")]
    public static extern uint CfGetPlaceholderStateFromAttributeTag(uint attributes, uint reparseTag);
    [DllImport("ntdll.dll")]
    public static extern sbyte RtlQueryProcessPlaceholderCompatibilityMode();
    [DllImport("ntdll.dll")]
    public static extern sbyte RtlSetProcessPlaceholderCompatibilityMode(sbyte mode);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindFirstFileW(string name, out FindData data);
    [DllImport("kernel32.dll")]
    public static extern bool FindClose(IntPtr handle);

    private static int fetchRequests;
    private static readonly Callback Fetch = delegate { Interlocked.Increment(ref fetchRequests); };
    private static readonly IntPtr Identity = Marshal.StringToHGlobalUni("winsight-cloud-probe");

    public static int FetchRequests { get { return Volatile.Read(ref fetchRequests); } }

    public static void Check(int hr, string what)
    {
        if (hr != 0) { throw new InvalidOperationException(what + " failed: 0x" + hr.ToString("X8")); }
    }

    public static void Register(string root)
    {
        var registration = new SyncRegistration
        {
            ProviderName = "WinSightCloudProbe",
            ProviderVersion = "1.0",
            ProviderId = new Guid("5b1f0f5e-2c7a-4f1e-9a53-3d0c3f0b7a11"),
        };
        registration.StructSize = (uint)Marshal.SizeOf(typeof(SyncRegistration));
        // Hydration FULL (dehydration allowed), population ALWAYS_FULL (no directory callbacks needed).
        var policies = new SyncPolicies { HydrationPrimary = 2, PopulationPrimary = 3 };
        policies.StructSize = (uint)Marshal.SizeOf(typeof(SyncPolicies));
        Check(CfRegisterSyncRoot(root, ref registration, ref policies, 0), "CfRegisterSyncRoot");
    }

    public static long Connect(string root)
    {
        var table = new[]
        {
            new CallbackRegistration { Type = 0, Callback = Marshal.GetFunctionPointerForDelegate(Fetch) },
            new CallbackRegistration { Type = unchecked((int)0xFFFFFFFF), Callback = IntPtr.Zero },
        };
        long key;
        Check(CfConnectSyncRoot(root, table, IntPtr.Zero, 0, out key), "CfConnectSyncRoot");
        return key;
    }

    // MARK_IN_SYNC = 1, DEHYDRATE = 2. Dehydration needs an exclusive handle; a directory needs
    // backup semantics to be opened at all.
    public static void Convert(string path, bool dehydrate, bool directory)
    {
        uint access = directory ? 0x80u | 0x100u : 0xC0000000u;
        uint share = dehydrate ? 0u : 7u;
        uint flags = directory ? 0x02000000u : 0x80u;
        using (var handle = CreateFileW(path, access, share, IntPtr.Zero, 3, flags, IntPtr.Zero))
        {
            if (handle.IsInvalid) { throw new InvalidOperationException("open " + path + " failed: " + Marshal.GetLastWin32Error()); }
            long usn;
            Check(CfConvertToPlaceholder(handle, Identity, 40, dehydrate ? 3u : 1u, out usn, IntPtr.Zero), "CfConvertToPlaceholder " + path);
        }
    }

    public static uint[] Describe(string path)
    {
        FindData data;
        var find = FindFirstFileW(path, out data);
        if (find == new IntPtr(-1)) { return new uint[] { 0xFFFFFFFF, 0, 0xFFFFFFFF }; }
        FindClose(find);
        uint tag = (data.FileAttributes & 0x400) != 0 ? data.Reserved0 : 0;
        return new[] { data.FileAttributes, tag, CfGetPlaceholderStateFromAttributeTag(data.FileAttributes, tag) };
    }
}
'@

$cli = (Resolve-Path -LiteralPath $CliPath).Path
$sample = Join-Path $env:SystemRoot "System32\cmd.exe"
$expected = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
$suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$root = Join-Path $env:USERPROFILE "WinSightCloudProbe-$suffix"
$control = Join-Path $env:USERPROFILE "WinSightCloudControl-$suffix"

# The mode WinSight will run in is the default one; the probe then exposes placeholders to itself so
# that what it records about each file is the truth, not the disguise.
$defaultMode = [CloudFilesProbe]::RtlQueryProcessPlaceholderCompatibilityMode()
[void][CloudFilesProbe]::RtlSetProcessPlaceholderCompatibilityMode(2)

$cases = [ordered]@{
    "control" = @{ Path = Join-Path $control "plain.exe" }
    "plain-in-sync-root" = @{ Path = Join-Path $root "plain.exe" }
    "hydrated-placeholder" = @{ Path = Join-Path $root "hydrated.exe" }
    "hydrated-in-directory-placeholder" = @{ Path = Join-Path $root "Folder\nested.exe" }
    "dehydrated-placeholder" = @{ Path = Join-Path $root "dehydrated.exe" }
}
$evidence = [ordered]@{
    measuredUtc = (Get-Date).ToUniversalTime().ToString("o")
    os = (Get-CimInstance Win32_OperatingSystem | ForEach-Object { "$($_.Caption) $($_.Version)" })
    defaultPlaceholderCompatibilityMode = [int]$defaultMode
    cli = $cli
    cliVersion = (& $cli --version)
    sampleSha256 = $expected
    cases = [ordered]@{}
}
$connection = $null
$registered = $false
try
{
    New-Item -ItemType Directory -Path $control, $root, (Join-Path $root "Folder") | Out-Null
    foreach ($case in $cases.Values) { Copy-Item -LiteralPath $sample -Destination $case.Path }

    [CloudFilesProbe]::Register($root)
    $registered = $true
    [CloudFilesProbe]::Convert((Join-Path $root "Folder"), $false, $true)
    [CloudFilesProbe]::Convert($cases["hydrated-placeholder"].Path, $false, $false)
    [CloudFilesProbe]::Convert($cases["hydrated-in-directory-placeholder"].Path, $false, $false)
    [CloudFilesProbe]::Convert($cases["dehydrated-placeholder"].Path, $true, $false)
    $connection = [CloudFilesProbe]::Connect($root)
    Start-Sleep -Seconds 2   # let anything that reacts to new files (Defender) finish first

    foreach ($name in $cases.Keys)
    {
        $path = $cases[$name].Path
        $before = [CloudFilesProbe]::Describe($path)
        $fetchBefore = [CloudFilesProbe]::FetchRequests
        $start = New-Object Diagnostics.ProcessStartInfo $cli
        $start.Arguments = "sign `"$path`" --json"
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $null = $process.StandardError.ReadToEndAsync()   # drained, so a full pipe can never stall the read
        $finished = $process.WaitForExit(120000)
        if (-not $finished) { $process.Kill() }
        $watch.Stop()
        $fields = $null
        try { $fields = ($stdout.Result | ConvertFrom-Json).reports[0].items[0].fields } catch { }
        $after = [CloudFilesProbe]::Describe($path)
        $evidence.cases[$name] = [ordered]@{
            path = $path
            attributesBefore = ('0x{0:X8}' -f $before[0])
            reparseTag = ('0x{0:X8}' -f $before[1])
            placeholderStateBefore = ('0x{0:X8}' -f $before[2])
            placeholderStateAfter = ('0x{0:X8}' -f $after[2])
            attributesAfter = ('0x{0:X8}' -f $after[0])
            exit = if ($finished) { $process.ExitCode } else { "timeout" }
            milliseconds = $watch.ElapsedMilliseconds
            # An unreadable file gets a report without a signature state; StrictMode would throw on it.
            state = if ($fields -and $fields.PSObject.Properties.Name -contains 'state') { $fields.state } else { $null }
            sha256Matches = [bool]($fields -and ($fields.PSObject.Properties.Name -contains "sha256") -and $fields.sha256 -eq $expected)
            fetchRequestsDuringRead = [CloudFilesProbe]::FetchRequests - $fetchBefore
            output = $stdout.Result
        }
        $c = $evidence.cases[$name]
        "{0}: readable={1} state={2} fetch={3} ms={4} attrs={5} tag={6} placeholder={7}->{8}" -f `
            $name, $c.sha256Matches, $c.state, $c.fetchRequestsDuringRead, $c.milliseconds, `
            $c.attributesBefore, $c.reparseTag, $c.placeholderStateBefore, $c.placeholderStateAfter
    }

    # RA-02: the persistence scan reads more than a signature - the compiled-in name of each image,
    # which it used to read by path outside the automatic-read guard. A Run value pointing at the
    # cloud-only file puts it on that path; the scan must finish without one download request. The
    # value is this user's, in this disposable VM, and is removed below whatever happens.
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $runValue = 'WinSightCloudFilesProbe'
    $cloudOnly = $cases['dehydrated-placeholder'].Path
    Set-ItemProperty -LiteralPath $runKey -Name $runValue -Value "`"$cloudOnly`" --probe"
    try
    {
        $fetchBefore = [CloudFilesProbe]::FetchRequests
        $start = New-Object Diagnostics.ProcessStartInfo $cli
        $start.Arguments = 'persistence --json'
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $null = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit(300000)
        if (-not $finished) { $process.Kill() }
        $watch.Stop()
        $entry = $null
        try {
            $entry = @(($stdout.Result | ConvertFrom-Json).reports[0].items |
                Where-Object { $_.fields.name -eq $runValue } | Select-Object -First 1)[0]
        } catch { }
        $evidence.persistence = [ordered]@{
            exit = if ($finished) { $process.ExitCode } else { 'timeout' }
            milliseconds = $watch.ElapsedMilliseconds
            fetchRequestsDuringScan = [CloudFilesProbe]::FetchRequests - $fetchBefore
            entryFound = $null -ne $entry
            image = if ($entry) { $entry.fields.image } else { $null }
            fileStatus = if ($entry) { $entry.fields.fileStatus } else { $null }
            status = if ($entry) { $entry.fields.status } else { $null }
            placeholderStateAfter = ('0x{0:X8}' -f ([CloudFilesProbe]::Describe($cloudOnly))[2])
        }
        $s = $evidence.persistence
        "persistence scan: found={0} fileStatus={1} status={2} fetch={3} ms={4} exit={5}" -f `
            $s.entryFound, $s.fileStatus, $s.status, $s.fetchRequestsDuringScan, $s.milliseconds, $s.exit
    }
    finally
    {
        Remove-ItemProperty -LiteralPath $runKey -Name $runValue -ErrorAction SilentlyContinue
    }

    # The primitives underneath, each in its own default-mode process, against the cloud-only file:
    # what attributes an ordinary process is shown, and whether an open that forbids recall is honoured
    # by the Cloud Files filter when the data is read.
    $primitive = @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class Primitive {
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public int Length; public IntPtr Root; public IntPtr Name; public uint Attributes; public IntPtr Sd; public IntPtr Qos; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public long C, A, W; public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle h, uint access, ref ObjectAttributes oa, out IoStatus io, IntPtr alloc, uint attrs, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadFile(SafeFileHandle h, byte[] b, int n, out int r, IntPtr o);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileInformationByHandle(SafeFileHandle h, out Info i);
    static string Read(SafeFileHandle h) {
        var buffer = new byte[4096]; int read;
        return ReadFile(h, buffer, buffer.Length, out read, IntPtr.Zero) ? "read " + read + " bytes" : "read failed " + Marshal.GetLastWin32Error();
    }
    public static string Attributes(string path) {
        using (var h = CreateFileW(path, 0x80, 7, IntPtr.Zero, 3, 0x02000000 | 0x00200000 | 0x00100000, IntPtr.Zero)) {
            if (h.IsInvalid) return "open failed " + Marshal.GetLastWin32Error();
            Info i; return GetFileInformationByHandle(h, out i) ? "attributes 0x" + i.Attributes.ToString("X8") : "query failed " + Marshal.GetLastWin32Error();
        }
    }
    public static string Win32NoRecallRead(string path) {
        using (var h = CreateFileW(path, 0x80000000, 7, IntPtr.Zero, 3, 0x00100000 | 0x00200000, IntPtr.Zero)) {
            return h.IsInvalid ? "open failed " + Marshal.GetLastWin32Error() : Read(h);
        }
    }
    public static string NtNoRecallRead(string path) {
        var name = @"\??\" + path; var buffer = Marshal.StringToHGlobalUni(name); var us = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
        try {
            Marshal.StructureToPtr(new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2 + 2), Buffer = buffer }, us, false);
            var oa = new ObjectAttributes { Length = Marshal.SizeOf(typeof(ObjectAttributes)), Name = us, Attributes = 0x40 };
            SafeFileHandle h; IoStatus io;
            var status = NtCreateFile(out h, 0x80100000, ref oa, out io, IntPtr.Zero, 0, 7, 1, 0x20 | 0x40 | 0x00200000 | 0x00400000, IntPtr.Zero, 0);
            using (h) { return status < 0 ? "open failed 0x" + status.ToString("X8") : Read(h); }
        } finally { Marshal.FreeHGlobal(us); Marshal.FreeHGlobal(buffer); }
    }
}
'@
    $evidence.primitives = [ordered]@{}
    $target = $cases['dehydrated-placeholder'].Path
    foreach ($method in 'Attributes', 'NtNoRecallRead', 'Win32NoRecallRead') {
        $child = "Add-Type -TypeDefinition @'`n$primitive`n'@`n[Primitive]::$method('$target')"
        $start = New-Object Diagnostics.ProcessStartInfo (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        $start.Arguments = '-NoProfile -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $fetchBefore = [CloudFilesProbe]::FetchRequests
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $process = [Diagnostics.Process]::Start($start)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $null = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit(90000)
        if (-not $finished) { $process.Kill() }
        $watch.Stop()
        $evidence.primitives[$method] = [ordered]@{
            result = if ($finished) { $stdout.Result.Trim() } else { 'timeout' }
            milliseconds = $watch.ElapsedMilliseconds
            fetchRequests = [CloudFilesProbe]::FetchRequests - $fetchBefore
        }
        $p = $evidence.primitives[$method]
        "primitive {0}: {1} fetch={2} ms={3}" -f $method, $p.result, $p.fetchRequests, $p.milliseconds
    }
}
finally
{
    if ($null -ne $connection) { [void][CloudFilesProbe]::CfDisconnectSyncRoot($connection) }
    if ($registered) { [void][CloudFilesProbe]::CfUnregisterSyncRoot($root) }
    foreach ($directory in $root, $control)
    {
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue }
    }
    $evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}
