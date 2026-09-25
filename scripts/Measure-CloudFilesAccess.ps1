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
# - connects a provider that records each download (FETCH_DATA) request with the process that made it
# and fails it at once, and asks winsight.exe to hash each file. It registers a sync root for the current
# user: run it in the disposable VM.
#
# Who asked matters. A download request is WinSight's when a WinSight process made it; another program
# on the machine (Defender reacting to a new Run value, for instance) can ask for the same file during
# a measurement. Each request is recorded with its process, and one the platform cannot attribute is
# counted as WinSight's.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class CloudFilesProbe
{
    // CF_CALLBACK_INFO (cfapi.h), field for field.
    [StructLayout(LayoutKind.Sequential)]
    public struct CallbackInfo
    {
        public uint StructSize;
        public long ConnectionKey;
        public IntPtr CallbackContext;
        public IntPtr VolumeGuidName;
        public IntPtr VolumeDosName;
        public uint VolumeSerialNumber;
        public long SyncRootFileId;
        public IntPtr SyncRootIdentity;
        public uint SyncRootIdentityLength;
        public long FileId;
        public long FileSize;
        public IntPtr FileIdentity;
        public uint FileIdentityLength;
        public IntPtr NormalizedPath;
        public long TransferKey;
        public byte PriorityHint;
        public IntPtr CorrelationVector;
        public IntPtr ProcessInfo;
        public long RequestKey;
    }

    // CF_OPERATION_INFO (cfapi.h), field for field.
    [StructLayout(LayoutKind.Sequential)]
    public struct OperationInfo
    {
        public uint StructSize;
        public int Type;
        public long ConnectionKey;
        public long TransferKey;
        public IntPtr CorrelationVector;
        public IntPtr SyncStatus;
        public long RequestKey;
    }

    // CF_OPERATION_PARAMETERS with the one member used here, TransferData: ParamSize, then the union
    // at offset 8.
    [StructLayout(LayoutKind.Explicit)]
    public struct TransferData
    {
        [FieldOffset(0)] public uint ParamSize;
        [FieldOffset(8)] public uint Flags;
        [FieldOffset(12)] public int CompletionStatus;
        [FieldOffset(16)] public IntPtr Buffer;
        [FieldOffset(24)] public long Offset;
        [FieldOffset(32)] public long Length;
    }

    // CF_PROCESS_INFO. CommandLine and SessionId came with Windows 10 1803; StructSize says whether
    // they are there.
    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInfo
    {
        public uint StructSize;
        public uint ProcessId;
        public IntPtr ImagePath;
        public IntPtr PackageName;
        public IntPtr ApplicationId;
        public IntPtr CommandLine;
        public uint SessionId;
    }

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
    [DllImport("cldapi.dll")]
    public static extern int CfExecute(ref OperationInfo operation, ref TransferData transfer);
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

    // CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO: without it the platform leaves ProcessInfo empty.
    private const uint RequireProcessInfo = 0x2;
    // CF_OPERATION_TYPE_TRANSFER_DATA, and a failure status: one outside the STATUS_CLOUD_FILE_* range
    // reaches the reader as STATUS_CLOUD_FILE_UNSUCCESSFUL.
    private const int TransferDataOperation = 0;
    private const int StatusUnsuccessful = unchecked((int)0xC0000001);
    // One entry per download request: when, the id, image and command line of the process that asked,
    // the file, and the HRESULT of failing it.
    private static readonly ConcurrentQueue<string[]> requests = new ConcurrentQueue<string[]>();
    private static readonly Callback Fetch = OnFetch;
    private static readonly IntPtr Identity = Marshal.StringToHGlobalUni("winsight-cloud-probe");

    public static int FetchRequests { get { return requests.Count; } }

    public static string[][] Requests() { return requests.ToArray(); }

    // Runs on a platform thread: nothing may escape from it. The structures are read only as far as
    // their StructSize covers.
    private static void OnFetch(IntPtr info, IntPtr parameters)
    {
        string processId = "0", image = "", commandLine = "", file = "", completion = "";
        try
        {
            if (Marshal.ReadInt32(info) >= Offset(typeof(CallbackInfo), "RequestKey"))
            {
                file = Text(Marshal.ReadIntPtr(info, Offset(typeof(CallbackInfo), "NormalizedPath")));
                var process = Marshal.ReadIntPtr(info, Offset(typeof(CallbackInfo), "ProcessInfo"));
                if (process != IntPtr.Zero)
                {
                    var size = Marshal.ReadInt32(process);
                    processId = ((uint)Marshal.ReadInt32(process, Offset(typeof(ProcessInfo), "ProcessId"))).ToString();
                    image = Text(Marshal.ReadIntPtr(process, Offset(typeof(ProcessInfo), "ImagePath")));
                    if (size >= Offset(typeof(ProcessInfo), "SessionId"))
                    {
                        commandLine = Text(Marshal.ReadIntPtr(process, Offset(typeof(ProcessInfo), "CommandLine")));
                    }
                }
            }
        }
        catch (Exception) { }
        try
        {
            // Failed at once. The platform keeps one request per file and makes every other reader
            // wait behind it without a request of its own: a request left pending would hide a read by
            // WinSight. A callback without a connection key, which the platform never sends, is not
            // answered.
            if (Marshal.ReadInt32(info) >= Offset(typeof(CallbackInfo), "RequestKey") + 8
                && Marshal.ReadInt64(info, Offset(typeof(CallbackInfo), "ConnectionKey")) != 0)
            {
                OperationInfo operation;
                TransferData transfer;
                DescribeFailure(info, out operation, out transfer);
                completion = "0x" + CfExecute(ref operation, ref transfer).ToString("X8");
            }
        }
        catch (Exception exception) { completion = exception.GetType().Name; }
        requests.Enqueue(new[] { DateTime.UtcNow.ToString("o"), processId, image, commandLine, file, completion });
    }

    // The failure of a download request: TRANSFER_DATA with an error status over the whole file, from
    // offset 0 to the end of the file, which fails every read of the file waiting on it.
    public static void DescribeFailure(IntPtr info, out OperationInfo operation, out TransferData transfer)
    {
        operation = new OperationInfo
        {
            StructSize = (uint)Marshal.SizeOf(typeof(OperationInfo)),
            Type = TransferDataOperation,
            ConnectionKey = Marshal.ReadInt64(info, Offset(typeof(CallbackInfo), "ConnectionKey")),
            TransferKey = Marshal.ReadInt64(info, Offset(typeof(CallbackInfo), "TransferKey")),
            RequestKey = Marshal.ReadInt64(info, Offset(typeof(CallbackInfo), "RequestKey")),
        };
        transfer = new TransferData
        {
            ParamSize = (uint)Marshal.SizeOf(typeof(TransferData)),
            CompletionStatus = StatusUnsuccessful,
            Offset = 0,
            Length = Marshal.ReadInt64(info, Offset(typeof(CallbackInfo), "FileSize")),
        };
    }

    private static int Offset(Type type, string field) { return Marshal.OffsetOf(type, field).ToInt32(); }

    private static string Text(IntPtr value) { return value == IntPtr.Zero ? "" : Marshal.PtrToStringUni(value); }

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
        Check(CfConnectSyncRoot(root, table, IntPtr.Zero, RequireProcessInfo, out key), "CfConnectSyncRoot");
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

# Who made a download request: 'winsight' for the process under test or any WinSight image, 'other' for
# another program, 'unattributed' when the platform could not say - which counts as WinSight, so that
# a bound on WinSight's requests fails closed.
function Get-FetchOwner([int]$ProcessId, [string]$Image, [int[]]$WinSightProcessIds) {
    if ($ProcessId -le 0 -or -not $Image -or $Image -eq 'UNKNOWN') { return 'unattributed' }
    if ($WinSightProcessIds -contains $ProcessId -or ($Image -split '\\')[-1] -like 'winsight*') { return 'winsight' }
    'other'
}

# The download requests received from index $From on, each with the process that asked. When the
# platform could not name the image, the name of the process still running under that id stands in.
function Get-Fetches([int]$From, [int[]]$WinSightProcessIds) {
    $all = [CloudFilesProbe]::Requests()
    @(for ($i = $From; $i -lt $all.Count; $i++) {
        $utc, $processId, $image, $commandLine, $file, $completion = $all[$i]
        $processId = [int]$processId
        if ((-not $image -or $image -eq 'UNKNOWN') -and $processId -gt 0) {
            $running = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($running) { $image = $running.ProcessName }
        }
        [ordered]@{
            utc = $utc; processId = $processId; image = $image; commandLine = $commandLine; file = $file; completion = $completion
            owner = Get-FetchOwner -ProcessId $processId -Image $image -WinSightProcessIds $WinSightProcessIds
        }
    })
}

# Adds to $Record the counts a gate bounds, and the requests themselves.
function Add-Fetches($Record, $Fetches) {
    $all = @($Fetches)
    $Record.fetchRequestsByWinSight = @($all | Where-Object { $_.owner -eq 'winsight' }).Count
    $Record.fetchRequestsUnattributed = @($all | Where-Object { $_.owner -eq 'unattributed' }).Count
    $Record.fetchRequesters = $all
}

# "none", or each request as <image>#<process id>/<owner>.
function Format-Fetches($Fetches) {
    $all = @($Fetches)
    if ($all.Count -eq 0) { return 'none' }
    ($all | ForEach-Object { '{0}#{1}/{2}' -f ($_.image -split '\\')[-1], $_.processId, $_.owner }) -join ', '
}

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
        $fetches = @(Get-Fetches -From $fetchBefore -WinSightProcessIds @($process.Id))
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
            fetchRequestsDuringRead = $fetches.Count
            output = $stdout.Result
        }
        $c = $evidence.cases[$name]
        Add-Fetches $c $fetches
        "{0}: readable={1} state={2} fetch={3} ms={4} attrs={5} tag={6} placeholder={7}->{8} by={9}" -f `
            $name, $c.sha256Matches, $c.state, $c.fetchRequestsDuringRead, $c.milliseconds, `
            $c.attributesBefore, $c.reparseTag, $c.placeholderStateBefore, $c.placeholderStateAfter, (Format-Fetches $fetches)
    }

    # RA-02: the persistence scan reads more than a signature - the compiled-in name of each image,
    # which it used to read by path outside the automatic-read guard. A Run value pointing at the
    # cloud-only file puts it on that path; the scan must finish without one download request of its
    # own. The value is this user's, in this disposable VM, and is removed below whatever happens.
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $runValue = 'WinSightCloudFilesProbe'
    $cloudOnly = $cases['dehydrated-placeholder'].Path
    Set-ItemProperty -LiteralPath $runKey -Name $runValue -Value "`"$cloudOnly`" --probe"
    try
    {
        # Whatever reacts to a new Run value - Defender, the shell - does so now, before the scan
        # starts. Its requests are recorded apart. A WinSight process among the requesters (Guardian
        # re-scanning) still counts.
        $settleSeconds = 30
        $settleFrom = [CloudFilesProbe]::FetchRequests
        Start-Sleep -Seconds $settleSeconds
        $settle = @(Get-Fetches -From $settleFrom -WinSightProcessIds @())
        $evidence.runValueSettle = [ordered]@{ seconds = $settleSeconds; fetchRequests = $settle.Count }
        Add-Fetches $evidence.runValueSettle $settle
        "after the Run value was written: fetch={0} in {1} s by={2}" -f $settle.Count, $settleSeconds, (Format-Fetches $settle)

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
        $fetches = @(Get-Fetches -From $fetchBefore -WinSightProcessIds @($process.Id))
        $evidence.persistence = [ordered]@{
            exit = if ($finished) { $process.ExitCode } else { 'timeout' }
            milliseconds = $watch.ElapsedMilliseconds
            fetchRequestsDuringScan = $fetches.Count
            entryFound = $null -ne $entry
            image = if ($entry) { $entry.fields.image } else { $null }
            fileStatus = if ($entry) { $entry.fields.fileStatus } else { $null }
            status = if ($entry) { $entry.fields.status } else { $null }
            placeholderStateAfter = ('0x{0:X8}' -f ([CloudFilesProbe]::Describe($cloudOnly))[2])
        }
        $s = $evidence.persistence
        Add-Fetches $s $fetches
        "persistence scan: found={0} fileStatus={1} status={2} fetch={3} ms={4} exit={5} by={6}" -f `
            $s.entryFound, $s.fileStatus, $s.status, $s.fetchRequestsDuringScan, $s.milliseconds, $s.exit, (Format-Fetches $fetches)
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
        $fetches = @(Get-Fetches -From $fetchBefore -WinSightProcessIds @())
        $evidence.primitives[$method] = [ordered]@{
            result = if ($finished) { $stdout.Result.Trim() } else { 'timeout' }
            milliseconds = $watch.ElapsedMilliseconds
            fetchRequests = $fetches.Count
            fetchRequesters = $fetches
        }
        $p = $evidence.primitives[$method]
        "primitive {0}: {1} fetch={2} ms={3} by={4}" -f $method, $p.result, $p.fetchRequests, $p.milliseconds, (Format-Fetches $fetches)
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
    $evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}
