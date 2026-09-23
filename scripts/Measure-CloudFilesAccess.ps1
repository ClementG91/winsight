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
            state = if ($fields) { $fields.state } else { $null }
            sha256Matches = [bool]($fields -and ($fields.PSObject.Properties.Name -contains "sha256") -and $fields.sha256 -eq $expected)
            fetchRequestsDuringRead = [CloudFilesProbe]::FetchRequests - $fetchBefore
            output = $stdout.Result
        }
        $c = $evidence.cases[$name]
        "{0}: readable={1} state={2} fetch={3} ms={4} attrs={5} tag={6} placeholder={7}->{8}" -f `
            $name, $c.sha256Matches, $c.state, $c.fetchRequestsDuringRead, $c.milliseconds, `
            $c.attributesBefore, $c.reparseTag, $c.placeholderStateBefore, $c.placeholderStateAfter
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
