<#
.SYNOPSIS
    Validates the read-only Controlled Folder Access report emitted by winsight integrity --json.

.DESCRIPTION
    This probe never changes Defender, WMI, services, WFP, ACLs, or elevation state.  It accepts
    only the report exits used by WinSight (0 for no notable findings and 1 for notable findings),
    validates the bounded CFA report contract, then writes a redacted evidence artifact.  When
    InputJsonPath is supplied, no CLI process is started; the file supplies a deterministic
    simulated exit code and stdout for contract falsification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CliPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [string]$InputJsonPath,

    [ValidateRange(250, 30000)]
    [int]$TestCaptureTimeoutMilliseconds = 30000,

    [ValidateRange(1024, 65536)]
    [int]$TestMaximumCaptureCharacters = 65536
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CfaFieldNames = @(
    'protection',
    'state',
    'rawStateValue',
    'concern',
    'runtimeSupportsProtection',
    'amRunningMode',
    'antivirusEnabled',
    'realTimeProtectionEnabled',
    'protectedFolders',
    'allowedApplicationsVisibility',
    'settingsDeepLink',
    # The Controlled Folder Access verdict is only honest beside what Windows Security Center says is
    # actually protecting the machine, so the item carries that cross-reference. These are validated
    # below, not merely counted: a field admitted to the contract without a rule widens it.
    'securityCenterReading',
    'antivirusConcern',
    'protectedThirdPartyAntivirus',
    'onThirdPartyAntivirus',
    'onAntivirus',
    'activityUnknownAntivirus'
)
$script:SecurityCenterReadings = @('Available', 'Unavailable')
$script:AntiVirusConcerns = @(
    'Protected', 'SignaturesOutOfDate', 'NoActiveAntiVirus', 'NoAntiVirusRegistered',
    'Unavailable', 'SignatureStatusUnknown', 'ActivityStatusUnknown'
)
$script:AntivirusActivities = @('On', 'Off', 'Snoozed', 'Expired', 'Unknown')
$script:AntivirusSignatures = @('UpToDate', 'OutOfDate', 'Unknown')
$script:AntivirusFieldNames = @(
    'protection',
    'concern',
    'reading',
    'registeredAntivirus',
    'activeAntivirus',
    'activeAntivirusCount',
    'onAntivirus',
    'onAntivirusCount',
    'registeredAntivirusCount',
    'offAntivirusCount',
    'snoozedAntivirusCount',
    'expiredAntivirusCount',
    'activityUnknownAntivirusCount',
    'signatureUnknownAntivirusCount',
    'hasActiveNonMicrosoftAntivirus'
)
$script:MaximumAntivirusProducts = 64
$script:MaximumAntivirusNameLength = 256
$script:MaximumJoinedAntivirusAliasLength =
    ($script:MaximumAntivirusProducts * $script:MaximumAntivirusNameLength) + (($script:MaximumAntivirusProducts - 1) * 2)
$script:States = @(
    'Unavailable', 'Unknown', 'Disabled', 'Enabled', 'Audit',
    'BlockDiskModificationOnly', 'AuditDiskModificationOnly'
)
$script:Concerns = @(
    'Protecting', 'Off', 'AuditOnly', 'BlockDiskModificationOnly',
    'AuditDiskModificationOnly', 'RuntimeRequirementsNotMet', 'DefenderNotRunning',
    'UnknownMode', 'Unavailable'
)
# Every operating mode Defender documents for AMRunningMode. The passive spelling differs across
# the Windows versions WinSight supports, and 'Not running' is the ordinary reading on a machine
# whose antivirus is a non-Microsoft product. Mirrors DefenderRuntimeEvidence.DocumentedRunningModes.
$script:RuntimeModes = @(
    'Normal', 'Passive', 'Passive Mode', 'SxS Passive Mode', 'EDR Block Mode', 'Not running'
)
$script:Visibilities = @('Visible', 'RequiresElevation', 'Unavailable')
$script:MaximumCaptureCharacters = $TestMaximumCaptureCharacters
$script:MaximumFixtureCharacters = 1048576
$script:MaximumOperatingSystemFactCharacters = 256
$script:LiveTimeoutMilliseconds = $TestCaptureTimeoutMilliseconds

function Fail-Contract([string]$Message) {
    throw [System.InvalidOperationException]::new($Message)
}

function Assert-ExactProperties([object]$Object, [string[]]$Expected, [string]$Name) {
    if ($null -eq $Object) { Fail-Contract "$Name is missing" }
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    # Missing-expected is checked before the count, and the order is the whole point. These names are
    # this script's own constants, so naming the one that is absent is precise and echoes nothing that
    # came from the CLI. The count check that follows cannot say which property is wrong without
    # printing names taken from the report, so it deliberately says nothing more - a contract
    # validator must not turn a crafted property name into a line in someone's build log.
    #
    # Ordering these the other way round is what made a real failure opaque: a report that had gained
    # six fields could only report "unexpected property count", when it could have named the first
    # expected field it no longer carried.
    foreach ($property in $Expected) {
        if ($actual -cnotcontains $property) { Fail-Contract "$Name is missing property '$property'" }
    }
    if ($actual.Count -ne $Expected.Count) {
        Fail-Contract ("{0} has an unexpected property count (expected {1}, actual {2})" -f $Name, $Expected.Count, $actual.Count)
    }
}

function Assert-String([object]$Value, [string]$Name) {
    if ($Value -isnot [string]) { Fail-Contract "$Name must be a string" }
}

function Assert-BoundedString([object]$Value, [string]$Name, [int]$MaximumLength) {
    Assert-String $Value $Name
    if ($Value.Length -eq 0 -or $Value.Length -gt $MaximumLength) { Fail-Contract "$Name is blank or exceeds its bounded length" }
}

function Assert-ClosedValue([object]$Value, [string[]]$Allowed, [string]$Name) {
    Assert-String $Value $Name
    if ($Allowed -cnotcontains $Value) { Fail-Contract "$Name has an unknown value" }
}

function Assert-CanonicalBoolean([object]$Value, [string]$Name) {
    Assert-ClosedValue -Value $Value -Allowed @('True', 'False') -Name $Name
}

function Get-NonNegativeCount([object]$Value, [string]$Name) {
    if ($Value -isnot [int] -and $Value -isnot [long]) { Fail-Contract "$Name must be an integer" }
    if ($Value -lt 0 -or $Value -gt [int]::MaxValue) { Fail-Contract "$Name is outside the supported range" }
    return [int]$Value
}

function Skip-JsonWhitespace {
    while ($script:JsonIndex -lt $script:JsonText.Length -and [char]::IsWhiteSpace($script:JsonText[$script:JsonIndex])) {
        $script:JsonIndex++
    }
}

function Read-JsonString {
    if ($script:JsonIndex -ge $script:JsonText.Length -or $script:JsonText[$script:JsonIndex] -ne '"') {
        Fail-Contract 'JSON string is malformed'
    }
    $script:JsonIndex++
    $value = [System.Text.StringBuilder]::new()
    while ($script:JsonIndex -lt $script:JsonText.Length) {
        $character = $script:JsonText[$script:JsonIndex]
        $script:JsonIndex++
        if ($character -eq '"') { return $value.ToString() }
        if ([int][char]$character -lt 0x20) { Fail-Contract 'JSON string contains a control character' }
        if ($character -ne '\') { [void]$value.Append($character); continue }
        if ($script:JsonIndex -ge $script:JsonText.Length) { Fail-Contract 'JSON escape is truncated' }
        $escape = $script:JsonText[$script:JsonIndex]
        $script:JsonIndex++
        switch ($escape) {
            '"' { [void]$value.Append('"'); break }
            '\' { [void]$value.Append('\'); break }
            '/' { [void]$value.Append('/'); break }
            'b' { [void]$value.Append([char]8); break }
            'f' { [void]$value.Append([char]12); break }
            'n' { [void]$value.Append("`n"); break }
            'r' { [void]$value.Append("`r"); break }
            't' { [void]$value.Append("`t"); break }
            'u' {
                if ($script:JsonIndex + 4 -gt $script:JsonText.Length) { Fail-Contract 'JSON unicode escape is truncated' }
                $hex = $script:JsonText.Substring($script:JsonIndex, 4)
                if ($hex -notmatch '^[0-9A-Fa-f]{4}$') { Fail-Contract 'JSON unicode escape is malformed' }
                [void]$value.Append([char][Convert]::ToInt32($hex, 16))
                $script:JsonIndex += 4
                break
            }
            default { Fail-Contract 'JSON escape is invalid' }
        }
    }
    Fail-Contract 'JSON string is unterminated'
}

function Read-JsonValue {
    Skip-JsonWhitespace
    if ($script:JsonIndex -ge $script:JsonText.Length) { Fail-Contract 'JSON value is truncated' }
    $character = $script:JsonText[$script:JsonIndex]
    if ($character -eq '{') {
        $script:JsonIndex++
        Skip-JsonWhitespace
        $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        if ($script:JsonIndex -lt $script:JsonText.Length -and $script:JsonText[$script:JsonIndex] -eq '}') { $script:JsonIndex++; return }
        while ($true) {
            Skip-JsonWhitespace
            $name = Read-JsonString
            if (-not $names.Add($name)) { Fail-Contract 'JSON object contains a duplicate decoded member name' }
            Skip-JsonWhitespace
            if ($script:JsonIndex -ge $script:JsonText.Length -or $script:JsonText[$script:JsonIndex] -ne ':') { Fail-Contract 'JSON object is missing a colon' }
            $script:JsonIndex++
            Read-JsonValue
            Skip-JsonWhitespace
            if ($script:JsonIndex -ge $script:JsonText.Length) { Fail-Contract 'JSON object is unterminated' }
            if ($script:JsonText[$script:JsonIndex] -eq '}') { $script:JsonIndex++; return }
            if ($script:JsonText[$script:JsonIndex] -ne ',') { Fail-Contract 'JSON object is missing a comma' }
            $script:JsonIndex++
        }
    }
    if ($character -eq '[') {
        $script:JsonIndex++
        Skip-JsonWhitespace
        if ($script:JsonIndex -lt $script:JsonText.Length -and $script:JsonText[$script:JsonIndex] -eq ']') { $script:JsonIndex++; return }
        while ($true) {
            Read-JsonValue
            Skip-JsonWhitespace
            if ($script:JsonIndex -ge $script:JsonText.Length) { Fail-Contract 'JSON array is unterminated' }
            if ($script:JsonText[$script:JsonIndex] -eq ']') { $script:JsonIndex++; return }
            if ($script:JsonText[$script:JsonIndex] -ne ',') { Fail-Contract 'JSON array is missing a comma' }
            $script:JsonIndex++
        }
    }
    if ($character -eq '"') { [void](Read-JsonString); return }
    $remaining = $script:JsonText.Substring($script:JsonIndex)
    $match = [regex]::Match($remaining, '^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)')
    if (-not $match.Success) { Fail-Contract 'JSON value is malformed' }
    $script:JsonIndex += $match.Length
}

function Assert-NoDuplicateJsonMembers([string]$Json, [string]$Name) {
    Assert-String $Json $Name
    $script:JsonText = $Json
    $script:JsonIndex = 0
    Read-JsonValue
    Skip-JsonWhitespace
    if ($script:JsonIndex -ne $script:JsonText.Length) { Fail-Contract "$Name has trailing JSON content" }
}

function Initialize-WinSightCfaBoundedCapture {
    if ($null -eq ('WinSightCfaBoundedCapture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class WinSightCfaBoundedCapture
{
    public string StandardOutput { get; private set; }
    public string StandardError { get; private set; }
    public int ExitCode { get; private set; }
    public bool TimedOut { get; private set; }
    public bool TreeCleanupSucceeded { get; private set; }
    public bool StreamTimedOut { get; private set; }
    public bool ExceededLimit { get; private set; }

    private sealed class BoundedText
    {
        public string Text;
        public bool Exceeded;
    }

    private static async Task<BoundedText> ReadBoundedAsync(StreamReader reader, int maximumCharacters)
    {
        var buffer = new char[4096];
        var text = new StringBuilder(Math.Min(maximumCharacters, 4096));
        var exceeded = false;
        while (true)
        {
            var read = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (read == 0) break;
            var remaining = maximumCharacters - text.Length;
            if (remaining > 0) text.Append(buffer, 0, Math.Min(remaining, read));
            if (read > remaining) exceeded = true;
        }
        return new BoundedText { Text = text.ToString(), Exceeded = exceeded };
    }

    private static class Native
    {
        internal const uint CreateSuspended = 0x00000004;
        internal const uint CreateNoWindow = 0x08000000;
        internal const uint HandleFlagInherit = 0x00000001;
        internal const uint JobObjectLimitKillOnJobClose = 0x00002000;
        internal const uint WaitObject0 = 0;
        internal const uint WaitFailed = 0xFFFFFFFF;
        internal const uint Infinite = 0xFFFFFFFF;
        internal const uint InvalidThreadResume = 0xFFFFFFFF;
        internal const uint GenericRead = 0x80000000;
        internal const uint FileShareRead = 0x00000001;
        internal const uint FileShareWrite = 0x00000002;
        internal const uint OpenExisting = 3;
        internal static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecurityAttributes
        {
            internal int Length;
            internal IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct StartupInfo
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal int dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessInformation
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal int dwProcessId;
            internal int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectBasicLimitInformation
        {
            internal long PerProcessUserTimeLimit;
            internal long PerJobUserTimeLimit;
            internal uint LimitFlags;
            internal UIntPtr MinimumWorkingSetSize;
            internal UIntPtr MaximumWorkingSetSize;
            internal uint ActiveProcessLimit;
            internal IntPtr Affinity;
            internal uint PriorityClass;
            internal uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IoCounters
        {
            internal ulong ReadOperationCount;
            internal ulong WriteOperationCount;
            internal ulong OtherOperationCount;
            internal ulong ReadTransferCount;
            internal ulong WriteTransferCount;
            internal ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct JobObjectExtendedLimitInformation
        {
            internal JobObjectBasicLimitInformation BasicLimitInformation;
            internal IoCounters IoInfo;
            internal UIntPtr ProcessMemoryLimit;
            internal UIntPtr JobMemoryLimit;
            internal UIntPtr PeakProcessMemoryUsed;
            internal UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreateProcess(
            string applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CreatePipe(
            out IntPtr readPipe,
            out IntPtr writePipe,
            ref SecurityAttributes pipeAttributes,
            uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            ref SecurityAttributes securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetInformationJobObject(
            IntPtr job,
            int jobObjectInformationClass,
            IntPtr jobObjectInformation,
            uint jobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool TerminateProcess(IntPtr process, uint exitCode);
    }

    private sealed class NativeCaptureProcess : IDisposable
    {
        private IntPtr _job;
        private IntPtr _process;
        private IntPtr _thread;

        public StreamReader StandardOutput { get; private set; }
        public StreamReader StandardError { get; private set; }

        private NativeCaptureProcess(IntPtr job, IntPtr process, IntPtr thread, StreamReader standardOutput, StreamReader standardError)
        {
            _job = job;
            _process = process;
            _thread = thread;
            StandardOutput = standardOutput;
            StandardError = standardError;
        }

        private static void ThrowLastWin32Error(string operation)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
        }

        private static IntPtr CreateKillOnCloseJob()
        {
            var job = Native.CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) ThrowLastWin32Error("CreateJobObject failed");
            var limits = new Native.JobObjectExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = Native.JobObjectLimitKillOnJobClose;
            var size = Marshal.SizeOf(typeof(Native.JobObjectExtendedLimitInformation));
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, buffer, false);
                if (!Native.SetInformationJobObject(job, 9, buffer, (uint)size)) ThrowLastWin32Error("SetInformationJobObject failed");
                return job;
            }
            catch
            {
                Native.CloseHandle(job);
                throw;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static NativeCaptureProcess Start(string executablePath)
        {
            IntPtr job = IntPtr.Zero;
            IntPtr standardOutputRead = IntPtr.Zero;
            IntPtr standardOutputWrite = IntPtr.Zero;
            IntPtr standardErrorRead = IntPtr.Zero;
            IntPtr standardErrorWrite = IntPtr.Zero;
            IntPtr standardInput = IntPtr.Zero;
            var processInformation = new Native.ProcessInformation();
            try
            {
                job = CreateKillOnCloseJob();
                var attributes = new Native.SecurityAttributes
                {
                    Length = Marshal.SizeOf(typeof(Native.SecurityAttributes)),
                    InheritHandle = true
                };
                if (!Native.CreatePipe(out standardOutputRead, out standardOutputWrite, ref attributes, 0)) ThrowLastWin32Error("CreatePipe for stdout failed");
                if (!Native.SetHandleInformation(standardOutputRead, Native.HandleFlagInherit, 0)) ThrowLastWin32Error("SetHandleInformation for stdout failed");
                if (!Native.CreatePipe(out standardErrorRead, out standardErrorWrite, ref attributes, 0)) ThrowLastWin32Error("CreatePipe for stderr failed");
                if (!Native.SetHandleInformation(standardErrorRead, Native.HandleFlagInherit, 0)) ThrowLastWin32Error("SetHandleInformation for stderr failed");
                standardInput = Native.CreateFile("NUL", Native.GenericRead, Native.FileShareRead | Native.FileShareWrite, ref attributes, Native.OpenExisting, 0, IntPtr.Zero);
                if (standardInput == Native.InvalidHandleValue) ThrowLastWin32Error("CreateFile for stdin failed");

                var startupInfo = new Native.StartupInfo
                {
                    cb = Marshal.SizeOf(typeof(Native.StartupInfo)),
                    dwFlags = 0x00000100,
                    hStdInput = standardInput,
                    hStdOutput = standardOutputWrite,
                    hStdError = standardErrorWrite
                };
                var commandLine = new StringBuilder("\"" + executablePath + "\" integrity --json");
                if (!Native.CreateProcess(executablePath, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                    Native.CreateSuspended | Native.CreateNoWindow, IntPtr.Zero, null, ref startupInfo, out processInformation))
                {
                    ThrowLastWin32Error("CreateProcess failed");
                }
                if (!Native.AssignProcessToJobObject(job, processInformation.hProcess)) ThrowLastWin32Error("AssignProcessToJobObject failed");
                if (Native.ResumeThread(processInformation.hThread) == Native.InvalidThreadResume) ThrowLastWin32Error("ResumeThread failed");

                Native.CloseHandle(standardOutputWrite); standardOutputWrite = IntPtr.Zero;
                Native.CloseHandle(standardErrorWrite); standardErrorWrite = IntPtr.Zero;
                Native.CloseHandle(standardInput); standardInput = IntPtr.Zero;
                var output = new StreamReader(new FileStream(new SafeFileHandle(standardOutputRead, true), FileAccess.Read, 4096, false), Encoding.UTF8, true, 4096);
                standardOutputRead = IntPtr.Zero;
                var error = new StreamReader(new FileStream(new SafeFileHandle(standardErrorRead, true), FileAccess.Read, 4096, false), Encoding.UTF8, true, 4096);
                standardErrorRead = IntPtr.Zero;
                var started = new NativeCaptureProcess(job, processInformation.hProcess, processInformation.hThread, output, error);
                job = IntPtr.Zero;
                processInformation.hProcess = IntPtr.Zero;
                processInformation.hThread = IntPtr.Zero;
                return started;
            }
            catch
            {
                if (processInformation.hProcess != IntPtr.Zero) Native.TerminateProcess(processInformation.hProcess, 1);
                throw;
            }
            finally
            {
                if (standardOutputRead != IntPtr.Zero) Native.CloseHandle(standardOutputRead);
                if (standardOutputWrite != IntPtr.Zero) Native.CloseHandle(standardOutputWrite);
                if (standardErrorRead != IntPtr.Zero) Native.CloseHandle(standardErrorRead);
                if (standardErrorWrite != IntPtr.Zero) Native.CloseHandle(standardErrorWrite);
                if (standardInput != IntPtr.Zero && standardInput != Native.InvalidHandleValue) Native.CloseHandle(standardInput);
                if (processInformation.hThread != IntPtr.Zero) Native.CloseHandle(processInformation.hThread);
                if (processInformation.hProcess != IntPtr.Zero) Native.CloseHandle(processInformation.hProcess);
                if (job != IntPtr.Zero) Native.CloseHandle(job);
            }
        }

        public bool WaitForExit(int timeoutMilliseconds)
        {
            var result = Native.WaitForSingleObject(_process, (uint)timeoutMilliseconds);
            if (result == Native.WaitObject0) return true;
            if (result == Native.WaitFailed) ThrowLastWin32Error("WaitForSingleObject failed");
            return false;
        }

        public int GetExitCode()
        {
            int exitCode;
            if (!Native.GetExitCodeProcess(_process, out exitCode)) ThrowLastWin32Error("GetExitCodeProcess failed");
            return exitCode;
        }

        public bool CloseProcessGroup()
        {
            if (_job == IntPtr.Zero) return false;
            var job = _job;
            _job = IntPtr.Zero;
            return Native.CloseHandle(job);
        }

        public void Dispose()
        {
            StandardOutput.Close();
            StandardError.Close();
            CloseProcessGroup();
            if (_thread != IntPtr.Zero) { Native.CloseHandle(_thread); _thread = IntPtr.Zero; }
            if (_process != IntPtr.Zero) { Native.CloseHandle(_process); _process = IntPtr.Zero; }
        }
    }

    public static WinSightCfaBoundedCapture Run(string executablePath, int timeoutMilliseconds, int maximumCharacters)
    {
        using (var process = NativeCaptureProcess.Start(executablePath))
        {
            var stopwatch = Stopwatch.StartNew();
            var outputTask = ReadBoundedAsync(process.StandardOutput, maximumCharacters);
            var errorTask = ReadBoundedAsync(process.StandardError, maximumCharacters);
            var timedOut = !process.WaitForExit(timeoutMilliseconds);
            var treeCleanupSucceeded = true;
            var remainingMilliseconds = Math.Max(0, timeoutMilliseconds - (int)stopwatch.ElapsedMilliseconds);
            var streamsCompleted = Task.WaitAll(new Task[] { outputTask, errorTask }, remainingMilliseconds);
            var streamTimedOut = !streamsCompleted;
            if (timedOut || streamTimedOut)
            {
                var groupClosed = process.CloseProcessGroup();
                var parentExited = process.WaitForExit(5000);
                var streamsDrained = Task.WaitAll(new Task[] { outputTask, errorTask }, 5000);
                treeCleanupSucceeded = groupClosed && parentExited && streamsDrained;
                if (!streamsDrained)
                {
                    process.StandardOutput.Close();
                    process.StandardError.Close();
                }
                return new WinSightCfaBoundedCapture
                {
                    StandardOutput = String.Empty,
                    StandardError = String.Empty,
                    ExitCode = -1,
                    TimedOut = timedOut,
                    TreeCleanupSucceeded = treeCleanupSucceeded,
                    StreamTimedOut = streamTimedOut,
                    ExceededLimit = false
                };
            }
            var output = outputTask.GetAwaiter().GetResult();
            var error = errorTask.GetAwaiter().GetResult();
            return new WinSightCfaBoundedCapture
            {
                StandardOutput = output.Text,
                StandardError = error.Text,
                ExitCode = process.GetExitCode(),
                TimedOut = timedOut,
                TreeCleanupSucceeded = treeCleanupSucceeded,
                StreamTimedOut = false,
                ExceededLimit = output.Exceeded || error.Exceeded
            };
        }
    }
}
'@
    }
}

function Get-CanonicalRawState([object]$Value) {
    if ($null -eq $Value) { return $null }
    Assert-String $Value 'rawStateValue'
    if ($Value -notmatch '^-?(0|[1-9][0-9]*)$') { Fail-Contract 'rawStateValue is not a canonical signed integer' }
    try { return [int]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture) }
    catch { Fail-Contract 'rawStateValue is outside the signed 32-bit range' }
}

function Get-CanonicalAntivirusInteger([object]$Value, [string]$Name) {
    Assert-String $Value $Name
    if ($Value -notmatch '^-?(0|[1-9][0-9]*)$') { Fail-Contract "$Name is not a canonical signed integer" }
    try { return [int]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture) }
    catch { Fail-Contract "$Name is outside the signed 32-bit range" }
}

function Get-CanonicalAntivirusCount([object]$Value, [string]$Name) {
    $count = Get-CanonicalAntivirusInteger $Value $Name
    if ($count -lt 0 -or $count -gt $script:MaximumAntivirusProducts) { Fail-Contract "$Name is outside the supported product range" }
    return $count
}

function Assert-NullableAntivirusNames([object]$Value, [string]$Name) {
    if ($null -eq $Value) { return }
    Assert-BoundedString $Value $Name $script:MaximumJoinedAntivirusAliasLength
}

function Join-AntivirusNames([object[]]$Products) {
    if ($Products.Count -eq 0) { return $null }
    return [string]::Join(', ', @($Products | ForEach-Object { $_.Name }))
}

function Test-MicrosoftDefenderName([string]$Name) {
    return $Name.IndexOf('Windows Defender', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $Name.IndexOf('Microsoft Defender', [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Assert-ExpectedField([object]$Actual, [object]$Expected, [string]$Name) {
    if ($null -eq $Expected) {
        if ($null -ne $Actual) { Fail-Contract "$Name must be null" }
    }
    elseif ($Actual -cne $Expected) { Fail-Contract "$Name contradicts the canonical antivirus item" }
}

function Assert-AntivirusItem([object]$Item) {
    Assert-ExactProperties -Object $Item -Expected @('severity', 'title', 'detail', 'fields') -Name 'antivirus item'
    Assert-ClosedValue -Value $Item.severity -Allowed @('info', 'notable') -Name 'antivirus severity'
    Assert-String $Item.title 'antivirus title'
    Assert-String $Item.detail 'antivirus detail'
    if ($Item.title -cne 'Antivirus protection (Windows Security Center)') {
        Fail-Contract 'antivirus title is not the stable report identity'
    }

    $fields = $Item.fields
    Assert-String $fields.protection 'antivirus protection'
    if ($fields.protection -cne 'Antivirus') { Fail-Contract 'antivirus protection identity is invalid' }
    Assert-ClosedValue -Value $fields.reading -Allowed $script:SecurityCenterReadings -Name 'antivirus reading'
    Assert-ClosedValue -Value $fields.concern -Allowed $script:AntiVirusConcerns -Name 'antivirus concern'
    Assert-NullableAntivirusNames $fields.registeredAntivirus 'registeredAntivirus'
    Assert-NullableAntivirusNames $fields.activeAntivirus 'activeAntivirus'
    Assert-NullableAntivirusNames $fields.onAntivirus 'antivirus onAntivirus'
    Assert-CanonicalBoolean $fields.hasActiveNonMicrosoftAntivirus 'hasActiveNonMicrosoftAntivirus'

    $registeredCount = Get-CanonicalAntivirusCount $fields.registeredAntivirusCount 'registeredAntivirusCount'
    $expectedFields = @($script:AntivirusFieldNames)
    for ($index = 0; $index -lt $registeredCount; $index++) {
        $prefix = "antivirusProduct.$index."
        $expectedFields += @("${prefix}name", "${prefix}activity", "${prefix}signature", "${prefix}rawActivity", "${prefix}rawSignature", "${prefix}legacyRawProductState")
    }
    Assert-ExactProperties -Object $fields -Expected $expectedFields -Name 'antivirus fields'

    $products = @()
    for ($index = 0; $index -lt $registeredCount; $index++) {
        $prefix = "antivirusProduct.$index."
        Assert-BoundedString $fields."${prefix}name" "${prefix}name" $script:MaximumAntivirusNameLength
        Assert-ClosedValue -Value $fields."${prefix}activity" -Allowed $script:AntivirusActivities -Name "${prefix}activity"
        Assert-ClosedValue -Value $fields."${prefix}signature" -Allowed $script:AntivirusSignatures -Name "${prefix}signature"
        $rawActivity = Get-CanonicalAntivirusInteger $fields."${prefix}rawActivity" "${prefix}rawActivity"
        $rawSignature = Get-CanonicalAntivirusInteger $fields."${prefix}rawSignature" "${prefix}rawSignature"
        if ($fields."${prefix}legacyRawProductState" -cne '0') {
            Fail-Contract "${prefix}legacyRawProductState is not the documented COM legacy sentinel"
        }
        $activity = $fields."${prefix}activity"
        $signature = $fields."${prefix}signature"
        $expectedRawActivity = @{ 'On' = 0; 'Off' = 1; 'Snoozed' = 2; 'Expired' = 3 }
        if ($activity -ceq 'Unknown') {
            if ($rawActivity -in @(0, 1, 2, 3)) { Fail-Contract "${prefix}rawActivity contradicts Unknown activity" }
        }
        elseif ($rawActivity -ne $expectedRawActivity[$activity]) { Fail-Contract "${prefix}rawActivity contradicts activity" }
        if ($signature -ceq 'Unknown') {
            if ($rawSignature -in @(0, 1)) { Fail-Contract "${prefix}rawSignature contradicts Unknown signature" }
        }
        elseif ($rawSignature -ne (@{ 'UpToDate' = 1; 'OutOfDate' = 0 })[$signature]) {
            Fail-Contract "${prefix}rawSignature contradicts signature"
        }
        $products += [pscustomobject]@{
            Name = $fields."${prefix}name"
            Activity = $activity
            Signature = $signature
            IsMicrosoftDefender = Test-MicrosoftDefenderName $fields."${prefix}name"
        }
    }

    $onProducts = @($products | Where-Object { $_.Activity -ceq 'On' })
    $unknownProducts = @($products | Where-Object { $_.Activity -ceq 'Unknown' })
    $onThirdPartyProducts = @($onProducts | Where-Object { -not $_.IsMicrosoftDefender })
    $protectedThirdPartyProducts = @($onThirdPartyProducts | Where-Object { $_.Signature -ceq 'UpToDate' })
    if ($fields.reading -ceq 'Unavailable' -and $products.Count -ne 0) {
        Fail-Contract 'unavailable Security Center item contains canonical product evidence'
    }
    $expectedConcern = if ($fields.reading -ceq 'Unavailable') { 'Unavailable' }
        elseif ($products.Count -eq 0) { 'NoAntiVirusRegistered' }
        elseif (@($onProducts | Where-Object { $_.Signature -ceq 'UpToDate' }).Count -gt 0) { 'Protected' }
        elseif ($unknownProducts.Count -gt 0) { 'ActivityStatusUnknown' }
        elseif (@($onProducts | Where-Object { $_.Signature -ceq 'Unknown' }).Count -gt 0) { 'SignatureStatusUnknown' }
        elseif ($onProducts.Count -gt 0) { 'SignaturesOutOfDate' }
        else { 'NoActiveAntiVirus' }
    if ($fields.concern -cne $expectedConcern) { Fail-Contract 'antivirus concern contradicts canonical product evidence' }
    if (($Item.severity -ceq 'info') -ne ($expectedConcern -ceq 'Protected')) {
        Fail-Contract 'antivirus severity contradicts canonical concern'
    }

    $expectedCounts = @{
        'activeAntivirusCount' = $onProducts.Count
        'onAntivirusCount' = $onProducts.Count
        'registeredAntivirusCount' = $products.Count
        'offAntivirusCount' = @($products | Where-Object { $_.Activity -ceq 'Off' }).Count
        'snoozedAntivirusCount' = @($products | Where-Object { $_.Activity -ceq 'Snoozed' }).Count
        'expiredAntivirusCount' = @($products | Where-Object { $_.Activity -ceq 'Expired' }).Count
        'activityUnknownAntivirusCount' = $unknownProducts.Count
        'signatureUnknownAntivirusCount' = @($products | Where-Object { $_.Signature -ceq 'Unknown' }).Count
    }
    foreach ($name in $expectedCounts.Keys) {
        if ((Get-CanonicalAntivirusCount $fields.$name $name) -ne $expectedCounts[$name]) {
            Fail-Contract "$name contradicts the canonical indexed products"
        }
    }
    Assert-ExpectedField $fields.registeredAntivirus (Join-AntivirusNames $products) 'registeredAntivirus'
    Assert-ExpectedField $fields.activeAntivirus (Join-AntivirusNames $onProducts) 'activeAntivirus'
    Assert-ExpectedField $fields.onAntivirus (Join-AntivirusNames $onProducts) 'antivirus onAntivirus'
    if (($fields.hasActiveNonMicrosoftAntivirus -ceq 'True') -ne ($onThirdPartyProducts.Count -gt 0)) {
        Fail-Contract 'hasActiveNonMicrosoftAntivirus contradicts canonical indexed products'
    }

    return [pscustomobject]@{
        Reading = $fields.reading
        Concern = $expectedConcern
        OnAntivirus = Join-AntivirusNames $onProducts
        ActivityUnknownAntivirus = Join-AntivirusNames $unknownProducts
        OnThirdPartyAntivirus = Join-AntivirusNames $onThirdPartyProducts
        ProtectedThirdPartyAntivirus = Join-AntivirusNames $protectedThirdPartyProducts
    }
}

function Assert-CfaItem([object]$Item, [object]$Antivirus) {
    Assert-ExactProperties -Object $Item -Expected @('severity', 'title', 'detail', 'fields') -Name 'CFA item'
    Assert-ClosedValue -Value $Item.severity -Allowed @('info', 'notable') -Name 'CFA severity'
    Assert-String $Item.title 'CFA title'
    Assert-String $Item.detail 'CFA detail'
    if ($Item.title -cne 'Controlled Folder Access (ransomware shield)') {
        Fail-Contract 'CFA title is not the stable report identity'
    }

    Assert-ExactProperties -Object $Item.fields -Expected $script:CfaFieldNames -Name 'CFA fields'
    $fields = $Item.fields
    if ($fields.protection -cne 'Controlled Folder Access') { Fail-Contract 'CFA protection identity is invalid' }
    Assert-ClosedValue -Value $fields.state -Allowed $script:States -Name 'state'
    Assert-ClosedValue -Value $fields.concern -Allowed $script:Concerns -Name 'concern'
    Assert-CanonicalBoolean $fields.runtimeSupportsProtection 'runtimeSupportsProtection'
    Assert-ClosedValue -Value $fields.allowedApplicationsVisibility -Allowed $script:Visibilities -Name 'allowedApplicationsVisibility'
    Assert-ClosedValue -Value $fields.securityCenterReading -Allowed $script:SecurityCenterReadings -Name 'securityCenterReading'
    Assert-ClosedValue -Value $fields.antivirusConcern -Allowed $script:AntiVirusConcerns -Name 'antivirusConcern'
    Assert-ExpectedField $fields.securityCenterReading $Antivirus.Reading 'securityCenterReading'
    Assert-ExpectedField $fields.antivirusConcern $Antivirus.Concern 'antivirusConcern'
    Assert-ExpectedField $fields.onAntivirus $Antivirus.OnAntivirus 'onAntivirus'
    Assert-ExpectedField $fields.activityUnknownAntivirus $Antivirus.ActivityUnknownAntivirus 'activityUnknownAntivirus'
    Assert-ExpectedField $fields.onThirdPartyAntivirus $Antivirus.OnThirdPartyAntivirus 'onThirdPartyAntivirus'
    Assert-ExpectedField $fields.protectedThirdPartyAntivirus $Antivirus.ProtectedThirdPartyAntivirus 'protectedThirdPartyAntivirus'

    # An unreadable Security Center establishes nothing, so it must not name a product or claim a
    # posture. This is the shape of the defect the whole antivirus milestone was raised against:
    # turning absent evidence into a verdict.
    if ($fields.securityCenterReading -ceq 'Unavailable') {
        if ($fields.antivirusConcern -cne 'Unavailable') {
            Fail-Contract 'unreadable Security Center reports an antivirus concern other than Unavailable'
        }
        foreach ($name in @('protectedThirdPartyAntivirus', 'onThirdPartyAntivirus', 'onAntivirus', 'activityUnknownAntivirus')) {
            if (-not [string]::IsNullOrEmpty($fields.$name)) {
                Fail-Contract "unreadable Security Center still names products in $name"
            }
        }
    }

    # Naming a third-party product as protecting is the single most reassuring thing this item can
    # say. It is allowed only when the concern actually established protection.
    if (-not [string]::IsNullOrEmpty($fields.protectedThirdPartyAntivirus) -and
        $fields.antivirusConcern -cne 'Protected') {
        Fail-Contract 'a protected third-party antivirus is named without a Protected antivirus concern'
    }

    # Every protected third-party product must also be one Security Center reports On: the protected
    # set is a subset of the On set, and a name appearing only in the former is unsourced.
    if (-not [string]::IsNullOrEmpty($fields.protectedThirdPartyAntivirus) -and
        [string]::IsNullOrEmpty($fields.onThirdPartyAntivirus)) {
        Fail-Contract 'a protected third-party antivirus is named while none is reported On'
    }
    Assert-String $fields.protectedFolders 'protectedFolders'
    if ($fields.protectedFolders -notmatch '^(0|[1-9][0-9]*)$') { Fail-Contract 'protectedFolders is not a bounded count' }
    if ($fields.settingsDeepLink -cne 'windowsdefender://RansomwareProtection') {
        Fail-Contract 'settingsDeepLink is invalid'
    }

    $rawState = Get-CanonicalRawState $fields.rawStateValue
    $state = $fields.state
    $concern = $fields.concern
    if ($state -ceq 'Unavailable') {
        if ($concern -cne 'Unavailable' -or $Item.severity -cne 'notable' -or
            $fields.runtimeSupportsProtection -cne 'False' -or
            $fields.allowedApplicationsVisibility -cne 'Unavailable' -or
            $fields.protectedFolders -cne '0' -or
            $null -ne $fields.amRunningMode -or $null -ne $fields.antivirusEnabled -or
            $null -ne $fields.realTimeProtectionEnabled) {
            Fail-Contract 'Unavailable CFA is hidden or internally contradictory'
        }
        return [pscustomobject]@{
            State = $state; Concern = $concern; RawStateValue = $rawState
            RuntimeSupportsProtection = $false; AllowedApplicationsVisibility = $fields.allowedApplicationsVisibility
            ProtectedFolderCount = [int]$fields.protectedFolders
        }
    }

    if ($null -eq $rawState) { Fail-Contract 'available CFA state is missing rawStateValue' }
    Assert-ClosedValue -Value $fields.amRunningMode -Allowed $script:RuntimeModes -Name 'amRunningMode'
    Assert-CanonicalBoolean $fields.antivirusEnabled 'antivirusEnabled'
    Assert-CanonicalBoolean $fields.realTimeProtectionEnabled 'realTimeProtectionEnabled'
    if ($fields.allowedApplicationsVisibility -ceq 'Unavailable') {
        Fail-Contract 'available CFA state has unavailable allowed-applications visibility'
    }
    $runtimeActuallySupportsProtection = $fields.amRunningMode -ceq 'Normal' -and
        $fields.antivirusEnabled -ceq 'True' -and $fields.realTimeProtectionEnabled -ceq 'True'
    if (($fields.runtimeSupportsProtection -ceq 'True') -ne $runtimeActuallySupportsProtection) {
        Fail-Contract 'runtimeSupportsProtection contradicts the measured runtime fields'
    }

    $expectedByState = @{
        'Disabled' = @{ Raw = 0; Concern = 'Off' }
        'Audit' = @{ Raw = 2; Concern = 'AuditOnly' }
        'BlockDiskModificationOnly' = @{ Raw = 3; Concern = 'BlockDiskModificationOnly' }
        'AuditDiskModificationOnly' = @{ Raw = 4; Concern = 'AuditDiskModificationOnly' }
    }
    # Defender reporting that it is not running outranks the configured value, exactly as
    # ControlledFolderAccessTriage.Concern does: CFA is a Defender feature, so with the antivirus
    # stopped no configured mode protects anything. The raw value must still survive the read.
    if ($fields.amRunningMode -ceq 'Not running') {
        if ($concern -cne 'DefenderNotRunning' -or $fields.runtimeSupportsProtection -cne 'False') {
            Fail-Contract 'Defender reporting Not running is not reported as DefenderNotRunning'
        }
        $rawByState = @{
            'Disabled' = 0; 'Enabled' = 1; 'Audit' = 2
            'BlockDiskModificationOnly' = 3; 'AuditDiskModificationOnly' = 4
        }
        if ($state -ceq 'Unknown') {
            if ($rawState -in @(0, 1, 2, 3, 4)) {
                Fail-Contract 'Unknown CFA state does not retain an unsupported raw value'
            }
        }
        elseif (-not $rawByState.ContainsKey($state)) { Fail-Contract 'CFA state is unsupported by this contract' }
        elseif ($rawState -ne $rawByState[$state]) { Fail-Contract "$state CFA has an invalid rawStateValue" }
    }
    elseif ($state -ceq 'Unknown') {
        if ($rawState -in @(0, 1, 2, 3, 4) -or $concern -cne 'UnknownMode') {
            Fail-Contract 'Unknown CFA state does not retain an unsupported raw value'
        }
    }
    elseif ($state -ceq 'Enabled') {
        if ($rawState -ne 1) { Fail-Contract 'Enabled CFA has an invalid rawStateValue' }
        $protectingEvidence = $fields.amRunningMode -ceq 'Normal' -and
            $fields.antivirusEnabled -ceq 'True' -and $fields.realTimeProtectionEnabled -ceq 'True'
        if ($protectingEvidence) {
            if ($concern -cne 'Protecting' -or $fields.runtimeSupportsProtection -cne 'True') {
                Fail-Contract 'positive CFA runtime evidence is not reported as Protecting'
            }
        }
        elseif ($concern -cne 'RuntimeRequirementsNotMet' -or $fields.runtimeSupportsProtection -cne 'False') {
            Fail-Contract 'Enabled CFA runtime shortfall is internally contradictory'
        }
    }
    elseif ($expectedByState.ContainsKey($state)) {
        $expected = $expectedByState[$state]
        if ($rawState -ne $expected.Raw -or $concern -cne $expected.Concern) {
            Fail-Contract "$state CFA has an invalid raw state or concern"
        }
    }
    else { Fail-Contract 'CFA state is unsupported by this contract' }

    if ($concern -ceq 'Protecting') {
        if ($Item.severity -cne 'info') { Fail-Contract 'Protecting CFA is not informational' }
    }
    elseif ($Item.severity -cne 'notable') { Fail-Contract 'non-protecting CFA is hidden as informational' }

    return [pscustomobject]@{
        State = $state; Concern = $concern; RawStateValue = $rawState
        RuntimeSupportsProtection = ($fields.runtimeSupportsProtection -ceq 'True')
        AllowedApplicationsVisibility = $fields.allowedApplicationsVisibility
        ProtectedFolderCount = [int]$fields.protectedFolders
    }
}

function Get-Input([string]$Path, [string]$Cli) {
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail-Contract 'InputJsonPath does not identify a file' }
        if ((Get-Item -LiteralPath $Path).Length -gt $script:MaximumFixtureCharacters) { Fail-Contract 'InputJsonPath exceeds the bounded fixture size' }
        $fixtureJson = Get-Content -LiteralPath $Path -Raw
        Assert-NoDuplicateJsonMembers $fixtureJson 'fixture JSON'
        try { $fixture = $fixtureJson | ConvertFrom-Json }
        catch { Fail-Contract 'InputJsonPath is not valid JSON' }
        Assert-ExactProperties -Object $fixture -Expected @('exitCode', 'stdout', 'stderr', 'operatingSystem') -Name 'fixture'
        if ($fixture.exitCode -isnot [long] -and $fixture.exitCode -isnot [int]) { Fail-Contract 'fixture exitCode must be an integer' }
        if ($fixture.exitCode -lt [int]::MinValue -or $fixture.exitCode -gt [int]::MaxValue) { Fail-Contract 'fixture exitCode is outside the signed 32-bit range' }
        Assert-String $fixture.stdout 'fixture stdout'
        Assert-String $fixture.stderr 'fixture stderr'
        if ($fixture.stdout.Length -gt $script:MaximumCaptureCharacters -or $fixture.stderr.Length -gt $script:MaximumCaptureCharacters) {
            Fail-Contract 'fixture stdout or stderr exceeds the bounded capture limit'
        }
        Assert-ExactProperties -Object $fixture.operatingSystem -Expected @('product', 'version', 'build', 'architecture') -Name 'fixture operatingSystem'
        foreach ($property in @('product', 'version', 'build', 'architecture')) {
            Assert-BoundedString $fixture.operatingSystem.$property "fixture operatingSystem.$property" $script:MaximumOperatingSystemFactCharacters
        }
        return [pscustomobject]@{
            ExitCode = [int]$fixture.exitCode
            StdOut = [string]$fixture.stdout
            StdErr = [string]$fixture.stderr
            OperatingSystem = [ordered]@{
                Product = [string]$fixture.operatingSystem.product
                Version = [string]$fixture.operatingSystem.version
                Build = [string]$fixture.operatingSystem.build
                Architecture = [string]$fixture.operatingSystem.architecture
            }
            Source = 'fixture'
        }
    }

    if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { Fail-Contract 'CliPath does not identify a file' }
    Initialize-WinSightCfaBoundedCapture
    $capture = [WinSightCfaBoundedCapture]::Run($Cli, $script:LiveTimeoutMilliseconds, $script:MaximumCaptureCharacters)
    if (-not $capture.TreeCleanupSucceeded) { Fail-Contract 'CLI process-tree cleanup did not succeed' }
    if ($capture.TimedOut) { Fail-Contract 'CLI exceeded the finite provider timeout' }
    if ($capture.StreamTimedOut) { Fail-Contract 'CLI streams exceeded the finite provider timeout' }
    if ($capture.ExceededLimit) { Fail-Contract 'CLI stdout or stderr exceeded the bounded capture limit' }
    if (-not [string]::IsNullOrEmpty($capture.StandardError)) { Fail-Contract 'CLI wrote an unexpected stderr diagnostic' }
    return [pscustomobject]@{
        ExitCode = $capture.ExitCode
        StdOut = $capture.StandardOutput
        StdErr = $capture.StandardError
        OperatingSystem = $null
        Source = 'live-cli'
    }
}

function Get-HostFacts {
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    catch { Fail-Contract 'unable to read host operating-system facts' }
    if ($null -eq $os) { Fail-Contract 'host operating-system facts are incomplete' }
    Assert-BoundedString ([string]$os.Caption) 'host operating-system product' $script:MaximumOperatingSystemFactCharacters
    Assert-BoundedString ([string]$os.Version) 'host operating-system version' $script:MaximumOperatingSystemFactCharacters
    Assert-BoundedString ([string]$os.BuildNumber) 'host operating-system build' $script:MaximumOperatingSystemFactCharacters
    Assert-BoundedString ([string]$os.OSArchitecture) 'host operating-system architecture' $script:MaximumOperatingSystemFactCharacters
    return [ordered]@{
        Product = [string]$os.Caption
        Version = [string]$os.Version
        Build = [string]$os.BuildNumber
        Architecture = [string]$os.OSArchitecture
    }
}

try {
    $fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = [System.IO.Path]::GetDirectoryName($fullOutputPath)
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    if (Test-Path -LiteralPath $fullOutputPath) { Fail-Contract 'OutputPath already exists; refusing to overwrite evidence' }

    $probeResult = Get-Input $InputJsonPath $CliPath
    if ($probeResult.ExitCode -notin @(0, 1)) { Fail-Contract 'CLI exit code is not a documented report exit' }
    if (-not [string]::IsNullOrEmpty($probeResult.StdErr)) { Fail-Contract 'CLI wrote an unexpected stderr diagnostic' }
    if ($probeResult.StdOut -notmatch '^\s*\[') { Fail-Contract 'CLI stdout is not a JSON report array' }
    Assert-NoDuplicateJsonMembers $probeResult.StdOut 'CLI stdout'
    try {
        $reports = @($probeResult.StdOut | ConvertFrom-Json)
        # Windows PowerShell 5.1 preserves a JSON root array as one array object here,
        # whereas newer PowerShell versions enumerate it. Normalize both behaviors.
        if ($reports.Count -eq 1 -and $reports[0] -is [System.Array]) { $reports = @($reports[0]) }
    }
    catch { Fail-Contract 'CLI stdout is malformed JSON' }
    if ($reports.Count -ne 1) { Fail-Contract 'CLI output must contain exactly one integrity report' }
    $report = $reports[0]
    Assert-ExactProperties -Object $report -Expected @('tool', 'summary', 'items', 'notableCount') -Name 'integrity report'
    if ($report.tool -cne 'integrity') { Fail-Contract 'report tool is not integrity' }
    Assert-String $report.summary 'report summary'
    $items = @($report.items)
    if ($items.Count -eq 1 -and $items[0] -is [System.Array]) { $items = @($items[0]) }
    $reportedNotableCount = Get-NonNegativeCount $report.notableCount 'notableCount'
    $actualNotableCount = 0
    foreach ($item in $items) {
        if ($null -eq $item -or @($item.PSObject.Properties | ForEach-Object { $_.Name }) -cnotcontains 'severity') {
            Fail-Contract 'report item is missing severity'
        }
        Assert-ClosedValue -Value $item.severity -Allowed @('info', 'notable') -Name 'report item severity'
        if ($item.severity -ceq 'notable') { $actualNotableCount++ }
    }
    if ($reportedNotableCount -ne $actualNotableCount) {
        Fail-Contract 'notableCount contradicts report item severities'
    }
    $cfaItems = @($items | Where-Object {
            if ($null -eq $_.fields) { return $false }
            $fieldNames = @($_.fields.PSObject.Properties | ForEach-Object { $_.Name })
            $fieldNames -ccontains 'protection' -and $_.fields.protection -ceq 'Controlled Folder Access'
        })
    if ($cfaItems.Count -ne 1) { Fail-Contract 'report must contain exactly one Controlled Folder Access item' }
    $antivirusItems = @($items | Where-Object {
            if ($null -eq $_.fields) { return $false }
            $fieldNames = @($_.fields.PSObject.Properties | ForEach-Object { $_.Name })
            $fieldNames -ccontains 'protection' -and $_.fields.protection -ceq 'Antivirus'
        })
    if ($antivirusItems.Count -ne 1) { Fail-Contract 'report must contain exactly one canonical antivirus item' }
    $antivirus = Assert-AntivirusItem $antivirusItems[0]
    $cfa = Assert-CfaItem $cfaItems[0] $antivirus
    $expectedExit = if ($reportedNotableCount -eq 0) { 0 } else { 1 }
    if ($probeResult.ExitCode -ne $expectedExit) { Fail-Contract 'CLI exit code contradicts whole-report notableCount' }

    $evidence = [ordered]@{
        SchemaVersion = 1
        Probe = 'cfa-provider'
        Source = $probeResult.Source
        CliExitCode = $probeResult.ExitCode
        ReportNotableCount = $reportedNotableCount
        OperatingSystem = if ($null -ne $probeResult.OperatingSystem) { $probeResult.OperatingSystem } else { Get-HostFacts }
        ControlledFolderAccess = [ordered]@{
            State = $cfa.State
            Concern = $cfa.Concern
            RawStateValue = $cfa.RawStateValue
            RuntimeSupportsProtection = $cfa.RuntimeSupportsProtection
            AllowedApplicationsVisibility = $cfa.AllowedApplicationsVisibility
            ProtectedFolderCount = $cfa.ProtectedFolderCount
        }
    }
    $json = ConvertTo-Json -InputObject $evidence -Depth 6
    [System.IO.File]::WriteAllText($fullOutputPath, $json, [System.Text.UTF8Encoding]::new($false))
    Write-Output $fullOutputPath
    exit 0
}
catch {
    [Console]::Error.WriteLine(('CFA provider contract failed: {0}' -f $_.Exception.Message))
    exit 1
}
