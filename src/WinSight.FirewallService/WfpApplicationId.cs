using System.Text;

namespace WinSight.FirewallService;

/// <summary>
/// Derives the <c>FWPM_CONDITION_ALE_APP_ID</c> value for an executable path from the path alone,
/// for the case <c>FwpmGetAppIdFromFileName0</c> cannot.
/// </summary>
/// <remarks>
/// <b>Why a fallback exists at all.</b> <c>FwpmGetAppIdFromFileName0</c> opens the file to learn
/// which volume it sits on, so it fails the moment the binary is absent — a removed application, an
/// unplugged USB volume, an offline UNC share. <c>WfpProvisioning</c> turned that into a
/// <see cref="System.ComponentModel.Win32Exception"/>, and the coordinator classified any such
/// exception as a failed transition, which rolled the whole policy back to audit-only, removed
/// every filter and reset the service to demand-start. One unresolvable entry disarmed enforcement
/// for every application, persistently — an attacker only had to delete their own blocked binary
/// and cause the service to reconcile.
///
/// <b>The app id is a path, not a file handle.</b> WFP's application id is the target's NT path in
/// lower case, UTF-16, including its terminating null. Nothing in that requires the file to exist;
/// only the DOS-drive-to-NT-device mapping does, and that belongs to the volume, not the file. So
/// the same bytes are rebuilt from <c>QueryDosDeviceW</c>, and the filter survives the binary's
/// absence rather than the policy dying with it. When the application returns, the id BFE computes
/// for the running image is the one already installed, so the block is still in force — which the
/// previous behaviour, having deleted the filter, could not claim.
///
/// <b>The native call stays the source of truth.</b> This runs only after it has refused, so a
/// healthy machine's filters are built from exactly the bytes WFP itself produces, and this code
/// never gets to disagree with it.
///
/// <b>The WFP interop is deliberately not repeated here.</b> <c>QueryDosDeviceW</c> is a kernel32
/// volume lookup, not a filtering-engine call, so this does not become the third home for WFP
/// declarations that <c>WfpInteropDuplicationTests</c> exists to prevent.
/// </remarks>
internal static partial class WfpApplicationId
{
    /// <summary>Upper bound on an app id blob, in bytes. A UTF-16 NT path cannot exceed this.</summary>
    internal const int MaxAppIdBytes = 64 * 1024;

    /// <summary>
    /// The app id for <paramref name="executablePath"/>, or <see langword="false"/> when the path
    /// cannot be mapped to an NT device path at all.
    /// </summary>
    internal static bool TryDerive(string executablePath, out byte[] appId) =>
        TryDerive(executablePath, QueryDosDevice, out appId);

    /// <summary>
    /// Builds the app id given a DOS-device resolver. Pure apart from the resolver, so the
    /// byte-level shape is testable without WFP, without elevation and without an existing file.
    /// </summary>
    /// <param name="executablePath">A fully qualified local path, e.g. <c>C:\apps\a.exe</c>.</param>
    /// <param name="queryDosDevice">Maps <c>"C:"</c> to <c>@"\Device\HarddiskVolume3"</c>.</param>
    /// <param name="appId">Lower-case NT path as null-terminated UTF-16 bytes.</param>
    internal static bool TryDerive(
        string executablePath,
        Func<string, string?> queryDosDevice,
        out byte[] appId)
    {
        ArgumentNullException.ThrowIfNull(queryDosDevice);
        appId = [];
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        // An NT path the caller already holds needs no mapping, only the casing and terminator.
        if (executablePath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            appId = Encode(executablePath);
            return appId.Length <= MaxAppIdBytes;
        }

        // Only a local drive-letter path has a device mapping. A UNC share reaches the network
        // redirector rather than a volume, and guessing one would install a filter matching nothing
        // while the status claimed the application was blocked.
        if (executablePath.Length < 3
            || !char.IsAsciiLetter(executablePath[0])
            || executablePath[1] != ':'
            || (executablePath[2] != '\\' && executablePath[2] != '/'))
        {
            return false;
        }

        string? device;
        try
        {
            device = queryDosDevice(executablePath[..2]);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return false;
        }
        if (string.IsNullOrEmpty(device) || !device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var remainder = executablePath[2..].Replace('/', '\\');
        appId = Encode(device.TrimEnd('\\') + remainder);
        return appId.Length <= MaxAppIdBytes;
    }

    /// <summary>
    /// WFP compares application ids as raw bytes, and the ids it derives itself are lower-cased and
    /// null-terminated. Both properties are part of the value, not cosmetic.
    /// </summary>
    private static byte[] Encode(string ntPath)
    {
        var normalized = ntPath.ToLowerInvariant();
        var bytes = new byte[(normalized.Length + 1) * 2];
        Encoding.Unicode.GetBytes(normalized, 0, normalized.Length, bytes, 0);
        return bytes;
    }

    private static string? QueryDosDevice(string driveWithColon)
    {
        // QueryDosDeviceW writes a REG_MULTI_SZ-style buffer; the first entry is the mapping.
        var buffer = new char[512];
        var length = NativeMethods.QueryDosDeviceW(driveWithColon, buffer, buffer.Length);
        if (length == 0)
        {
            return null;
        }
        var span = buffer.AsSpan(0, (int)Math.Min(length, (uint)buffer.Length));
        var terminator = span.IndexOf('\0');
        return new string(terminator >= 0 ? span[..terminator] : span);
    }

    private static partial class NativeMethods
    {
        [System.Runtime.InteropServices.LibraryImport(
            "kernel32.dll",
            EntryPoint = "QueryDosDeviceW",
            StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf16,
            SetLastError = true)]
        internal static partial uint QueryDosDeviceW(
            string deviceName,
            [System.Runtime.InteropServices.Out] char[] targetPath,
            int max);
    }
}
