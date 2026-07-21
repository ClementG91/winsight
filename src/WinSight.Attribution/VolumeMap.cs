using System.Runtime.InteropServices;
using System.Text;

namespace WinSight.Attribution;

/// <summary>
/// The machine's live NT device to drive-letter mapping, the piece
/// <see cref="KernelPathNormalizer"/> needs and deliberately does not gather itself.
/// </summary>
/// <remarks>
/// Kept apart from the normaliser so the translation stays a pure function of its inputs: the
/// normaliser can then be tested against any machine's layout, including ones that do not exist,
/// rather than only against whatever volumes the test runner happens to have.
///
/// The map is read once when a session starts. A volume mounted mid-session will not resolve, which
/// costs an attribution rather than producing a wrong one — the safe direction.
/// </remarks>
public static class VolumeMap
{
    /// <summary>Reads the current mapping, e.g. <c>\Device\HarddiskVolume3</c> to <c>C:</c>.</summary>
    public static IReadOnlyDictionary<string, string> Current()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in DriveLetters())
        {
            var device = QueryDevice(drive);
            if (!string.IsNullOrWhiteSpace(device))
            {
                // Several letters can name one device (a SUBST or a mounted folder). First wins,
                // which keeps the answer stable rather than depending on enumeration order.
                map.TryAdd(device, drive);
            }
        }
        return map;
    }

    private static IEnumerable<string> DriveLetters()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            // "C:\" as Windows reports it; QueryDosDevice wants "C:" with no separator.
            var name = drive.Name.TrimEnd('\\', '/');
            if (name.Length == 2 && name[1] == ':')
            {
                yield return name;
            }
        }
    }

    private static string? QueryDevice(string driveLetter)
    {
        try
        {
            var buffer = new char[512];
            var length = NativeMethods.QueryDosDevice(driveLetter, buffer, buffer.Length);
            if (length == 0)
            {
                return null;
            }
            // The result is a double-null-terminated list: a letter can have more than one target
            // when it has been reassigned. The first entry is the current one, so stop at the
            // first terminator rather than taking the whole buffer.
            var end = Array.IndexOf(buffer, '\0');
            var target = new string(buffer, 0, end < 0 ? Math.Min(length, buffer.Length) : end);
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int QueryDosDevice(string deviceName, [Out] char[] targetPath, int max);
    }
}
