using System.IO;

namespace WinSight.Dashboard;

/// <summary>
/// Remembers whether the operator turned real-time ransomware protection on.
/// </summary>
/// <remarks>
/// <b>What was broken.</b> Nothing read or wrote the checkbox's state, so every launch started with
/// protection off and said nothing about it. Combined with the decoy sweep running only from
/// <c>Start</c>, that produced a complete failure chain: turn protection on, reboot Windows - no
/// SessionEnding handler, so <c>Dispose</c> never runs - and the decoys stay in Documents, Desktop
/// and Pictures while protection comes back off, so the orphan sweep never runs either. The README
/// and the tooltip both promise the decoys are removed when you turn it off.
///
/// <b>Why a plain text file.</b> It matches how the UI language is already stored, holds no secret,
/// and a value it cannot parse means off - the safe answer for the one feature that writes to the
/// operator's own folders.
/// </remarks>
public sealed class ProtectionSettingsStore
{
    private const string EnabledMarker = "ransomware=on";
    private const int MaximumBytes = 4 * 1024;

    private readonly string _path;

    public ProtectionSettingsStore(string? path = null) =>
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSight",
            "protection.txt");

    public static ProtectionSettingsStore Default { get; } = new();

    /// <summary>Whether ransomware protection was on when WinSight last ran. False if unknown.</summary>
    public bool RansomwareProtectionEnabled
    {
        get
        {
            try
            {
                if (!File.Exists(_path) || new FileInfo(_path).Length > MaximumBytes)
                {
                    return false;
                }
                foreach (var line in File.ReadAllLines(_path))
                {
                    if (line.Trim().Equals(EnabledMarker, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException
                                         or UnauthorizedAccessException
                                         or System.Security.SecurityException)
            {
                // Unreadable state means off, which plants nothing.
            }
            return false;
        }
    }

    /// <summary>Records the operator's choice. Best-effort: a failure never blocks the toggle.</summary>
    public void SetRansomwareProtectionEnabled(bool enabled)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, enabled ? EnabledMarker + Environment.NewLine : string.Empty);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or System.Security.SecurityException)
        {
            // The protection still works this session; only the memory of it is lost.
        }
    }
}
