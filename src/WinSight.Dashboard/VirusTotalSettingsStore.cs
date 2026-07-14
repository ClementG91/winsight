using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace WinSight.Dashboard;

/// <summary>
/// Stores the optional VirusTotal API key encrypted for the current Windows user.
/// Environment configuration remains authoritative for CLI and managed deployments.
/// </summary>
public sealed class VirusTotalSettingsStore
{
    public const string EnvironmentVariable = "WINSIGHT_VT_KEY";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("WinSight.VirusTotal.ApiKey.v1");
    private readonly string _path;
    private bool _environmentOverrideActive;

    public VirusTotalSettingsStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinSight",
            "vt-api-key.bin");
    }

    public static VirusTotalSettingsStore Default { get; } = new();

    public bool HasStoredKey => LoadStoredKey() is not null;

    public bool HasEnvironmentKey =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(EnvironmentVariable));

    public bool EnvironmentOverrideActive => _environmentOverrideActive;

    public static bool IsPlausibleApiKey(string? value) =>
        value is { Length: >= 32 and <= 128 } &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    public string? LoadStoredKey()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var protectedBytes = File.ReadAllBytes(_path);
            var clearBytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            var key = Encoding.UTF8.GetString(clearBytes);
            CryptographicOperations.ZeroMemory(clearBytes);
            return IsPlausibleApiKey(key) ? key : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                     or SecurityException or CryptographicException)
        {
            return null;
        }
    }

    public void Save(string key)
    {
        if (!IsPlausibleApiKey(key))
        {
            throw new ArgumentException("The VirusTotal API key format is invalid.", nameof(key));
        }

        var clearBytes = Encoding.UTF8.GetBytes(key);
        byte[]? protectedBytes = null;
        var temporaryPath = _path + ".tmp";
        try
        {
            protectedBytes = ProtectedData.Protect(clearBytes, Entropy, DataProtectionScope.CurrentUser);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllBytes(temporaryPath, protectedBytes);
            File.Move(temporaryPath, _path, overwrite: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
            try
            {
                File.Delete(temporaryPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A stale temporary file contains only DPAPI-protected bytes.
            }
        }
    }

    public void Clear()
    {
        if (File.Exists(_path))
        {
            File.Delete(_path);
        }
    }

    public void ApplyToCurrentProcess()
    {
        if (HasEnvironmentKey)
        {
            _environmentOverrideActive = true;
            return;
        }
        if (LoadStoredKey() is not { } key)
        {
            return;
        }

        Environment.SetEnvironmentVariable(EnvironmentVariable, key, EnvironmentVariableTarget.Process);
    }

    public void ApplySavedKeyToCurrentProcess(string key)
    {
        if (!_environmentOverrideActive)
        {
            Environment.SetEnvironmentVariable(EnvironmentVariable, key, EnvironmentVariableTarget.Process);
        }
    }

    public void DisableForCurrentProcess()
    {
        if (!_environmentOverrideActive)
        {
            Environment.SetEnvironmentVariable(EnvironmentVariable, null, EnvironmentVariableTarget.Process);
        }
    }
}
