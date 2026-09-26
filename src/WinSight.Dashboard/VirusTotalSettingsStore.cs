using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using WinSight.Core;

namespace WinSight.Dashboard;

/// <summary>
/// Stores the optional VirusTotal API key encrypted for the current Windows user.
/// Environment configuration remains authoritative for CLI and managed deployments.
/// </summary>
public sealed class VirusTotalSettingsStore
{
    private const int MaximumProtectedKeyBytes = 8 * 1024;
    public const string EnvironmentVariable = VirusTotalConfiguration.EnvironmentVariable;
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
        VirusTotalConfiguration.HasEnvironmentKey;

    public bool EnvironmentOverrideActive => _environmentOverrideActive;

    public static bool IsPlausibleApiKey(string? value) =>
        VirusTotalConfiguration.IsPlausibleApiKey(value);

    public string? LoadStoredKey()
    {
        try
        {
            using var lease = AutomaticFileAccess.TryAcquire(_path);
            if (lease is null || lease.IsDirectory || lease.Length > MaximumProtectedKeyBytes)
            {
                return null;
            }

            var protectedBytes = new byte[checked((int)lease.Length)];
            using (var stream = lease.OpenRead(FileOptions.SequentialScan))
            {
                stream.ReadExactly(protectedBytes);
            }
            if (!lease.IsCurrent())
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                return null;
            }
            var clearBytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(protectedBytes);
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
        try
        {
            protectedBytes = ProtectedData.Protect(clearBytes, Entropy, DataProtectionScope.CurrentUser);
            if (protectedBytes.Length > MaximumProtectedKeyBytes)
            {
                throw new CryptographicException("The protected VirusTotal key exceeds the safety limit.");
            }
            if (!AtomicFile.TryWrite(_path, protectedBytes))
            {
                throw new IOException("The protected VirusTotal key could not be written safely.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clearBytes);
            if (protectedBytes is not null)
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
    }

    public void Clear()
        => _ = AutomaticFileAccess.TryDeleteFile(_path);

    public void ApplyToCurrentProcess()
    {
        if (HasEnvironmentKey)
        {
            _environmentOverrideActive = true;
            VirusTotalConfiguration.SetStoredProcessKey(null);
            return;
        }
        if (LoadStoredKey() is not { } key)
        {
            return;
        }

        VirusTotalConfiguration.SetStoredProcessKey(key);
    }

    public void ApplySavedKeyToCurrentProcess(string key)
    {
        if (!_environmentOverrideActive)
        {
            VirusTotalConfiguration.SetStoredProcessKey(key);
        }
    }

    public void DisableForCurrentProcess()
    {
        if (!_environmentOverrideActive)
        {
            VirusTotalConfiguration.SetStoredProcessKey(null);
        }
    }
}
