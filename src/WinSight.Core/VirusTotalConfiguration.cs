namespace WinSight.Core;

/// <summary>
/// Resolves the optional VirusTotal credential without copying a dashboard-stored key into the
/// process environment, where every child process would inherit it.
/// </summary>
public static class VirusTotalConfiguration
{
    public const string EnvironmentVariable = "WINSIGHT_VT_KEY";
    private static string? _storedProcessKey;

    /// <summary>An externally supplied environment key remains authoritative.</summary>
    public static string? CurrentApiKey
    {
        get
        {
            var environment = Environment.GetEnvironmentVariable(EnvironmentVariable);
            if (IsPlausibleApiKey(environment))
            {
                return environment;
            }
            return Volatile.Read(ref _storedProcessKey);
        }
    }

    public static bool HasEnvironmentKey =>
        IsPlausibleApiKey(Environment.GetEnvironmentVariable(EnvironmentVariable));

    public static bool IsPlausibleApiKey(string? value) =>
        value is { Length: >= 32 and <= 128 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    /// <summary>Sets a DPAPI-loaded key for this process only; null disables it.</summary>
    public static void SetStoredProcessKey(string? key)
    {
        if (key is not null && !IsPlausibleApiKey(key))
        {
            throw new ArgumentException("The VirusTotal API key format is invalid.", nameof(key));
        }
        Volatile.Write(ref _storedProcessKey, key);
    }

    /// <summary>Removes the credential from a child launched without ShellExecute.</summary>
    public static void RemoveFromChildEnvironment(System.Diagnostics.ProcessStartInfo startInfo)
    {
        ArgumentNullException.ThrowIfNull(startInfo);
        if (startInfo.UseShellExecute)
        {
            throw new InvalidOperationException("A ShellExecute launch cannot have an isolated environment.");
        }
        startInfo.Environment.Remove(EnvironmentVariable);
    }
}
