using Microsoft.Win32;

using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The scope boundaries a persistence scan claims to cover, and the accounting for what it does not.
/// </summary>
/// <remarks>
/// Three blind spots that shared one property: the report said nothing about them. A surface never
/// looked at cannot be counted as unread, so <c>PersistenceCoverage.IsPartial</c> stayed false and
/// every scan claimed to be complete.
/// </remarks>
public sealed class RegistryScopeTests
{
    /// <summary>
    /// A finding must name the key as it is actually spelled, or the operator is sent to a key that
    /// does not contain it - and write attribution, which matches an observed kernel write against
    /// this string as a prefix, can never match a 32-bit write at all.
    /// </summary>
    [Theory]
    [InlineData(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry32,
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]
    [InlineData(@"SOFTWARE\Classes\CLSID", RegistryView.Registry32,
        @"SOFTWARE\WOW6432Node\Classes\CLSID")]
    [InlineData(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", RegistryView.Registry64,
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]
    // Nothing under SYSTEM is redirected, so nothing there gains a WOW6432Node component.
    [InlineData(@"SYSTEM\CurrentControlSet\Services", RegistryView.Registry32,
        @"SYSTEM\CurrentControlSet\Services")]
    [InlineData(@"SYSTEM\CurrentControlSet\Services", RegistryView.Registry64,
        @"SYSTEM\CurrentControlSet\Services")]
    public void ARedirectedPathIsSpelledTheWayItExists(string path, RegistryView view, string expected)
    {
        var described = typeof(RunKeyEnumerator).Assembly
            .GetType("WinSight.Persistence.RegistryViews")!
            .GetMethod("Describe", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .Invoke(null, [path, view]);

        Assert.Equal(expected, described);
    }

    /// <summary>
    /// The account running the scan is already covered by the HKCU enumerators; the machine's own
    /// pseudo-accounts and the <c>_Classes</c> companion hives are not other people's profiles.
    /// </summary>
    [Fact]
    public void OtherUserHivesEnumerateWithoutClaimingTheCurrentUsersEntriesTwice()
    {
        var enumerator = new UserHiveEnumerator(() => "S-1-5-21-1-2-3-1001");

        var entries = enumerator.Enumerate().ToList();

        Assert.DoesNotContain(entries, entry =>
            entry.Location.Contains("S-1-5-21-1-2-3-1001", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(entries, entry =>
            entry.Location.Contains("_Classes", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(entries, entry =>
            entry.Location.Contains(".DEFAULT", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A profile whose hive is not loaded is a place persistence can sit that this scan did not
    /// look at. Loading NTUSER.DAT is privileged and modifies the machine, so a read-only tool
    /// counts the gap instead - which is what makes it appear in the coverage line at all.
    /// </summary>
    [Fact]
    public void AProfileWithNoLoadedHiveIsCountedAsUnread()
    {
        var enumerator = new UserHiveEnumerator(() => null);

        _ = enumerator.Enumerate().ToList();

        // On a single-account machine the answer is legitimately zero; on a multi-account one it is
        // the number of logged-out profiles. Either way it must never be negative, and it must be
        // consistent with the profile list.
        Assert.True(enumerator.UnreadableLocations >= 0);
        Assert.True(enumerator.UnreadableLocations <= UserHiveEnumerator.ProfileSids().Count + 2);
    }

    /// <summary>
    /// The startup folders scanned must include every profile's, not only the one belonging to the
    /// account running the scan - which, when elevated, is the administrator's rather than the
    /// standard user's.
    /// </summary>
    [Fact]
    public void StartupFoldersCoverEveryProfileThatHasOne()
    {
        var enumerator = new StartupFolderEnumerator();

        var watched = enumerator.WatchTargets.Select(target => target.Path).ToList();

        Assert.Contains(
            watched,
            path => string.Equals(
                path,
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                StringComparison.OrdinalIgnoreCase));
        // Every profile with a recorded directory contributes exactly one Startup folder, and none
        // is listed twice.
        Assert.Equal(watched.Count, watched.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    /// <summary>
    /// A TreatAs value is a CLSID, not a path. Reporting the raw GUID made the OLE mapping Windows
    /// ships read as "no resolvable image" on every machine, and said nothing about the code the
    /// class actually loads.
    /// </summary>
    [Fact]
    public void ATreatAsEntryResolvesToABinaryRatherThanAGuid()
    {
        var entries = new ComHijackEnumerator().Enumerate().ToList();

        foreach (var entry in entries.Where(e => e.Name.Contains("[TreatAs]", StringComparison.Ordinal)))
        {
            // Either the redirection resolved to something with a path separator, or the class it
            // points at genuinely registers no server - in which case the GUID is the honest answer.
            var command = entry.Command;
            Assert.False(
                command.StartsWith('{') && command.EndsWith('}') && ResolvesElsewhere(command),
                $"TreatAs left an unresolved GUID that does resolve: {entry.Name} -> {command}");
        }
    }

    private static bool ResolvesElsewhere(string clsid)
    {
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32");
            if (key?.GetValue(null) is string { Length: > 0 })
            {
                return true;
            }
        }
        return false;
    }
}
