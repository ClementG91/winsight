using Microsoft.Win32;

using WinSight.Core;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The whole live chain Guardian runs in the dashboard - a real RegNotifyChangeKeyValue watch, the
/// debounce, the scoped re-scan through <see cref="PersistenceScanner"/>, reconciliation and the
/// Detected event - against a private HKCU key, so nothing a user relies on is touched.
/// </summary>
public sealed class GuardianEndToEndRegistryTests : IDisposable
{
    private readonly string _subPath = $@"Software\WinSightGuardianE2E-{Guid.NewGuid():N}";

    public GuardianEndToEndRegistryTests() => Registry.CurrentUser.CreateSubKey(_subPath)!.Dispose();

    public void Dispose() => Registry.CurrentUser.DeleteSubKeyTree(_subPath, throwOnMissingSubKey: false);

    [Fact]
    public void AValueWrittenAfterStartIsDetectedThroughTheRealWatcher()
    {
        IAutostartEnumerator[] enumerators = [new PrivateRunKeyEnumerator(_subPath)];
        var verifier = new FixedVerifier();
        using var monitor = new PersistenceMonitor(
            enumerators,
            CompositePersistenceChangeSource.ForEnumerators(enumerators),
            (surfaces, token) => new PersistenceScanner(surfaces, verifier).ScanWithCoverage(token));
        using var detected = new ManualResetEventSlim(false);
        string? name = null;
        monitor.Detected += (_, e) =>
        {
            name = e.Detected.Entry.Name;
            detected.Set();
        };

        monitor.Start();
        using (var key = Registry.CurrentUser.OpenSubKey(_subPath, writable: true)!)
        {
            key.SetValue("Planted", @"""C:\Windows\System32\notepad.exe""");
        }

        Assert.True(detected.Wait(TimeSpan.FromSeconds(30)), "Guardian did not report a value written after start.");
        Assert.Equal("Planted", name);
    }

    [Fact]
    public void AUserRunValueIsReportedOnceNotOncePerRegistryView()
    {
        // WOW64 redirects HKLM\Software, never HKCU: reading the user's Run key under both the 64-bit
        // and the 32-bit view returns the same value twice. Guardian then saw every user-level startup
        // item as two arrivals, announced them as a coalesced burst instead of opening the decision
        // window the whole feature exists for, and wrote each one into the alert journal twice.
        var name = $"WinSightViewProbe{Guid.NewGuid():N}";
        using (var run = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true)!)
        {
            run.SetValue(name, @"""C:\Windows\System32\notepad.exe""");
        }
        try
        {
            var mine = new RunKeyEnumerator().Enumerate().Where(entry => entry.Name == name).ToList();

            Assert.Single(mine);
        }
        finally
        {
            using var run = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true)!;
            run.DeleteValue(name, throwOnMissingValue: false);
        }
    }

    private sealed class PrivateRunKeyEnumerator(string subPath) : IAutostartEnumerator
    {
        public string Surface => "Private run key";

        public IReadOnlyList<PersistenceWatchTarget> WatchTargets { get; } =
            [PersistenceWatchTarget.Registry(RegistryHive.CurrentUser, RegistryView.Registry64, subPath)];

        public bool CanConfirmAbsence => true;

        public IEnumerable<RawAutostart> Enumerate()
        {
            using var key = Registry.CurrentUser.OpenSubKey(subPath);
            foreach (var value in key?.GetValueNames() ?? [])
            {
                yield return new RawAutostart(AutostartVector.RunKey, value, $@"HKCU\{subPath}",
                    key!.GetValue(value) as string ?? string.Empty);
            }
        }
    }

    private sealed class FixedVerifier : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            new(SignatureState.Unsigned, null);

        public IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            paths.Distinct(StringComparer.OrdinalIgnoreCase)
                .ToDictionary(path => path, path => Verify(path), StringComparer.OrdinalIgnoreCase);
    }
}
