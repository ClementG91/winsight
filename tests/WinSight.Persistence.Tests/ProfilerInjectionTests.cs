using Microsoft.Win32;

using WinSight.Persistence;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// .NET profiler injection, the surface that was not enumerated at all.
/// </summary>
/// <remarks>
/// <b>What was uncovered.</b> The CLR loads an arbitrary DLL into a managed process at startup when
/// <c>COR_ENABLE_PROFILING=1</c> and a profiler is named. Nothing about the DLL needs to be a
/// profiler; it is a supported loading mechanism, which is exactly why it is used as one
/// (ATT&amp;CK T1574.012). The code then runs inside a legitimate signed process, and the only
/// trace is a registry value.
///
/// <b>Why the tests write to HKCU.</b> The user's own environment key is the variant that needs no
/// elevation, and it is the one a test can exercise honestly - by setting the values, scanning, and
/// removing them. The machine-wide and per-service variants read the same code path with a
/// different key, so what is proved here is the decision, not one key's spelling. Nothing outside
/// the test's own uniquely-named values is touched, and they are removed in a finally block.
/// </remarks>
public sealed class ProfilerInjectionTests : IDisposable
{
    private const string UserEnvironment = "Environment";
    private readonly List<string> _written = [];

    public void Dispose()
    {
        using var key = Registry.CurrentUser.OpenSubKey(UserEnvironment, writable: true);
        foreach (var name in _written)
        {
            try { key?.DeleteValue(name, throwOnMissingValue: false); }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void Set(string name, string value)
    {
        using var key = Registry.CurrentUser.OpenSubKey(UserEnvironment, writable: true)
            ?? Registry.CurrentUser.CreateSubKey(UserEnvironment);
        key.SetValue(name, value, RegistryValueKind.String);
        _written.Add(name);
    }

    private static IReadOnlyList<RawAutostart> Scan() =>
        [.. new ProfilerInjectionEnumerator().Enumerate()];

    /// <summary>
    /// The mechanism, spelled the direct way: profiling on, a DLL named by path.
    /// </summary>
    [Fact]
    public void AProfilerNamedByPathIsFound()
    {
        var image = @"C:\Users\Public\totally-a-profiler.dll";
        Set("COR_ENABLE_PROFILING", "1");
        Set("COR_PROFILER_PATH", image);

        var entry = Assert.Single(Scan(), raw => raw.Command == image);

        Assert.Equal(AutostartVector.ProfilerInjection, entry.Vector);
        Assert.Contains("Environment", entry.Location, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Environment variables are expanded, because that is how the value is usually written and an
    /// unexpanded one resolves to no image at all.
    /// </summary>
    [Fact]
    public void ThePathIsExpanded()
    {
        Set("COR_ENABLE_PROFILING", "1");
        Set("COR_PROFILER_PATH", @"%SystemRoot%\Temp\p.dll");

        var expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Temp\p.dll");

        Assert.Contains(Scan(), raw => string.Equals(
            raw.Command, expected, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// A CLSID with no resolvable registration is still reported. The registration is the finding,
    /// and one whose image cannot be found is if anything more interesting than one that can - a
    /// scan that stayed quiet about it would be quiet about the more suspicious case.
    /// </summary>
    [Fact]
    public void AProfilerNamedOnlyByAnUnresolvableClsidIsStillReported()
    {
        const string clsid = "{0F0F0F0F-DEAD-BEEF-0000-000000000001}";
        Set("COR_ENABLE_PROFILING", "1");
        Set("COR_PROFILER", clsid);

        Assert.Contains(Scan(), raw => raw.Command == clsid);
    }

    /// <summary>
    /// Both halves are required. A profiler named but not enabled loads nothing, and reporting it
    /// would flag every machine with a development tool installed.
    /// </summary>
    [Fact]
    public void AProfilerNamedButNotEnabledIsNotAFinding()
    {
        var image = @"C:\Users\Public\disabled-profiler.dll";
        Set("COR_ENABLE_PROFILING", "0");
        Set("COR_PROFILER_PATH", image);

        Assert.DoesNotContain(Scan(), raw => raw.Command == image);
    }

    /// <summary>Profiling enabled with nothing named loads nothing either.</summary>
    [Fact]
    public void EnabledWithNothingNamedIsNotAFinding()
    {
        Set("COR_ENABLE_PROFILING", "1");

        Assert.DoesNotContain(
            Scan(), raw => raw.Location.Contains("HKCU", StringComparison.Ordinal));
    }

    /// <summary>
    /// The surface is part of the default scan. An enumerator nothing runs detects nothing.
    /// </summary>
    [Fact]
    public void TheSurfaceIsInTheDefaultScan() =>
        Assert.Contains(
            PersistenceScanner.DefaultEnumerators(),
            enumerator => enumerator is ProfilerInjectionEnumerator);

    /// <summary>
    /// A profiler is loaded into somebody else's process, so a third-party one is adverse for the
    /// same reason an LSA package is - including a legitimate APM agent, which an operator should
    /// be told about and can then recognise.
    /// </summary>
    [Fact]
    public void TheSurfaceCountsAsPrivileged() =>
        Assert.True(PrivilegedSurfaceTriage.IsPrivilegedSurface(AutostartVector.ProfilerInjection));

    /// <summary>The live enumeration does not throw on an ordinary machine.</summary>
    [Fact]
    public void TheSurfaceEnumeratesOnThisMachine()
    {
        var entries = Scan();

        Assert.All(entries, entry =>
            Assert.Equal(AutostartVector.ProfilerInjection, entry.Vector));
    }

    /// <summary>
    /// The managed half of the same technique: a type instantiated as the process's
    /// AppDomainManager before any application code runs.
    /// </summary>
    /// <remarks>
    /// It needs no profiling flag, it is set in the same places by the same means, and it puts an
    /// attacker's assembly inside the target process just as effectively. The native half was
    /// covered and this was not.
    /// </remarks>
    [Fact]
    public void AnAppDomainManagerAssemblyIsFound()
    {
        Set("APPDOMAIN_MANAGER_ASM", "Contoso.Agent, Version=1.0.0.0");
        Set("APPDOMAIN_MANAGER_TYPE", "Contoso.Agent.Manager");

        var entry = Assert.Single(
            Scan(), raw => raw.Command.Contains("Contoso.Agent", StringComparison.Ordinal));

        Assert.Equal(AutostartVector.ProfilerInjection, entry.Vector);
        Assert.Contains("AppDomainManager", entry.Name, StringComparison.Ordinal);
        Assert.Contains("Contoso.Agent.Manager", entry.Command, StringComparison.Ordinal);
    }

    /// <summary>
    /// The assembly alone is enough. There is no enabling flag to pair it with, so requiring one
    /// would mean never reporting it.
    /// </summary>
    [Fact]
    public void TheAssemblyAloneIsEnough()
    {
        Set("APPDOMAIN_MANAGER_ASM", "Solo.Assembly");

        Assert.Contains(Scan(), raw => raw.Command.Contains("Solo.Assembly", StringComparison.Ordinal));
    }

    /// <summary>A type with no assembly names nothing loadable and is not a finding.</summary>
    [Fact]
    public void ATypeWithoutAnAssemblyIsNotAFinding()
    {
        Set("APPDOMAIN_MANAGER_TYPE", "Orphan.Type");

        Assert.DoesNotContain(
            Scan(), raw => raw.Command.Contains("Orphan.Type", StringComparison.Ordinal));
    }
}
