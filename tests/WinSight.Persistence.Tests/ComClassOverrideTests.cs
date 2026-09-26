using Microsoft.Win32;
using WinSight.Core;
using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// WS-54. Every per-user CLSID was reported, and on the audit machine 3,842 of the 3,896 were exact
/// copies of the machine's own registration - same class, same server - which change nothing COM
/// loads. They buried the case the surface exists for: a per-user value that sends a class the
/// machine registers to another binary (MITRE T1546.015).
/// </summary>
public sealed class ComClassOverrideTests
{
    [Theory]
    [InlineData(@"C:\Program Files\Java\bin\jp2iexp.dll", @"C:\Program Files\Java\bin\jp2iexp.dll")]
    [InlineData(@"""C:\Program Files\Java\bin\jp2iexp.dll""", @"c:\program files\java\bin\JP2IEXP.DLL")]
    [InlineData(@"%SystemRoot%\System32\shell32.dll", @"C:\WINDOWS\System32\shell32.dll")]
    public void ACopyOfTheMachineRegistrationIsADuplicate(string user, string machine)
    {
        // The environment expansion makes the third case depend on the machine's SystemRoot.
        var machineValue = machine.Replace(@"C:\WINDOWS", Environment.GetEnvironmentVariable("SystemRoot"), StringComparison.OrdinalIgnoreCase);

        Assert.Equal(ComHijackEnumerator.ComMachineRelation.SameServer,
            ComHijackEnumerator.Classify(user, machineValue, machineClassExists: true));
    }

    [Fact]
    public void AnotherServerForAMachineClassIsAnOverride() =>
        Assert.Equal(ComHijackEnumerator.ComMachineRelation.DifferentServer,
            ComHijackEnumerator.Classify(@"C:\Users\me\AppData\Roaming\evil.dll", @"C:\Windows\System32\thumbcache.dll", machineClassExists: true));

    [Fact]
    public void AServerKindTheMachineClassDoesNotHaveIsAnOverride() =>
        // The machine registers only a LocalServer32; a per-user InprocServer32 is what COM now loads.
        Assert.Equal(ComHijackEnumerator.ComMachineRelation.DifferentServer,
            ComHijackEnumerator.Classify(@"C:\Users\me\evil.dll", machineValue: null, machineClassExists: true));

    [Fact]
    public void AClassTheMachineDoesNotRegisterIsPerUser() =>
        // Kept and reported, unflagged: a per-user application, or a phantom class that something
        // references and nothing registers - which is itself a hijack worth seeing.
        Assert.Equal(ComHijackEnumerator.ComMachineRelation.UserOnly,
            ComHijackEnumerator.Classify(@"C:\Users\me\app.dll", machineValue: null, machineClassExists: false));

    private static AutostartEntry Override(SignatureVerdict signature, bool overrides = true) =>
        new AutostartEntry(AutostartVector.ComHijack, "{11111111-1111-1111-1111-111111111111} [InprocServer32]",
            @"HKCU\SOFTWARE\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InprocServer32",
            @"C:\Users\me\x.dll", @"C:\Users\me\x.dll", @"C:\Users\me\x.dll",
            ImageResolutionStatus.Present, signature)
        { OverridesMachineClass = overrides };

    [Fact]
    public void ASignedThirdPartyOverrideIsAFinding() =>
        Assert.True(Override(new SignatureVerdict(SignatureState.SignedTrusted, "CN=Contoso Ltd")).IsAdverse);

    [Fact]
    public void AMicrosoftSignedOverrideIsNot() =>
        Assert.False(Override(new SignatureVerdict(SignatureState.SignedTrusted, "CN=Microsoft Corporation, O=Microsoft Corporation")).IsAdverse);

    [Fact]
    public void ASignedPerUserClassThatOverridesNothingIsNot() =>
        Assert.False(Override(new SignatureVerdict(SignatureState.SignedTrusted, "CN=Contoso Ltd"), overrides: false).IsAdverse);

    [Fact]
    public void TheOverrideIsNotPartOfTheIdentity()
    {
        // An upgrade must not re-announce an existing per-user class because it gained the flag.
        var flagged = Override(SignatureVerdict.Unsigned);

        Assert.Equal(PersistenceIdentity.FromEntry(flagged with { OverridesMachineClass = false }), PersistenceIdentity.FromEntry(flagged));
    }

    [Fact]
    public void OnThisMachineNoEmittedEntryIsACopyOfTheMachineRegistration()
    {
        var entries = new ComHijackEnumerator().Enumerate().ToList();

        foreach (var entry in entries.Where(e => !e.Name.EndsWith("[TreatAs]", StringComparison.Ordinal)))
        {
            var view = entry.Location.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                ? RegistryView.Registry32
                : RegistryView.Registry64;
            var clsid = entry.Name[..entry.Name.IndexOf(' ', StringComparison.Ordinal)];
            var key = entry.Name[(entry.Name.IndexOf('[', StringComparison.Ordinal) + 1)..^1];
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)
                .OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\{key}");
            var machineValue = machine?.GetValue(null) as string;
            Assert.False(
                machineValue is not null
                    && string.Equals(machineValue.Trim().Trim('"'), entry.Command.Trim().Trim('"'), StringComparison.OrdinalIgnoreCase),
                $"{entry.Name} duplicates the machine registration {machineValue}");
        }
    }
}
