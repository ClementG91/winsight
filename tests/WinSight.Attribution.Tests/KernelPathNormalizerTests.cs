using Xunit;

namespace WinSight.Attribution.Tests;

/// <summary>
/// The translation attribution depends on. Its failure mode is silence — mistranslate, and every
/// detection simply comes back unattributed while the plumbing looks healthy — so the cases that
/// must return null are pinned as carefully as the ones that must translate.
/// </summary>
public sealed class KernelPathNormalizerTests
{
    private const string UserSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    private static KernelPathNormalizer Normalizer() => new(
        new Dictionary<string, string>
        {
            [@"\Device\HarddiskVolume3"] = "C:",
            [@"\Device\HarddiskVolume5"] = "D:",
        },
        UserSid);

    [Fact]
    public void FilePath_TranslatesADevicePathToItsDriveLetter()
    {
        Assert.Equal(
            @"C:\Users\me\Documents\report.docx",
            Normalizer().NormalizeFilePath(@"\Device\HarddiskVolume3\Users\me\Documents\report.docx"));
    }

    [Fact]
    public void FilePath_UsesTheRightDriveWhenSeveralAreMapped()
    {
        Assert.Equal(@"D:\data\file.bin", Normalizer().NormalizeFilePath(@"\Device\HarddiskVolume5\data\file.bin"));
    }

    [Fact]
    public void FilePath_KeepsAPathThatIsAlreadyWin32()
    {
        // Kernel sessions do report some events with ordinary paths; refusing them would drop
        // attributions for no reason.
        Assert.Equal(@"C:\Windows\System32\cmd.exe", Normalizer().NormalizeFilePath(@"C:\Windows\System32\cmd.exe"));
    }

    [Fact]
    public void FilePath_RefusesAnUnmappedDevice()
    {
        // A volume with no drive letter. The raw kernel path would match nothing downstream, so
        // saying nothing beats emitting something unusable.
        Assert.Null(Normalizer().NormalizeFilePath(@"\Device\HarddiskVolume9\hidden\file.txt"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(@"\??\GLOBALROOT\Device\Something\file")]
    [InlineData(@"relative\path.txt")]
    public void FilePath_RefusesWhatItCannotTranslate(string? kernelPath)
    {
        Assert.Null(Normalizer().NormalizeFilePath(kernelPath));
    }

    [Fact]
    public void FilePath_HandlesADeviceRootWithNothingAfterIt()
    {
        Assert.Equal(@"C:\", Normalizer().NormalizeFilePath(@"\Device\HarddiskVolume3"));
    }

    [Fact]
    public void RegistryKey_TranslatesTheMachineHiveToTheFormFindingsUse()
    {
        Assert.Equal(
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            Normalizer().NormalizeRegistryKey(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"));
    }

    [Fact]
    public void RegistryKey_TranslatesTheCurrentUsersHiveToHkcu()
    {
        Assert.Equal(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            Normalizer().NormalizeRegistryKey(
                $@"\REGISTRY\USER\{UserSid}\Software\Microsoft\Windows\CurrentVersion\Run"));
    }

    [Fact]
    public void RegistryKey_KeepsAnotherUsersHiveDistinct()
    {
        // Folding every user hive into HKCU would attribute another account's autostart entry to
        // this one.
        var other = "S-1-5-21-9999999999-8888888888-7777777777-1002";

        Assert.Equal(
            $@"HKU\{other}\Software\Foo",
            Normalizer().NormalizeRegistryKey($@"\REGISTRY\USER\{other}\Software\Foo"));
    }

    [Fact]
    public void RegistryKey_DoesNotFoldTheClassesCompanionHiveIntoHkcu()
    {
        // "{sid}_Classes" is its own hive, not a subkey of the user's, and collapsing it would
        // collide with a genuinely different key.
        var classes = $"{UserSid}_Classes";

        Assert.Equal(
            $@"HKU\{classes}\CLSID",
            Normalizer().NormalizeRegistryKey($@"\REGISTRY\USER\{classes}\CLSID"));
    }

    [Fact]
    public void RegistryKey_WithoutAKnownUserStillReportsTheHive()
    {
        var normalizer = new KernelPathNormalizer(currentUserSid: null);

        Assert.Equal(
            $@"HKU\{UserSid}\Software\Foo",
            normalizer.NormalizeRegistryKey($@"\REGISTRY\USER\{UserSid}\Software\Foo"));
    }

    [Fact]
    public void RegistryKey_KeepsAKeyAlreadyInAbbreviatedForm()
    {
        Assert.Equal(@"HKLM\SOFTWARE\Foo", Normalizer().NormalizeRegistryKey(@"HKLM\SOFTWARE\Foo"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"\REGISTRY\SOMETHINGELSE\Foo")]
    [InlineData(@"\REGISTRY\USER\")]
    [InlineData(@"C:\not\a\registry\key")]
    public void RegistryKey_RefusesWhatItCannotTranslate(string? kernelKey)
    {
        Assert.Null(Normalizer().NormalizeRegistryKey(kernelKey));
    }

    [Fact]
    public void HiveNamesAreMatchedRegardlessOfCase()
    {
        // Kernel paths are not consistently cased between providers and Windows versions.
        Assert.Equal(@"HKLM\Software\Foo", Normalizer().NormalizeRegistryKey(@"\Registry\Machine\Software\Foo"));
    }
}
