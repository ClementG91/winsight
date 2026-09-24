using WinSight.Core;
using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// The compiled-in name a scan attaches to an entry, read end to end through the real resolution
/// and the real file.
/// </summary>
public sealed class OriginalFileNameScanTests : IDisposable
{
    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"winsight-origname-{Guid.NewGuid():N}");

    public OriginalFileNameScanTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        foreach (var file in Directory.EnumerateFiles(_directory))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }
        Directory.Delete(_directory, recursive: true);
    }

    // WS-74. The scan named the genuine powershell.exe "PowerShell.EXE.MUI" - the name of its language
    // file - and that name is in no table, so the most common abuse in the rule's own documentation
    // left the scanner as an ordinary signed entry.
    [Fact]
    public void TheGenuineInterpreterIsFlaggedWhenHandedAnEncodedCommand()
    {
        var powershell = Path.Combine(System32, @"WindowsPowerShell\v1.0\powershell.exe");

        var entry = ScanOne($"\"{powershell}\" -NoProfile -enc SQBFAFgA", new TrustedMicrosoft());

        Assert.Equal(ImageResolutionStatus.Present, entry.ImageStatus);
        Assert.Equal("powershell.exe", entry.OriginalFileName, ignoreCase: true);
        Assert.Equal(InterpreterAbuse.EncodedCommand, entry.Abuse);
        Assert.True(entry.IsSuspicious);
    }

    // The masquerade case the name exists for (MITRE T1036.003) still holds with the new reader.
    [Fact]
    public void ARenamedCopyOfTheInterpreterIsStillRecognised()
    {
        var copy = Path.Combine(_directory, "updater.exe");
        File.Copy(Path.Combine(System32, "cmd.exe"), copy);

        var entry = ScanOne($"\"{copy}\" /c %TEMP%\\stage.cmd", new TrustedMicrosoft());

        Assert.Equal("cmd.exe", entry.OriginalFileName, ignoreCase: true);
        Assert.Equal(InterpreterAbuse.PerUserPayload, entry.Abuse);
    }

    // RA-02. The name used to be read by path through FileVersionInfo, outside the automatic-read
    // guard: a file whose data is elsewhere was read anyway, which for a cloud-only file is a
    // download. Such a file now yields no name, and the rule falls back to the file name.
    [Fact]
    public void AnImageWhoseDataIsNotLocalIsNotReadForItsName()
    {
        var copy = Path.Combine(_directory, "agent.exe");
        File.Copy(Path.Combine(System32, "cmd.exe"), copy);
        File.SetAttributes(copy, File.GetAttributes(copy) | FileAttributes.Offline);

        var entry = ScanOne($"\"{copy}\" /c run.cmd", new TrustedMicrosoft());

        Assert.Equal(ImageResolutionStatus.Present, entry.ImageStatus);
        Assert.Null(entry.OriginalFileName);
    }

    // RA-02. A file swapped in after the resolution found the image must not lend the entry its
    // name: the entry describes the file the resolution saw.
    [Fact]
    public void AFileSwappedInDuringTheScanDoesNotLendItsName()
    {
        var image = Path.Combine(_directory, "agent.exe");
        var impostor = Path.Combine(_directory, "impostor.exe");
        File.Copy(Path.Combine(System32, "cmd.exe"), image);
        File.Copy(Path.Combine(System32, "whoami.exe"), impostor);

        // The verifier runs between the resolution and the name read, which is the window.
        var entry = ScanOne($"\"{image}\" /c run.cmd", new SwappingVerifier(impostor, image));

        Assert.False(File.Exists(impostor));
        Assert.Null(entry.OriginalFileName);
    }

    [Fact]
    public void AnUnchangedImageKeepsItsName()
    {
        var image = Path.Combine(_directory, "agent.exe");
        File.Copy(Path.Combine(System32, "whoami.exe"), image);

        var entry = ScanOne($"\"{image}\"", new TrustedMicrosoft());

        Assert.Equal("whoami.exe", entry.OriginalFileName, ignoreCase: true);
    }

    private static AutostartEntry ScanOne(string command, ISignatureVerifier verifier)
    {
        var scan = new PersistenceScanner(
            [new OneEntry(new RawAutostart(
                AutostartVector.RunKey, "Entry", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", command))],
            verifier).ScanWithCoverage();
        return Assert.Single(scan.Entries);
    }

    private sealed class OneEntry(RawAutostart entry) : IAutostartEnumerator
    {
        public string Surface => "Run keys";

        public IEnumerable<RawAutostart> Enumerate() => [entry];
    }

    private class TrustedMicrosoft : ISignatureVerifier
    {
        public SignatureVerdict Verify(string path, CancellationToken cancellationToken = default) =>
            new(SignatureState.SignedTrusted, "CN=Microsoft Windows, O=Microsoft Corporation");

        public virtual IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default) =>
            paths.Distinct(StringComparer.OrdinalIgnoreCase).ToDictionary(
                path => path, path => Verify(path, cancellationToken), StringComparer.OrdinalIgnoreCase);
    }

    private sealed class SwappingVerifier(string replacement, string target) : TrustedMicrosoft
    {
        public override IReadOnlyDictionary<string, SignatureVerdict> VerifyMany(
            IReadOnlyCollection<string> paths, CancellationToken cancellationToken = default)
        {
            File.Move(replacement, target, overwrite: true);
            return base.VerifyMany(paths, cancellationToken);
        }
    }
}
