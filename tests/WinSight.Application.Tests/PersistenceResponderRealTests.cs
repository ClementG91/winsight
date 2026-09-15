using Microsoft.Win32;

using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The real registry/file mutator against a temporary HKCU test key and a temporary startup folder,
/// unelevated. Nothing under a real Run key or the user's actual Startup folder is touched.
/// </summary>
public sealed class PersistenceResponderRealTests : IDisposable
{
    private readonly string _subKey = $@"Software\WinSight.Tests\Response\{Guid.NewGuid():N}";
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-startup-").FullName;

    public void Dispose()
    {
        Registry.CurrentUser.DeleteSubKeyTree(_subKey, throwOnMissingSubKey: false);
        Directory.Delete(_directory, recursive: true);
    }

    private PersistenceResponder Responder(out Quarantine quarantine)
    {
        var root = Path.Combine(_directory, "quarantine");
        quarantine = new Quarantine(root);
        return new PersistenceResponder(new RegistryAndFilePersistenceMutator(), quarantine,
            new ActionJournal(Path.Combine(_directory, "journal.jsonl")));
    }

    private static PersistenceActionTarget RegistryTarget(string subKey, string valueName, string command) =>
        PersistenceActionResolver.Resolve(new AutostartEntry(
            AutostartVector.RunKey, valueName, $@"HKCU\{subKey} [Registry64]", command, command, command,
            ImageResolutionStatus.Present, SignatureVerdict.Unknown))!;

    [Fact]
    public void ARealHkcuValueIsQuarantinedRemovedAndRestoredExactly()
    {
        const string command = @"C:\Users\me\AppData\Local\evil.exe --run";
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", command, RegistryValueKind.ExpandString);
        }
        var responder = Responder(out var quarantine);
        var target = RegistryTarget(_subKey, "Updater", command);

        var block = responder.Block(target);
        Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);
        using (var key = Registry.CurrentUser.OpenSubKey(_subKey))
        {
            Assert.Null(key!.GetValue("Updater")); // gone from the live surface
        }

        var restore = responder.Restore(block.ActionId);
        Assert.Equal(ResponseOutcome.Succeeded, restore.Outcome);
        using (var key = Registry.CurrentUser.OpenSubKey(_subKey))
        {
            // Data and kind both preserved: an ExpandString restored as String would stop expanding.
            Assert.Equal(command, key!.GetValue("Updater", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
            Assert.Equal(RegistryValueKind.ExpandString, key.GetValueKind("Updater"));
        }
        Assert.Empty(quarantine.List());
    }

    [Fact]
    public void AChangedValueIsNotRemoved()
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\new-legit.exe", RegistryValueKind.String);
        }
        var responder = Responder(out _);

        var block = responder.Block(RegistryTarget(_subKey, "Updater", @"C:\old-evil.exe"));

        Assert.Equal(ResponseOutcome.TargetChanged, block.Outcome);
        using var unchanged = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\new-legit.exe", unchanged!.GetValue("Updater"));
    }

    [Fact]
    public void ARealStartupFileIsQuarantinedRemovedAndRestored()
    {
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (string.IsNullOrEmpty(startup))
        {
            return;
        }
        // A file inside the user's real Startup folder, uniquely named so nothing else is touched.
        var name = $"winsight-test-{Guid.NewGuid():N}.cmd";
        var path = Path.Combine(startup, name);
        File.WriteAllText(path, "@echo off\r\n");
        try
        {
            var responder = Responder(out var quarantine);
            var target = PersistenceActionResolver.Resolve(new AutostartEntry(
                AutostartVector.StartupFolder, name, $"User startup: {startup}", path, path, path,
                ImageResolutionStatus.Present, SignatureVerdict.Unknown))!;
            Assert.Equal(ResponsePrivilege.CurrentUser, target.Privilege);

            var block = responder.Block(target);
            Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);
            Assert.False(File.Exists(path));

            var restore = responder.Restore(block.ActionId);
            Assert.Equal(ResponseOutcome.Succeeded, restore.Outcome);
            Assert.Equal("@echo off\r\n", File.ReadAllText(path));
            Assert.Empty(quarantine.List());
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void RestoreRefusesWhenTheOriginIsReoccupied()
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\evil.exe", RegistryValueKind.String);
        }
        var responder = Responder(out _);
        var target = RegistryTarget(_subKey, "Updater", @"C:\evil.exe");
        var block = responder.Block(target);

        // Something legitimate now sits under the same name.
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\legit.exe", RegistryValueKind.String);
        }

        Assert.Equal(ResponseOutcome.TargetChanged, responder.Restore(block.ActionId).Outcome);
        using var check = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\legit.exe", check!.GetValue("Updater")); // the occupant is untouched
    }
}
