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
/// <remarks>
/// Registry cases run twice: through the default mutator, which uses a registry transaction where
/// Windows has TxR active and falls back otherwise, and with transactions forced off, so the verified
/// non-transacted path is exercised on every machine. These tests used to return early on
/// <c>NotSupported</c> - which is what current Windows 11 answered - so on such a machine they never
/// exercised a removal or a restore at all.
/// </remarks>
public sealed class PersistenceResponderRealTests : IDisposable
{
    private readonly string _subKey = $@"Software\WinSight.Tests\Response\{Guid.NewGuid():N}";
    private readonly string _directory = Directory.CreateTempSubdirectory("winsight-startup-").FullName;

    public void Dispose()
    {
        Registry.CurrentUser.DeleteSubKeyTree(_subKey, throwOnMissingSubKey: false);
        Directory.Delete(_directory, recursive: true);
    }

    private PersistenceResponder Responder(out Quarantine quarantine, bool useTransactions = true)
    {
        var root = Path.Combine(_directory, "quarantine");
        quarantine = new Quarantine(root);
        return new PersistenceResponder(new RegistryAndFilePersistenceMutator(useTransactions), quarantine,
            new ActionJournal(Path.Combine(_directory, "journal.jsonl")));
    }

    private static PersistenceActionTarget RegistryTarget(string subKey, string valueName, string command) =>
        PersistenceActionResolver.Resolve(new AutostartEntry(
            AutostartVector.RunKey, valueName, $@"HKCU\{subKey} [Registry64]", command, command, command,
            ImageResolutionStatus.Present, SignatureVerdict.Unknown))!;

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ARealHkcuValueIsQuarantinedRemovedAndRestoredExactly(bool useTransactions)
    {
        const string command = @"C:\Users\me\AppData\Local\evil.exe --run";
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", command, RegistryValueKind.ExpandString);
        }
        var responder = Responder(out var quarantine, useTransactions);
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AChangedValueIsNotRemoved(bool useTransactions)
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\new-legit.exe", RegistryValueKind.String);
        }
        var responder = Responder(out _, useTransactions);

        var block = responder.Block(RegistryTarget(_subKey, "Updater", @"C:\old-evil.exe"));

        Assert.Equal(ResponseOutcome.TargetChanged, block.Outcome);
        using var unchanged = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\new-legit.exe", unchanged!.GetValue("Updater"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ARegistryValueReplacedAfterCaptureIsNotRemoved(bool useTransactions)
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\old.exe", RegistryValueKind.String);
        }
        var target = RegistryTarget(_subKey, "Updater", @"C:\old.exe");
        var mutator = new RegistryAndFilePersistenceMutator(useTransactions);
        var captured = Assert.IsType<PersistenceSnapshot>(mutator.Capture(target));

        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\replacement.exe", RegistryValueKind.String);
        }

        Assert.Equal(PersistenceMutationOutcome.TargetChanged, mutator.RemoveIfUnchanged(target, captured));
        using var check = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\replacement.exe", check!.GetValue("Updater"));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExpandStringPayloadIsRestoredWithoutLosingEnvironmentVariables(bool useTransactions)
    {
        const string raw = @"%LOCALAPPDATA%\payload.exe --run";
        var expanded = Environment.ExpandEnvironmentVariables(raw);
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", raw, RegistryValueKind.ExpandString);
        }
        var responder = Responder(out _, useTransactions);
        var block = responder.Block(RegistryTarget(_subKey, "Updater", expanded));

        Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);
        Assert.Equal(ResponseOutcome.Succeeded, responder.Restore(block.ActionId).Outcome);
        using var restored = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(raw, restored!.GetValue(
            "Updater", null, RegistryValueOptions.DoNotExpandEnvironmentNames));
        Assert.Equal(RegistryValueKind.ExpandString, restored.GetValueKind("Updater"));
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RestoreRefusesWhenTheOriginIsReoccupied(bool useTransactions)
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\evil.exe", RegistryValueKind.String);
        }
        var responder = Responder(out _, useTransactions);
        var target = RegistryTarget(_subKey, "Updater", @"C:\evil.exe");
        var block = responder.Block(target);
        Assert.Equal(ResponseOutcome.Succeeded, block.Outcome);

        // Something legitimate now sits under the same name.
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\legit.exe", RegistryValueKind.String);
        }

        Assert.Equal(ResponseOutcome.TargetChanged, responder.Restore(block.ActionId).Outcome);
        using var check = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\legit.exe", check!.GetValue("Updater")); // the occupant is untouched
    }

    /// <summary>
    /// A target in another hive is refused before anything is opened. The transacted path used to
    /// open the target's subkey under HKCU whatever hive it named, so a machine-wide target would have
    /// been matched against - and removed from - the same path in the user's own hive.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AMachineHiveTargetIsNeverActedOnThroughTheUserHive(bool useTransactions)
    {
        using (var key = Registry.CurrentUser.CreateSubKey(_subKey))
        {
            key.SetValue("Updater", @"C:\user-owned.exe", RegistryValueKind.String);
        }
        var userTarget = RegistryTarget(_subKey, "Updater", @"C:\user-owned.exe");
        var mutator = new RegistryAndFilePersistenceMutator(useTransactions);
        var snapshot = Assert.IsType<PersistenceSnapshot>(mutator.Capture(userTarget));
        var machineTarget = userTarget with { Hive = RegistryHive.LocalMachine };

        Assert.Equal(PersistenceMutationOutcome.Failed, mutator.RemoveIfUnchanged(machineTarget, snapshot));
        Assert.Equal(PersistenceMutationOutcome.Failed, mutator.RestoreIfFree(machineTarget, snapshot.Payload));
        using var check = Registry.CurrentUser.OpenSubKey(_subKey);
        Assert.Equal(@"C:\user-owned.exe", check!.GetValue("Updater"));
    }

    [Fact]
    public void AStartupFileReplacedAfterCaptureIsNotRemoved()
    {
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (string.IsNullOrEmpty(startup))
        {
            return;
        }
        var name = $"winsight-race-{Guid.NewGuid():N}.cmd";
        var path = Path.Combine(startup, name);
        File.WriteAllText(path, "old");
        try
        {
            var target = PersistenceActionResolver.Resolve(new AutostartEntry(
                AutostartVector.StartupFolder, name, $"User startup: {startup}", path, path, path,
                ImageResolutionStatus.Present, SignatureVerdict.Unknown))!;
            var mutator = new RegistryAndFilePersistenceMutator();
            var captured = Assert.IsType<PersistenceSnapshot>(mutator.Capture(target));

            File.WriteAllText(path, "replacement");

            Assert.Equal(PersistenceMutationOutcome.TargetChanged,
                mutator.RemoveIfUnchanged(target, captured));
            Assert.Equal("replacement", File.ReadAllText(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
