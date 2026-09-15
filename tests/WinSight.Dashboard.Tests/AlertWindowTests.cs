using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls.Primitives;

using WinSight.Application;
using WinSight.Core;
using WinSight.Persistence;
using WinSight.Response;

using Xunit;

namespace WinSight.Dashboard.Tests;

/// <summary>
/// The Guardian decision window itself, not only its presenter: what it offers, that it never defaults
/// to a destructive action, and that every confirmation names an undo that actually works.
/// </summary>
/// <remarks>
/// It joins the localization collection because it reads culture-dependent text, and that collection
/// runs on its own rather than in parallel with tests that switch the culture. No Application instance
/// is created: another test owns the process's single one.
/// </remarks>
[Collection(LocalizationCollection.Name)]
public sealed class AlertWindowTests
{
    [Theory]
    [InlineData(ResponseOutcome.Succeeded, "AlertBlocked")]
    [InlineData(ResponseOutcome.TargetChanged, "AlertRefusedChanged")]
    [InlineData(ResponseOutcome.TargetNotFound, "AlertRefusedChanged")]
    [InlineData(ResponseOutcome.NotAuthorized, "AlertRefusedUnavailable")]
    [InlineData(ResponseOutcome.NotSupported, "AlertRefusedUnavailable")]
    [InlineData(ResponseOutcome.Failed, "AlertFailed")]
    [InlineData(ResponseOutcome.TargetProtected, "AlertFailed")]
    public void EveryOutcomeHasAMessageAndNothingUnexpectedReadsAsSuccess(ResponseOutcome outcome, string key) =>
        Assert.Equal(key, AlertWindow.MessageKeyFor(outcome));

    [Fact]
    public void BlockIsNeverTheDefaultAndItsConfirmationNamesARestoreThatWorks() => RunSta(state =>
    {
        var mutator = new FakeMutator();
        var presenter = state.Presenter(mutator);
        var window = new AlertWindow(RunEntry(), presenter);

        // No keystroke may remove a startup item: Enter and Escape both mean "decide later".
        Assert.True(window.LaterButton.IsDefault);
        Assert.True(window.LaterButton.IsCancel);
        Assert.False(window.BlockButton.IsDefault);
        Assert.True(window.BlockButton.IsEnabled);

        window.BlockButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));

        Assert.True(mutator.Removed);
        var blockId = Assert.Single(state.Journal.Read(), e => e.Kind == ResponseActionKind.QuarantinePersistence).ActionId;
        Assert.Contains($"winsight restore {blockId}", window.StatusText.Text, StringComparison.Ordinal);
        Assert.Equal(Visibility.Visible, window.StatusPanel.Visibility);
        // One decision per alert: nothing left to click twice.
        Assert.False(window.BlockButton.IsEnabled);
        Assert.False(window.AllowButton.IsEnabled);

        // The id shown is the real handle: restoring with it succeeds.
        Assert.Equal(ResponseOutcome.Succeeded, presenter.Restore(blockId).Outcome);
        window.Close();
    });

    [Fact]
    public void AnItemWithNoReversibleRemovalOffersOnlyAllowAndSaysWhy() => RunSta(state =>
    {
        var service = new AutostartEntry(AutostartVector.Service, "svc", @"HKLM\SYSTEM\...\Services\svc",
            @"C:\svc.exe", @"C:\svc.exe", @"C:\svc.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);
        var window = new AlertWindow(service, state.Presenter(new FakeMutator()));

        Assert.False(window.BlockButton.IsEnabled);
        Assert.True(window.AllowButton.IsEnabled);
        Assert.Equal(LocalizationManager.Instance["AlertRefusedUnavailable"], window.HintText.Text);
        window.Close();
    });

    [Fact]
    public void AnAllowThatCouldNotBeStoredIsReportedAsAFailureNotAsAllowed() => RunSta(state =>
    {
        // A rule store the lock cannot be derived from: Allow cannot persist anything.
        var presenter = new GuardianAlertPresenter(
            new FakeMutator(), rules: new RuleStore("C:\\invalid\0rules.json"), journal: state.Journal);
        var window = new AlertWindow(RunEntry(), presenter);

        window.AllowButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));

        Assert.Equal(LocalizationManager.Instance["AlertFailed"], window.StatusText.Text);
        Assert.DoesNotContain("winsight revoke", window.StatusText.Text, StringComparison.Ordinal);
        window.Close();
    });

    [Fact]
    public void AStoredAllowNamesARevokeThatWorks() => RunSta(state =>
    {
        var presenter = state.Presenter(new FakeMutator());
        var entry = RunEntry();
        var window = new AlertWindow(entry, presenter);

        window.AllowButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));

        var ruleId = Assert.Single(presenter.AllowRules()).Id;
        Assert.Contains($"winsight revoke {ruleId}", window.StatusText.Text, StringComparison.Ordinal);
        Assert.NotNull(presenter.SuppressingRule(entry));

        // The id shown is the real handle: revoking with it makes the item alert again.
        Assert.Equal(ResponseOutcome.Succeeded, presenter.Revoke(ruleId));
        Assert.Null(presenter.SuppressingRule(entry));
        window.Close();
    });

    private static AutostartEntry RunEntry() =>
        new(AutostartVector.RunKey, "Updater", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [Registry64]",
            @"C:\u.exe", @"C:\u.exe", @"C:\u.exe", ImageResolutionStatus.Present, SignatureVerdict.Unsigned);

    /// <summary>Throwaway per-test state: one journal, quarantine and rule store under a temp directory.</summary>
    private sealed class TestState(string root)
    {
        public ActionJournal Journal { get; } = new(Path.Combine(root, "journal.jsonl"));

        public GuardianAlertPresenter Presenter(FakeMutator mutator) =>
            new(mutator, new Quarantine(Path.Combine(root, "quarantine")),
                new RuleStore(Path.Combine(root, "rules.json")), Journal);
    }

    /// <summary>Runs a WPF assertion on an STA thread, in English, against a throwaway state directory.</summary>
    private static void RunSta(Action<TestState> body)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            var root = Directory.CreateTempSubdirectory("winsight-alertwindow-").FullName;
            var original = LocalizationManager.Instance.CurrentCode;
            try
            {
                LocalizationManager.Instance.SetCulture("en");
                body(new TestState(root));
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                LocalizationManager.Instance.SetCulture(original);
                Directory.Delete(root, recursive: true);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        Assert.True(thread.Join(TimeSpan.FromSeconds(15)), "The alert window test did not finish.");
        Assert.Null(failure);
    }

    private sealed class FakeMutator : IPersistenceMutator
    {
        public bool Removed { get; private set; }

        public PersistenceSnapshot? Capture(PersistenceActionTarget target) => new([1, 2, 3], @"C:\u.exe");

        public bool Remove(PersistenceActionTarget target)
        {
            Removed = true;
            return true;
        }

        public bool OriginIsFree(PersistenceActionTarget target) => true;

        public bool Restore(PersistenceActionTarget target, byte[] payload) => true;
    }
}
