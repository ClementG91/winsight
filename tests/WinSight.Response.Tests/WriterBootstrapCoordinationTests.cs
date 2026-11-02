using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;

using Xunit;

namespace WinSight.Response.Tests;

public sealed class WriterBootstrapCoordinationTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("winsight-bootstrap-writer-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void EstablishedWriterWaitsForUnrelatedBootstrapInsteadOfFailingStorage(bool nested, bool undo)
    {
        var parent = nested ? Directory.CreateDirectory(Path.Combine(_root, "nested")).FullName : _root;
        var path = Path.Combine(parent, "journal.jsonl");
        var journal = new ActionJournal(path, TimeSpan.FromMilliseconds(100));
        var entry = Entry();
        var undoId = Guid.NewGuid();
        Assert.True(journal.TryAppend(entry));
        var bytes = File.ReadAllBytes(path);
        using (var reader = ReadLegacy(Path.Combine(_root, "missing-rules.json")))
        {
            var blocked = undo ? journal.TryMarkUndone(entry.ActionId, undoId) : journal.TryAppendWithStatus(Entry());
            Assert.Equal("LockTimeout", blocked.Status.ToString());
            Assert.False(blocked.Durable);
            Assert.Equal(bytes, File.ReadAllBytes(path));
        }
        var released = undo ? journal.TryMarkUndone(entry.ActionId, undoId) : journal.TryAppendWithStatus(Entry());
        Assert.True(released.Durable, released.Detail);
        var entries = journal.ReadWithCoverage().Entries;
        if (undo)
        {
            Assert.Equal(undoId, Assert.Single(entries).UndoneByActionId);
        }
        else
        {
            Assert.Equal(2, entries.Count);
        }
    }

    [Fact]
    public void EstablishedWriterDoesNotRequireDirectoryListing()
    {
        var path = Path.Combine(_root, "journal.jsonl");
        var journal = new ActionJournal(path);
        var entry = Entry();
        Assert.True(journal.TryAppend(entry));
        var directory = new DirectoryInfo(_root);
        var original = directory.GetAccessControl();
        var denied = directory.GetAccessControl();
        denied.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!,
            FileSystemRights.ListDirectory, AccessControlType.Deny));
        try
        {
            directory.SetAccessControl(denied);
            Assert.True(journal.TryAppendWithStatus(Entry()).Durable);
            Assert.True(journal.TryMarkUndone(entry.ActionId, Guid.NewGuid()).Durable);
            Assert.Equal(2, journal.ReadWithCoverage().Entries.Count);
        }
        finally
        {
            var restored = new DirectorySecurity();
            restored.SetSecurityDescriptorBinaryForm(original.GetSecurityDescriptorBinaryForm(), AccessControlSections.Access);
            directory.SetAccessControl(restored);
        }
    }

    private static ActionJournalEntry Entry() => new(Guid.NewGuid(), ResponseActionKind.AddRule,
        ResponseOutcome.Succeeded, "target", DateTimeOffset.UtcNow, true);

    private static IDisposable ReadLegacy(string path)
    {
        var type = typeof(ActionJournal).Assembly.GetType("WinSight.Response.ResponseFileLock");
        Assert.NotNull(type);
        var method = type.GetMethod("AcquireReader", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsAssignableFrom<IDisposable>(method.Invoke(null, [path, TimeSpan.FromSeconds(1)]));
    }
}
