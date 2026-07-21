using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// A Startup folder that exists but will not open must not read as an empty one.
/// </summary>
/// <remarks>
/// The Startup folders are a classic drop point, and an attacker who puts something in one can also
/// deny read access to it. The enumerator answered that with an empty list, so the surface reported
/// clean — the same shape as the scheduled-tasks defect, where one denied directory became "this
/// machine has no scheduled tasks".
/// </remarks>
public sealed class StartupFolderCoverageTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(), $"winsight-startup-{Guid.NewGuid():N}");

    public StartupFolderCoverageTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void AReadableFolderReportsItsContentsAndNoGap()
    {
        var dir = Path.Combine(_root, "user");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "updater.exe"), "");
        var enumerator = new StartupFolderEnumerator([(dir, "User startup")]);

        var entry = Assert.Single(enumerator.Enumerate());

        Assert.Equal("updater.exe", entry.Name);
        Assert.Equal(0, enumerator.UnreadableLocations);
    }

    [Fact]
    public void AnEmptyFolderIsNotAGap()
    {
        var dir = Path.Combine(_root, "empty");
        Directory.CreateDirectory(dir);
        var enumerator = new StartupFolderEnumerator([(dir, "User startup")]);

        Assert.Empty(enumerator.Enumerate());

        Assert.Equal(0, enumerator.UnreadableLocations);
    }

    [Fact]
    public void AFolderThatDoesNotExistIsNotAGap()
    {
        // A machine with no all-users Startup folder is ordinary, not suspicious.
        var enumerator = new StartupFolderEnumerator([(Path.Combine(_root, "absent"), "Common startup")]);

        Assert.Empty(enumerator.Enumerate());

        Assert.Equal(0, enumerator.UnreadableLocations);
    }

    [Fact]
    public void AFolderThatCannotBeListedIsCountedAsAGap()
    {
        // The actual scenario, not a stand-in: a drop point whose ACL denies listing, which is what
        // someone hiding something there would do.
        var denied = DenyListing(Path.Combine(_root, "denied"));
        var enumerator = new StartupFolderEnumerator([(denied, "User startup")]);

        Assert.Empty(enumerator.Enumerate());

        Assert.Equal(1, enumerator.UnreadableLocations);
    }

    [Fact]
    public void OneUnreadableFolderDoesNotHideTheOther()
    {
        var readable = Path.Combine(_root, "readable");
        Directory.CreateDirectory(readable);
        File.WriteAllText(Path.Combine(readable, "ok.exe"), "");
        var denied = DenyListing(Path.Combine(_root, "denied2"));
        var enumerator = new StartupFolderEnumerator(
            [(denied, "Common startup"), (readable, "User startup")]);

        Assert.Single(enumerator.Enumerate());

        Assert.Equal(1, enumerator.UnreadableLocations);
    }

    /// <summary>Creates a directory the current user is explicitly denied from listing.</summary>
    private static string DenyListing(string path)
    {
        Directory.CreateDirectory(path);
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
            System.Security.AccessControl.FileSystemRights.ListDirectory,
            System.Security.AccessControl.AccessControlType.Deny));
        info.SetAccessControl(security);
        return path;
    }

    /// <summary>Lifts the deny rule so the directory can be removed again.</summary>
    private static void AllowListing(string path)
    {
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
        security.RemoveAccessRuleAll(new System.Security.AccessControl.FileSystemAccessRule(
            System.Security.Principal.WindowsIdentity.GetCurrent().User!,
            System.Security.AccessControl.FileSystemRights.ListDirectory,
            System.Security.AccessControl.AccessControlType.Deny));
        info.SetAccessControl(security);
    }

    public void Dispose()
    {
        try
        {
            // The deny rules must be lifted first, or the temp directory outlives the test run.
            foreach (var directory in Directory.GetDirectories(_root))
            {
                AllowListing(directory);
            }
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException
                                     or UnauthorizedAccessException
                                     or DirectoryNotFoundException)
        {
        }
    }
}
