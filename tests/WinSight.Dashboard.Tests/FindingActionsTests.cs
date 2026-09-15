using WinSight.Reporting;
using Xunit;

namespace WinSight.Dashboard.Tests;

public sealed class FindingActionsTests
{
    [Fact]
    public void ExistingAbsolutePath_ReturnsExistingImage()
    {
        var file = Path.GetTempFileName();
        try
        {
            var item = Item(new Dictionary<string, string?> { ["image"] = file });

            Assert.Equal(Path.GetFullPath(file), FindingActions.ExistingAbsolutePath(item));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData("tool.exe")]
    [InlineData("..\\tool.exe")]
    [InlineData("C:\\does-not-exist\\tool.exe")]
    [InlineData("\\\\server\\share\\tool.exe")]
    [InlineData("\\\\?\\C:\\Windows\\notepad.exe")]
    [InlineData("\\\\.\\C:\\Windows\\notepad.exe")]
    public void ExistingAbsolutePath_RejectsUnsafeOrMissingPath(string path)
    {
        var item = Item(new Dictionary<string, string?> { ["path"] = path });

        Assert.Null(FindingActions.ExistingAbsolutePath(item));
    }

    private static ReportItem Item(IReadOnlyDictionary<string, string?> fields) =>
        new(Severity.Notable, "test", "detail", fields);

    [Fact]
    public void AnExistingDriveLetterPathMustAlsoBeOnLocalStorage()
    {
        var file = Path.GetTempFileName();
        try
        {
            var item = Item(new Dictionary<string, string?> { ["image"] = file });
            var inspected = new List<string>();

            var result = FindingActions.ExistingAbsolutePath(item, candidate =>
            {
                inspected.Add(candidate);
                return false; // A mapped drive has the same syntax as this existing local file.
            });

            Assert.Null(result);
            Assert.Equal([file], inspected);
        }
        finally
        {
            File.Delete(file);
        }
    }
}
