using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// WS-45 and WS-46. An entry is loaded by a process that may not see the machine as the scanner
/// does: a 32-bit process, where System32 is SysWOW64, or another account, whose variables expand
/// its command. Resolving in the scanner's view verified another file, or called a real one missing.
/// </summary>
public sealed class LoaderContextTests : IDisposable
{
    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string SysWow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

    private readonly string _root = Path.Combine(Path.GetTempPath(), "winsight-loader-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void A32BitProcessOpensSysWow64ForSystem32()
    {
        var wow64 = LoaderContext.Wow64Process;

        Assert.Equal(Path.Combine(SysWow64, "x.dll"), CommandLine.Redirect(Path.Combine(System32, "x.dll"), wow64));
        Assert.Equal(Path.Combine(System32, "x.dll"), CommandLine.Redirect(Path.Combine(Windows, "Sysnative", "x.dll"), wow64));
        Assert.Equal(Path.Combine(System32, "x.dll"), CommandLine.Redirect(Path.Combine(System32, "x.dll"), LoaderContext.Native));
    }

    [Theory]
    [InlineData(@"drivers\etc\hosts")]
    [InlineData(@"spool\drivers\x.dll")]
    [InlineData(@"catroot2\x.cat")]
    [InlineData(@"DriverStore\FileRepository\x.inf")]
    public void TheRedirectorsExemptionsStayInSystem32(string relative)
    {
        var path = Path.Combine(System32, relative);

        Assert.Equal(path, CommandLine.Redirect(path, LoaderContext.Wow64Process));
    }

    [Fact]
    public void AFullSystem32PathInA32BitContextVerifiesThe32BitFile()
    {
        var resolution = CommandLine.ResolveExecutable(Path.Combine(System32, "kernel32.dll"), LoaderContext.Wow64Process);

        Assert.Equal(ImageResolutionStatus.Present, resolution.Status);
        Assert.Equal(Path.Combine(SysWow64, "kernel32.dll"), resolution.ImagePath, ignoreCase: true);
    }

    [Fact]
    public void ABareNameOnlySysWow64HoldsIsFoundInA32BitContext()
    {
        var only32 = Directory.EnumerateFiles(SysWow64, "*.dll")
            .Select(Path.GetFileName)
            .FirstOrDefault(name => !File.Exists(Path.Combine(System32, name!)));
        Assert.NotNull(only32);

        var wow64 = CommandLine.ResolveExecutable(only32, LoaderContext.Wow64Process);
        var native = CommandLine.ResolveExecutable(only32);

        Assert.Equal(ImageResolutionStatus.Present, wow64.Status);
        Assert.Equal(Path.Combine(SysWow64, only32!), wow64.ImagePath, ignoreCase: true);
        Assert.NotEqual(wow64.ImagePath, native.ImagePath, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void A32BitProcessExpandsProgramFilesToTheX86Folder()
    {
        var x86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
        Assert.False(string.IsNullOrEmpty(x86));

        Assert.Equal(x86 + @"\a\b.dll", CommandLine.Expand(@"%ProgramFiles%\a\b.dll", LoaderContext.Wow64Process));
        Assert.Equal(
            Environment.GetEnvironmentVariable("ProgramFiles") + @"\a\b.dll",
            CommandLine.Expand(@"%ProgramFiles%\a\b.dll", LoaderContext.Native));
    }

    [Fact]
    public void AnotherAccountsVariablesExpandItsCommand()
    {
        var appData = Path.Combine(_root, "AppData", "Roaming");
        Directory.CreateDirectory(Path.Combine(appData, "Vendor"));
        var tool = Path.Combine(appData, "Vendor", "tool.exe");
        File.WriteAllBytes(tool, [0x4D, 0x5A]);
        var account = LoaderContext.ForAccount(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["APPDATA"] = appData,
        });

        var resolution = CommandLine.ResolveExecutable(@"""%APPDATA%\Vendor\tool.exe"" --silent", account);

        Assert.Equal(ImageResolutionStatus.Present, resolution.Status);
        Assert.Equal(tool, resolution.ImagePath, ignoreCase: true);
    }

    [Fact]
    public void APerAccountVariableTheAccountLacksIsNeverTheScannersOwn()
    {
        var unknown = LoaderContext.ForAccount(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal(@"%LOCALAPPDATA%\x.exe", CommandLine.Expand(@"%LOCALAPPDATA%\x.exe", unknown));
        Assert.Equal(@"%USERNAME%", CommandLine.Expand("%USERNAME%", unknown));
        // A machine-wide variable is the same for every account.
        Assert.Equal(Windows + @"\x.exe", CommandLine.Expand(@"%SystemRoot%\x.exe", unknown), ignoreCase: true);
        Assert.NotEqual(ImageResolutionStatus.Present, CommandLine.ResolveExecutable(@"%LOCALAPPDATA%\x.exe", unknown).Status);
    }

    [Fact]
    public void AnAccountsProfileGivesItsFolders()
    {
        var environment = AccountEnvironment.For("S-1-5-21-1-2-3-424242", _ => @"D:\Users\bob");

        Assert.NotNull(environment);
        Assert.Equal(@"D:\Users\bob", environment["USERPROFILE"]);
        Assert.Equal(@"D:\Users\bob\AppData\Roaming", environment["APPDATA"]);
        Assert.Equal(@"D:\Users\bob\AppData\Local", environment["localappdata"]);
        Assert.Equal(@"D:\Users\bob\AppData\Local\Temp", environment["TEMP"]);
        Assert.Equal("D:", environment["HOMEDRIVE"]);
        Assert.Equal(@"\Users\bob", environment["HOMEPATH"]);
        Assert.Null(AccountEnvironment.For("S-1-5-21-1-2-3-424242", _ => null));
        Assert.Null(AccountEnvironment.For("S-1-5-21-1-2-3-424242", _ => "relative"));
    }

    [Fact]
    public void TheSystemAccountsProfileIsItsOwn()
    {
        // The machine records the service accounts' profiles in ProfileList like any other.
        var environment = AccountEnvironment.For("S-1-5-18");

        Assert.NotNull(environment);
        Assert.EndsWith(@"config\systemprofile\AppData\Roaming", environment["APPDATA"], StringComparison.OrdinalIgnoreCase);
    }

    private static string Task(string principal, string context = "Author") => $"""
        <?xml version="1.0" encoding="UTF-16"?>
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Principals>{principal}</Principals>
          <Actions Context="{context}"><Exec><Command>%APPDATA%\x.exe</Command></Exec></Actions>
        </Task>
        """;

    [Theory]
    [InlineData("<Principal id=\"Author\"><UserId>S-1-5-18</UserId></Principal>", "S-1-5-18")]
    [InlineData("<Principal id=\"Author\"><UserId>NT AUTHORITY\\SYSTEM</UserId></Principal>", "S-1-5-18")]
    [InlineData("<Principal id=\"Author\"><UserId>LOCAL SERVICE</UserId></Principal>", "S-1-5-19")]
    [InlineData("<Principal id=\"Author\"><UserId>S-1-5-21-9-9-9-1001</UserId></Principal>", "S-1-5-21-9-9-9-1001")]
    [InlineData("<Principal id=\"Author\"><GroupId>S-1-5-32-545</GroupId></Principal>", null)]
    [InlineData("<Principal id=\"Other\"><UserId>S-1-5-20</UserId></Principal><Principal id=\"Author\"><UserId>S-1-5-18</UserId></Principal>", "S-1-5-18")]
    public void ATaskRunsAsItsActionsPrincipal(string principal, string? expected) =>
        Assert.Equal(expected, ScheduledTaskPrincipal.Sid(Task(principal), _ => throw new InvalidOperationException("no lookup")));

    [Fact]
    public void OnlyAMachineLocalAccountNameIsLookedUp()
    {
        var asked = new List<string>();
        string? Translate(string account)
        {
            asked.Add(account);
            return "S-1-5-21-7-7-7-1001";
        }

        Assert.Null(ScheduledTaskPrincipal.Sid(Task(@"<Principal id=""Author""><UserId>CONTOSO\bob</UserId></Principal>"), Translate));
        Assert.Null(ScheduledTaskPrincipal.Sid(Task(@"<Principal id=""Author""><UserId>bob</UserId></Principal>"), Translate));
        Assert.Empty(asked);

        var local = $@"{Environment.MachineName}\bob";
        Assert.Equal("S-1-5-21-7-7-7-1001", ScheduledTaskPrincipal.Sid(Task($@"<Principal id=""Author""><UserId>{local}</UserId></Principal>"), Translate));
        Assert.Equal([local], asked);
    }

    [Fact]
    public void TheScannersOwnTasksKeepTheScannersView()
    {
        var cache = new Dictionary<string, LoaderContext>(StringComparer.OrdinalIgnoreCase);

        Assert.Null(ScheduledTaskPrincipal.Loader("S-1-5-21-1-1-1-1001", "S-1-5-21-1-1-1-1001", cache));
        Assert.Null(ScheduledTaskPrincipal.Loader(null, "S-1-5-21-1-1-1-1001", cache));
        var system = ScheduledTaskPrincipal.Loader("S-1-5-18", "S-1-5-21-1-1-1-1001", cache);
        Assert.NotNull(system?.Environment);
        Assert.Same(system, ScheduledTaskPrincipal.Loader("s-1-5-18", "S-1-5-21-1-1-1-1001", cache));
    }
}
