using WinSight.Persistence;

using Xunit;

namespace WinSight.Persistence.Tests;

/// <summary>
/// Scheduled tasks are a top-tier persistence vector, and WinSight reported <b>zero</b> of them
/// unelevated while listing the surface as covered.
/// </summary>
/// <remarks>
/// The old source parsed the XML files under <c>%SystemRoot%\System32\Tasks</c>, which is
/// administrators-only; <c>Directory.GetFiles</c> throws for the whole tree rather than skipping
/// what it cannot read, and that exception was turned into an empty list. Measured on a real
/// desktop: 0 tasks unelevated, 104 elevated, with nothing in the report suggesting anything was
/// missing. Reading through the Task Scheduler service instead needs no elevation and sees more
/// (195 on the same machine). These tests drive a scripted source, so the enumerator is covered
/// without COM and without depending on whatever tasks the test machine happens to have.
/// </remarks>
public sealed class ScheduledTaskEnumeratorTests
{
    private const string TaskXml = """
        <?xml version="1.0" encoding="UTF-16"?>
        <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Actions Context="Author">
            <Exec>
              <Command>C:\Users\me\AppData\Local\Updater\update.exe</Command>
              <Arguments>/silent</Arguments>
            </Exec>
          </Actions>
        </Task>
        """;

    [Fact]
    public void ReportsTheCommandOfEveryVisibleTask()
    {
        var source = new ScriptedSource([
            new ScheduledTaskDefinition(@"\Updater\RunDaily", TaskXml),
        ]);

        var entry = Assert.Single(new ScheduledTaskEnumerator(source).Enumerate());

        Assert.Equal(AutostartVector.ScheduledTask, entry.Vector);
        Assert.Equal(@"Updater\RunDaily", entry.Name);
        Assert.Equal(@"C:\Users\me\AppData\Local\Updater\update.exe", entry.Command);
    }

    [Fact]
    public void LocatesATaskUnderTheTasksDirectory()
    {
        // The location is what the operator is told to go and look at, and what the live watcher
        // watches, so it must still read as a path under \System32\Tasks.
        var source = new ScriptedSource([
            new ScheduledTaskDefinition(@"\Microsoft\Windows\UpdateOrchestrator\Foo", TaskXml),
        ]);

        var entry = Assert.Single(new ScheduledTaskEnumerator(source).Enumerate());

        Assert.Contains(@"System32\Tasks", entry.Location, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(@"UpdateOrchestrator\Foo", entry.Location, StringComparison.OrdinalIgnoreCase);
    }

    // THE regression this whole change exists for. An unreachable source and a machine with no
    // tasks both produce an empty list; only one of them is a fact about the machine.
    [Fact]
    public void AnUnreachableServiceIsReportedAsUnreadable_NotAsNoTasks()
    {
        var source = new ScriptedSource([], unreadable: true);
        var enumerator = new ScheduledTaskEnumerator(source);

        Assert.Empty(enumerator.Enumerate());

        Assert.Equal(1, enumerator.UnreadableLocations);
    }

    [Fact]
    public void AMachineWithNoTasksIsNotReportedAsUnreadable()
    {
        var enumerator = new ScheduledTaskEnumerator(new ScriptedSource([]));

        Assert.Empty(enumerator.Enumerate());

        Assert.Equal(0, enumerator.UnreadableLocations);
    }

    [Fact]
    public void ATaskWithNoExecActionContributesNothing()
    {
        // Plenty of real tasks run a COM handler rather than an executable; they are not autostart
        // commands and must not become empty rows.
        var source = new ScriptedSource([
            new ScheduledTaskDefinition(@"\ComHandlerTask", """
                <?xml version="1.0" encoding="UTF-16"?>
                <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                  <Actions Context="Author">
                    <ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>
                  </Actions>
                </Task>
                """),
        ]);

        Assert.Empty(new ScheduledTaskEnumerator(source).Enumerate());
    }

    [Fact]
    public void MalformedTaskXmlDoesNotStopTheOthers()
    {
        var source = new ScriptedSource([
            new ScheduledTaskDefinition(@"\Broken", "not xml at all"),
            new ScheduledTaskDefinition(@"\Good", TaskXml),
        ]);

        var entry = Assert.Single(new ScheduledTaskEnumerator(source).Enumerate());

        Assert.Equal("Good", entry.Name);
    }

    private sealed class ScriptedSource(
        IReadOnlyList<ScheduledTaskDefinition> tasks, bool unreadable = false) : IScheduledTaskSource
    {
        public bool Unreadable => unreadable;

        public IEnumerable<ScheduledTaskDefinition> Enumerate() => tasks;
    }
}
