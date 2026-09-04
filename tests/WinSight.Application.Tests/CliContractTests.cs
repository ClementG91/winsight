using WinSight.Application;
using Xunit;

namespace WinSight.Application.Tests;

/// <summary>
/// The command line's contract with whatever is invoking it, which the README says is a scheduled
/// task.
/// </summary>
/// <remarks>
/// <b>Two ways it lied.</b> Exit code 1 meant both "something notable was found" and "the scan could
/// not run": a live ETW pump that ended unexpectedly returned 1 exactly as a scan that found a rogue
/// Run key does, so nothing automating WinSight could tell a finding from a broken observation. And
/// no option was ever validated - <c>--jsonn</c> silently produced human output, which downstream is
/// an empty parse rather than an error.
/// </remarks>
public sealed class CliContractTests
{
    /// <summary>
    /// Findings stay in 0/1 and failures start at 10, so a caller that only tests for non-zero is
    /// unaffected while one that wants the distinction can have it.
    /// </summary>
    [Fact]
    public void FindingsAndFailuresOccupySeparateRanges()
    {
        Assert.Equal(0, CliContract.Clean);
        Assert.Equal(1, CliContract.Notable);
        Assert.Equal(2, CliContract.UsageError);
        Assert.True(CliContract.ObservationFailed >= 10);
        Assert.True(CliContract.ServiceUnavailable >= 10);
        Assert.True(CliContract.UnexpectedFailure >= 10);
    }

    [Fact]
    public void EveryFailureCodeIsDistinct()
    {
        int[] codes =
        [
            CliContract.Clean, CliContract.Notable, CliContract.UsageError,
            CliContract.ObservationFailed, CliContract.ServiceUnavailable,
            CliContract.UnexpectedFailure,
        ];

        Assert.Equal(codes.Length, codes.Distinct().Count());
    }

    [Theory]
    [InlineData("--jsonn")]
    [InlineData("--flaged")]
    [InlineData("-j")]
    [InlineData("--verbose")]
    public void AMisspeltOptionIsRejectedRatherThanIgnored(string option) =>
        Assert.Equal(option, CliContract.FirstUnknownOption(["persistence", option]));

    [Theory]
    [InlineData("persistence --json")]
    [InlineData("--flagged --json")]
    [InlineData("av --watch")]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("--version")]
    [InlineData("")]
    public void EveryDocumentedOptionIsAccepted(string commandLine) =>
        Assert.Null(CliContract.FirstUnknownOption(
            commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries)));

    [Theory]
    [InlineData("--JSON", "--json")]
    [InlineData("--FLAGGED", "--flagged")]
    [InlineData("--WATCH", "--watch")]
    [InlineData("--HELP", "--help")]
    [InlineData("-H", "-h")]
    [InlineData("--VERSION", "--version")]
    [InlineData("--NO-NETWORK", "--no-network")]
    public void ValidatedOptionsAreAlsoAppliedCaseInsensitively(string supplied, string queried) =>
        Assert.True(CliContract.HasOption(["persistence", supplied], queried));

    /// <summary>A bare word is a verb, validated by the dispatcher that owns the catalogue.</summary>
    [Fact]
    public void BareWordsAreNotTreatedAsOptions() =>
        Assert.Null(CliContract.FirstUnknownOption(["process", "4242"]));

    /// <summary>
    /// <c>winsight persistence extensions</c> ran a persistence scan and said nothing about the
    /// second word, so the operator got a report for a tool they had not asked about.
    /// </summary>
    [Fact]
    public void ASecondVerbIsSurfacedRatherThanDropped() =>
        Assert.Equal(["extensions"], CliContract.ExtraVerbs(["persistence", "extensions"], "persistence"));

    [Fact]
    public void OneVerbWithOptionsLeavesNothingOver() =>
        Assert.Empty(CliContract.ExtraVerbs(["persistence", "--json", "--flagged"], "persistence"));

    [Fact]
    public void AVerbThatIsNotPresentClaimsNothing() =>
        Assert.Empty(CliContract.ExtraVerbs(["--json"], "all"));

    /// <summary>The published table must actually name every code, or it is documentation drift.</summary>
    [Fact]
    public void TheExitCodeTableNamesEveryCode()
    {
        var table = CliContract.ExitCodeTable;

        foreach (var code in new[]
        {
            CliContract.Clean, CliContract.Notable, CliContract.UsageError,
            CliContract.ObservationFailed, CliContract.ServiceUnavailable,
            CliContract.UnexpectedFailure,
        })
        {
            Assert.Contains(
                code.ToString(System.Globalization.CultureInfo.InvariantCulture),
                table,
                StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The help text and the contract must agree, since the help text is what an operator reads.
    /// </summary>
    [Fact]
    public void TheHelpTextCarriesTheSameCodes()
    {
        Assert.Contains("Exit codes", CliHelp.Text, StringComparison.Ordinal);
        foreach (var code in new[]
        {
            CliContract.ObservationFailed, CliContract.ServiceUnavailable, CliContract.UnexpectedFailure,
        })
        {
            Assert.Contains(
                $"  {code.ToString(System.Globalization.CultureInfo.InvariantCulture)}",
                CliHelp.Text,
                StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// An option the verb cannot honour is a usage error, not something to drop.
    /// </summary>
    /// <remarks>
    /// <c>--watch</c> was accepted globally and honoured by four verbs, so
    /// <c>winsight persistence --watch</c> ran a one-shot scan, printed it and exited. The operator
    /// asked to be told when something changed and was handed a snapshot, with nothing saying the
    /// word they typed had been dropped - and somebody who leaves that in a scheduled task believes
    /// they have a live watch.
    ///
    /// This class already refuses a second verb and a misspelled option for exactly that reason. It
    /// was fixed where the argument was wrong and missed where the argument is right and the verb
    /// cannot do it.
    /// </remarks>
    [Theory]
    [InlineData("persistence")]
    [InlineData("hosts")]
    [InlineData("processes")]
    [InlineData("firewall")]
    [InlineData("all")]
    public void WatchOnAVerbThatCannotWatchIsAUsageError(string verb) =>
        Assert.Equal("--watch", CliContract.FirstUnsupportedOption([verb, "--watch"], verb));

    [Theory]
    [InlineData("av")]
    [InlineData("avmonitor")]
    [InlineData("attribution")]
    [InlineData("dns")]
    public void WatchOnAVerbThatCanWatchIsAccepted(string verb) =>
        Assert.Null(CliContract.FirstUnsupportedOption([verb, "--watch"], verb));

    [Fact]
    public void AVerbWithoutWatchIsUnaffected() =>
        Assert.Null(CliContract.FirstUnsupportedOption(
            ["persistence", "--json", "--flagged", "--no-network"], "persistence"));

    /// <summary>
    /// The message names where the option does work, because "unsupported" on its own sends
    /// somebody back to the help text to find out.
    /// </summary>
    [Fact]
    public void TheWatchableVerbsAreNamedForTheUsageMessage()
    {
        var verbs = CliContract.WatchableVerbList;

        Assert.Contains("av", verbs, StringComparison.Ordinal);
        Assert.Contains("dns", verbs, StringComparison.Ordinal);
        Assert.Contains("attribution", verbs, StringComparison.Ordinal);
        // The alias is not listed twice under two spellings.
        Assert.DoesNotContain("avmonitor", verbs, StringComparison.Ordinal);
    }
}
