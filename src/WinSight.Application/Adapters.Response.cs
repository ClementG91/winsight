using System.Globalization;

using WinSight.Core;
using WinSight.Reporting;
using WinSight.Response;

namespace WinSight.Application;

/// <summary>
/// The operator-confirmed response surface on the command line: name the processes holding a file, and
/// suspend, resume or terminate one.
/// </summary>
/// <remarks>
/// Every mutation here requires an explicit <c>--confirm</c>: there is no interactive prompt on a
/// command line, so the confirmation has to be in the invocation itself. Each action goes through
/// <see cref="ProcessResponder"/>, which revalidates the captured identity, refuses protected and
/// WinSight processes, and records the attempt in the append-only action journal. Suspension is
/// reversible and is the action to prefer; termination is offered but never automatic.
/// </remarks>
public static partial class Adapters
{
    /// <summary>
    /// Names the processes currently holding a file open (Restart Manager), as an inventory report.
    /// Read-only: it identifies, it never acts. Useful when a decoy or document is being rewritten and
    /// the question is which process is doing it.
    /// </summary>
    public static ToolReport DescribeHolders(string? rawPath)
    {
        var builder = new ToolReport.Builder("holders");
        var path = SignaturePathGuard.LocalFileArgument(rawPath);
        if (path is null)
        {
            builder.Add(Severity.Notable, "not an ordinary local file",
                "the argument is not an existing local file path (UNC and device paths are refused)",
                new Dictionary<string, string?> { ["kind"] = "holderTarget", ["path"] = rawPath });
            return builder.Build("holders: no local file to inspect");
        }

        var identification = new FileHolderIdentifier(new RestartManagerInspector(), new Win32ProcessInspector())
            .Identify([path]);
        foreach (var candidate in identification.Candidates)
        {
            builder.Add(Severity.Info,
                UntrustedDisplayText.Neutralize(candidate.AppName),
                $"pid {candidate.Identity.Pid} — "
                    + UntrustedDisplayText.Neutralize(candidate.Identity.ImagePath),
                new Dictionary<string, string?>
                {
                    ["kind"] = "fileHolder",
                    ["pid"] = candidate.Identity.Pid.ToString(CultureInfo.InvariantCulture),
                    ["app"] = candidate.AppName,
                    ["image"] = candidate.Identity.ImagePath,
                    ["imageSha256"] = candidate.Identity.ImageSha256,
                });
        }
        return builder.Build($"{identification.Candidates.Count} process(es) holding the file "
            + $"({identification.Confidence}: {identification.Reason})");
    }

    /// <summary>
    /// Suspends, resumes or terminates a process by id, after revalidating that it is still the same
    /// process. Refuses without <paramref name="confirmed"/>, and refuses protected processes.
    /// </summary>
    public static int RespondToProcess(ResponseActionKind kind, string? pidArgument, bool confirmed)
    {
        if (!int.TryParse(pidArgument, CultureInfo.InvariantCulture, out var pid) || pid < 0)
        {
            Console.Error.WriteLine($"usage: winsight {VerbFor(kind)} <pid> --confirm");
            return CliContract.UsageError;
        }
        if (!confirmed)
        {
            Console.Error.WriteLine(
                $"'{VerbFor(kind)}' changes a running process and requires --confirm");
            return CliContract.UsageError;
        }

        var inspector = new Win32ProcessInspector();
        // Say "protected" when that is the real reason, rather than reporting it as unreadable: a
        // critical Windows process cannot be opened either, and the two are not the same refusal.
        if (ProtectedProcesses.IsProtected(pid, inspector.ImageFileName(pid)))
        {
            Console.WriteLine($"{ResponseOutcome.TargetProtected}: {VerbFor(kind)} pid {pid} "
                + "— refused, this is a protected process");
            return CliContract.Notable;
        }
        var identity = inspector.Capture(pid, hashImage: true);
        if (identity is null)
        {
            Console.Error.WriteLine($"no process with id {pid} that WinSight can open");
            return CliContract.Notable;
        }

        var target = Path.GetFileName(identity.ImagePath);
        var responder = new ProcessResponder(inspector, new Win32ProcessController());
        var result = kind switch
        {
            ResponseActionKind.SuspendProcess => responder.Suspend(identity, target),
            ResponseActionKind.ResumeProcess => responder.Resume(identity, target),
            ResponseActionKind.TerminateProcess => responder.Terminate(identity, target),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "not a process action"),
        };

        Console.WriteLine(
            $"{result.Outcome}: {VerbFor(kind)} pid {pid} ({UntrustedDisplayText.Neutralize(target)})"
            + (result.Reversible ? " — reversible, see `winsight actions`" : string.Empty));
        return ExitCodeFor(result.Outcome);
    }

    /// <summary>The Allow rules in force, with the id <c>winsight revoke</c> takes. Read-only.</summary>
    public static ToolReport Rules() => Rules(new GuardianAlertPresenter());

    internal static ToolReport Rules(GuardianAlertPresenter presenter)
    {
        var rules = presenter.AllowRules();
        var builder = new ToolReport.Builder("rules");
        foreach (var rule in rules)
        {
            builder.Add(Severity.Info,
                $"{rule.Decision} — {rule.Scope}",
                $"{rule.CreatedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} — "
                    + UntrustedDisplayText.Neutralize(rule.Item ?? rule.ImagePath ?? string.Empty),
                new Dictionary<string, string?>
                {
                    ["kind"] = "responseRule",
                    ["ruleId"] = rule.Id.ToString(),
                    ["decision"] = rule.Decision.ToString(),
                    ["scope"] = rule.Scope.ToString(),
                    ["duration"] = rule.Duration.ToString(),
                    ["item"] = rule.Item,
                    ["image"] = rule.ImagePath,
                    ["created"] = rule.CreatedUtc.ToString("O", CultureInfo.InvariantCulture),
                });
        }
        return builder.Build(rules.Count == 0
            ? "no allow rules in force"
            : $"{rules.Count} allow rule(s) in force; `winsight revoke <id> --confirm` removes one");
    }

    /// <summary>Puts back a blocked startup item, by the block's action id. Requires --confirm.</summary>
    public static int RestoreBlocked(string? idArgument, bool confirmed) =>
        RestoreBlocked(new GuardianAlertPresenter(), idArgument, confirmed);

    internal static int RestoreBlocked(GuardianAlertPresenter presenter, string? idArgument, bool confirmed)
    {
        if (RejectUnconfirmedId("restore", idArgument, confirmed, out var id) is { } usage)
        {
            return usage;
        }
        var result = presenter.Restore(id);
        Console.WriteLine($"{result.Outcome}: restore {UntrustedDisplayText.Neutralize(result.Target)}");
        return ExitCodeFor(result.Outcome);
    }

    /// <summary>Removes an Allow rule, by its id, so the item alerts again. Requires --confirm.</summary>
    public static int RevokeRule(string? idArgument, bool confirmed) =>
        RevokeRule(new GuardianAlertPresenter(), idArgument, confirmed);

    internal static int RevokeRule(GuardianAlertPresenter presenter, string? idArgument, bool confirmed)
    {
        if (RejectUnconfirmedId("revoke", idArgument, confirmed, out var id) is { } usage)
        {
            return usage;
        }
        var outcome = presenter.Revoke(id);
        Console.WriteLine($"{outcome}: revoke rule {id}");
        return ExitCodeFor(outcome);
    }

    /// <summary>A usage exit code when the id is malformed or the change is unconfirmed; null when it may run.</summary>
    private static int? RejectUnconfirmedId(string verb, string? argument, bool confirmed, out Guid id)
    {
        if (!Guid.TryParse(argument, out id))
        {
            Console.Error.WriteLine($"usage: winsight {verb} <id> --confirm  (ids are listed by `winsight actions`)");
            return CliContract.UsageError;
        }
        if (!confirmed)
        {
            Console.Error.WriteLine($"'{verb}' changes WinSight's decisions and requires --confirm");
            return CliContract.UsageError;
        }
        return null;
    }

    /// <summary>One mapping from an action outcome to an exit code, shared by every response verb.</summary>
    internal static int ExitCodeFor(ResponseOutcome outcome) => outcome switch
    {
        ResponseOutcome.Succeeded => CliContract.Clean,
        ResponseOutcome.Failed => CliContract.UnexpectedFailure,
        _ => CliContract.Notable, // a stated refusal: protected, changed, gone, or not supported
    };

    private static string VerbFor(ResponseActionKind kind) => kind switch
    {
        ResponseActionKind.SuspendProcess => "suspend",
        ResponseActionKind.ResumeProcess => "resume",
        ResponseActionKind.TerminateProcess => "terminate",
        _ => kind.ToString(),
    };
}
