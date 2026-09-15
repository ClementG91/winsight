# Objective-See plan: M2 decisions, M5-M8 slices - final state, 2026-09-15

Continues [`2026-09-14-response-layer-m0-m2.md`](2026-09-14-response-layer-m0-m2.md), against
[`OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md`](../OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md). It records what is
implemented and wired on the working tree, and what is not. It does not qualify a released artifact:
CI and the isolated VM campaign remain pending.

A standing rule governed this work: **no component without a production caller**. Every type and
public member added here was audited for a production call site (qualified by receiver, so that
same-named members such as `Restore` on different types could not hide one another). Anything
speculative was removed rather than kept "for later".

## M2 - BlockBlock: Guardian alerts are decisions (done, user-privilege vectors)

| Piece | Role | Tests |
|---|---|---|
| `GuardianAlertPresenter` (Application) | The decision logic: what an alert offers, and Allow / Block / Restore / Revoke. It composes the responder itself, so every decision lands in **one** journal | `GuardianAlertPresenterTests` |
| `AlertWindow` (Dashboard) | Thin WPF view over the presenter. "Decide later" is both default and cancel, so no keystroke removes a startup item. Each confirmation shows the exact undo command with its id | `AlertWindowTests` (real window, STA) |
| `MainWindow` wiring | An allowed item is acknowledged without being announced; a single arrival opens a decision window; a burst keeps the coalesced balloon. Windows are de-duplicated per item, capped at three (then the balloon), and closed with the dashboard | build + `VirusTotalSettingsWindowTests` (constructs `MainWindow`) |
| CLI | `winsight rules` (read-only), `winsight restore <id> --confirm`, `winsight revoke <id> --confirm` | `AdaptersActionHistoryTests`, manual refusal paths |

Every decision is visible and reversible: Block -> `restore` (by the block's action id, which also marks
the block undone), Allow -> `revoke` (by the rule id, which is also the Allow's journal id). Block
covers HKCU Run/RunOnce values and per-user Startup files; machine-wide items offer Allow only until the
service response tier ships.

## M5 - RansomWhere?: identification of the holding process (done, CLI)

- `RestartManagerInspector` / `IFileLockInspector`: names the processes holding files open, unelevated
  (`RestartManagerRealTests`, real held file).
- `FileHolderIdentifier`: revalidates each named pid against a fresh capture (drops a recycled pid),
  refuses protected processes, scores confidence (`FileHolderIdentifierTests`).
- Production: **`winsight holders <path>`**, and **`winsight suspend|resume|terminate <pid> --confirm`**
  through `ProcessResponder` (revalidation, protected-process refusal, journal) - verified end to end on
  a spawned child process, including refusal without `--confirm` and of a protected pid.

Not built, deliberately: automatic suspension on a decoy touch. It needs the ransomware alert window
to carry Resume/Terminate first; a suspend whose only undo is a command line is not the
operator-confirmed response the plan requires. The speculative coordinator and suspension gate written
for it were removed rather than left without a caller.

## M6 - OverSight: event-driven, process-level camera/microphone (done, CLI)

- `ConsentStoreChangeSignal` over the reusable `RegistryKeyWatcher`: a consent-store change wakes the
  watch loop immediately, the 1 s poll kept as fallback. Used by `AvWatchHost` (dashboard) and
  `winsight av --watch`. `CameraMicWakeOnChangeTests` shows a wake in ~0.1 s against a 30 s interval.
- `CaptureDeviceProcessLocator` + `RunningImageSource`: maps a desktop application's device use to
  revalidated process identities; packaged apps are reported unsupported rather than guessed.
  `winsight av --watch` names the process per activation.

Remaining: package-family mapping for packaged apps; a terminate/allow decision in the dashboard.

## M7 - What's Your Sign?: Explorer entry point (done)

- `SignaturePathGuard`, `FileSignatureReporter`, `SignatureContextMenuRegistrar` (`SignatureToolingTests`).
- `winsight sign <path> [--json]` and `Adapters.ReportSignature`, one verified path for CLI and window.
- **`SignatureWindow`**: `winsight-dashboard.exe --signature <path>` opens only this window - no
  dashboard, monitors or tray icon - showing verdict, signer, the most important caveat (revoked,
  user-installed root, revocation not checked) and copyable hashes. Verified end to end on this machine
  with `notepad.exe`: rendered "Signé et approuvé" / Microsoft, the SHA-256 shown equals
  `Get-FileHash`, and the process exits when the window closes (`SignatureWindowTests`,
  `DashboardStartupPolicyTests`).
- `register-signature-verb` / `unregister-signature-verb` lifecycle commands (idempotent).

Out of scope: the Windows 11 modern context menu (packaged `IExplorerCommand`), a VirusTotal view.

## M8 - depth items done

- **ReiKey**: `InputFilterWatcher` / `InputFilterDiff` alert when a keyboard/mouse class filter is added
  or removed; `winsight input --watch`.
- **KnockKnock / TaskExplorer**: `ReportItemFilter` with `--unsigned` and `--nonmicrosoft`, stacking with
  `--flagged` (severity stays with `--flagged` only, so one filter has one spelling).

Remaining M8: resident drivers, runtime DLL loads, dashboard task/connection views, away mode.

## Defects found by review, and fixed

1. **Regression: a restricted hive failed the camera/mic worker.** `RegistryKeyWatcher.Start` documented
   "false when the key cannot be opened" but threw on a policy-restricted HKLM; the exception reached
   `AvWatchHost`, which restart-looped. It now returns false, and `CameraMicMonitor.Watch` treats any
   change-signal fault as "poll only".
2. **A throwing subscriber could blind a watch thread** - contained (`AThrowingSubscriberDoesNotBlindTheWatch`).
3. **Subscribers ran under a lock** in `InputFilterWatcher` - now raised outside it.
4. **Duplicated native watcher.** A second copy of the registry watcher had to be fixed separately for
   the same bug; it was deleted and its user moved to `RegistryKeyWatcher`.
5. **The Explorer verb was broken.** It could be registered, but the dashboard ignored `--signature`.
6. **False promises in the alert UI.** "Can be restored" had no restore path, and Allow had no way to be
   listed or revoked. Both now exist and every confirmation names its undo.
7. **An Allow that failed to store was reported as allowed.** It is now reported as a failure.
8. **Two journals from one presenter.** A constructor let a responder and its presenter write to
   different journals (and tests to the operator's real one); the presenter now composes the responder.
9. **Rule store traps.** It accepted "until reboot"/"until process exit" rules it could never expire,
   and its lock creation could throw into monitors. It now refuses those durations and fails open.
10. **Top-level documentation was no longer true** ("nothing is modified"; "not reachable from File
    Explorer") - corrected in the README.
11. **Maintainability.** `Adapters.cs` additions split into `Adapters.Actions.cs`, `Adapters.Response.cs`
    and `Adapters.Signature.cs`; one exit-code mapping shared by every response verb; dead members
    removed (`FileSignatureReport.ToJson`, `ReportItemFilter.TryParse`, the `Flagged` token,
    `GuardianAlertOptions.Reason`, `RuleStore.PruneRebootScoped`, an unused resource key) and
    internal-only members narrowed.

12. **Untested entry points.** The command-line response verbs had injectable overloads but no tests,
    which had pulled `WinSight.Application` down to 82.3%; `AdaptersResponseTests` now cover every
    refusal path and the undo verbs (85.3%).
13. **No guard on translated format strings.** A French or Spanish string that lost a `{0}` would have
    thrown at runtime - in the very confirmation that explains how to undo a Block.
    `SatelliteResource_KeepsEveryFormatPlaceholder` now fails the build instead, with a parser guard.
14. **A planted Allow rule could hide persistence silently.** Allowed arrivals were acknowledged
    without any record. They are now journalled as "not announced", naming the rule and its revoke
    (`ASilencedArrivalIsStillRecordedNamingTheRuleAndItsRevoke`), and `THREAT_MODEL.md` states the
    evasion path and this mitigation. The threat model's claims of an automatic suspension and of a
    shipped service tier were also corrected.

## Validation on the working tree

- `dotnet format --verify-no-changes`: clean. `dotnet build winsight.sln -c Release`: 0 warnings, 0 errors.
- `Measure-Coverage.ps1 -Configuration Release`: **2,972 tests, 0 failures across all 23 test
  projects**; gate passed. Gated view: `WinSight.Application` 85.3%, `WinSight.InputHooks` 86.9%,
  `WinSight.NetMonitor` 86.9%, `winsight-dashboard` 88.6%, `WinSight.Response` 88.7%, `WinSight.Core`
  88.8%, `WinSight.AvMonitor` 94.7%, `WinSight.Attribution` 94.8%; engine libraries 82.7% overall;
  privileged managed logic 94.2%.
- Dead-code audit: every type added and every public member checked has a production call site;
  no reference to a removed member remains.
- End to end on this machine: `winsight suspend|resume|terminate` on a spawned child (and refusal of
  pid 4 and of a missing `--confirm`); `winsight actions` showing those entries; `winsight rules`,
  `restore` and `revoke` refusal paths; the Explorer signature window on `notepad.exe` (verdict, signer,
  SHA-256 equal to `Get-FileHash`, clean exit on close).

This is local rehearsal evidence on a working-tree build, not CI-attested release evidence.
