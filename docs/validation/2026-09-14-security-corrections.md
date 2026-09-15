# Security audit revalidation and corrections — 2026-09-14

Base commit: `e0265c6b0dd1c40354a592a89c29fdcbdc65f45b` (v0.12.1).
Corrections are in the working tree; this record does not qualify a released artifact.
Host: Windows build 26200, x64, non-administrative test process.

> A later pass on the same day is recorded separately in
> [`2026-09-14-guardian-av-msix-ransomware-hardening.md`](2026-09-14-guardian-av-msix-ransomware-hardening.md);
> the results below are left as recorded for the state they describe.

## Verdict

The audit found reproducible security and reliability defects. The previous test campaigns did
not exercise these cases, so their success cannot establish that the current or published product
is free of them. Authenticode signing of WinSight's own distribution remains excluded from the
release-readiness blocker assessment, as requested. Verification of other files' signatures
remains a security requirement and is included here.

## Findings and corrections

| Finding | Evidence and correction | Regression evidence |
|---|---|---|
| Package sidecar can manufacture a trusted verdict | An unsigned PE next to a `PKCX`/PKCS#7 collection containing only a public trusted certificate changed from `Unsigned` to `SignedTrusted`. No private key, valid package signature or file binding was needed. Removed this fallback; require embedded Authenticode or verified catalog membership. | `PackageSidecarTrustTests`: both direct and ancestor-directory attacks fail on the old code and pass after correction; native catalog tests remain green. |
| Stale root-store classification and cached trust | A process-lifetime snapshot missed later root changes. Each batch now reads immutable machine/user root sets; their fingerprint participates in the signature cache identity. An unreadable store cannot establish a machine anchor or populate the cache. | `TrustStoreRefreshTests`, using injected stores and chain roots; no real trust store was modified. |
| Cleanup deletes an edited or replaced document | Path-only decoy deletion could delete a different file at the same name. Cleanup now verifies identity and pristine content with writes/deletion excluded and requests deletion through that same handle. | `CanaryCleanupSafetyTests`, using temporary files, including same-content replacements and edits. |
| Guardian merges distinct persistence entries | Source location was omitted and arguments were lowercased/whitespace-collapsed. Identity now retains source, location and the argument payload, preserving meaningful name characters. | `GuardianRegressionTests`, `PersistenceIdentityArgumentsTests`. |
| A removed and reinstalled entry does not alert again | The live baseline and journal dedup suppressed later arrivals. Confirmed absences now leave the baseline; a new arrival refreshes an existing pending journal event. Scoped or failed sources cannot remove other sources' observations. | `GuardianRegressionTests`, including scoped scans, partial startup reads and repeated arrivals. |
| Lossy persisted baseline | Older identities cannot encode the corrected semantics. Baseline v3 stores source/location and encoded, lossless strings. Old formats are silently reseeded once. | v1/v2 upgrade and v3 multiline round-trip cases in `GuardianRegressionTests`. |
| Monitor shutdown can deadlock after scan serialization | A worker notifying under its scan lock can wait on WPF while UI disposal waits on the same lock. Notification must occur outside that lock. | Guardian shutdown regression. |
| Malformed extension metadata aborts scanning | Valid JSON with unexpected types threw outside the parser's handled failure path. Shape checks now isolate invalid manifests and retain valid extensions; bad localization falls back without discarding permissions. | `ManifestShapeTests`: object/array/primitive mismatches, invalid permission items and short localization tokens. |
| Camera/microphone coverage and worker health are lost | The monitor discarded acquisition coverage and the UI displayed an unconditional active state. The worker now exposes its state and coverage, retries ordinary acquisition failures, and does not infer deactivation from unreadable data. | `CameraMicCoverageTests`, `AvWatchHealthTests`, actual emitting-subscriber failure test. |
| Hosts path can be redirected by inherited environment | `SystemRoot` from the process environment could point at a fake hosts file. Discovery now uses the Windows system-folder API; nonlocal explicit sources are rejected before opening. | `HostsPathTrustTests`. |
| Dashboard file actions can touch mapped network drives | Drive-letter syntax alone did not prove local storage before `File.Exists`. The existing local-storage guard now runs before file access. | `FindingActionsTests`, injected denied-storage decision on an otherwise existing file. |
| Required CI check omits packaging | The stable required `build-test` job depended only on `verify`. It now requires both verification and native packaging matrices, including installer tests. | Workflow dependency review; remote execution on these changes remains pending. |
| Product/readiness claims exceed evidence | Blanket parity/superiority and current readiness statements were not supported by the implemented response workflows or comparative testing. Current documents identify the gaps and retain old qualification as historical evidence. | Updated README, readiness and Objective-See comparison; official product descriptions linked in the comparison. |

## Independent counter-review (second pass, same day)

A second reviewer re-derived each finding from the code, reproduced it where possible, and treated
the first pass's tests and documents as claims. The inherited working tree was preserved (a patch
and copies of untracked files were saved outside the repository before any edit; no reset).

### Confirmed findings of the first pass

- **Package sidecar trust** — reproduced on an isolated checkout of `e0265c6`:
  `PackageSidecarTrustTests` fail there with `Expected: Unsigned / Actual: SignedTrusted` and pass
  on the final tree. The removed code imported the certificate bag without checking any CMS signature
  or file binding, so copying a genuine Store package's `AppxSignature.p7x` beside any PE was enough.
- **Root-store snapshots and cache invalidation**, **identity-based decoy cleanup**, **Guardian
  identity/argument semantics**, **scoped-scan retention**, **baseline v3**, **manifest shape
  isolation**, **hosts path from the system-folder API** (checked in a process with a poisoned
  `SystemRoot`: `C:\WINDOWS\system32`), **local-storage check before `File.Exists`**, and the
  **`build-test` dependency on `verify` and `package`** (gate script evaluated for success, failure,
  skipped and cancelled results under `bash -e`).

### Incomplete or unverified in the first pass, corrected here

| Defect | Reproduction on the inherited tree | Correction | Evidence |
|---|---|---|---|
| Ransomware badge counted watched directories, not decoys | A directory whose decoy names were all occupied by preserved files had `WatchedDirectoryCount = 1` and zero canaries, rendered Active | `RansomwareMonitor.ArmedDirectoryCount` requires a live watch and the full decoy set; `RansomwareHost.Health` feeds the dashboard | `RansomwareArmedCoverageTests` (failed/partial/active) — `src/WinSight.Ransomware/RansomwareMonitor.cs`, `RansomwareFileWatcher.IsWatching` |
| Manifest records for directories outside the session were dropped | `RestoreRecords`/`RemoveOrphans` filtered by the current directories and then rewrote or deleted the manifest | Records are retained; deletion still requires the expected path, identity and pristine bytes | `RecordsForADirectoryOutsideThisSessionAreKeptUntilThatDirectoryIsCleaned` |
| Tests wrote the operator's real decoy manifest | `%LOCALAPPDATA%\WinSight\canary-manifest.txt` contained a `wsg-mon-…` test path after the suite | Internal `RansomwareMonitor` constructor with seed/manifest; monitor tests use temporary state | real manifest timestamp unchanged by later runs |
| Guardian `Dispose` waited for a full scan on the UI thread | New test: 5 s timeout during startup and change scans | `Dispose` cancels a lifetime token before taking the scan lock | `DisposeCancelsAnInFlightScanInsteadOfWaitingForIt` (2 cases, failed on inherited code) |
| Reconciled arrivals could be persisted without delivery | Subscriber exception at startup, or shutdown between reconcile and publish, left the identity in the saved baseline | Undelivered identities are excluded from every save; saved after delivery (at-least-once) | `AnArrivalWhoseSubscriberFailedIsReportedAgainOnTheNextLaunch`, `ShutdownDuringAReconcileNeverAcknowledgesTheUnreportedArrival` (failed on inherited code) |
| `CanConfirmAbsence` on scheduled tasks with swallowed errors | `ComScheduledTaskSource.Collect` ignored denied folders and task definitions | `Collect` reports incompleteness, setting `Unreadable` | `ScheduledTaskCollectionReportsDeniedFoldersAndUnreadableTasks` |
| Denied CLSID read aborted whole surfaces | The first pass removed `ClsidResolver`'s catch; credential providers, BHOs and task COM handlers then stopped at the first denied class | `TryResolveInprocServer` reports the gap; enumerators count it and continue; no HKCU-to-HKLM fall-through | `DeniedClassOverrideIsUnreadableRatherThanTheMachineRegistration` |
| Camera/mic re-activation hidden by a partial read | With one source unreadable, an observed stop was carried as active, so the next start produced no event; a restart between polls was also missed | Only unobserved apps are carried; a newer `LastUsedTimeStart` is an activation | `ARestartIsReportedWhileAnotherSourceStaysUnreadable`, `ARestartBetweenTwoPollsIsStillAnActivation` (failed on inherited code) |
| Dashboard health | A failed Guardian start rendered Off; health was refreshed only on toggles, so a later worker failure stayed green | `GuardianHost.Health`; 5 s health refresh timer; broad start catch so ransomware restore still runs | `GuardianHealthTests`; WPF wiring requires the VM dashboard check |
| Mistyped extension display fields discarded permissions | `name: 42` or `default_locale: 42` beside `<all_urls>` removed the extension | Display fields are read leniently; permission arrays stay strict | `MistypedDisplayFieldsDoNotEraseExploitablePermissions` (5 cases, failed before) |

`AvWatchHostTests.InUse` generated a new `LastStart` on every access, which models a restart; it now
uses a fixed session start, as Windows does during one capture.

### Findings that were exaggerated or need qualification

- The two named integration risks were only partly closed: notification had moved outside the scan
  lock and startup arrivals were published after an arming failure, but shutdown still blocked on
  scans and undelivered arrivals could still be acknowledged (fixed above).
- "Every built-in source can confirm absence" was asserted by a test without an audit of swallowed
  errors (see scheduled tasks and CLSID resolution above). Denied per-service keys are now counted,
  so an unelevated scan reports `Services & drivers` as incomplete and does not confirm removals there.

## Validation on the final working tree

Environment: Windows 11 Pro 26200 x64, .NET SDK 10.0.303, unelevated. All commands from the
repository root.

| Command | Result |
|---|---|
| `dotnet build winsight.sln -c Release` | success, no errors |
| `dotnet format winsight.sln --verify-no-changes --no-restore` | pass after formatting; the inherited tree failed this gate (`PersistenceMonitor.cs`, `PersistenceScanner.cs` whitespace and CRLF files) |
| `./scripts/Measure-Coverage.ps1` (Release, full suite) | 22 test assemblies, 2,757 tests, 0 failed; engine libraries 82.4 % (every gated engine assembly ≥ 80 %), privileged managed logic 94.2 % |
| `./scripts/Test-VulnerablePackages.ps1` | no known vulnerable direct or transitive packages (advisory data only) |
| `./scripts/Test-McpServer.ps1 -ServerPath src/WinSight.Cli/bin/Release/…/winsight.exe -Version 0.12.1` | stdio negotiation and read-only tool contract passed |
| `winsight hosts|extensions|certs|av --json --no-network`; `winsight persistence --NOPE` | valid envelopes (exit 0/1 by findings); usage error exit 2 |
| `winsight persistence --json --no-network`, final tree vs `e0265c6`, 3 runs each | 24.8–31.2 s vs 23.7–24.9 s (per-file anchor chain build now runs for every trusted file) |

The inherited tree also passed its full suite (2,738 tests) while containing the defects above.

**Store applications, measured:** on this machine the final tree reports
`C:\Program Files\WindowsApps\Microsoft.Paint_…\PaintApp\mspaint.exe` (a HKCU `LocalServer32`
registration) as `notable [unsigned]` where `e0265c6` reported `signature valid`. This is the
expected consequence of removing the unsound fallback and a false positive for legitimate Store
software until a bound package verifier exists.

Not performed: installation, SCM/WFP, trust-store modification, elevated ETW, mapped-drive creation,
dashboard UI automation, native Arm64 execution, CI execution of these changes.
## Compatibility and remaining qualification

- Legitimate MSIX members without an individual signature or a verified catalog can now be
  reported unsigned. Package-aware trust requires a separately verified package-to-file binding.
- Legacy decoy manifests contain no original identity. Such files are preserved; an upgrade may
  leave decoys requiring manual cleanup. Edited and replaced documents are also preserved.
- Guardian's first start after upgrading an old baseline cannot compare offline changes against
  the discarded lossy identity format. It establishes the new reference silently.
- An incomplete source cannot prove a removal. An entry removed and restored entirely between
  observable snapshots remains outside the detector's evidence.
- Root changes during an ongoing verification batch remain a snapshot boundary. Local verdicts
  are observations, not authorization to execute a file.
- The corrected executable bytes still need CI on supported native architectures and a fresh
  isolated Windows VM campaign for installer lifecycle, WFP/SCM, IPC, ETW recovery and dashboard
  behavior. Historical v0.12.0 qualification does not substitute for that campaign.
- No controlled comparison has established better detection, prevention, false-positive rate,
  latency or resource use than Objective-See. First-connection decisions, persistence removal and
  ransomware process suspension remain product gaps.

- Package-aware trust for Store applications is missing: a verifier bound to the installed package
  identity and content (for example the Windows package content-integrity API) would be needed to
  remove the measured Paint false positive without reintroducing the sidecar bypass.
- A source that is routinely incomplete for an unelevated user (other user hives, scheduled tasks,
  services) never confirms removals, so a remove-and-reinstall there is not re-alerted.
- Arrivals beyond the bounded change log's capacity enter the baseline without a notification
  (pre-existing design); delivery is otherwise at-least-once and may repeat after a crash.
- Camera/mic keys merge HKCU and HKLM per app; an app active only in an unreadable hive while
  observed stopped in the other can produce a deactivation. A preserved decoy name makes that
  directory unarmed until the operator moves the file.
- The dashboard health timer, Guardian start-failure rendering and shutdown latency are WPF wiring
  that unit tests do not exercise; they belong to the VM dashboard campaign.

No release signing, installation, service reconfiguration, firewall enforcement, trust-store
modification, commit, push or publication was performed for this correction record.
