# Third pass: Guardian failure boundary, capture provenance, MSIX content trust, decoy concurrency — 2026-09-14

Base commit: `e0265c6b0dd1c40354a592a89c29fdcbdc65f45b`. All changes are uncommitted working-tree
changes on top of the corrections recorded in
[`2026-09-14-security-corrections.md`](2026-09-14-security-corrections.md), which is left as the record of the earlier passes
(only a pointer to this file was added). This record does not qualify a released artifact.

Evidence kinds are kept apart below: **simulated** (unit tests with fakes), **real Windows** (tests or
probes against this machine's registry, packaging API, Store packages and file system, unelevated),
**VM qualification** and **CI**. No VM or CI run was performed for this state (see the last section).

Local evidence folder (git-ignored): `out/validation-20260914-round3/` — `code-state.txt` binds the
results to `HEAD` plus the SHA-256 of the tracked diff and of every untracked file.

## 1. Findings of the counter-review, reproduced before correction

The probe `out/counter-review-20260914/Probe.csproj` (git-ignored lab) was run unchanged before any
edit:

| Probe | Before | After |
|---|---|---|
| `-- subscriber` (handler throws during monitoring) | process terminated: `Unhandled exception … CONTROLLED_SUBSCRIBER_FAILURE` at `PublishDetections → RunReconcile → Timer` | `PROCESS_SURVIVED` |
| non-cooperative acquisition during `Dispose` | `DISPOSE_COMPLETED_DURING_NONCOOPERATIVE_READ=False` | `True` |
| stop observed while another source unreadable (no provenance) | `PARTIAL_OTHER_HIVE_EVENTS=Deactivated` | empty (no event) |

All three findings are **confirmed**. The second is a contract limit demonstrated synthetically; the
real acquisitions were inspected: the scanner checks cancellation between surfaces and between
signature files, registry reads and Task Scheduler COM calls do not observe it, and the WMI
subscription query had an infinite default timeout (now 30 s).

## 2. Corrections and before/after evidence

| Area | Defect (how shown) | Correction | Evidence after |
|---|---|---|---|
| Guardian notifications | Probe crash above; a failing handler also blocked other handlers | Non-catastrophic failures contained per handler; undelivered arrivals retried (≤ 4 attempts, back-off 2/10/60 s, then stop), excluded from saved baselines; `Diagnostics` exposes counts and the last exception; `RetryNow` | `GuardianFailureBoundaryTests` (simulated): retry until delivered, bounded attempts with no hidden loop, independent handlers without duplication |
| Guardian scans/saves | Any exception other than IO/access/security on a timer thread ended the process; a failed scoped scan lost its pending surfaces; the file store silently skipped failed saves | Contained, recorded, requeued, retried; `FilePersistenceBaselineStore.Save` throws | `AnUnexpectedScanFailureIsContainedAndTheSameSurfacesAreScannedAgain`, `ABaselineSaveFailureIsVisibleAndRetried` (simulated) |
| Guardian shutdown | Probe above | 300 ms bounded wait; the scan thread completes source disposal and the final save when it leaves | `DisposeReturnsDuringANonCooperativeRead…` (startup and rescan), `ConcurrentStartAndDisposeNeverDeadlock…` (40 iterations; source disposed exactly once), existing dispatching-notification tests (simulated); five consecutive runs of the Guardian classes passed |
| Dashboard health | Guardian degradation invisible | Degraded Guardian is Partial; each new fault journalled once | `GuardianHealthTests` (simulated); WPF wiring needs the VM dashboard check |
| Absence evidence | A denied IFEO key aborted the whole IFEO enumeration (real Windows: `DefenderAgentScan.exe` denied unelevated, keys after it unread in both views) | Per-key containment with count and scope | Real-Windows scope probe below |
| Scoped absence | Routinely partial sources (other user hives, services, scheduled tasks, IFEO) confirmed no removal, so remove-and-reinstall there never re-alerted | `IAutostartEnumerator.UnreadableScopes`; removals confirmed outside attributed scopes; unattributed gaps keep the whole-source rule | `GuardianScopedAbsenceTests` (simulated). Real Windows, unelevated: `Other user hives` 1 scope, `Services & drivers` 1 (`…\Services\nsi`), `Scheduled Tasks` 8 task scopes, `IFEO debuggers` 2 — all four became partially confirmable |
| Camera/mic provenance | Probe above | Observations keyed by (device, store, app); gaps attributed to a store, the desktop-app subtree or an app key; unknown provenance never yields a stop during partial coverage; restarts via newer start time | `CameraMicCoverageTests` (simulated: both stores active/stopped with loss and recovery of each, restart while the other store is hidden, unrelated gap, app-key gap); `ADeniedAppKeyIsAScopedGapNotAMissingApp` (real registry, temporary HKCU test key with a deny ACE, removed afterwards) |
| MSIX members | Microsoft Paint (`mspaint.exe`, HKCU `LocalServer32`) reported `notable [unsigned]` after the unsafe fallback was removed | `PackageContentSignatureVerifier`: validated block map (`IAppxFactory::CreateValidatedBlockMapReader`), single CMS signer with code-signing EKU chained offline at a verified RFC 3161 timestamp, manifest hash and `Identity/@Publisher` equal to the signer, file listed and `ValidateFileHash` true; deterministic COM release | Real Windows: Paint verdict `signature valid` (signer certificate expired 2026-08-13, timestamp verified). Feasibility probes: altered block map and certificate-bag signature → `0x80096010`. `PackageContentSignatureTests` (real installed Store packages, tampering on temp copies): copied genuine package trusted; one flipped byte → signed-untrusted; unrelated PE under the member name → signed-untrusted, under an unlisted name → no claim; altered block map / certificate bag → no claim; altered manifest → never trusted; another package's metadata → never trusted. Earlier `PackageSidecarTrustTests` still pass |
| Decoy manifest concurrency | Stress test (60 iterations): the launch sweep racing restored protection stranded the new session's 3 decoys (failed before) | Named-mutex serialization, merge with disk, atomic replace; session ownership via a named mutex held while the session runs | `AConcurrentOrphanSweepNeverDiscards…` (real file system, also asserts live decoys survive), `AnotherSessionsLiveDecoysAreNotOrphans…`, three repeated runs |
| Unstarted monitor disposal | Earlier `Remove()` deleted the manifest when its own records were empty; the unit test disposing `RansomwareHost.CreateDefault()` did so on the real profile | `Remove()` is a no-op for a session that never planted | `DisposingAMonitorThatNeverPlantedLeavesEveryoneElsesRecordsAlone` (failed before: manifest rewritten) |
| Decoy coverage | A decoy deleted after planting still counted as armed | Armed requires the planted decoys to still exist | `ADecoyThatDisappearsAfterStartupNoLongerCountsAsArmed` (failed before) |

### Addendum (same day, CI paused by the account's GitHub Actions limit)

| Area | Defect (how shown) | Correction | Evidence after |
|---|---|---|---|
| Guardian change log capacity | Nothing acknowledges the 256-entry display log and nothing read `DroppedChanges`: the 257th distinct arrival in a session entered the baseline without notification (`ArrivalsBeyondTheDisplayLogCapacityAreStillReported`: expected 44 late arrivals, actual 0) | Arrivals are reported regardless of list capacity; `Diagnostics.UnlistedArrivals` | Same test passes (simulated) |
| Operator retry | `RetryNow` had no entry point once automatic retries stopped | Tray item "Retry Guardian" (EN/FR/ES) visible while degraded; tooltip diagnostics line | `GuardianHealthTests` diagnostics line (simulated); menu wiring is WPF/WinForms code-behind for the VM dashboard check |
| MSIX untrusted signer | Not exercised before | — (behaviour measured) | Real Windows: a package built with `makeappx`, signed with `signtool` by a throwaway self-signed key whose subject copies Microsoft's, is refused by `CreateValidatedBlockMapReader` with `0x800B0109`; the member stays unsigned (`AGenuinelySignedPackageFromAnUntrustedSignerClaimingMicrosoftIsNotTrusted`, runs when the Windows SDK 10.0.26100 tools are present). No trust store was modified |

Addendum validation (`out/validation-20260914-round4/`, `combined_state_sha256=FB0682D4…0230`): format
verify pass; Release build success; `Measure-Coverage.ps1` 22 assemblies, **2,799 tests, 0 failed**,
engine libraries 82.8 % (all ≥ 80 %), privileged managed logic 94.2 %; NuGet audit clean; MCP contract
pass; counter-review probes `True` / no event / `PROCESS_SURVIVED`; `winsight persistence` 24.9–26.0 s
(23.7–24.9 s at `e0265c6`). The round-3 local release candidate predates this addendum and is not
its binary; CI and VM remain pending.

### Second addendum: deep review of background threads and state writes

| Area | Defect (how shown) | Correction | Evidence after |
|---|---|---|---|
| Ransomware watcher | Real Windows probe: after a subscriber `InvalidOperationException` the drain loop ended silently (`SUBSCRIBER_CALLS=1`, coverage still complete); any other exception type ended the process; a monitor subscriber fault skipped `Detector.Reset()` | Per-handler containment, processing faults counted, detector re-armed in `finally`, coverage incomplete on failures | Probe `SUBSCRIBER_CALLS=2`, coverage incomplete; `RansomwareSubscriberFailureTests` (real file system) |
| Camera/mic host | A subscriber fault stopped the watch for the session; no controlled recovery after a reader fault | Per-handler containment (partial health), bounded restarts 5/30/120 s | `AvWatchHostTests` (containment with a second activation still delivered, restart, exhausted budget) |
| Guardian registry watcher | Real Windows probe: a subscriber exception on the wait-loop thread terminated the process; one key failing to arm threw out of `Start` | Containment with count; per-key arming | Probe `REGISTRY_WATCH_CALLS=2`; `RegistryWatcherFailureTests` (temporary HKCU key) |
| Guardian file-system watcher | Subscriber exception on a thread-pool callback would end the process | Containment with count | `RegistryWatcherFailureTests.AFileSystemSubscriberFault…` (temporary folder) |
| Alert journal | `Append` swallowed write failures, so "journal first" could silently fail and Guardian acknowledged the arrival | `TryAppend` + `WriteFailures`; Guardian handler keeps the arrival unacknowledged; tooltip line; handlers dispatch to the UI asynchronously | `AFailedWriteIsReportedAndCountedInsteadOfVanishing`; WPF wiring for the VM dashboard check |
| Decoy seed | Test with 8 concurrent first uses: different seeds (failed before, and intermittently after a first partial fix) | Read / create atomically / re-read with bounded retries; a malformed seed replaced once | `CanarySeedConcurrencyTests` stable over repeated runs |
| Protection setting | Non-atomic write could read back as "off" | Temp file + move | Code review; existing settings tests |

Checked without defect: PE import parser (30,000 mutated images, 0 exceptions), hosts parser (20,000
random inputs, 0 exceptions), firewall IPC broad catches (deliberate, documented), no signature
verdict used by privileged firewall decisions, no TODO/FIXME markers.

Validation (`out/validation-20260914-round5/`): format verify pass; Release build success;
`Measure-Coverage.ps1` 22 assemblies, **2,808 tests, 0 failed**, engine 82.8 %, privileged managed
94.2 %; NuGet audit clean; MCP contract pass; auditor probe replay: all eight original defects remain
fixed; counter-review probes `True` / no event / `PROCESS_SURVIVED`.

### Incident on the development profile

The previous pass's test suite first overwrote `%LOCALAPPDATA%\WinSight\canary-manifest.txt` with a
test record (recorded in the earlier report), and the unstarted-monitor disposal later deleted the
file. It held only that test record. A read-only check computed WinSight's decoy names from the
existing seed for the default folders and found none present, so no operator decoy was stranded. No
personal file was opened, modified or deleted. Current tests pass explicit temporary manifests; the
default-host test no longer performs manifest I/O.

## 3. Validation on the final working tree

Windows 11 Pro 26200 x64, .NET SDK 10.0.303, unelevated. Logs and outputs are in
`out/validation-20260914-round3/`.

| Command | Result | Kind |
|---|---|---|
| `dotnet format winsight.sln --verify-no-changes --no-restore` | pass | local |
| `dotnet build winsight.sln -c Release` | success | local |
| `./scripts/Measure-Coverage.ps1 -ResultsDirectory out/validation-20260914-round3/coverage` | 22 test assemblies, **2,795 tests, 0 failed**; engine libraries 82.9 % (every gated engine assembly ≥ 80 %; Core 89.1, Persistence 87.7, AvMonitor 94.2, Ransomware 92.0, Application 87.1), privileged managed logic 94.2 %; no exclusion added | simulated + real Windows |
| `./scripts/Test-VulnerablePackages.ps1` | no known vulnerable direct or transitive packages (adds first-party `System.Security.Cryptography.Pkcs` 10.0.11) | advisory |
| `./scripts/Test-McpServer.ps1` (build output and published single-file `winsight.exe`) | stdio negotiation and read-only tool contract passed | real Windows |
| `winsight hosts/extensions/certs/av/persistence --json --no-network`; unknown option | valid envelopes, exit 0/1 by findings; usage error exit 2; persistence 24.1 s (23.7–24.9 s at `e0265c6`) | real Windows |
| Counter-review probes | `True`, no event, `PROCESS_SURVIVED` | simulated |
| `./scripts/Build-Release.ps1 -Version 0.12.1 -Architectures x64` (local, unsigned by the excluded policy, not installed) | setup `82F05F3C…4289`, zip `F93DE9F2…9B24`, SBOM `6696E764…F52D`; extracted `winsight.exe` `9F5C8489…B1C5`, dashboard `6375693A…CF5`, firewall service `D8C99619…33A` (full hashes in `artifact-hashes.txt`) | local build |
| `./scripts/Test-PeArchitecture.ps1` on the three extracted executables | valid x64 PE images | local |
| Published `winsight.exe persistence` | Paint `signature valid` through package content verification | real Windows |

`code-state.txt` was regenerated after the final documentation edits; source files did not change
between the test run, the release build and that record.

## 4. Limits and remaining qualification

- **VM qualification not run.** The kit (`VM_QUALIFICATION_KIT.md`) requires a CI-built, attested
  candidate and an administrative guest session; producing the candidate needs a push and the guest
  needs credentials, neither of which was authorised here. The VM `WinSight-Qualification-Fresh` and
  its `S0-clean-before-winsight` snapshot exist on the host. Installer lifecycle, SCM/WFP, IPC, ETW
  recovery, dashboard behaviour (health refresh, Failed/Partial rendering, close latency) and native
  Arm64 remain unqualified for this state.
- **CI not run** for this state (no push).
- MSIX: no revocation checking (offline by design); package registration is not verified; an
  expired signer without a verifiable timestamp is untrusted (not exercised with a crafted
  package: no signing key or packaging tool was used); verdicts are cached by file fingerprint for up to five minutes, so
  a replaced block map or signature beside an unchanged file is picked up on cache expiry.
- Guardian: if the process exits during a deferred shutdown, the final save is skipped and the last periodic
  baseline is used; handlers already running when `Dispose` begins are not awaited.
- Camera/mic: a first partial read seeds silently; a capture that started and stopped entirely between
  two polls is not observable.
- Ransomware: sessions in different Windows logon sessions use `Local\` mutex names and do not see each
  other's ownership (the manifest is per-user, so this requires the same user in two logon sessions).
