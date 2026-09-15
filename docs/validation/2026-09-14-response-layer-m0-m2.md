# Objective-See plan: M0-M2 implementation record - 2026-09-14

Base commit `e0265c6` plus the uncommitted working-tree changes from the earlier corrections and this
session. This record documents progress against
[`OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md`](../OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md); it does not qualify
a released artifact. CI and the isolated VM campaign remain pending.

## Owner decisions applied

Recorded in the plan (section "Owner decisions"): Q1 ask-mode allowances = yes (Windows Update, time
service, visible and removable); Q2 sign-in start preselected = no; Q3 kernel driver = only if the M9
measurements show it is materially better, decided after M9.

## M0 - baseline and documentation (done)

- Documentation corrected: `ARCHITECTURE.md` project tree rewritten to the real solution, the
  "prompt-on-new-connection" claim replaced by the user-mode limit + M4 plan, "22 enumerators" made
  generic; `README.md` camera/mic row now says "application" and the signature row says "not reachable
  from File Explorer". `SurfaceCountDocumentationTests` still passes.
- CI and VM qualification of the current state: **not run** (GitHub Actions quota; no VM campaign).

## M1 - response foundation (engine done)

New engine library `WinSight.Response` (gated at 83.9 %, native interop files excluded):

| Component | What it does | Tests |
|---|---|---|
| `ProcessIdentity` / `IProcessInspector` | `(pid, start time, image path, hash)` capture and match | `Win32ProcessActionsTests` (real child process) |
| `ProtectedProcesses` | fixed refusal list (core Windows + WinSight processes, reserved pids) | `ProcessResponderTests` |
| `ProcessResponder` + `Win32ProcessController` | revalidate -> refuse protected -> suspend/resume/terminate -> journal | `ProcessResponderTests` (fakes), `Win32ProcessActionsTests` (real suspend/resume/terminate) |
| `RuleStore` | per-user allow/block rules, versioned JSON, atomic + mutex-serialized, expiry/reboot pruning | `RuleStoreTests` incl. 16-way concurrent add |
| `ActionJournal` | append-only, bounded, atomic rotation, undo linking | `ActionJournalAndQuarantineTests` |
| `Quarantine` | private-DACL per-user store, manifest + payload, hash-verified restore | `ActionJournalAndQuarantineTests` |
| `AtomicFile` (Core) | shared atomic write used by the new stores | exercised across the above |

Invariant: the MCP server has no action primitive and does not reference `WinSight.Response`
(`ResponseIsNotReachableFromMcpTests`, `WinSight.Mcp.Tests`).

Not yet built (M1 integration surfaces, deferred to their consumers): the WPF alert window, the
sign-in start setting, the service response command tier, and the CLI `actions` history view.

## M2 - Guardian reversible block (first slice done)

`WinSight.Application`: `PersistenceActionResolver`, `PersistenceResponder`,
`RegistryAndFilePersistenceMutator`.

- Supported at user privilege: **HKCU Run/RunOnce values** and **the current user's Startup-folder
  files**. HKLM, services, tasks, WMI and all-users items resolve as service-tier and are reported
  unsupported until the service response command family ships.
- Block = revalidate against the alert -> quarantine (registry value **with its kind preserved**, or
  the file's bytes) -> remove. Restore = write back only if the origin is still free.

Evidence (`PersistenceResponderTests` fakes; `PersistenceResponderRealTests` real Windows, unelevated):

- A real HKCU `ExpandString` value is quarantined, removed, and restored with its data **and kind**
  intact.
- A value or startup file changed since the alert is refused (`TargetChanged`), the live item untouched.
- A real file in the user's Startup folder is quarantined, removed and restored byte-for-byte.
- Restore refuses when the origin is reoccupied; the new occupant is left intact.
- A failed removal discards the quarantine copy (no duplicate on a later restore).
- Test registry keys under `HKCU\Software\WinSight.Tests` are deleted after the run.

## Validation on the final working tree (`out/validation-20260914-m2/`)

- `dotnet format --verify-no-changes`: pass.
- `dotnet build winsight.sln -c Release`: success.
- `Measure-Coverage.ps1`: 23 test assemblies, **2,850 tests, 0 failed**; engine libraries 82.8 %
  (WinSight.Response 83.9 %, WinSight.Application 86.7 %, all engine libraries >= 80 %); privileged
  managed logic 94.2 %.

## Autonomous VM qualification run (host-orchestrated, rehearsal)

Ran the M0-M2 candidate end to end on the isolated `WinSight-Qualification-Fresh` VM
(Windows 11, build 10.0.26200) with **no in-guest interaction**: a logon-triggered scheduled
task (`WinSightQualification`, armed once via `arm-autorun.ps1`) runs `run-guest-checks.ps1`
from the shared folder; the host only restores a snapshot, starts the VM, and reads the JSON
result back. Baseline snapshot `S0-autorun-clean` (clean Win11, nothing installed, task armed)
was taken for repeatability; the VM was restored to it afterwards, so it is left clean.

Result (`guest-results/guest-results.json`, `startedUtc 2026-09-14T16:56:46Z`,
`finishedUtc 2026-09-14T17:14:19Z`, `errors: []`):

- **Artifact integrity**: `hashOk = true` (setup SHA-256 `162ECA37…A186F35` matched its `.sha256`).
- **Per-user silent install**: `installed = true`, `winsight 0.12.1` at
  `%LOCALAPPDATA%\Programs\WinSight`, no elevation.
- **All 14 read-only scanners ran on real data, no crash**: persistence (674 items),
  av (0/0), net (48 conn, 1 noteworthy), dns (31), processes (124, 1 unsigned),
  modules (5217 across 103 procs, 14 unsigned, incomplete unelevated), extensions (0),
  certs (42 roots, 10 flagged), hosts (0), input (3 filters, 1 non-Windows),
  drivers (400, 0 untrusted), integrity (8 checked, 2 need attention), hijack (none),
  presence (none). Non-zero exit codes here mean "noteworthy findings present", not error.
- **MCP stays read-only**: `initialize` + `tools/list` returned 18 720 chars of tool
  definitions with **no** mutation verb (suspend/terminate/kill/quarantine/remove/disable/
  block/delete/restore/mutate) → `mcpReadOnly = true`. Confirms the response layer is not
  reachable over MCP, matching `ResponseIsNotReachableFromMcpTests`.

Notes / harness corrections made after the run:

- `responseDllPresent` came back `false`, but the suite ships as **self-contained single-file
  executables** (`winsight.exe`, `winsight-dashboard.exe`, `winsight-firewall-service.exe`) —
  there are no loose DLLs at all, so the probe was inapplicable. `run-guest-checks.ps1` now
  reports `packaging = single-file` and sets `responseDllPresent = null` in that case. This is
  consistent with M1 integration surfaces not yet shipping a response entry point; it is not a
  regression.
- The run briefly stalled because a stray console selection put the guest console into
  QuickEdit/select mode, which freezes the running process. `run-guest-checks.ps1` now clears
  `ENABLE_QUICK_EDIT_MODE` at startup so unattended runs cannot be frozen this way.

This is a local rehearsal on a working-tree build, not CI-attested release evidence.

## Remaining (not started this session)

M1 UI/service integration; M3 (sign-in start, alert delivery); M4 (LuLu ask-mode default-deny);
M5 (RansomWhere? process identification + opt-in suspension); M6 (OverSight process-level + event
driven); M7 (What's Your Sign? Explorer verb); M8 (depth items); M9 (measured evaluation);
M10 (production hardening, native Arm64). None can be qualified without CI and the VM campaign.
