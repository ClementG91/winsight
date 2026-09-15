# Objective-See parity and beyond: implementation plan

Status: **proposed plan**, 2026-09-14. Nothing in this document is implemented yet unless a section
says so explicitly. It is the working plan for closing the gaps recorded in
[`OBJECTIVE_SEE_PARITY.md`](OBJECTIVE_SEE_PARITY.md) and for earning, with evidence, any claim that
WinSight is comparable to or better than Objective-See on Windows.

Base state: commit `e0265c6` plus the uncommitted corrections recorded in
[`validation/2026-09-14-security-corrections.md`](validation/2026-09-14-security-corrections.md) and
[`validation/2026-09-14-guardian-av-msix-ransomware-hardening.md`](validation/2026-09-14-guardian-av-msix-ransomware-hardening.md).

All code, comments, UI resource keys, commit messages and documentation produced by this plan are
written in English. User-facing strings are localized through the existing EN/FR/ES resources.

---

## 1. Goals, definitions and non-goals

### 1.1 What "parity" means here

Parity is defined per Objective-See tool, against the capabilities that tool's official product page
describes (checked 2026-09-14), across four levels that must never be conflated:

| Level | Meaning |
|---|---|
| **Inventory** | The information is enumerated on demand. |
| **Detection** | A change or event is recognised when it happens. |
| **Alert** | The operator is told, with enough context to decide. |
| **Response** | The operator can act from the alert: allow, block, remove, suspend, terminate - and undo. |

A tool reaches parity when WinSight covers every level that the Objective-See tool offers, on the
closest honest Windows mechanism, with a test that proves it and a qualification record for anything
privileged. Platform differences are stated, not hidden.

### 1.2 What "better" may mean, and how it is earned

"Better" is only claimed for a **measured** property on a stated scenario set (section 7, M9):
detection rate, time to alert, false positives on a clean-machine soak, CPU/memory/IO budget, or a
capability Objective-See does not offer on its platform. No superiority is claimed from module counts,
and no head-to-head claim is made against tools that cannot run on Windows.

### 1.3 Principles that constrain every milestone

1. **Operator-confirmed, reversible response.** No automatic destructive action. Every action is
   preceded by revalidation, recorded in an append-only action journal, and reversible where the
   platform allows it (quarantine and restore rather than delete).
2. **One exception, opt-in and bounded:** automatic *suspension* (never termination) of a process that
   touched a ransomware decoy with high confidence, if and only if the operator enabled it (M5).
3. **AI is not an authority boundary.** The MCP server stays read-only. No response action is ever
   reachable from MCP; a contract test enforces this.
4. **Least privilege.** Same-user actions run in the unprivileged dashboard. Machine-wide actions go
   through the authenticated LocalSystem service with an administrator-only capability tier.
5. **No driver in this plan.** Everything here is user mode. A kernel minifilter/callout remains a
   separate, explicitly deferred decision (section 9, D6).
6. **Honest reporting.** Unknown is not absent; partial is not complete; a failed action is visible.
7. **Evidence per claim.** Unit tests for decisions, real-Windows tests for API behaviour, VM
   qualification for privileged or system-mutating behaviour, CI on native x64 and Arm64.

### 1.4 Non-goals

- Signature-based antivirus, cloud console, fleet management or telemetry.
- Silent automatic remediation of persistence, network or processes.
- An in-process Explorer shell extension (crash surface in every file window).
- Authenticode signing of WinSight's own binaries (excluded from this plan's blockers).

---

## 2. Verified baseline (2026-09-14)

### 2.1 What exists

| Area | Current capability | Levels covered |
|---|---|---|
| Persistence scan | 27 autostart surfaces, signature verdicts (embedded, catalog, verified MSIX package content), command-line triage | Inventory |
| Guardian | Registry and file-system change watchers, scoped rescans, cross-run reconciliation, at-least-once alert delivery, diagnostics, retry | Detection, Alert |
| Outbound firewall | LocalSystem service, WFP per-application allow/block, audit-only until armed, pending list of unruled applications (the triggering connection is not held) | Inventory, Response (explicit rules) |
| Ransomware | Visible decoys, rename/delete bursts, entropy on write, identity-safe cleanup, armed-coverage health, touched-decoy attribution when elevated | Detection, Alert |
| Camera/mic | Consent-store polling (1 s) with store provenance, restart detection, bounded worker restart | Detection, Alert (application name, not process id) |
| Connections/DNS | IP Helper connection list with process attribution; DNS cache; live DNS via ETW (elevated) | Inventory, Detection (DNS elevated) |
| Processes/modules/`process <pid>` | Lineage, unsigned modules, live sockets per process | Inventory |
| Signature verification | Shared verifier used by every scanner; no file-manager integration | Inventory (inside WinSight only) |
| Input interception | Keyboard/mouse class filter drivers | Inventory |
| Drivers | Registered kernel drivers with verdicts (not resident set) | Inventory |
| Hijack | Unquoted service paths, writable service/PATH directories, phantom imports (static) | Inventory |
| Presence | System-log resume timeline with wake source | Inventory |
| Integration | Unified dashboard (EN/FR/ES), CLI (18 verbs, JSON), read-only MCP, alert journal | - |

### 2.2 Qualification state

- Local Release suite: 2,808 tests passing, coverage gates met (engine 82.8 %, privileged managed
  94.2 %).
- **Not qualified for this state:** CI (quota), isolated VM campaign (installer, WFP/SCM, IPC, ETW,
  dashboard), native Arm64 privileged runtime.

### 2.3 Structural gaps that cut across tools

1. **No response layer.** Every Objective-See tool with an alert also offers a decision; WinSight's
   alerts are informational only.
2. **Monitors only run while the dashboard is open.** The installer creates no sign-in start; BlockBlock,
   LuLu, OverSight, RansomWhere? and ReiKey run as soon as the user logs in.
3. **Balloons cannot carry decisions.** WinForms tray balloons have no buttons and may be suppressed.
4. **No shared rule store.** Allow/ignore decisions cannot be expressed for Guardian, ransomware or
   camera/mic.
5. **Camera/mic names an application, not a process**, so no process-level response is possible yet.

---

## 3. Gap analysis per Objective-See tool

Sources: official product pages for BlockBlock, LuLu, RansomWhere?, OverSight, KnockKnock, What's Your
Sign?, ReiKey, KextViewr, TaskExplorer, Netiquette, DHS and Do Not Disturb, checked 2026-09-14.

| Objective-See tool | Capability on its page | WinSight today | Gap | Milestone |
|---|---|---|---|---|
| **BlockBlock** | Alerts when persistence is added; Block removes the item; Allow; rules by process/file/item; temporary decisions | Detection + alert | Allow/Block decision, removal with restore, rules, always-on at sign-in | M1, M2, M3 |
| **LuLu** | Blocks unknown outgoing connections pending a decision; rules by process or endpoint; durations (permanent, process lifetime, timed); passive mode | Explicit per-app rules; unruled apps listed as pending after connecting | Default-deny for unknown apps with a prompt, endpoint scopes, durations, passive mode | M1, M4 |
| **RansomWhere?** | Detects untrusted process creating encrypted files, suspends it, Allow/Block (terminate + prevent), remembered rules | Detection + alert; attribution only when elevated | Unelevated process identification, suspension, Resume/Terminate, trust rules | M1, M5 |
| **OverSight** | Mic/webcam activation alerts naming the process; allow once/always; block terminates process; ignore external devices; custom action | Activation alerts naming the application; 1 s polling | Process identification, allow/block rules, event-driven latency, notification preferences | M1, M6 |
| **KnockKnock** | Persistence inventory, VirusTotal lookup/submission, no removal | Inventory, opt-in VirusTotal hash lookup in scans | Filters (#unsigned/#nonMicrosoft), per-item VirusTotal view; submission stays out (privacy) | M8 |
| **What's Your Sign?** | File-manager context menu: signature, notarization/revocation, hashes, entitlements | Verifier exists; no file-manager entry point | Out-of-process Explorer verb and signature details window | M7 |
| **ReiKey** | Scans keyboard event taps; real-time alert on new taps | Class-level input filter inventory | Live alert on new filter registration; per-device-instance filters | M8 |
| **KextViewr** | Loaded kernel modules, Apple/non-Apple filters, JSON export | Registered drivers with verdicts | Elevated resident-driver pass, filters, boot-configuration context | M8 |
| **TaskExplorer** | Tasks with signatures, libraries, files, connections, VirusTotal, filters | `process <pid>`, processes/modules scans | Dashboard task view with filters; open-files view (elevated, bounded) | M8 |
| **Netiquette** | Live sockets per process, filter, JSON export | Connections scan, JSON | Live-refresh dashboard view with filters | M8 |
| **DHS** | Vulnerable and hijacked applications, weak imports | Static hijack scan | Runtime DLL-load observation (elevated ETW) | M8 |
| **Do Not Disturb** | Lid-open detection while away, local/remote alerts, optional photo, custom actions, passive mode | Resume timeline after the fact | Armed "away" mode with live wake/unlock/device-arrival alerts; remote alerts and photos stay out (privacy, network) | M8 |

---

## 4. Documentation audit (findings from reading the current docs)

Inconsistencies and statements that must change, independent of new features:

| Document | Finding | Action | When |
|---|---|---|---|
| `ARCHITECTURE.md` | States "a prompt-on-new-connection UX" for the firewall; `WFP_DESIGN.md` records that a user-mode filter cannot hold a connection pending a decision | Replace with the M4 design (default-deny unknown + prompt + retry) or the current limit | M0 |
| `ARCHITECTURE.md` | "The 22 enumerators", while README and parity doc say 27 surfaces | Align to the tested surface count (`SurfaceCountDocumentationTests`) | M0 |
| `ARCHITECTURE.md` | Lists a `drivers/` folder "(Phase 3/4)" that does not exist; module list omits most current projects | Update the tree to the real solution | M0 |
| `README.md` | Camera/mic row says "Which process turned the webcam or microphone on"; the consent store gives the application, not a process | Say "which application", until M6 lands | M0 |
| `README.md` | "Signature verification ↔ What's Your Sign?" implies a file-manager tool | Mark as "inside WinSight only" until M7 | M0 |
| `ROADMAP.md` | Scope decision "Observe, do not remediate" and "Automatic remediation: not building" | Revise to "no automatic remediation; operator-confirmed, reversible response" once M1 is accepted | M1 |
| `evals/README.md` | "WinSight never remediates" | Reword to "never remediates on its own; MCP has no action primitive" | M1 |
| `OBJECTIVE_SEE_PARITY.md` | Mixes historical narrative with the gap table | Keep narrative; replace the gap table with the section 3 matrix and update it per milestone | M0, then each milestone |
| `DETECTIONS.md`, `THREAT_MODEL.md` | Describe a read-only suite | Add the response surface, its trust boundaries and new adversary cases | M1 |
| `MCP.md` | Read-only guarantee | Add the explicit invariant that response actions are never exposed, with the test name | M1 |

---

## 5. Architecture decisions required before implementation

Each decision is recorded as a short ADR section in `ARCHITECTURE.md` before its milestone starts.

| ID | Decision | Recommendation | Rationale |
|---|---|---|---|
| **D1** | Where response actions execute | Same-user actions in the dashboard process; machine-wide actions in the existing LocalSystem service, in a **new command family with an administrator-only capability tier**, separate from firewall commands | Reuses the qualified IPC authentication; keeps the firewall authority unchanged; privileged actions stay auditable |
| **D2** | How alerts carry decisions | A WinSight **alert window** (topmost, keyboard accessible, localized) with the tray balloon as fallback; not Windows App SDK toasts | No new runtime dependency or AUMID/COM activation; full control of wording and timeouts; works when notifications are suppressed |
| **D3** | Always-on monitoring | Opt-in "Start WinSight at sign-in" (per-user `Run` value launching the dashboard in tray mode), offered by the installer and settings | Matches Objective-See tools running at login without a new service; the entry is recognisable to Guardian |
| **D4** | Rule store | One versioned, atomically written, per-user JSON rule store for Guardian, ransomware and camera/mic; firewall rules stay in the service-owned policy store | Same honesty rules as the baseline and manifest; machine-wide network policy keeps its ACL-protected store |
| **D5** | Quarantine | Per-user quarantine directory with a private DACL; each item is a manifest (original location, type, data, hashes, time, action id) plus payload; restore revalidates that the target location is unoccupied | Reversible removal without trusting paths alone (same lesson as decoy cleanup) |
| **D6** | Kernel driver | Remains deferred; revisit only after M4/M5 measurements show a user-mode gap that matters | Driver needs its own signing and safety programme |
| **D7** | Process identity for actions | Act on (pid, process start time, image path, image SHA-256) captured at alert time and revalidated immediately before acting | Prevents acting on a recycled pid or replaced image |

---

## 6. Cross-cutting requirements

### 6.1 Security invariants for every action

- Revalidate the target (D7 for processes; value data/hash for persistence; rule target for network)
  immediately before acting; refuse on mismatch with a stable reason.
- Never act on protected or critical processes (csrss, wininit, services, lsass, smss, System, protected
  processes, WinSight's own processes); refuse with a stated reason.
- Every attempt, success, refusal and undo is appended to an **action journal** (append-only, bounded,
  atomic rotation), readable by MCP as history but never writable from MCP.
- Actions from the CLI require an explicit `--confirm` flag and are refused without an interactive or
  confirmed context; MCP has none.
- No action triggers network access.

### 6.2 Testing layers

| Layer | Used for |
|---|---|
| Unit tests with fakes | Decision logic, revalidation, rule matching, journaling, failure paths |
| Real-Windows tests (unelevated, temporary resources) | API behaviour: Restart Manager, thread suspension of a child test process, HKCU values, temporary scheduled tasks under a test folder, temporary startup files |
| VM qualification (new kit sections) | Elevated/system actions: services, HKLM, WMI subscriptions, WFP default-deny, service capability tier, sign-in start, installer changes |
| CI (native x64 + Arm64) | Full suite, coverage gates, packaging, installer lifecycle |

Coverage gates stay at 80 % per engine library and privileged managed half; new libraries join the
engine list in `scripts/Measure-Coverage.ps1`.

### 6.3 Performance budgets (verified in M9)

- Idle dashboard with all monitors: < 1 % average CPU, < 150 MB working set.
- Guardian alert latency after a Run-key write: p95 < 2 s.
- Camera/mic activation alert: p95 < 1.5 s after M6.
- Ransomware decoy touch to suspension (when enabled): p95 < 1 s.
- Firewall prompt after a blocked first connection: p95 < 1 s.

### 6.4 Localization and accessibility

Every new user-facing string gets EN/FR/ES resources and a `LocalizationTests` entry. Alert windows are
fully keyboard operable, readable by screen readers, and never auto-select a destructive default.

---

## 7. Milestones

Effort is relative (S ≈ days, M ≈ 1-2 weeks, L ≈ 3-4 weeks of focused work) and excludes review
latency. Each milestone ends with its documentation updates and, where stated, a VM record.

### M0 - Qualify the current state and correct documentation (S)

**Goal.** Establish the baseline every later milestone builds on.

Work:
1. Commit the pending corrections on a branch; run CI on native x64 and Arm64 once the quota allows.
2. Run the VM qualification kit on the CI candidate (installer, ETW, WFP/SCM/IPC, dashboard close,
   Guardian/ransomware/camera health rendering, Retry Guardian tray item).
3. Apply the M0 rows of section 4.

Acceptance: green CI on the exact commit; VM record under `docs/validation/`; docs consistent.

### M1 - Response foundation (L)

**Goal.** A safe, shared way to decide and act, used by every later milestone.

New project `WinSight.Response` (engine library, coverage-gated):
- `ResponseAction` records: `SuspendProcess`, `ResumeProcess`, `TerminateProcess`,
  `QuarantinePersistence`, `RestorePersistence`, `DisablePersistence`, `AddRule`, `RemoveRule`.
- `ProcessIdentity` (D7) with capture and revalidation; critical-process refusal list.
- `ActionJournal` (append-only, atomic rotation, bounded) and `ActionResult` with stable reasons.
- `RuleStore` (D4): versioned JSON, atomic write, named-mutex serialization, schema validation, rule
  scopes (item, image path, image path + signer, publisher) and durations (once, until reboot, until
  process exit, timed, permanent).
- `Quarantine` (D5): private-DACL directory, manifest + payload, restore with collision checks.

Dashboard:
- `AlertWindow` (D2) with decision buttons, details expander (signature, anchor, command line,
  attribution, rule preview), no destructive default, timeout behaviour per alert type.
- "Start WinSight at sign-in" setting and installer task (D3); Guardian labels its own entry.
- Action history view reading the action journal.

Service (D1):
- New command family `ResponseCommand` on the existing pipe with an administrator-only capability
  tier; request validation mirrors `FirewallProtocol` (bounded frames, strict enums, no exception
  detail across IPC); separate dispatcher and authority class.

CLI/MCP:
- `winsight actions` (read-only history); mutation verbs require `--confirm`.
- MCP contract test: the tool list contains no action; journal exposure is read-only.

Tests: unit tests for every refusal and revalidation path; real-Windows test suspending/resuming a
spawned child process; journal/rule store crash-consistency tests; MCP invariant test.

Docs: `ROADMAP.md` scope revision, `ARCHITECTURE.md` D1-D7, `THREAT_MODEL.md` (new mutation surface,
adversaries: forged alert window input, TOCTOU on pid/image, rule store tampering by same user, action
replay), `CODING_STANDARDS.md` (action invariants), `MCP.md`, `evals/README.md`, `PRIVACY.md` (no
change expected; confirm).

Acceptance: all invariants in 6.1 covered by tests; VM section for the service capability tier.

### M2 - BlockBlock parity: Guardian decisions and reversible removal (L)

**Goal.** Allow or Block a new persistence item from its alert, with restore.

Per vector (first slice = highest value):

| Vector | Block action | Undo | Privilege |
|---|---|---|---|
| Run/RunOnce (HKCU) | Quarantine value (name, type, data) then delete | Restore value | User |
| Run/RunOnce (HKLM), Winlogon, IFEO Debugger, AppInit, BootExecute, LSA packages | Quarantine value then delete | Restore | Service tier |
| Startup folder file | Move to quarantine | Move back if slot free | User (per-user folder) / service (all users) |
| Scheduled task | Export XML, **disable** task (not delete) | Re-enable | User for own tasks / service |
| Service | Record start type, set Disabled (never delete) | Restore start type | Service tier |
| COM hijack (HKCU CLSID) | Export subtree, delete | Import subtree | User |
| WMI subscription | Export filter/consumer/binding, remove binding | Recreate binding | Service tier |

Revalidation: the current identity (source, location, name, arguments, target hash) must equal the
alert's identity; otherwise refuse ("item changed since the alert").

Guardian integration: Allow creates a rule suppressing future alerts for the chosen scope; Block runs
the action, and the resulting absence is reconciled as expected (no second alert for our own removal);
a later reinstallation alerts again unless an Allow rule matches.

Tests: real-Windows HKCU Run/startup-folder/COM/per-user task flows with restore; unit tests for every
vector's revalidation and refusal; VM section for HKLM, services, WMI and all-users items.

Docs: `GUARDIAN_DESIGN.md` (response section), `DETECTIONS.md`, `RECOVERY.md` (restore quarantined
items), `OBJECTIVE_SEE_PARITY.md` (BlockBlock row).

Acceptance: block and restore proven per vector at its privilege level; no action without
revalidation; quarantine survives restart.

### M3 - Always-on sensors and alert delivery (M)

**Goal.** Monitoring that matches "runs at login" tools without widening privileges.

- Tray-mode start at sign-in (D3) with a first-run explanation.
- Startup order: journal/rule store, Guardian, camera/mic, ransomware (if enabled), attribution
  (if elevated), then UI.
- Alert window queueing, coalescing and a "decide later" state that keeps the item pending.
- Health view: one line per monitor with its reason (already partially present) and last fault.

Tests: startup ordering unit tests; VM check that monitors are active after sign-in without opening the
dashboard window.

Docs: `INSTALLATION.md`, `ADMINISTRATION.md`, `README.md`.

### M4 - LuLu parity: unknown applications blocked pending a decision (L)

**Goal.** An unknown application's outbound connection is blocked and the operator is asked, without a
kernel driver.

Design (spike first, then ADR):
1. New enforcement mode **Ask** (explicitly armed, like Enforcement): the service installs a
   low-weight WFP **block** filter for outbound connections in its sublayer, plus permit filters for
   ruled applications and the mandatory infrastructure allowances already defined in `WFP_DESIGN.md`
   (loopback, DHCP, DNS to configured resolvers, WinSight IPC, Windows Update/BITS and time service as
   reviewed allowances).
2. The service subscribes to WFP drop net events for that filter (`FwpmNetEventSubscribe*` with engine
   net-event collection enabled), maps each drop to the application id and endpoint, deduplicates, and
   raises a `PendingConnection` through IPC.
3. The dashboard prompts: Allow/Block, scope (application; application + remote address/port), duration
   (once for this process, until reboot, timed, permanent). Allow installs a permit filter; the
   application's retry then succeeds. The first attempt is dropped, not held; the prompt says so.
4. **Passive mode:** Ask without blocking (record and allow), for onboarding.
5. Safety: fail open to audit if the dashboard is not running for N seconds after a drop burst
   (configurable), if the service loses its event subscription, or on emergency disable; never block
   the service's own IPC; rate-limit prompts per application.

Tests: unit tests for rule scoping, deduplication, fail-open policy; VM protocol extension: unknown app
blocked, prompt, allow + retry succeeds, block persists across reboot, passive mode, fail-open on
dashboard absence, emergency disable, Arm64 equivalent.

Docs: `WFP_DESIGN.md` (Ask mode), `ARCHITECTURE.md` (replace the old prompt claim), `THREAT_MODEL.md`
(prompt spoofing, drop-event flooding), `RECOVERY.md` (lost network under Ask), `ADMINISTRATION.md`,
`README.md`, `OBJECTIVE_SEE_PARITY.md` (LuLu row).

Acceptance: VM record with the full scenario set on x64; Arm64 marked separately.

### M5 - RansomWhere? parity: identify and suspend the encrypting process (L)

**Goal.** Name the process touching decoys without elevation, optionally suspend it, then ask.

1. **Unelevated identification:** on a decoy touch or burst, query the Windows **Restart Manager**
   (`RmStartSession`, `RmRegisterResources`, `RmGetList`) for processes holding the touched files;
   combine with elevated ETW attribution when available; record confidence.
2. **Suspension** (M1 action, opt-in "Suspend a process that touches a decoy"): documented thread
   enumeration (`CreateToolhelp32Snapshot` + `OpenThread` + `SuspendThread`) repeated until no new
   thread appears; a spike compares it with `DebugActiveProcess`. Only same-user or service-tier
   processes; critical/protected processes refused.
3. **Alert decisions:** Resume, Terminate (and optionally block the image from starting again through
   an IFEO-free mechanism: a rule consulted by the ransomware monitor plus a firewall block; no IFEO
   write), Allow (trust rule for signed publisher or image hash).
4. Entropy writer correlation: prefer Restart Manager results for files scored as encrypted.

Tests: real-Windows test with a synthetic child process that opens and rewrites a decoy in a temporary
directory: identification via Restart Manager, suspension, resume, terminate; refusal tests for
protected processes; unit tests for confidence and opt-in gating.

Docs: `RANSOMWARE_DESIGN.md`, `ATTRIBUTION_DESIGN.md` (Restart Manager path), `THREAT_MODEL.md`
(suspending an innocent process, decoy-touch spoofing to trigger suspension of a victim), `README.md`,
`OBJECTIVE_SEE_PARITY.md` (RansomWhere? row).

Acceptance: synthetic encryptor suspended within budget when enabled; no suspension when disabled;
every refusal path tested.

### M6 - OverSight parity: process-level camera/microphone alerts and decisions (M)

1. **Event-driven acquisition:** `RegNotifyChangeKeyValue` on the consent-store keys (HKCU/HKLM,
   webcam/microphone, NonPackaged subtree) triggering an immediate read; polling kept as fallback.
2. **Process identification:** non-packaged application path → running processes with that image path;
   packaged application → processes of that package family; report ambiguity when several match.
3. **Decisions:** Allow once, Always allow (rule), Block (terminate the identified process through M1,
   with revalidation); preferences: notify on deactivation, ignore listed devices if the platform
   exposes the device identity, passive mode.

Tests: real-registry tests on a test base path for event-driven reads; process mapping with a spawned
test executable; unit tests for ambiguity and rules.

Docs: `README.md` (process claim becomes true), `DETECTIONS.md`, `OBJECTIVE_SEE_PARITY.md`.

### M7 - What's Your Sign? parity: out-of-process Explorer entry point (S-M)

1. Per-user classic context-menu verb (`HKCU\Software\Classes\*\shell\WinSight.Signature`) launching
   `winsight-dashboard.exe --signature "%1"`; no in-process shell extension. Windows 11 shows it under
   "Show more options"; the modern menu (IExplorerCommand with package identity) is out of scope.
2. Signature window: state, signer, anchor, revocation standing, catalog or MSIX package evidence,
   timestamp, MD5/SHA-1/SHA-256, opt-in VirusTotal hash lookup, copy/export JSON.
3. CLI `winsight sign <path> [--json]`.
4. Installer task to add/remove the verb; uninstall removes it.

Tests: verb registration/removal on HKCU test classes; path argument validation (UNC and device paths
refused like `FindingActions`); presenter tests.

Docs: `README.md`, `INSTALLATION.md`, `OBJECTIVE_SEE_PARITY.md` (remove from "not planned", record the
out-of-process design).

### M8 - Depth items (M each, independent)

| Item | Objective-See analogue | Work | Privilege | Docs |
|---|---|---|---|---|
| Live input-filter alerts + per-device-instance filters | ReiKey | Registry watch on keyboard/mouse class and `Enum\...\UpperFilters`; Guardian-style alert | User read | `DETECTIONS.md` |
| Resident drivers + boot configuration | KextViewr | Elevated `EnumDeviceDrivers` pass with address check; test-signing/DSE context from the integrity scanner; #nonMicrosoft filter | Elevated optional | `DETECTIONS.md` |
| Runtime DLL loads | DHS | Elevated ETW image-load observation correlated with phantom-import and writable-directory findings | Elevated | `DETECTIONS.md`, `ATTRIBUTION_DESIGN.md` |
| Task view | TaskExplorer | Dashboard process view with #unsigned/#nonMicrosoft/#flagged filters and per-process pivot | User | `README.md` |
| Live connections | Netiquette | Auto-refreshing connection view with filters and JSON export | User | `README.md` |
| Persistence filters and VirusTotal view | KnockKnock | Dashboard filters; per-item opt-in hash lookup view (no file submission) | User, network opt-in | `PRIVACY.md` unchanged |
| Away mode | Do Not Disturb | Armed mode: alert on resume, session unlock, device arrival and power events while armed; local alert only | User | `DETECTIONS.md` |
| Process and file event monitors | ProcessMonitor/FileMonitor | `winsight monitor process|file --watch` over elevated ETW with JSON lines | Elevated | CLI docs |

### M9 - Measured evaluation: the basis of any "better" claim (L)

1. **Scenario catalog** (`evals/scenarios/`, VM only): persistence installs per vector; synthetic
   encryptor over a decoy-bearing corpus; camera/microphone activation; unknown outbound application;
   DLL planting in a writable directory; driver registration; away-mode wake.
2. **Harness** in the VM kit: runs each scenario, records alert time, action outcome, false positives,
   CPU/memory/IO via performance counters.
3. **Clean-machine soak:** 7 days of normal use on a reference VM image; counts every alert; each is
   classified as true or false positive.
4. **Report** `docs/validation/<date>-evaluation-<commit>.md` with results against the budgets in 6.3
   and the parity matrix; comparisons with Objective-See are capability comparisons plus WinSight's
   measured numbers, never an unmeasured head-to-head.

Acceptance: budgets met or gaps recorded; only measured properties appear as "better" in `README.md`
and `OBJECTIVE_SEE_PARITY.md`.

### M10 - Production hardening that parity depends on (M)

- Native Arm64 privileged qualification on physical hardware.
- Recommend machine-wide install when response actions or Ask mode are used; document that per-user
  binaries are writable by the same user.
- Tamper evidence for rule store, quarantine manifests and action journal (integrity check against a
  DPAPI-protected key; stated limit: same-user malware can still act as the user).
- Endurance: 72 h VM run with all monitors, sign-in cycles and sleep/resume.
- Crash reporter coverage for the new windows and service commands.

---

## 8. Sequencing and dependencies

```text
M0 ─► M1 ─┬─► M2 ─┐
          ├─► M3 ─┼─► M9 ─► claims update
          ├─► M4 ─┤
          ├─► M5 ─┤
          └─► M6 ─┘
M7 (after M0, independent)      M8 items (after M1, independent)      M10 (parallel, gates release)
```

Suggested order by security value per effort: **M0 → M1 → M3 → M2 → M5 → M4 → M6 → M7 → M8 → M9**,
with M10 running alongside from M4 onwards. M4 is the largest privileged change and should start its
spike early even if implementation follows M5.

Release gates:
- A release may claim a tool's parity only after its milestone's acceptance criteria and qualification
  record exist for that exact candidate.
- "Better" wording requires the M9 report for that candidate.

---

## 9. Risks and open questions for the owner

| # | Risk or question | Mitigation / proposal |
|---|---|---|
| R1 | Ask mode (M4) can cut network access | Explicit arming, passive onboarding, fail-open policy, emergency disable, VM-only first |
| R2 | Suspension (M5) of an innocent process | Opt-in, high-confidence trigger only, critical-process refusal, one-click resume, journal |
| R3 | Removal (M2) breaks legitimate software | Disable instead of delete where possible, quarantine + restore, revalidation, Allow rules |
| R4 | Same-user malware tampers with rules or journal | Tamper evidence (M10) and machine-wide install recommendation; stated limit |
| R5 | Alert fatigue | Coalescing, rules, passive modes, measured false-positive rate in M9 |
| Q1 | Should Ask mode's infrastructure allowances include Windows Update and time sync by default? | Proposal: yes, as reviewed and visible allowances |
| Q2 | Should "Start at sign-in" be preselected in the installer? | Proposal: offered, not preselected, for the first release that ships it |
| Q3 | Is a future kernel driver (D6) ever in scope? | Proposal: decide after M9 measurements |

---

### Owner decisions (2026-09-14)

| Question | Decision |
|---|---|
| Q1 - Ask-mode infrastructure allowances | **Yes.** Windows Update/BITS/Delivery Optimization and the Windows Time service are default allowances, listed visibly in the policy view and removable by an elevated operator. |
| Q2 - "Start at sign-in" preselected in the installer | **No.** Offered as an unchecked installer task and a dashboard setting. |
| Q3 - Kernel driver | **Yes, if the M9 measurements show it is materially better** than the user-mode design on a scenario that matters (for example holding a first connection, or blocking a write before it lands). The decision is recorded after M9 with its evidence; D6 stays deferred until then. |

## 10. Documentation update matrix

| Document | M0 | M1 | M2 | M3 | M4 | M5 | M6 | M7 | M8 | M9 | M10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `README.md` | ✓ |   | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |   |
| `ROADMAP.md` | ✓ | ✓ |   |   |   |   |   |   |   | ✓ |   |
| `ARCHITECTURE.md` | ✓ | ✓ |   | ✓ | ✓ |   |   |   |   |   |   |
| `OBJECTIVE_SEE_PARITY.md` | ✓ |   | ✓ |   | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |   |
| `THREAT_MODEL.md` |   | ✓ | ✓ |   | ✓ | ✓ | ✓ |   |   |   | ✓ |
| `DETECTIONS.md` |   | ✓ | ✓ |   |   | ✓ | ✓ |   | ✓ |   |   |
| `GUARDIAN_DESIGN.md` |   |   | ✓ | ✓ |   |   |   |   |   |   |   |
| `WFP_DESIGN.md` |   |   |   |   | ✓ |   |   |   |   |   |   |
| `RANSOMWARE_DESIGN.md` |   |   |   |   |   | ✓ |   |   |   |   |   |
| `ATTRIBUTION_DESIGN.md` |   |   |   |   |   | ✓ |   |   | ✓ |   |   |
| `MCP.md` |   | ✓ |   |   |   |   |   |   |   |   |   |
| `CODING_STANDARDS.md` |   | ✓ |   |   |   |   |   |   |   |   |   |
| `INSTALLATION.md` / `ADMINISTRATION.md` |   |   |   | ✓ | ✓ |   |   | ✓ |   |   | ✓ |
| `RECOVERY.md` |   |   | ✓ |   | ✓ | ✓ |   |   |   |   |   |
| `PRIVACY.md` |   | review |   |   | review |   |   |   | review |   |   |
| `PRODUCTION_READINESS.md` | ✓ |   |   |   | ✓ |   |   |   |   | ✓ | ✓ |
| `validation/VM_QUALIFICATION_KIT.md` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |   | ✓ |   | ✓ | ✓ |
| `evals/README.md` |   | ✓ |   |   |   |   |   |   |   | ✓ |   |
| `CHANGELOG.md` | every milestone |
