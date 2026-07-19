## Unreleased

Step-by-step progress log. Newest first. Every CI-green step lands here.

### Phase 4 (ransomware): canary planting + file watcher
- The thin I/O layer over the heuristics core, all user-mode (it watches the user's own
  Documents/Desktop/Pictures — no elevation). `CanaryManager` plants hidden decoy files and answers
  `IsCanary`; `RansomwareSignalClassifier` (pure, tested) maps a filesystem change to a signal;
  `RansomwareFileWatcher` runs a `FileSystemWatcher`, classifies each change, and feeds the bounded
  burst detector, raising `Detected` once; `RansomwareMonitor` wires planting + watching and removes
  the decoys on dispose. A touched canary fires immediately (a decoy has no legitimate reason to
  change); a rename/delete burst fires once. Validated by real-`FileSystemWatcher` functional tests
  (canary touch, rename burst, plant-detect-cleanup). Entropy-on-write is deliberately not wired yet:
  legitimately compressed files (.docx/.jpg/.zip) are high-entropy and would false-positive.
  Attribution (which process) and stopping the write both need elevation / a minifilter — deferred.

### Phase 4 (ransomware): heuristics core
- First slice of RansomWhere-class behavior detection: a pure, unit-tested `WinSight.Ransomware`
  core, same "decisions in a tested core, thin watcher later" discipline as the firewall and Guardian.
  `ShannonEntropy` scores a byte buffer in bits/byte and flags "looks encrypted" only above a
  conservative threshold *and* a minimum sample size, so a tiny high-entropy fragment cannot trigger.
  `RansomwareBurstDetector` is a bounded, clock-injected sliding-window counter that fires exactly
  once per burst — or immediately on a touched canary/decoy — and stops accumulating until `Reset`,
  so a flood cannot grow its state. Detect-and-alert only; the file-system watcher, canary planting,
  entropy-on-write sampling, and dashboard alert are the next increments, and *stopping* the
  encryption needs a minifilter + EV cert (deferred). See `docs/RANSOMWARE_DESIGN.md`.

### Guardian: scoped re-scan — near-instant detection
- A change now re-scans only the surface that fired, not all 22. The change source carries the watch
  target that fired (`PersistenceSurfaceChangedEventArgs.ChangedTargets`); the monitor maps it to the
  owning enumerator(s) via `WatchTargets` and re-scans just those, falling back to a full scan when
  the origin is unknown. Validated on a real machine: detecting a new HKCU Run value dropped from
  ~20s (a full re-scan that also re-verifies signatures) to **~0.5s** (a 500 ms debounce plus a
  ~30 ms scoped scan). Writing-process attribution and live WMI/ETW surfaces stay deferred — both
  need elevation, which would break the unprivileged in-dashboard model; a future opt-in elevated
  "deep monitoring" mode could add them.

### Guardian: broaden real-time coverage to more registry persistence surfaces
- The live registry watcher now covers, beyond Run/Services/Winlogon, the high-value surfaces most
  abused for persistence: Image File Execution Options (IFEO debugger hijacks), AppInit_DLLs, Active
  Setup, SilentProcessExit, LSA packages, BootExecute, AppCertDlls, time providers, print
  monitors/providers, netsh helpers, credential providers, browser helper objects, and Windows
  Load/Run — ~17 live surfaces in total. Each just declares `WatchTargets` and reuses the proven
  `RegNotifyChangeKeyValue` watcher; arming the whole default set stays within the WaitAny handle cap
  (a test asserts this). COM/CLSID hijack (too noisy to watch as a subtree) and the WMI subscription
  surface (no registry/file backing) stay covered by the on-start reconciliation diff instead.

### Guardian uses the same robust, cached signature verifier as the on-demand scan
- Surfaced by a real-machine smoke test: a live registry add fired a Guardian detection correctly
  (unsigned/missing → notable, loud; other → calm), but a signed OS binary (`notepad.exe`) read as
  `VerificationError` instead of `SignatureValid`, because `GuardianHost` used the bare default
  `AuthenticodeVerifier` while the on-demand scan uses
  `CachingSignatureVerifier(NativeSignatureVerifier())` (WinVerifyTrust + catalog fallback + cache).
  Guardian now uses the same verifier, so a binary reads identically whether via scan or Guardian,
  and — since Guardian re-scans fully on every change — the cache avoids re-verifying unchanged
  binaries each time. Re-validated on a real machine: `notepad.exe` now reads `SignatureValid`,
  signer `CN=Microsoft Windows`.

### Guardian: on-start reconciliation across runs
- The baseline is now persisted across runs, so persistence that appears while WinSight is not
  running surfaces on the next launch (once), instead of being silently absorbed into a fresh
  baseline. `FilePersistenceBaselineStore` writes a small local-only file
  (`%LocalAppData%\WinSight\guardian-baseline.tsv`, atomic temp+move, bounded, corrupt-tolerant —
  a missing or malformed file is treated as a first run, never a crash). `PersistenceMonitorCore`
  gains `ReconcileFromPersistedBaseline`: it diffs the current scan against the persisted baseline,
  surfaces the new entries, then resets the baseline to exactly the current state so items removed
  while WinSight was off drop out and cannot re-alert. Wired by default via `GuardianHost`; a first
  run with no saved baseline stays silent and only records one for next time.

### Guardian: real-time persistence monitoring (Phase 3, BlockBlock-class)
- The persistence scanner is promoted from on-demand to live. The 22 autostart enumerators stay
  the single source of truth; new watchers are only dumb triggers. On a change signal the monitor
  debounces, re-scans the affected surface, diffs against a baseline, and surfaces genuinely new
  entries — verdict-checked through the same Authenticode path as the manual scan.
- **Pure core** (`PersistenceIdentity`, `PersistenceDiffEngine`, `PersistenceChangeLog`,
  `PersistenceMonitorCore`): bounded like `PendingOutboundLog` (caps at `MaxChanges`, counts
  dropped arrivals instead of silently truncating), seeds a silent baseline on first scan so a
  machine does not alert on pre-existing persistence, and reports each new entry once. Fully
  unit-tested.
- **Registry watcher** (`RegNotifyChangeKeyValue` on Run/Services/Winlogon) and **filesystem
  watcher** (`FileSystemWatcher` on the Startup folders and `\System32\Tasks`), combined by a
  composite source. Each has a real-Windows functional test (private HKCU key, temp folder) that
  asserts a change actually signals — validated off a VM.
- **Dashboard**: hosts the monitor while running and raises a Notable/Info tray balloon on a new
  startup item (en/fr/es), reusing the existing proven `ShowBalloonTip` path. `GuardianHost` and
  `PersistenceMonitorPresenter` are the tested integration seam.
- Honest limits, stated in `docs/GUARDIAN_DESIGN.md`: detect-and-alert only (blocking the write
  needs a driver + EV cert, Phase 4+); sees *what* appeared, not *who* wrote it; real-time while
  the dashboard runs. Live end-to-end dashboard smoke test still recommended.

### Firewall enforcement verification must mask the INDEXED flag WFP sets itself
- The exact-inventory verification required a block filter to read back with `Flags == 0`, but WFP
  sets `FWPM_FILTER_FLAG_INDEXED` (0x40) on any app-id filter on its own. Every genuine block
  therefore failed verification, which the coordinator treated as an apply failure: it rolled back,
  removed the filters, and reported `Degraded`. Enforcement never survived enabling — or a reboot —
  yet the whole unit suite passed. Confirmed on a real VM: `VerifyExact` returned false while the
  copied `curl.exe` was demonstrably blocked (http 000) and the System32 copy still reached the
  network (http 200). The check now masks the INDEXED flag and keeps every other flag
  disqualifying. Re-validated end-to-end on the VM: enable reports `Active`, the blocked app is cut
  and the unblocked one passes, emergency disable restores connectivity.

### Firewall WFP runtime truth is reconciled, not cached
- The LocalSystem coordinator now requires a complete-state WFP reconciler. Each enforcement
  transition enumerates all native filters, removes every object linked to WinSight's provider
  or sublayer, recreates exactly the enabled block policies for IPv4 and IPv6 in one transaction,
  and verifies provider, sublayer, filter keys, layers, actions and app-id conditions before
  publishing `Active`. Disabled policies never create or preserve a filter.
- Authenticated status re-verifies the actual native inventory while holding the transition
  lock. Missing, extra, malformed or unreadable WFP state becomes `Degraded`; emergency and
  AuditOnly startup cleanup no longer depend on policy-store paths and therefore remove orphans.
- Client connect, request write and response read are independently bounded. The dashboard
  obtains status again after assembling paged collections and builds its protection state from
  that final response, preventing a stale `Active` view. Real BFE restart, external removal,
  orphan cleanup and x64/Arm64 behavior remain blocked on the isolated-VM protocol.

### Firewall IPC v3 and reboot-safe authority transaction
- Protocol v3 binds each policy and pending-app page to an uppercase SHA-256 identity and
  total count of the complete, deterministically ordered collection. Every continuation
  repeats that identity; snapshot drift, duplicates, omissions and inconsistent terminal
  counts fail closed. v1/v2 return one complete page or `NotSupported`, never an unsafe
  partial view. Negotiation probes v3, v2 and v1 in order and descends only after an
  authenticated zero-byte close.
- The service start type is now inside the coordinator's serialized authority boundary.
  Startup and enable require SCM auto-start before WFP can become Active; failed enable
  rolls filters, durable intent and SCM back to AuditOnly/demand-start. Emergency disable
  removes filters, persists AuditOnly, then restores demand-start; an SCM failure remains
  visible as Degraded and never reapplies a block.
- `status` treats only SCM error 1060 as absence, while every other query error is a stable
  failure. `enforce-status` labels storage as persisted desired mode and leaves effective
  runtime unknown; only authenticated IPC can report effective state. Product and EN/FR/ES
  guidance now direct operators to verify SCM registration, running state and LocalSystem
  identity without claiming those gates have passed.

### Firewall IPC: authenticate both ends and preserve runtime truth across upgrades
- The dashboard now proves that the connected named-pipe object is owned by LocalSystem
  before it writes any request. The service explicitly assigns that owner, reserves the
  first pipe instance for its lifetime, and does not announce `FW_PIPE_LISTENING` until
  the reservation succeeds. A name collision therefore stops the listener with a stable,
  redacted failure instead of allowing an interactive-user pipe squatter to impersonate
  active filtering.
- Replies are accepted only when both request id and protocol version match the request.
  Peer authentication or correlation failure is fixed-message, fail-closed, and never
  triggers legacy negotiation. The v1 wire shape remains strict, but a new service now
  projects enforcement to v1 only while the effective runtime state is `Active`; degraded
  desired enforcement is projected as audit-only so an older dashboard cannot silently lie.
- One reserved server instance is reused between clients. Separate bounded deadlines evict
  peers that never send a request or never read a response, while the service-side policy/WFP
  transition between those I/O operations keeps its independent service-lifetime cancellation.
- English, French and Spanish presentation now says the pipe endpoint is reachable rather
  than claiming SCM installation, and emergency confirmation consistently names firewall
  filtering. Native LocalSystem ownership, two-account squatting, SCM and WFP qualification
  remains blocked on explicit human execution of the isolated-VM protocol.

### Firewall: enforcement can be enabled again — the product can actually filter
- WinSight could not block anything. `EnforcementCoordinator.EnableAsync` existed, but nothing
  could reach it: the console verb `enforce-enable` was disabled by the LocalSystem hardening
  (6d5d908), and the pipe's `IFirewallMutationAuthority` only ever exposed UpsertPolicy,
  RemovePolicy and EmergencyDisable. The machine had a brake and no accelerator, so it was stuck
  in audit-only permanently: policies were saved and reported, and never filtered. Verified on a
  real VM — the dashboard offers only "Emergency disable".
- This is the "separate, later, explicitly gated increment" the dispatcher documented. Enabling
  enforcement now goes over the authenticated pipe as `FirewallCommand.EnableEnforcement`, which
  keeps both invariants that were in tension:
  - the hardening's invariant — only the SYSTEM service mutates WFP, after validating its trusted
    storage. The console stays out of the WFP engine; re-enabling the console verb would have
    reopened exactly the hole 6d5d908 closed.
  - the original design's invariant — enabling is "not something the unprivileged dashboard can
    trigger". It is a mutation, so it needs `MutateMachinePolicy`: an elevated administrator or
    SYSTEM. An unprivileged dashboard holds only `ReadStatus` and is refused. Confirmed on a real
    VM in both directions: non-elevated dashboard reads the state but is refused the mutation;
    elevated is accepted.
- Enforcement is refused outright when the engine cannot filter, rather than persisting a mode
  that reports as armed while nothing is enforced. That case is now reported as its own outcome
  ("this machine has no usable filtering engine") instead of collapsing into a generic rejection
  a user might retry, expecting protection that could never arrive.
- Dashboard: an "Enable enforcement" button sits next to the emergency disable — accelerator and
  brake in one place — with a confirmation that states plainly that saved blocks take effect
  immediately, and a distinct success message for the moment blocks start filtering. Localized
  en/fr/es. Enabling remains reversible at any time by the existing emergency disable.

### Firewall service: the service can actually start (provision the whole chain it owns)
- On a real VM the service failed to start (`sc start` reported 1053, empty event log) and
  `enforce-status` returned `[FW_ENFORCEMENT_STATUS_UNAVAILABLE]`: the storage trust guard refused
  the very directory the service had just provisioned, so startup returned before signalling the
  SCM. Two causes, both found against real Windows ACLs:
  - Only the leaf (`ProgramData\WinSight\firewall`) was hardened. The intermediate
    `ProgramData\WinSight`, which `Directory.CreateDirectory` creates implicitly, kept ProgramData's
    inherited ACL (Users get `Write`, and `CREATOR OWNER` materialises into a `FullControl` entry
    for whoever created it) and stayed owned by the creating user rather than Administrators. The
    trust inspector was right to refuse it: that owner could delete and recreate the hardened leaf
    with its own ACL and plant a policy the SYSTEM service reads. Provisioning now creates the
    chain, then hardens and claims ownership of every component below ProgramData, innermost first
    (hardening a parent first locks the caller out of creating its child). ProgramData itself and
    the drive root belong to Windows and are never touched. Existing installs self-repair.
  - `C:\ProgramData` grants Users `Write`, which on a directory means `CreateFiles`, so the chain
    was refused whatever we did below it. Adding a new child to a directory cannot modify, replace,
    or delete the already-existing, independently protected next link — that needs
    `Delete`/`DeleteChildren`/`ChangePermissions`/`TakeOwnership`, which stay dangerous on every
    component. Add-child rights are now benign on ancestors and stay dangerous on the leaf and on
    the directory directly holding it, where a planted sibling (a side-loadable DLL, or the policy
    file before it exists) actually lands. Callers that do not specify stay fail-closed.

### Firewall service: fix path-trust so a legitimate install is actually trusted
- The LocalSystem path-trust inspector (ServicePathTrust) rejected every real install location,
  including `C:\Program Files\...`, so `install` would always print `[FW_INSTALL_FAILED]`. Three
  defects in the raw ACL -> trust translation, none reachable by the mocked unit tests, surfaced
  only against real Windows ACLs (verified on a real machine):
  - Composite-mask bug: probing `rights & (WriteData | Modify | FullControl)` flagged a plain
    Read&Execute grant as writable, because `Modify`/`FullControl` share the Read/Execute bits.
    Now only the atomic write/delete/ownership bits are tested; `Modify`/`FullControl` are still
    caught because they contain those bits.
  - Inherit-only ACEs (`PropagationFlags.InheritOnly`), which grant nothing on the component
    itself, were counted against it. They are now excluded, matching Windows' own access check.
  - `CreateDirectories` on a directory (the default `C:\` right that lets any user `mkdir C:\foo`)
    was treated as fatal, so no path under `C:\` could ever be trusted. Creating a *new*
    sub-directory cannot tamper with an existing protected child (that needs `Delete`/
    `DeleteChildren`, still flagged), so it is no longer dangerous on directories; on a file the
    same 0x4 bit is `AppendData` (grows the binary) and stays dangerous.
- Extracted the translation into a pure, unit-tested `ServicePathRights.Map(rights, isDirectory)`.
  Verified on a real machine: the `C:\ -> Program Files` ancestor chain and an Administrators-owned
  leaf are now Trusted, while user-writable paths stay Denied. The strict owner rule (a service exe
  owned by TrustedInstaller is not a valid leaf) is unchanged.

### Detection: add print providers (verified false-positive-free)
- Add PrintProviderEnumerator: the DLLs the print spooler (spoolsv, SYSTEM) loads as print
  providers (...\Control\Print\Providers\{name} -> Name); a rogue one runs as SYSTEM, a
  documented persistence/privesc vector distinct from print monitors. It follows the proven
  DLL -> Authenticode model, so unlike the shim surface it cannot false-positive.
- Verified on a real machine: 2 providers (inetpp.dll, win32spl.dll), both correctly
  SignedTrusted, neither flagged. Localized en/fr/es.

### Detection: drop the shim-database surface (false-positive avoidance)
- Verification pass on a real machine confirmed the new autostart surfaces are clean:
  credential providers (21) and browser helper objects (4) all resolved to correctly
  Authenticode-signed DLLs, none flagged. But an installed application shim is a .sdb file,
  which is never Authenticode-signed, so the shim-database surface would flag every
  legitimate installed shim as unsigned/suspicious — a guaranteed false positive. Removed
  it; the credential-provider, browser-helper-object and Windows Load/Run surfaces stay.

### Firewall: block feedback now tells you whether it is actually enforcing
- A block only filters traffic once enforcement is enabled (an elevated action). Blocking
  an app while enforcement was off said "applied" yet nothing happened on the network — the
  exact confusion seen during testing. Now a saved-but-not-enforced block reports "Saved. It
  filters only once enforcement is enabled", across both the firewall controls and the
  "Block outbound" action, checking the live enforcement state after the change.
- Logic is in FirewallControlPresenter.OutcomeMessageKey (UI-agnostic, unit-tested);
  localized in en/fr/es.

### Firewall: block an app's outbound straight from a finding
- Any finding that owns an on-disk executable (a network connection, a running process, or
  a persistence entry) now offers a "Block outbound" action that sends a Block policy to the
  firewall service over the authenticated pipe. This is the observe-then-decide loop of a
  Little Snitch / LuLu: see what an app is doing, block its network in one click.
- Which findings qualify is decided by a UI-agnostic FirewallActionPresenter (the tool's
  image field must resolve to an absolute .exe; DLLs and non-program tools are excluded),
  unit-tested without a UI. The outcome reuses the existing localized result messages, and
  the action is localized in en/fr/es.

### Detection: two more autostart surfaces (Windows Load/Run, application shims)
- Add WindowsLoadRunEnumerator: the legacy Load/Run values under
  ...\Windows NT\CurrentVersion\Windows (HKLM + HKCU), an old but still-abused logon
  autostart spot distinct from AppInit_DLLs.
- Add ShimDatabaseEnumerator: installed application-compatibility shim databases
  (...\AppCompatFlags\InstalledSDB\{guid} -> DatabasePath); a custom .sdb can inject code
  into a target at load (MITRE T1546.011). Persistence coverage now spans 22 surfaces.

### Detection: two new autostart surfaces (credential providers, BHOs)
- Add CredentialProviderEnumerator: the COM credential providers the logon/lock UI loads
  (HKLM\...\Authentication\Credential Providers\{CLSID}); a rogue one runs in the trusted
  logon context and can capture credentials (MITRE T1556-class).
- Add BrowserHelperObjectEnumerator: Explorer/IE in-process COM add-ins
  (HKLM\...\Explorer\Browser Helper Objects\{CLSID}, both registry views); a classic
  injection/persistence spot (MITRE T1176).
- Each CLSID is resolved to its InprocServer32 DLL via a shared ClsidResolver, so the
  scanner surfaces the real binary (and its Authenticode verdict), not an opaque GUID.
  Both are registered in the default scan and localized in en/fr/es. Persistence coverage
  goes from 18 to 20 surfaces.

### Scans are now cancellable
- Thread a CancellationToken through the synchronous scan pipeline: ISignatureVerifier
  (Verify/VerifyMany) and its four implementations, ConnectionMonitor/ProcessLister/
  ModuleLister snapshots, and PersistenceScanner.Scan. Adapters passes the token it
  already receives down to them.
- Cancellation kills the netstat and Get-AuthenticodeSignature child processes immediately
  (via CancellationToken.Register) and is observed at batch/enumeration boundaries, so the
  dashboard Stop button and the MCP scan timeout now actually abort in-flight work instead
  of orphaning a background thread. The pipeline stays synchronous by design.


### Code quality: review polish
- McpModels.Protect no longer rebuilds and re-sorts the path-redaction table on every
  field; it is computed once as a static (the user folder paths are process-stable).
- VirusTotalEnricher.Lookup returns IReadOnlyDictionary, matching the read-only collection
  convention used everywhere else.
- Convert six single-assignment constructors to C# 12 primary constructors (ConnectionMonitor,
  ProcessLister, ModuleLister, HostsReader, CameraMicMonitor, ExtensionScanner).
- Fix a corrupted doc comment in BrowserExtension.


### Code quality: remove sync-over-async from child-process output reads
- AuthenticodeVerifier.RunPowerShell and ConnectionMonitor.RunNetstat blocked on
  ReadToEndAsync via GetAwaiter().GetResult(), a pattern the project standards forbid.
  Both now drain stdout on a background reader thread (OutputDataReceived +
  BeginOutputReadLine) and stay fully synchronous, with the same kill-on-timeout safety.


### Phase 2 fix: firewall dashboard controls cannot crash the app
- The firewall mutation handlers are async void event handlers; an unexpected exception
  (e.g. a pipe ACL denial surfacing as UnauthorizedAccessException) had no caller to catch
  it and would tear down the tray app. RunFirewallMutationAsync now nets those and reports
  a message via the summary line instead, mirroring the rest of the defensive UI.


### Phase 2 fix: unify executable-path canonicalization across the firewall
- The CLI enforcement path (EnforcementCoordinator.SetPolicyAsync) and the WFP key
  derivation used their own weaker path normalization, while the IPC dispatcher and the
  policy store used OutboundPolicyEvaluator.CanonicalPath. A quoted or dot-segmented path
  could therefore be stored one way but keyed another, orphaning a filter that the next
  boot re-apply could not reproduce, and could dodge dedup into a duplicate-policy save
  failure.
- OutboundPolicyEvaluator.CanonicalPath is now the single canonicalizer (quote-stripped,
  absolute-required, normalized) used by the store, the dispatcher, the coordinator, and
  the WFP filter-key derivation. Regression tests cover quoted/relative-segment paths and
  the coordinator persisting the canonical form.

### Phase 2 fix: dashboard could not authenticate to the service (impersonation)
- The pipe client connected without requesting impersonation, so the service's
  `RunAsClient` identity check saw an anonymous token and denied every request with
  Unauthorized. The gateway maps that to "service unavailable", so the dashboard showed
  "service not installed" even when the service was running, and no control worked.
- `FirewallServiceClient` now connects with `TokenImpersonationLevel.Impersonation`, so the
  service can verify the caller's real Windows identity. Reproduced end to end against a
  live console host (GetStatus went from Unauthorized to a real AuditOnly status), and
  covered by a new regression test that exercises the real authorisation path (the existing
  tests injected a fake authoriser and so missed it).

### Phase 2 interactive firewall controls in the dashboard
- The Outbound Firewall view is now interactive. When the firewall tool has a live status
  and the privileged service answered, a controls bar appears: "Block an app…" (file
  picker), and, for the selected policy row, Allow / Block / Remove, plus an "Emergency
  disable" kill switch (confirmed) that returns the machine to audit-only and lifts every
  block. Each action calls the authenticated pipe and re-reads the status so the grid
  updates immediately; the outcome (applied / unavailable / unauthorized / rejected) is
  shown localized.
- Enabling enforcement itself stays out of the unprivileged dashboard: the controls set
  per-app policy and can emergency-disable, but turning enforcement on remains the elevated
  service action.
- Decision logic (policy-row parsing, outcome-to-message mapping) lives in a UI-agnostic
  `FirewallControlPresenter` in the application layer, unit-tested without WPF. New strings
  are localized in English, French, and Spanish; the footer no longer claims the dashboard
  is read-only.

### Phase 2 dashboard-side write path + async entry point
- `FirewallServiceGateway` now exposes the policy write path over the authenticated pipe:
  `SetPolicyAsync`, `RemovePolicyAsync`, and `EmergencyDisableAsync`, each returning a
  `FirewallMutationResult` (Applied / ServiceUnavailable / Unauthorized / Rejected). The
  privileged service authorises by Windows identity; enabling enforcement itself stays an
  out-of-band privileged action, not something the unprivileged dashboard can trigger.
- Fix the service entry point to be async end to end. The enforcement verbs and host
  startup previously used `.GetAwaiter().GetResult()`, which the project standards forbid;
  they now await through an async `Main`, `RunHostAsync`, and async verb handlers.

### Phase 2 enforcement survives a reboot (service auto-start)
- Enabling enforcement now switches the installed service to auto-start, so it launches on
  boot and reinstalls the (non-persistent) WFP block filters. A firewall that stops
  enforcing after a reboot is a hole; audit-only leaves the service demand-start.
  `enforce-disable` returns it to demand-start. Implemented with `ChangeServiceConfig`.
- Validated on the VM that a service restart re-applies stored blocks; this closes the
  boot case so the same holds across a reboot while enforcement is enabled.

### Phase 2 multi-application block and the real WFP engine
- The per-application outbound block is now multi-app: each blocked application is keyed by
  a stable, per-path GUID (SHA-256 of the canonical path), so many apps can be blocked at
  once and adding or removing one never disturbs another. Verified end to end on the VM:
  a copied `curl.exe` was blocked over both IPv4 and IPv6 while the real `curl.exe` and
  every other app kept working, then unblocked cleanly.
- Add `WfpOutboundFirewallEngine`, the real `IOutboundFirewallEngine`: a Block policy
  installs a per-app block filter, an Allow/Ask policy lifts it, and it idempotently
  provisions the WinSight provider/sublayer. This is the bridge from the durable policy
  store to WFP. It is not the shipped default; the service stays audit-only until
  enforcement is explicitly enabled.
- CLI: `wfp-block-add <path>` and `wfp-block-remove <path>` are now per-application, plus a
  new `wfp-block-status <path>`. `wfp-status` reports the containers and audit filter.

### Phase 2 outbound block now covers IPv6 as well as IPv4
- Install every WinSight WFP filter (the PERMIT audit filter and the per-application BLOCK
  filter) at BOTH `FWPM_LAYER_ALE_AUTH_CONNECT_V4` and `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
  An IPv4-only filter is bypassable: an application that reaches the network over IPv6
  would not be blocked. Both halves are added and removed in one transaction.
- Note on testing: `ping` is not a valid target for an app-scoped block, because
  `ping.exe` performs its ICMP echo through the IP Helper service (`IcmpSendEcho`), so at
  the ALE connect layer the traffic is attributed to that service, not to `ping.exe`. Use
  a tool that opens its own TCP socket (e.g. a copied `curl.exe`) to observe a per-app
  block.

### Phase 2 per-application outbound BLOCK (WFP, isolated to one app)
- Add `wfp-block-add <path>` and `wfp-block-remove` verbs. `wfp-block-add` installs a WFP
  BLOCK filter that stops outbound connections for a SINGLE application, matched by its
  app id (`FwpmGetAppIdFromFileName0` + a `FWPM_CONDITION_ALE_APP_ID` equal condition).
  Only that binary is affected; every other application keeps connecting normally.
- One block filter at a time, added in a transaction and idempotent (a new block replaces
  the prior one). `wfp-status` now reports the block-filter presence too.
- This is the first actually-blocking capability. It is deliberately per-app (never a
  global block), requires elevation and a prior `wfp-provision`, and is intended for
  validation on an isolated VM with a harmless test executable. It is not wired into the
  shipped service path: the default build still installs and blocks nothing.

### Phase 2 non-blocking WFP PERMIT filter (proves filter interop)
- Add `wfp-filter-add` and `wfp-filter-remove` verbs. They add and remove a single PERMIT
  filter in the WinSight sublayer at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`. A PERMIT authorizes
  the outbound connect, which is already the default, so it blocks nothing: it exists only
  to prove the full filter interop (`FwpmFilterAdd0` with the complete `FWPM_FILTER0`,
  `FWP_VALUE0` and `FWPM_ACTION0` marshalling) works and is cleanly removable.
- The filter is added inside a transaction, is idempotent, and references the WinSight
  provider and sublayer. `wfp-status` now also reports the permit-filter presence.
- Requires elevation and a prior `wfp-provision`. No blocking logic exists yet;
  connectivity is untouched.

### Phase 2 WFP provider and sublayer (containers only, no filter)
- Add `wfp-provision`, `wfp-deprovision` and `wfp-status` verbs to the firewall service.
  They create and remove the WinSight-owned WFP provider and sublayer, which are
  namespace containers: they filter no traffic and cannot block a connection. They exist
  so future audit-only filters have a stable owner.
- All mutation runs inside a WFP transaction (all-or-nothing) and is idempotent
  (already-exists / not-found are treated as success). Both objects are non-persistent,
  so a reboot removes them: the safest default while enforcement is still being validated.
- Requires elevation. Validated end to end on an isolated VM: the read-only `wfp-selftest`
  opened the engine and enumerated existing filters, confirming the interop before this
  mutating (but non-filtering) step.

### Phase 2 read-only WFP interop probe
- Add a `wfp-selftest` verb to the firewall service executable. It opens a Windows
  Filtering Platform engine session and counts the existing filters, then closes
  everything. It NEVER adds, changes or removes a filter, provider or sublayer, so it
  cannot affect connectivity. This is the safe first step of the WFP work: it confirms
  the interop and privileges before any enforcement code exists. Requires elevation.

### Phase 2 outbound-firewall service is installable (opt-in, audit-only)
- Ship `winsight-firewall-service.exe` in both installers and portable archives, with
  PE-architecture validation for x64 and Arm64. The per-user setup never registers it:
  installing a Windows service needs Administrator rights, so it stays opt-in.
- The service executable gains `install`, `uninstall`, `status` and `run` verbs.
  `install`/`uninstall` require an elevated console and register a demand-start,
  LocalSystem, audit-only service through the Service Control Manager (advapi32
  `CreateService`/`DeleteService`). The binary path is stored quoted, so a spaced
  install directory is registered correctly. The service installs no WFP filter.
- Once registered, the dashboard's Outbound Firewall view switches from "service not
  installed" to the live audit-only status. Enforcement remains a separate, later step.
- Add command-line and binary-path-quoting tests. Verified end to end: the single-file
  service publishes and its read-only `status` verb queries the SCM correctly.

### Phase 2 outbound-firewall dashboard view (read-only)
- Add an "Outbound Firewall" navigation entry that shows the WinSight firewall service
  over the authenticated pipe: whether it is installed, its mode, whether enforcement is
  active, and the stored per-application policies. `FirewallServiceAdapter` projects the
  gateway view into the shared report shape, so it reuses the existing rendering, export
  and localization pipeline.
- When the service is not installed or unreachable, the view degrades to an explicit
  "service not installed, traffic is not being filtered, read-only" message rather than
  an error, so the dashboard never implies the machine is being filtered when it is not.
- Localize the status, mode and per-app action labels in English, French and Spanish;
  executable paths stay verbatim as forensic evidence. Add adapter and localized-presenter
  tests (solution total now 281).
- Read-only in this increment: the dashboard never mutates policy. Scope unchanged, the
  shipped build stays audit-only and installs no WFP filter.

### Phase 2 firewall service endpoint (audit-only) and AI-surface evals
- Implement the outbound-firewall service endpoint in library form, still audit-only
  and installing no WFP filter. `AuditOnlyFirewallEngine` never mutates WFP and reports
  `IsSupported = false`, so enforcement can never be presented as active.
- Add `FirewallRequestDispatcher`: an unauthenticated caller only ever receives
  `Unauthorized`, store and engine faults collapse to `InternalFailure` with no
  exception text on the wire, the persisted mode is never promoted to enforcement, and
  `EmergencyDisable` always returns the machine to audit-only even from a corrupt store.
- Add `NamedPipeFirewallServer` and `FirewallServiceClient` over a hardened local pipe:
  full control for SYSTEM and Administrators, read/write for interactive users, an
  explicit deny for network logons, and verification of the impersonated Windows
  identity before any command runs. `FirewallConnectionHandler` serves one exchange
  over any duplex stream so the logic is tested without a pipe or elevation.
- Host the endpoint as a least-privilege Windows service worker (`WinSight.FirewallService`)
  built on `Microsoft.Extensions.Hosting.WindowsServices`. It runs the listener for the
  service lifetime, provisions an ACL-protected policy directory under ProgramData
  (full control for SYSTEM and Administrators only, inheritance removed), and installs no
  WFP filter. Console execution is supported for local debugging.
- Add 17 firewall/service tests, including a real same-user named-pipe round trip, the
  hardened pipe- and directory-ACL assertions, and the worker start/stop lifecycle; the
  firewall project has 50 tests and the service project 5.
- Add an optional, developer-only LLM-as-a-judge eval harness under `evals/` that scores
  the AI-facing report for accuracy, calibration, privacy, actionability and
  non-authority. The scan uses the local `--json` contract with no network; only an
  explicitly configured judge command contacts a model. Prompt and verdict outputs are
  git-ignored, alongside exported `winsight-*.json` scan reports.
- Scope is unchanged: the shipped build stays read-only and audit-only. No increment
  installs a live WFP filter until it has been safety-tested on an isolated Windows VM.

## v0.8.1, 2026-07-14

### Multilingual result semantics and Phase 1 hardening
- Complete the English, French and Spanish dashboard presentation for structured
  findings: persistence vectors and states, camera/microphone activity, missing
  process images, loaded modules, hosts-file reasons, certificate risks, empty
  extension permissions, firewall direction/action and connection ownership.
  Forensic values such as paths, process names and domains remain byte-for-byte
  evidence rather than translated display text.
- Grow each localization catalog from 138 to 185 parity-checked entries, replace
  placeholder “result(s)” wording with natural singular/plural forms, and add
  category-level presentation tests in all three languages.
- Extract localized finding presentation, the navigation catalog and allowlisted
  Windows launches from `MainWindow`, and isolate optional VirusTotal enrichment
  from scanner adapters. This reduces UI/network coupling without changing the
  stable report or JSON shape.
- Truncate long result cells visually with full-value hover tooltips, preventing
  service names, paths and extension permissions from crowding adjacent columns;
  copying and JSON export continue to preserve the complete values.
- Propagate cancellation into VirusTotal requests and hashing boundaries, including
  dashboard and MCP scan paths. Caller cancellation is never mistaken for an
  ordinary reputation timeout.
- Bound quota-accounting input to 64 KiB and encrypted API-key input to 8 KiB,
  persist both through flushed same-volume temporary files, and continue to fail
  closed for corrupt or oversized quota state.
- Make the shared signature cache synchronized, five-minute expiring and LRU-bounded
  to 4096 file fingerprints (path, size, creation time and modification time), so a
  long-running dashboard cannot retain unlimited or indefinitely stale verdicts.
- Add cancellation, oversized-state, cache eviction, localized result/enum and
  Windows action allowlist regressions. The suite now contains 256 test cases.
- Keep the product scope unchanged: WinSight remains read-only in Phase 1 and Phase 2
  remains the least-privilege WFP outbound firewall described in `docs/WFP_DESIGN.md`.

## v0.8.0, 2026-07-14

### Context-aware dashboard and secure optional reputation
- Route completed overview reports by navigation category: the overview shows the
  complete balanced scan, while Network, DNS, Persistence and every other page show
  only their own evidence. A category that has not run displays an explicit prompt
  instead of stale findings from another scanner.
- Remove the redundant report selector and make JSON export follow the active view,
  so the visible scope and exported scope cannot silently disagree.
- Replace the oversized stop control with a compact, right-aligned button while
  retaining the safe between-step cancellation behaviour and explanatory tooltip.
- Rebuild the header layout for consistent vertical alignment and add an accessible
  Settings entry in English, French and Spanish.
- Add an in-app VirusTotal setup dialog. Each user supplies their own key, which is
  encrypted at rest with Windows DPAPI for that account, never exported, and applied
  without restarting. Environment configuration remains authoritative for managed
  automation; MCP scans still prohibit all reputation-network requests.
- Enforce Community-key allowances across dashboard and CLI processes with persistent
  rolling-minute (4), UTC daily (500) and UTC monthly (15,500) counters. Accounting
  fails closed, HTTP quota errors are never retried, and the UI/docs clearly reserve
  Community keys for personal/non-commercial use. Identical hashes within one scan
  are deduplicated before consuming quota.
- Add explicit, user-initiated links to trusted Windows surfaces for each relevant
  category: Startup apps, privacy, Resource Monitor, network settings, Firewall,
  Task Manager, installed apps and certificate management. WinSight itself remains
  read-only and never deletes, kills, disables or blocks an item.
- Add regression tests for cross-tab isolation, incomplete overview state, localized
  resource parity, VirusTotal key validation and DPAPI store round trips.

## v0.7.2, 2026-07-14

### Honest persistence file and signature states
- Preserve the normalized Windows target for orphaned service/driver registrations
  even when the file is absent. A value such as `system32\DRIVERS\WinSetupMon.sys`
  now reports the expected `%SystemRoot%` path instead of an empty image field.
- Separate file resolution from Authenticode verification with explicit
  `FileMissing`, `AccessDenied`, `SignatureValid`, `Unsigned`, `InvalidSignature`
  and `VerificationError` outcomes. Missing/inaccessible files state that their
  signature was not checked; they are never presented as unsigned malware.
- Correct PowerShell signature mapping: `UnknownError` is invalid, while
  `NotSupportedFileFormat`, `Incompatible`, absent output and future unknown states
  are verification errors rather than fabricated unsigned verdicts.
- Add regression coverage for missing relative drivers, missing unquoted paths with
  spaces, verifier non-invocation for absent files and every documented PowerShell
  signature status.
- Update the official MCP C# SDK from 1.3.0 to the current stable 1.4.1. Keep the
  production protocol on stable `2025-11-25`; the breaking `2026-07-28` revision is
  still a release candidate as of this release date.
- Let the local release builder cross-package both x64 and Arm64 while executing MCP
  smoke tests only for the host architecture; native x64/Arm64 CI still executes
  each binary. This removes a false local failure from trying to launch Arm64 code
  on an x64 workstation without weakening the release gate.
- Document the WinSetupMon orphan pattern, precise report semantics and safe
  per-user VirusTotal key setup. VirusTotal remains optional and is never called
  when no local file/hash exists.

## v0.7.1, 2026-07-14

### Unified WinSight visual identity
- Add an original geometric vision-and-telemetry logo with a transparent high-resolution
  source, an optimized 256 px UI asset and a nine-resolution Windows ICO.
- Replace the dashboard's placeholder letter and generic system shield with the WinSight
  mark in the header, window chrome, taskbar and notification area.
- Embed the same icon in both native CLI/dashboard executables and the Windows installer,
  so Start menu, desktop shortcuts, Explorer and Add/Remove Programs share one identity.
- Display the brand in the repository README and ship the complete, documented asset set
  in x64/Arm64 ZIPs and installations. Release validation now checks alpha, dimensions,
  every ICO frame and the icons actually embedded in both executables.

## v0.7.0, 2026-07-14

### Local read-only MCP integration
- Ship a `winsight mcp` mode in the existing native x64 and Arm64 CLI binary,
  using the official MCP C# SDK and the stable `2025-11-25` protocol over local
  standard input/output only. No HTTP endpoint, network listener or background MCP
  service is created, and no third self-contained runtime is duplicated in packages.
- Expose capability discovery, one-scanner execution and the balanced overview as
  read-only, idempotent, non-destructive and closed-world tools, plus machine-readable
  capability and security-model resources.
- Keep AI disclosure summary-only and noteworthy-only by default. Bound evidence to
  200 items per report, serialize scans through one execution gate, apply a 90-second
  safety limit, redact user-profile paths and omit raw command fields.
- Require both the server-side `WINSIGHT_MCP_ALLOW_SENSITIVE=1` gate and explicit
  per-call evidence flags before raw paths or command lines can leave the scanner.
  Disable VirusTotal and every other network-enrichment path for MCP scans even when
  the parent process has an API key.
- Add projection/privacy tests and a real MCP subprocess integration test. Extend
  release packaging and native installer lifecycle tests to negotiate the installed
  server, inspect every tool annotation and invoke structured capability discovery.
- Document AI-client configuration, data-flow privacy, interpretation rules and the
  explicit ban on MCP remediation primitives.

## v0.6.0, 2026-07-14

### Fail-open firewall service foundation
- Add a versioned durable policy store for the future privileged service. Policy
  paths are canonicalized and deduplicated, counts and file sizes are bounded,
  unknown or duplicate JSON members are rejected, and enforcement values require an
  explicit service-side gate.
- Require literal absolute executable identities across the privilege boundary;
  environment variables are no longer expanded under the future service account.
- Persist through a write-through temporary file and atomic same-volume replacement,
  reject reparse-point storage, and expose a recovery API that converts malformed or
  inaccessible state into an empty audit-only configuration instead of carrying an
  old blocking decision forward.
- Add a strict 64 KiB length-prefixed local protocol for status, policy and emergency
  disable commands. Validate exact protocol versions, request IDs, command payloads,
  paths, enum values and response invariants before a future service can act.
- Add 25 security-focused tests covering round trips, corrupt/future/oversized state,
  atomic preservation, enforcement gating, duplicate or unknown JSON, truncated and
  oversized frames, bounded pagination, relative-path rejection and contradictory
  service status.
- Keep WFP mutation and the named-pipe host disabled. The protocol codec is not an
  authentication boundary; the future service must enforce pipe ACLs and verify the
  impersonated Windows identity before decoding or executing a request.

## v0.5.1, 2026-07-14

### Supported runtime baseline
- Move every user-mode component and both self-contained distributions to .NET 10
  LTS, extending the supported runtime lifecycle through November 2028 while
  preserving the Windows 10 22H2, Windows 11, x64 and Arm64 support matrix.
- Pin the reproducible build to SDK 10.0.301 and align `System.Management` with the
  serviced .NET 10 line. Remove the obsolete standalone Registry compatibility
  package now supplied by the Windows target framework.
- Make the minimum Windows API contract explicit in the target framework and update
  CI, release automation, contributor instructions and user-facing examples to the
  same runtime and release baseline.
- Adapt the Authenticode signer extraction path to .NET 10's certificate-loader
  diagnostics without weakening the existing WinVerifyTrust verification or
  catalog-aware fallback.
- Apply the .NET 10 analyzer's concrete-collection optimization to dashboard report
  selection without changing the UI contract.

## v0.5.0, 2026-07-14

### Native Windows distribution and documented detection contract
- Ship separate self-contained x64 and Arm64 portable archives and per-user Windows
  installers. Each installer selects English, French or Spanish, creates normal
  Start-menu/uninstall entries, requests no elevation by default and rejects the
  wrong processor architecture instead of silently installing an emulated build.
- Add a pinned, checksum- and Authenticode-verified Inno Setup bootstrap plus one
  reproducible release script for local builds, CI and tagged releases.
- Exercise the complete install/start/uninstall lifecycle on native x64 and native
  Arm64 GitHub-hosted Windows runners, including real WPF startup in all three UI
  languages and PE-machine validation for both executables.
- Publish SPDX 2.2 SBOMs, SHA-256 files, build-provenance attestations and SBOM
  attestations for every architecture alongside installers and portable archives.
- Document the supported Windows baseline, processor selection, silent deployment,
  integrity verification, complete detection inventory, verdict semantics and
  important blind spots. Explicitly disclose that public binaries are not yet
  Authenticode-signed because the project has no public code-signing certificate.
- Update project, security and contributor documentation to cover the dashboard,
  packages, installer supply chain and dual-architecture release gate.

## v0.4.0, 2026-07-14

### Runtime multilingual dashboard
- Localize the complete dashboard chrome, safety guidance, progress, errors, tray
  menu and analysis catalog in English, French and Spanish using standard .NET
  satellite resources with English as the safe fallback.
- Detect the Windows UI culture, remember the user's explicit choice and allow
  language switching from the header without restarting or interrupting a scan.
- Localize overview report names and severity labels while preserving raw Windows
  evidence exactly as collected for forensic accuracy.
- Add exhaustive resource-key coverage, culture fallback and catalog localization
  tests. CI and release pipelines now smoke-test all three packaged languages.

## v0.3.0, 2026-07-14

### Understandable dashboard and supply-chain hardening
- Replace the technical tool picker with a guided French dashboard: plain-language
  descriptions, contextual safety advice, clearer priority labels and explicit
  read-only/privacy messaging for non-technical users.
- Add real overview progress, cooperative stop-between-steps, selected-finding
  details, JSON export, clipboard copy, validated file-location opening and trusted
  Windows management-tool shortcuts. No untrusted finding value is executed.
- Add a reusable progress contract and tests for overview membership, cancellation
  before work starts and percentage calculation.
- Pin every GitHub Action to an immutable commit SHA, make the NuGet vulnerability
  audit fail closed, and attach GitHub build-provenance attestations to release ZIPs.
- Enable the latest recommended .NET analyzers across the solution.
- Update TraceEvent and the test SDK/runner packages; retain the .NET 8 line for
  Windows framework packages instead of mixing .NET 10 assets into this LTS target.

## v0.2.1, 2026-07-14

### Dashboard startup hotfix
- Override invariant globalization for the WPF frontend. WPF resolves XAML binding
  languages to a specific culture during layout; inheriting the libraries' invariant
  mode caused `Cannot find non-neutral culture related to 'en-us'` and terminated the
  packaged dashboard just after launch.
- Add `winsight-dashboard --smoke-test`, which loads the real XAML, bindings, layout
  and tray integration before exiting. Both CI and the tag-release workflow now run
  this packaged-executable smoke test, preventing a file-exists-only false green.

## v0.2.0, 2026-07-14

### Dashboard/tray, Phase 2 contracts, and release hardening
- **WPF dashboard + system tray**: `winsight-dashboard` consumes the same shared
  reports as the CLI, runs scans off the UI thread, filters noteworthy findings and
  exposes every snapshot tool without duplicating detection logic.
- **Reusable application entry point**: CLI adapters now expose canonical single-tool
  and overview runners; the CLI and dashboard therefore share verifier caches,
  report semantics and future module additions.
- **Clean application boundary**: scanner orchestration now lives in the dedicated
  `WinSight.Application` library. The dashboard no longer references the CLI
  executable, so both frontends depend on a testable application layer.
- **Phase 2 firewall foundation**: path-scoped `allow` / `block` / `ask` policies,
  a pure policy evaluator and the privileged WFP-engine boundary are implemented and
  unit-tested. Enforcement remains disabled until the service, authenticated IPC,
  audit mode and recovery path in `docs/WFP_DESIGN.md` exist.
- **Reproducible build graph**: added `winsight.sln`, a pinned .NET 8 SDK and a
  central 0.2.0 version. CI now restores once, verifies formatting, builds/tests the
  solution, audits NuGet packages, smoke-publishes both Windows executables and
  retains test/release artifacts.
- **Deterministic integration tests**: machine-wide module, process and persistence
  enumeration tests use injected signature verdicts; focused Authenticode tests still
  exercise the real catalog/native chain without repeatedly scanning thousands of
  host-specific files or timing out shared runners.
- **Frontend and dispatch coverage**: application-command and dashboard-catalog
  tests ensure every scanner remains reachable exactly once; firewall-policy tests
  now reject relative executable paths before they can cross the privileged boundary.
- **Release integrity**: tagged releases package both the CLI and dashboard and
  publish a SHA-256 checksum alongside the archive.
- README and architecture records now reflect the completed DNS/WMI/startup-folder
  work, the shipped dashboard, the real Windows build flow and the current WFP plan.

## Phase 1, user-mode tools

### Core, catalog signatures actually work now (major false-positive fix)
Running the tools against a real Windows box exposed a signal-destroying bug and
several large false-positive sources. A security tool that cries wolf is worse than
none, so this pass makes the verdicts trustworthy:
- **Catalog verification was silently failing.** The catalog-aware fallback fed its
  script to `powershell -Command -` over stdin, which produced NO output from a
  non-interactive child process, so every catalog-signed system binary (cmd.exe,
  DWrite.dll, every driver…) read as *Unsigned*. Switched to `-EncodedCommand`
  (base64 UTF-16LE). Result on a clean machine: modules unsigned **3097 → ~750**,
  processes **73 → ~32**, persistence flagged **258 → 4**.
- **New `Unknown` signature state.** A file whose signature *cannot be checked* (the
  catalog probe failed, e.g. under heavy load) is now reported `Unknown`, never a
  fabricated `Unsigned`. Only a definitive check yields `Unsigned`, so the tool
  fails safe (silent) instead of failing loud (false alarms). `Unknown` is never a
  flag-worthy signal.
- **Chunking + retry.** Signature batches are split by script length (so the encoded
  command never overflows the OS arg limit) and each chunk retries until every path
  is covered, so a transient PowerShell hiccup no longer downgrades a whole chunk to
  false "unsigned". The progress/error streams are silenced and drained so nothing
  leaks to the terminal mid-scan.
- **Certificates: no more SHA-1-self-signed false positives.** A root is *self-signed*,
  so its own SHA-1 signature is not a trust input, nearly every established public
  root (DigiCert, Baltimore, Comodo…) is SHA-1 self-signed. Weak-signature is now
  flagged only on a NON-self-signed cert in the root store. Flagged roots **40 → 10**
  (the remainder are genuine 1024-bit legacy roots).
- **Persistence: driver ImagePaths resolve.** `\SystemRoot\…`, `\??\C:\…` and bare
  `system32\drivers\x.sys` NT paths are normalised to real files, and the default
  Winlogon shell (`explorer.exe`, which lives in `%windir%`) resolves, so ~150
  legitimate Windows drivers and the default shell are no longer flagged "no image".

### Persistence, svchost ServiceDll payloads, HKCU Winlogon, SilentProcessExit
- **ServiceDll resolution**: for svchost-hosted services the ImagePath is just
  svchost.exe (signed Microsoft), the real payload is `Parameters\ServiceDll`. That
  DLL is now surfaced and signature-checked as its own entry, closing the classic
  "malicious service DLL rides under a trusted host" blind spot.
- **Winlogon HKCU**: Shell/Userinit are now also read from HKCU, the per-user,
  no-admin variant of the logon hijack was previously invisible.
- **SilentProcessExit monitors** (MITRE T1546.012): a MonitorProcess registered under
  IFEO silent-exit monitoring launches every time its target exits, the quiet
  companion of the IFEO Debugger hijack. New enumerator; 18 autostart surfaces now.
- VirusTotal enrichment cap lowered 8 → 4 to match the free-tier rate limit
  (requests past 4 were guaranteed 429s that burned quota for nothing).

### Core, security hardening pass
- **Binary-planting resistance**: the PowerShell (signature fallback) and netstat
  (connection fallback) child processes are now launched by absolute `System32` path,
  never resolved through the search path, a security tool running elevated must not
  be hijackable via a planted `powershell.exe`/`netstat.exe`.
- **No more unbounded child waits**: both spawns read stdout asynchronously and kill
  the process tree on timeout. Previously a hung child blocked `ReadToEnd()` forever
  (the `WaitForExit` timeout was unreachable) and leaked a zombie process.
- **VirusTotal input validation**: `Lookup` refuses anything that is not a
  well-formed SHA-256 (64 hex chars), so no attacker-influenced string can alter the
  request URL. The `HttpClient` is now injectable for testing.
- **Resource-exhaustion guard**: the Scheduled Tasks enumerator skips files over
  1 MB under `\Tasks` instead of reading them whole into memory.
- **Connection-table TOCTOU**: `GetExtendedTcpTable/UdpTable` retries on
  `ERROR_INSUFFICIENT_BUFFER` (table grew between the size and fill calls) instead of
  silently returning zero connections.
- **Fewer false positives**: IPv4/IPv6 multicast (SSDP, mDNS), broadcast and
  `0.0.0.0/8` destinations are no longer classified as external.
- CLI: `--help` now documents `dns --watch`; `all` includes the certificate audit.

### Hosts, hosts-file hijack / AV-block detection
- `HostsReader` parses the Windows hosts file and flags the two malware patterns: an
  entry redirecting a hostname to a non-sink external address (phishing/MITM hijack),
  or one blackholing a security/update domain (AV / Windows Update block). Benign
  ad/tracker sink entries (`0.0.0.0`/`127.0.0.1`) are left unflagged. New `winsight
  hosts` subcommand, included in `all`. Parsing is a pure static, unit-tested; the
  real-file read is smoke-tested. Read-only.

### Persistence, screensaver hijack (SCRNSAVE.EXE)
- `ScreensaverEnumerator` surfaces the per-user screensaver executable (a `.scr` is
  just a PE Windows runs on idle, MITRE T1546.002). Reads `SCRNSAVE.EXE` from
  `HKCU\Control Panel\Desktop` and its Group Policy twin, each signature-checked. 17
  autostart surfaces now.

### Certificates, trusted-root store audit (rogue-CA detection)
- `CertStoreAuditor` reads the machine + user trusted-root stores (`X509Store`,
  read-only) and flags rogue-CA signals: a trusted root that holds a **private key**
  (arbitrary trusted certs can be minted locally, Superfish/eDellRoot class), a
  **weak signature** (SHA-1/MD5/MD2) or an **undersized RSA key** (<2048-bit). New
  `winsight certs` subcommand. Risk classification is pure and unit-tested; a Windows
  integration test asserts the real store read returns well-formed roots. Read-only.

### Extensions, browser extension audit (supply-chain)
- `ExtensionScanner` reads the Chromium-family profiles (Chrome, Edge, Brave, Vivaldi,
  Opera) for installed extensions and parses each manifest, name (with `__MSG_`
  locale resolution), version and declared permissions/host_permissions. Extensions
  declaring broad-reach permissions (`<all_urls>`, `tabs`, `webRequest`, `cookies`,
  `nativeMessaging`, `debugger`, `scripting`, wildcard hosts, …) are flagged high-risk.
  New `winsight extensions` (alias `ext`) subcommand, included in `all`. Read-only,
  roots injectable so parsing is unit-tested against a fixture (no browser needed).

### Modules, loaded-DLL audit (injection / side-load detection)
- `ModuleLister` enumerates the DLLs loaded into every accessible running process
  (System.Diagnostics) and batch-verifies each distinct module's Authenticode
  signature through the shared verifier. Unsigned or untrusted DLLs loaded into a
  running process, the classic injection / search-order-hijack signal, are reported
  as notable; the summary carries the totals (loaded modules across N processes, M
  unsigned). New `winsight modules` (alias `dll`) subcommand. Processes that can't be
  opened (protected, cross-bitness, exited) are skipped, never guessed. Read-only.

### Processes, running-process viewer (TaskExplorer-class)
- `ProcessLister` snapshots every running process via `Win32_Process` (System.Management):
  pid, name, full image path, parent pid and command line, then batch-verifies each
  distinct image's Authenticode signature through the shared verifier, so unsigned or
  untrusted running code surfaces as notable. New `winsight processes` (alias `ps`)
  subcommand; `--flagged` shows only unsigned/untrusted images, `--json` for the GUI.
  Read-only, no admin needed for the basics. Integration test asserts a non-empty,
  well-formed snapshot (incl. the test process) and honours the injected verifier.

### DNS, real-time ETW watch
- `DnsEtwWatcher` opens an ETW session on Microsoft-Windows-DNS-Client for live DNS
  visibility: `winsight dns --watch` prints every name a process resolves as it
  happens, complementing the one-shot cache reader. Requires Administrator (ETW
  session); the session stops cleanly on Ctrl+C and a clear message is shown when not
  elevated. Adds the `Microsoft.Diagnostics.Tracing.TraceEvent` dependency.

### Signatures, native WinVerifyTrust (perf, tamper)
- `NativeSignatureVerifier` verifies the embedded Authenticode signature via
  WinVerifyTrust (native, no process spawn), fast, and detects tampering directly.
  Files with no embedded signature (catalog-signed OS binaries) defer to the
  catalog-aware `AuthenticodeVerifier`; any native failure defers too, so a verdict is
  never fabricated. Wired as the default (behind the cache). Uses only the stable
  WINTRUST struct layouts; `MapResult` unit-tested + the native->catalog chain covered
  by a Windows integration test.

### Reputation, opt-in VirusTotal
- Optional VirusTotal file-reputation for flagged persistence items: set
  `WINSIGHT_VT_KEY` (your own API key) and each flagged, resolvable binary is SHA-256
  hashed and looked up (capped for rate limits), malicious/total counts + a report
  link in text and `--json`. STRICTLY opt-in and the ONLY network call; without a key
  WinSight stays 100% local. `HashUtil` + `VirusTotalClient` (ParseStats unit-tested).

### Performance, shared signature-verdict cache
- `CachingSignatureVerifier` (decorator) caches verdicts by path + last-write time and
  is shared across tools, so the same system binaries checked by persistence and
  connections in one `winsight all` run are verified once; cache auto-invalidates on
  file change.

### Persistence, AppCertDLLs + time providers
- `AppCertDllsEnumerator` (DLLs injected into processes that call CreateProcess/etc.,
  MITRE T1546.009) and `TimeProviderEnumerator` (W32Time provider DllNames). 16
  autostart surfaces now.

### Persistence, COM hijacking (HKCU CLSID)
- `ComHijackEnumerator` surfaces per-user COM server registrations
  (HKCU\Software\Classes\CLSID\{clsid}\InprocServer32), COM hijacking (MITRE
  T1546.015). HKCU-scoped for high signal (vs the thousands of legit HKLM system
  CLSIDs). 14 autostart surfaces now.

### Persistence, print monitors + netsh helpers
- `PrintMonitorEnumerator` (spooler-loaded Driver DLLs, run as SYSTEM) and
  `NetshHelperEnumerator` (DLLs loaded when netsh runs), two more classic ASEPs.
  13 autostart surfaces now.

### Persistence, LSA packages + System32 module resolution
- `LsaPackagesEnumerator` surfaces LSA Security/Authentication/Notification packages
  (DLLs loaded into LSASS, a classic SSP / password-filter persistence + credential
  theft vector). `CommandLine.ExtractExecutable` now resolves bare module names
  against System32 (adding `.dll`), so LSA/AppInit/driver DLLs signature-check
  properly. 11 autostart surfaces now.

### Persistence, Startup folders
- `StartupFolderEnumerator` surfaces items in the per-user and all-users Startup
  folders, resolving `.lnk` targets via WScript.Shell (COM, best-effort) so the
  signature check sees the real binary. 10 autostart surfaces now.

### Firewall, program + ports per rule
- `FirewallRuleReader` now enriches each rule with its bound program
  (MSFT_NetFirewallApplicationFilter) and protocol/ports (MSFT_NetFirewallPortFilter),
  joined by InstanceID, the LuLu-relevant "which app, which ports". Best-effort:
  degrades to name-only if the filters aren't present.

### Firewall, rule viewer (LuLu-class, read-only phase 1)
- `FirewallRuleReader` lists Windows Defender Firewall rules (MSFT_NetFirewallRule
  via System.Management), see what your firewall allows/blocks. New `winsight
  firewall` subcommand. Per-rule program/port enrichment and an enforcing,
  prompt-on-connection firewall are later phases.

### Connections, IPv6 support (audit fix)
- `NativeConnectionReader` now reads the IPv6 TCP/UDP tables (AF_INET6,
  MIB_*6ROW_OWNER_PID) alongside IPv4, and `IsExternal` treats IPv6 ULA (fc00::/7)
  as private. A connection monitor that ignored IPv6 would miss modern C2/exfil.

### DNS, resolver-cache visibility (DNSMonitor-class)
- `DnsCacheReader` surfaces recently resolved domains + answers from the resolver
  cache (MSFT_DNSClientCache via System.Management, managed, no admin, no process
  spawn). New `winsight dns` subcommand, included in `all`. Real-time ETW
  (Microsoft-Windows-DNS-Client) is the future enhancement.

### Persistence, WMI event subscriptions
- `WmiSubscriptionEnumerator` surfaces permanent WMI subscription consumers
  (CommandLine + ActiveScript) from root\subscription, a stealthy, fileless
  persistence technique. Adds the `System.Management` dependency; access-denied /
  missing-namespace degrade to empty (never throws). 9 autostart surfaces now.

### CLI polish
- `winsight --version` and `winsight --help` / `-h`.

## Repo, collaboration & release readiness
- Full GPL-3.0 `LICENSE` text; `CODE_OF_CONDUCT` (Contributor Covenant 2.1),
  `CONTRIBUTING`, `SECURITY` (private vulnerability reporting); issue templates
  (bug/feature) + config, PR template, `CODEOWNERS`, Dependabot (NuGet + Actions),
  `.gitattributes`, README badges. A `release` workflow publishes a self-contained
  `winsight.exe` to a GitHub Release on `v*` tags.

## Phase 1, user-mode tools

### Connections, native IP Helper tables
- `NativeConnectionReader` reads the TCP/UDP tables via GetExtendedTcpTable /
  GetExtendedUdpTable (structured, fast, locale-independent) with owning PIDs,
  replacing the netstat text spawn (kept as a fallback). Endianness/state mapping is
  pure + unit-tested; the real native call is exercised by the connections
  integration test on Windows CI.

### Camera/Mic, real-time monitor (OverSight-class)
- `CameraMicMonitor` raises Activated/Deactivated events the moment an app turns the
  webcam/mic on or off, via a pure unit-tested snapshot Diff over a polling loop
  (driver-free; RegNotifyChangeKeyValue is the future event-driven optimization).
  `winsight av --watch` prints live alerts until Ctrl+C.

### Integration tests, proving each part functions on real Windows
- Integration tests execute the real pipeline on the CI Windows runner: persistence
  scan (registry + signature batch), ConsentStore read, connection snapshot, and
  catalog-signed-binary verification. First proof the blind-authored code FUNCTIONS,
  not just compiles. `AuthenticodeVerifier` now matches PowerShell output back to
  inputs by normalised full path (robust to path-string form differences).

### Signature hardening, catalog-aware Authenticode
- `ISignatureVerifier` abstraction + `AuthenticodeVerifier`: one batched
  `Get-AuthenticodeSignature` per scan, catalog + embedded aware, detects tampering
  (HashMismatch), managed fallback that never throws. Persistence + Connections now
  batch-verify. Fixes false "unsigned" on catalog-signed Windows binaries and the
  signed-then-tampered false negative. Native `WTGetSignatureInfo` kept as a future
  perf swap behind the interface.

### Pro/maintainable foundation + CLI consolidation
- Central Package Management (`Directory.Packages.props`) + `.editorconfig`.
- Collapsed the 3 per-tool CLIs into one signed `winsight` binary with subcommands.
- New `WinSight.Reporting` layer: tool-agnostic report shape rendered as text or a
  stable camelCase `--json` contract (for the future GUI/automation). Tools stay pure
  data producers; presentation lives once in `Cli/Adapters`.

### Module 3, Connections (Netiquette-class)
- Active TCP/UDP snapshot attributed to the owning process + its signature; flags
  external, established connections owned by unsigned/unresolved processes.
  (Interim: `netstat -ano` parse; native `GetExtendedTcpTable` is next.)

### Module 2, Camera/Mic (OverSight-class)
- CapabilityAccessManager ConsentStore reader: which apps used the webcam/mic and
  what is live right now.

### Module 1, Persistence (KnockKnock-class)
- 8 autostart surfaces: Run/RunOnce/RunServices/Policies\Explorer\Run (HKLM+HKCU ×
  64/32-bit), Services & drivers, Winlogon Shell/Userinit, Scheduled Tasks (Tasks
  XML), AppInit_DLLs, IFEO debuggers, Active Setup, BootExecute. Managed Authenticode
  triage (later replaced by the catalog-aware verifier), resilient per-surface scan.

### Bootstrap
- Prior-art check (no unified OSS Objective-See equivalent on Windows), architecture,
  GPL-3.0, GitHub Actions `windows-latest` CI (auto-discovers all projects).
