## v0.11.6, 2026-08-24

- Clarified the dashboard's Windows-security scan so Defender Controlled Folder Access is no
  longer grouped under the misleading "Kernel protections" label. Core isolation, Memory
  integrity, Secure Boot and ransomware folder protection are now described as independent
  controls; a disabled CFA result remains notable when Defender reports the documented mode `0`.
- Made a successful VirusTotal key save close the modal and report the outcome in the main window,
  corrected the French action to "Enregistrer en toute sécurité", and separated the local-analysis
  status dot from translated text so the badge is geometrically centred in every language. The
  resizable settings dialog now separates provider and confirmation actions into two responsive
  rows, preventing translated labels or larger text from clipping the primary action.
- Made WFP ownership crash-safe with one dynamic session, exact startup/teardown reconciliation,
  fail-closed partial-state handling and non-durable `Ask` semantics.
- Hardened the LocalSystem service registration with checked rollback, a service SID, an exact
  required-privilege allowlist and bounded restart recovery; the VM protocol now verifies that SCM
  profile through `QueryServiceConfig2W` and runs 17/35 skip/full checks.
- Replaced PowerShell-based/catalog-blind signature paths with in-process, cache-only WinTrust and
  Windows catalog verification while holding the hashed file open. Inaccessible evidence is now
  `Unknown`; the content-bound cache also refuses to retain a verdict when the file changes during
  verification. Collectors surface unreadable or partial acquisition instead of clean-looking gaps.
  Browser corruption/localization regressions are covered explicitly; the engine is back above the
  enforced 80% per-library floor rather than weakening the gate.
- Kept DPAPI VirusTotal keys out of the process environment, stripped managed keys from product-
  launched children, refused credential-bearing redirects and bounded provider responses/quota
  state. Alert and crash evidence is bounded, corruption-aware and redacts the active key.
- Updated .NET 10 servicing dependencies and hardened releases with read-only build credentials,
  tag-on-main proof, shell-injection-safe tag handling, exact checksum/asset binding and verified
  Inno Setup reuse. Native Arm64 remains CI-only; privileged runtime qualification remains a VM gate.
- Corrected stale installation, signing, WFP, Arm64, privacy and production-readiness documentation;
  historical qualification records remain intact and explicitly candidate-bound.

## v0.11.5, 2026-08-09

Step-by-step progress log. Newest first. Every CI-green step lands here.

- The signed `v0.11.4` tag produced no release. Its x64 release package and native installer gate
  passed, but the Arm64 release launched every test project concurrently. On two attempts, two
  different timing-sensitive tests that were already green on the same native Arm64 runner in PR
  and `main` missed independent five-second rendezvous under testhost contention: first the policy
  store identity-change hook, then a `FileSystemWatcher` notification. Release tests now run one
  project at a time with MSBuild's `--maxcpucount:1`; the assertions and their timeouts remain
  unchanged. The version advances to `0.11.5` instead of moving the published signed tag.

## v0.11.4, 2026-08-09

Step-by-step progress log. Newest first. Every CI-green step lands here.

- The signed `v0.11.3` tag produced no release: its x64 release runner passed the product, PE and
  MCP checks, then found that the installer harness invoked each WPF dashboard smoke test with
  PowerShell's call operator. Windows GUI applications are not reliably waited for by that form, so
  uninstall cleanup raced a still-terminating dashboard and reported its executable as locked. The
  harness now uses `Start-Process -Wait -PassThru` for every language, verifies the concrete exit
  code, and cannot begin uninstall until each dashboard process has exited. The version advances to
  `0.11.4` instead of moving the published signed tag.

## v0.11.3, 2026-08-09

Step-by-step progress log. Newest first. Every CI-green step lands here.

- The signed `v0.11.2` tag produced no release: its x64 release runner exposed a missing
  `TimeoutException` allowance in the hostile peer-storm test while the listener remained healthy;
  the same SHA was green in PR/main, Arm64 release, and the packaged-service VM stress. The test
  already allowed capacity/scheduling rejection during deliberate saturation and asserted recovery
  after drain, but caught only the equivalent `IOException`. It now accepts both peer-local outcomes
  and keeps the post-drain response as the product invariant. The version advances to `0.11.3`
  instead of moving the published signed tag.

### The firewall control channel now reserves capacity for recovery

- A fresh Windows 11 x64 VM stress run found a second peer-controlled failure after the pool work:
  a client could connect and close before the overlapped `WaitForConnectionAsync` completion was
  observed. Windows surfaced that one-instance race as `IOException`; the accept loop treated it as
  systemic, emitted `[FW_PIPE_LISTENER_FAILED]` and stopped the otherwise healthy LocalSystem
  service. The fixed loop creates the failed instance's successor before closing it and continues;
  creation, DACL and configuration failures remain terminal. Failure diagnostics now select one
  fixed redacted category instead of discarding the cause or logging exception text. The failing
  binary stopped in the first hostile round. The corrected binary completed 25 rounds comprising
  150 silent connections, 150 parallel valid clients (25 served and 125 explicitly unavailable
  under deliberate same-privilege lane saturation) and 625 abrupt closes with no listener-failure
  event, then left WFP empty and SCM absent (1060).
- The corrected source was rebuilt as the complete local x64 package, not only as an instrumented
  service. That package passed the native installer lifecycle, MCP, dashboard EN/FR/ES smoke tests,
  protected-path and hostile-account trust gates, WFP contract/pre-arm checks, LocalSystem SCM and
  elevated/restricted IPC. Its packaged service then repeated the same 25-round hostile stress with
  no listener-loss event and cleaned back to empty WFP plus SCM 1060. This remains local pre-publish
  evidence; GitHub CI/release artifacts retain their own immutable gates and attestations.
- Found while qualifying the published v0.11.1 artifact on a clean VM. The dashboard reported
  "firewall service unavailable" while `sc query WinSightFirewall` reported `RUNNING`, the pipe
  existed in the namespace, and every connection attempt returned `ERROR_SEM_TIMEOUT`. A stop and
  start restored it. The state survived for minutes and looked healthy to anything watching the SCM.
- **The cause was one accept instance.** `NamedPipeFirewallServer` created a single
  `NamedPipeServerStream` with `maxNumberOfServerInstances: 1` and served it in a serial loop. A peer
  that connects and then sends nothing holds that instance for the whole request read timeout — five
  seconds — and a peer that reconnects in a loop holds it indefinitely. Unprivileged callers may open
  this pipe by design: they get a read-only capability. So any local user could deny the dashboard
  its control channel, and the service would keep reporting itself Running throughout.
- The first pool correction was insufficient: a local caller could occupy every identical slot, and
  the pool could lose instances independently while the service still appeared healthy. It also
  created readiness before every slot existed and could release the name reservation during repair.
- The listener now owns one accept loop. It claims the name with `FirstPipeInstance`, then creates a
  successor instance before dispatching or disposing each connected predecessor. A startup,
  successor-creation or unexpected request-processing failure is terminal: every accepting and
  connected pipe is closed immediately. Cooperative tasks drain for a fixed bound; a task that
  ignores cancellation is observed in the background after the listener's two-second drain. The
  service host takes the fixed `[FW_PIPE_LISTENER_FAILED]` path, requests graceful shutdown and arms
  a dedicated background-thread watchdog. If the process is still alive eight seconds later, it
  invokes `FailFast` with the fixed `[FW_PIPE_WATCHDOG_EXPIRED]` code. This bypasses `ProcessExit`
  handlers and finalizers instead of letting either delay containment. The worker arms the watchdog
  before calling the logger or host lifetime; both diagnostics and graceful stop are best-effort.
  Requested shutdown arms it silently only after the listener has returned: it emits no listener-
  failure diagnostic and does not request host stop again. Normal process exit removes the background
  thread; a stuck privileged teardown still reaches the same hard bound.
- Caller identity is established before admission. Read-only/denied callers and callers allowed to
  mutate machine policy use distinct bounded lanes; read saturation cannot consume the reserved
  mutation lane used by emergency disable. An over-capacity connection is closed immediately without
  reading or writing, so rejection cannot block the accept loop. The current dashboard now sends v3
  only: a zero-byte close is service unavailability and can never trigger a v2/v1 request or mutation.
  The service keeps strict v1/v2 response support only for already-deployed older dashboards. The
  service-side coordinator still serializes every WFP transition.
- Each policy-store instance serializes complete loads and saves. Read handles also share deletion,
  so another process can finish reading the complete previous snapshot while the single writer
  atomically replaces an existing path with Windows `ReplaceFile` semantics; first creation uses a
  non-overwriting move, and replacement never ignores metadata errors. If revalidation reports only
  the stable `IdentityChanged` classification after an old trusted handle opened, the complete load
  is retried from a fresh inspection/handle at most twice. Every ACL, owner, reparse or inspection
  failure — including `IdentityChanged` from the initial inspection — remains immediately fail-closed.
  The coordinator retains its whole-transition writer lock.
- These changes alter the privileged IPC boundary. Earlier IPC VM evidence does not qualify this
  candidate; clean x64 and native Arm64 service/IPC/WFP qualification remains required.

### The service could outlive its own endpoint

- `FirewallServiceWorker` stopped the host when the listener threw, but not when it returned. A
  listener that completed quietly — before readiness, or after announcing itself listening — left
  `ExecuteAsync` returning normally, which does not stop a `BackgroundService` host. The service
  stayed Running with nothing accepting connections.
- Now any exit the shutdown token did not ask for is treated as endpoint loss: it logs
  `[FW_PIPE_LISTENER_FAILED]` and stops the host. Reporting Running while serving nobody is the state
  that makes every caller's timeout look like the caller's fault.
- Pinned by three tests covering the quiet completion before readiness, the accept loop returning
  after readiness, and the mirror case where a requested shutdown must **not** raise the fault path.

### `INSTALLATION.md` prescribed a firewall-service install that cannot succeed

- The document told operators to run `winsight-firewall-service.exe install` from "the install or
  extracted directory". For the default per-user installation under `%LOCALAPPDATA%\Programs\WinSight`
  that command returns `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]` with exit 1 and creates nothing —
  verified on a clean VM against the published artifact.
- The refusal is correct: a LocalSystem service whose binary sits where an unprivileged account can
  rewrite it is a privilege escalation waiting to happen. The documentation was the part that was
  wrong, by describing a path the product deliberately refuses.
- It now states the refusal, shows the exact diagnostic code, and names the two directories that do
  work — the portable ZIP extracted somewhere only administrators can write, or the installer run
  elevated for all users. The per-user install section points forward to it, so the choice is visible
  before the install rather than after the failure.

## v0.11.1, 2026-08-05

An audit pass immediately after v0.11.0 found the defect that release was about, a second time, in
the tool next to the one that was fixed. Shipping the correction rather than holding it, because the
text a client reads to decide what it may ask for is functional surface, not documentation.

### `winsight_overview` described seven of the ten scanners it runs

- The tool named persistence, camera/mic, network, DNS, extensions, hosts and certificates while
  `Adapters.OverviewCommands` runs ten. `input`, `integrity` and `hijack` were absent from the
  description and present in the work.
- **This is worse than the `winsight_scan` drift it sat beside**, because it understates something
  the tool already does. A model summarising "the overview covers X" from this description leaves
  keyboard-interception, code-integrity and hijack findings out of its account of the machine, and
  nothing anywhere signals the omission — the scanner list at least failed loudly, by making five
  scanners unreachable.
- Fixed the way the first one was: by deleting the copy rather than correcting it. The description
  points at the capability catalog, which marks which scanners are in the overview and is already
  pinned to the dispatcher by a test. A list that cannot be written twice cannot drift.
- **The lesson is the miss, not the fix.** v0.11.0 corrected the instance that was reported without
  sweeping the class, and the second instance was three lines away.

### Smaller corrections from the same pass

- `--help` documents **18** verbs and `README.md` claimed 17. Corrected, and pinned by a test that
  names the README as the thing to update, so the next verb added fails loudly instead of quietly
  widening the gap.
- The prompt bodies and `winsight_process`'s argument guards were reachable only through the
  protocol integration test, which spawns the real server at a 100-second per-response budget. That
  test proves the wire format and is worth its cost; it is the wrong sole guardian of a string
  constant and an input check. Both are now pinned in-process, in milliseconds.
- Measured while auditing, because the command-line rule had been reasoned about and not timed: the
  persistence scan is unchanged. v0.10.3 ran 45.1 s and 43.6 s on the same machine, v0.11.0 ran
  49.9 s and 41.3 s — overlapping ranges, with the cost dominated by Authenticode verification
  rather than by string matching.

## v0.11.0, 2026-08-05

Persistence stops trusting a signature to answer a question the signature was never asked, and the
MCP surface stops advertising a third of itself out of a stale sentence.

### Scheduled tasks reported the interpreter and threw away the payload

- An Exec action stores the program in `<Command>` and what it is told to run in `<Arguments>`. The
  parser read the first and discarded the second, so a task invoking
  `rundll32.exe C:\Users\…\AppData\Roaming\evil.dll,Start` was recorded as `rundll32.exe`: a
  Microsoft binary, a valid signature, an unremarkable row, and the DLL it loads appearing **nowhere
  in the report**. The surface most used for modern persistence was the one producing the least
  evidence.
- Measured on a real desktop after the fix: **58 of 81** scheduled-task entries carry arguments.
  None of them was visible before. Of the 15 autostart entries that resolve to an interpreter,
  12 were scheduled tasks, and all 12 had an empty command line.
- **The one test covering this parser had the defect written into it.** Its fixture already
  contained `<Arguments>/A</Arguments>` and it asserted the value that dropped them, so the bug was
  certified as the contract. That is the more useful half of this entry: the parser was not
  untested, it was tested wrong.
- Pairing is done through each `Command` element's own parent rather than by matching `Exec`
  elements, so the flat descendant search that made this robust against unexpected nesting is kept:
  a `Command` somewhere unforeseen still yields its command, simply without arguments, rather than
  vanishing. Persistence identity is keyed on the resolved target, never the raw command, so
  Guardian does not see 58 entries change underneath it on first run.

### A valid signature no longer clears the command line

- Every persistence verdict was a fact about a **file** — is it there, is it signed, does the
  signature stand — which is blind by construction to the technique that dominates Windows
  persistence, because the file is genuinely Microsoft's and genuinely signed. A Run key holding
  `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval(…)` resolved to
  `C:\Windows\System32\rundll32.exe`, verified as `SignatureValid`, and was reported as routine.
- Such an entry is now flagged and carries `commandLineConcern` — `RemotePayload`,
  `PerUserPayload`, `EncodedCommand` or `ScriptletCom` — **beside** its unchanged status, never
  instead of it. Reporting only the signature reads as an all-clear on exactly the entries this
  exists to catch.
- **The gate is the interpreter, not the pattern.** Ordinary software passes profile paths and URLs
  on its command line all day; what is not ordinary is a program whose whole purpose is to execute
  what it is handed being pointed at a per-user location, at the network, or at an encoded body.
  Requiring both halves is what keeps this quiet.
- **Measured before it was written, and again after.** 4 351 autostart items, 15 resolving to an
  interpreter, **zero findings** — total and notable counts unchanged. Zero is the intended shape on
  a healthy machine and the reason the rule has tests that make it fire against synthetic entries: a
  silent detector and a broken one are indistinguishable from outside.
- It performs **no I/O**. It runs inside `IsSuspicious`, which is evaluated repeatedly while a
  report is built, so it is a pure function over two strings and can neither block a scan nor throw
  into one. The consequence is stated rather than hidden: it claims "runs from a per-user location",
  never "that directory is writable", which would mean asking the filesystem.
- Hidden-window and no-profile switches are deliberately **not** sufficient on their own, and a
  payload assembled at runtime is out of reach of static analysis. Both are recorded as limits in
  [`docs/DETECTIONS.md`](docs/DETECTIONS.md) rather than implied away.
- **Three separate surfaces render a persistence verdict, and flagging the entry only fixed one of
  them.** The report builds its own line, the dashboard rebuilds one from fields in three languages,
  and Guardian's journal builds a third. The last is the one that mattered most: it is the sentence
  an operator reads when they come back to a machine that alerted while they were away, and the one
  `winsight_alerts` hands an MCP client. All three would have announced a notable detection and then
  described it as "signature valid" — an accurate half-sentence that sends the reader back to bed.
  All three now carry the reason beside the verdict, with the dashboard's translated into EN/FR/ES
  and covered by the existing translation-parity gate.

### The MCP surface advertised ten of its fifteen scanners

- `winsight_scan` took a free string whose valid values existed only in its prose description, and
  that description had gone stale: it named ten scanners while the dispatcher accepted fifteen.
  `input`, `integrity`, `drivers`, `hijack` and `presence` were reachable by a client that already
  knew their names and **invisible to one reading the tool schema** — which is how a model decides
  what it may ask for. A whole privilege-escalation scanner could not be discovered.
- This was the same failure the CLI had already had once, where `hijack` shipped wired into
  everything except `--help`. The fix there was to stop maintaining a second copy; this is that fix
  for the protocol surface. The valid values now travel in the JSON Schema as an enumeration, and
  tests pin the published set, the capability catalog and the dispatcher to each other.
- **The first attempt at the fix introduced the same class of bug in the opposite direction, and
  probing the running server is what caught it.** Relying on a camel-case policy passed to the
  converter's constructor produced a schema advertising `"Persistence"` while
  `winsight_get_capabilities` answered `"persistence"` — a client following the catalog would have
  sent a value its own schema rejected. Naming every member explicitly is the only form both the
  exporter and the converter read, and a round-trip test now asserts that rather than trusting it.

### `winsight_process` gives an AI client the pivot it was missing

- The per-process drill-down existed and was reachable only from the CLI. An MCP client that saw a
  flagged outbound connection had to re-run the processes, modules and connections scanners and join
  them by hand — slow, and the join is where the mistakes are.
- It shares the single-scan gate rather than taking its own, because it costs what a scan costs: two
  full signature-verification passes running beside each other is not an improvement.
- A pid that is not running answers "not running", which is a different answer from a process that
  is running and has nothing notable. `pid 0` is refused rather than described, because the System
  Idle Process has no image and "not running" about it would be false.

### Prompts and a verdict model, for the answers that are wrong in a way nobody can see

- The server published no prompts at all. It now publishes two, `winsight_triage_machine` and
  `winsight_explain_alert`, each encoding a failure whose output reads as a confident, well-formed
  answer: reporting traffic as blocked when nothing is filtering, and reporting "nobody knows who
  wrote this" when the truth is "WinSight was not allowed to look".
- Server instructions already carry those rules, but instructions are advisory context a model may
  compress or lose behind a long conversation. A prompt is chosen by the user at the moment they
  ask, which puts the rule in the same turn as the request.
- `winsight://verdict-model` joins the two existing resources. It states the distinctions where the
  accurate reading and the natural-sounding one differ and the natural-sounding one is the stronger
  claim — chiefly that `FileMissing` means the signature was **never checked** rather than that the
  file is unsigned.
- The packaged-installer contract, which runs on native x64 and native Arm64, now asserts the
  published scanner enumeration, the absent-pid answer, both prompts and all three resources.

### v0.10.7 - the AI surface can see the whole tool, and speaks the current protocol
- **What a user of v0.10.6 gains.** An MCP client asking about this machine could reach fifteen
  scanners and the detection journal, and was blind to WinSight's own outbound firewall: not whether
  it was armed, not which applications were blocked, not which ones had reached the network before
  anyone ruled on them. That is now readable, read-only, with the two states that matter kept apart
  so a client cannot report traffic as blocked while nothing is being filtered.
- The server also speaks the current `2026-07-28` specification revision without dropping clients on
  older ones, which the previous release could not do.
- **What did not change.** No new capability, no new privilege, no listening socket. The one channel
  the MCP process opens is declared in its capability document and its security model.
- **Still not production-ready, and the verdict has not moved.** The WFP/SCM qualification is bound
  to commit `3ad4b92` and has not been re-run against this candidate, the privileged Arm64 gates
  remain `NOT_RUN` for want of hardware, and this release is unsigned under the explicit policy dated
  2026-07-30. Windows will show an unknown publisher. The checksums and GitHub attestations prove
  where the bytes came from; they do not give the operating system a publisher to trust.

### A scanner test measured machine churn instead of the filter it named
- `TheFlaggedViewNeverExceedsTheFullOne` ran each scanner twice and compared the counts. A machine
  moves between two scans, so a runner reported `modules: flagged returned 133 of 113` because
  processes started while the two ran. Nothing was wrong with the product.
- It was **vacuous exactly where it failed**: `modules` ignores `--flagged` outright, since an
  unsigned module loaded into a running process is never routine, so the two runs differed only by
  elapsed time. A red result there could never have meant what the failure message claimed.
- It now takes one observation and asserts what `--flagged` actually promises: every item in a
  flagged report is notable, and the header agrees with the body. That holds on any machine and
  catches the leak the count comparison never could, an `Info` item surviving the filter. Verified
  against all fifteen scanners on a live machine before the assertion was written.

### The outbound firewall's posture is visible to MCP clients
- An AI client asking "what is the security posture of this machine" could reach all fifteen scanners
  and the detection journal, and could not see **WinSight's own outbound firewall** at all: not whether
  it is armed, not which applications are blocked, not which ones reached the network before anyone
  ruled on them. `winsight_outbound_firewall` closes that gap.
- **It reports two states, and refuses to merge them.** `mode` is what an operator requested;
  `effectiveState` is what is running. A client that reads only the first would tell a user their
  traffic is blocked while `Degraded` means enforcement was requested and nothing is being filtered.
  The tool description, the server instructions and a test each pin that separation.
- **Unreachable is not "off".** When the service cannot be contacted the answer is that WinSight could
  not verify it, never that outbound filtering is disabled, because a client will repeat whichever one
  it is given as fact. A read that times out raises an error rather than returning a posture.
- **The one channel this process opens is now declared rather than implied.** The MCP process talks to
  the firewall service over its authenticated named pipe, sending status and list commands only. The
  service authorises by Windows identity and refuses every mutation to an unelevated caller, so the
  MCP process has exactly the reach an unelevated dashboard has. Inside WinSight the tool holds a
  posture-only interface instead of the service gateway, so read-only does not depend on nobody adding
  the wrong call later. The capability document gained `firewallServiceIpc` and moved to schema 1.1.
- Posture evidence goes through the same projector as every scanner, so profile paths are redacted
  unless the server was launched with `WINSIGHT_MCP_ALLOW_SENSITIVE=1`. Posture reads take their own
  queue rather than sharing the scan gate, so the cheapest question on the server is not stuck behind
  a ninety-second scan.
- **Verified honestly.** The unreachable path is exercised end-to-end over the real protocol, in the
  packaged-installer contract on x64 and Arm64. The armed, degraded and audit-only paths are covered
  through an injected reader; confirming them against a live privileged service belongs to the VM
  qualification, which has not been re-run against this candidate.

### The MCP surface speaks the 2026-07-28 revision without losing older clients
- The published documentation still described a pinned `2025-11-25` on SDK 1.4.1 and called
  `2026-07-28` an unshipped release candidate. Both statements were stale on `main`; `docs/MCP.md` now
  matches what the server actually does.

### v0.10.6 - the first release under the explicit unsigned policy
- **SignPath Foundation declined the application on 2026-07-29.** The reason was visibility, not
  quality: the programme requires established public trust signals - stars, forks, contributors,
  external references - and this project does not have them yet. That is a fair reading of a young
  repository, and it is recorded here rather than paraphrased away.
- The per-release waiver model is **retired**, not renewed. Two waivers had already been granted and
  the second was written as the last; a third would have made "one release only" meaningless. What
  replaces it is an explicit, dated repository policy: releases are unsigned, `REQUIRE_SIGNED_RELEASE`
  is `false`, and the workflow refuses any value other than an explicit `true` or `false` so the
  posture can never be ambiguous. `-DisableSignature` makes an accidental signature impossible even if
  stale secrets survive somewhere, and it is mutually exclusive with `-RequireSignature`.
- **Windows will show an unknown publisher, and every surface says so.** This is a real limitation of
  the product, not a footnote: the checksums and GitHub attestations prove where the bytes came from,
  they do not give the operating system a publisher to trust.
- **What v0.10.5 users gain.** That release reports an unknown antivirus state as fact - "nothing is
  scanning" from data that established nothing. This release replaces that with Microsoft's documented
  Security Center interfaces and keeps indeterminate states indeterminate. For a tool whose only job
  is to tell the truth about a machine, that is the reason to ship rather than wait.
- Also carried: the ETW session lifecycle hardening, the Controlled Folder Access contract measured
  against the canonical antivirus item, native Arm64 test coverage on every pull request, and the
  removal of blocking disk I/O from the ETW trace callback.
- **Still not production-ready, and the verdict has not moved.** The WFP/SCM qualification must be
  re-run against this candidate, the privileged Arm64 gates remain `NOT_RUN` for want of hardware, and
  an unsigned release closes no signing gate.

### ETW observers survive quota and orphan-session failures

- Attribution, outbound observation and DNS now share a conservative ETW session lifecycle.
  Versioned PID/process-start names prevent PID reuse from becoming ownership evidence,
  `NoRestartOnCreate` preserves concurrent live observers, and only exact proven WinSight orphans
  are explicitly stopped.
- Non-catastrophic ETW failures are contained at the dashboard, firewall-service and CLI boundaries.
  Resource exhaustion such as `0x800705AA` degrades observation with a stable redacted reason
  instead of terminating the elevated dashboard or the LocalSystem service.
- VM qualification is candidate-bound and fail-closed for flat artifacts, native architecture,
  integrity exit 1, AuditOnly IPC and abrupt-termination ETW recovery. Window Close is tested as
  tray hide; tray Exit is the normal cleanup path.

### Antivirus posture no longer invents certainty from an undocumented state word
- Production inventory now uses Microsoft's documented `IWSCProductList`/`IWscProduct` COM
  interfaces with the antivirus provider only. The former `root\SecurityCenter2` `productState`
  decoder remains a compatibility helper but is no longer an acquisition truth source.
- `On`, `Off`, `Snoozed` and `Expired` are distinct. Future activity/signature values remain
  `Unknown`, preserve their raw integers in explicitly named COM properties, and produce explicit
  notable indeterminate concerns. The legacy public WMI `RawProductState` word retains its original
  meaning and sentinel rather than being silently repurposed.
  An unknown activity no longer means “nothing is scanning”, and an unknown signature no longer
  means “definitions are out of date”.
- Vendor-controlled display names are collapsed to one line, bounded to 256 UTF-16 code units and
  replaced with an explicit unnamed-product placeholder when blank. Inspection itself is bounded;
  invalid UTF-16 and Unicode format/bidirectional controls are removed. Indexed name/state fields
  replace delimiter-based associations, so a vendor name cannot forge another state entry.
- The real COM call sequence now crosses injectable elemental list/product wrappers, and caller
  cancellation reaches both Security Center and Controlled Folder Access. Dashboard AV/CFA details
  are reconstructed from structured fields through equivalent EN/FR/ES resources.
- This correction does not promote v0.10.5: that historical release remains unsigned and not
  production-ready. SignPath/AuthentiCode, exact-candidate CI/CodeQL/package, current-candidate x64
  WFP/SCM, privileged Arm64 and remaining session gates stay open.

### The SYSTEM component's coverage bar is 80%, same as everything else
- **54% was an average of two incomparable things.** Split, the privileged assembly reads: hand-written
  policy logic **827/905 lines (91.4%)**, and a native boundary - P/Invoke marshalling into
  `fwpuclnt.dll` and `advapi32`, WFP provisioning, SCM installation, the process entry point - at
  roughly 12%. Averaging them produced a number that justified a 54% ratchet on a component that was
  in fact better covered than most engine libraries.
- The gate now measures the half where a percentage means something and holds it to **the same 80% as
  the engine libraries**. The native boundary is excluded on a stated ground: the VM protocol in
  `docs/validation/VM_QUALIFICATION_KIT.md` qualifies it, which is evidence of a different kind rather
  than an absence of evidence. Excluding a file is a claim that something else covers it; if that stops
  being true, the exclusion is the bug, and the script says so.
- **The first cut of that split was wrong and the data caught it.** It read 79.8% - two lines under the
  bar - because the exclusion list named the hand-written native files but not `LibraryImports.g.cs`,
  the 144 lines of P/Invoke marshalling stubs the `[LibraryImport]` generator emits. Those are the same
  boundary, just generated rather than typed. Lowering the bar by 0.2% would have been precisely the
  metric-gaming this project avoids; excluding generator output is the honest fix, because holding
  hand-written tests against emitted code measures the generator.

### The WFP qualification record needs a re-run, and the change that caused it was ours
- `docs/validation/README.md` now records that the WFP enforcement / SCM lifecycle gate binds to
  `f0a3f16` and that its surface has since changed - because the host-disposal and
  `EnforcementCoordinator` fixes landed inside exactly what those 25 checks exercise. The protocol
  already demanded a candidate-aware delta review; this is that review, written down rather than
  assumed.
- Measured, not assumed, for the other two: the IPC surface is unchanged since `c9177cd` and
  `src/WinSight.Firewall/` unchanged since `f84ac36`, so those records still qualify their candidates.

### Blocking file I/O removed from the ETW trace callback, and the SYSTEM component given a floor
- **The outbound observer read the policy file on the ETW trace thread.** `OnConnection` runs in the
  kernel session's `TcpIpConnect` callback, and every five seconds it called
  `LoadOrAuditAsync().GetAwaiter().GetResult()` - synchronous disk I/O, on that thread. A real-time
  ETW session **drops events when its consumer is slow**, so the firewall observer risked losing the
  very connections it exists to record. The surrounding comments already claimed I/O was kept off
  that path; now it is. `Ruled()` never touches the disk: the snapshot is primed at service start,
  refreshed on a pool thread when stale, and read with a `Volatile.Read`.
- The refresh is **tracked, not fired and forgotten**. A background file read that outlives the
  service races its own store during teardown - which surfaced immediately as a test failing to
  delete its own directory. `StopAsync` now awaits the reload in flight.
- **`EnforcementCoordinator` no longer implements `IDisposable`.** Its teardown is asynchronous, and
  the synchronous bridge was `DisposeAsync().AsTask().GetAwaiter().GetResult()` - the sync-over-async
  pattern this project's own standards forbid, on the shutdown path of a SYSTEM service. Removing it
  made the compiler find the one caller that was taking it, in the privileged status path. A
  synchronous entry point that can only be implemented by blocking is not a convenience.
- **The service host was never disposed at all.** `RunAsync()` starts and stops a host; it does not
  dispose it, so the WFP engine handle was left to process exit. Teardown is now explicit and
  asynchronous - required, not preferred, since a provider refuses to dispose an `IAsyncDisposable`-only
  singleton synchronously.
- **The coverage floor protected the inverse of the risk.** Pure detection libraries - the ones that
  cannot break anything - were held to 80%, while the only component that runs as SYSTEM and drives
  WFP had no floor at all. It cannot meet 80% today (54.5%: much of it is P/Invoke and service
  lifecycle only a privileged VM exercises), so it gets a **ratchet** pinned just under the measured
  figure. Coverage can no longer regress there, and raising the number is the point.
- Pinned by a test that fails on wall-clock: 200 stale-snapshot connections must complete in under two
  seconds, which they cannot if the callback is waiting on the store again.

### Arm64 is tested before a tag, not after one
- **CI tested only x64.** `package` built an Arm64 installer without ever running a test on that
  architecture, so the only Arm64 test run in the entire project happened inside `release.yml`, after
  a tag had been pushed. On 2026-07-27 that is precisely where a thread-pool starvation defect
  surfaced and failed a release build - a defect no pull request could have caught, because no pull
  request ever ran a test on Arm64. Finding it at tag time is finding it at the worst possible time.
- `verify` now has a third leg on native **`windows-11-arm`**, running the full suite and the coverage
  floor on every pull request. The SDK architecture is matrix-driven rather than hardcoded `x64`:
  installing an x64 SDK on the Arm64 runner would have silently tested the emulated target and proved
  nothing about native Arm64. The job timeout moved to 45 minutes, sized for the slower runner.
- The `build-test` gate needs no change to enforce it - it requires the whole `verify` matrix, which
  is the reason it exists as a gate rather than as individually required legs.
- **A deterministic guard replaces a symptom.** The end-to-end camera/microphone test saw the
  starvation only as an occasional timeout, which reads as flakiness and invites a re-run - the exact
  mechanism by which a real regression eventually gets waved through. There is now an assertion on the
  property itself: the watch loop must not be running on a thread-pool thread.
- **Pinning a label is not pinning an image, and `RELEASE.md` now says so.** GitHub migrated both
  `windows-latest` and `windows-2025` to a Visual Studio 2026 image in June 2026, and hosted images
  are re-cut weekly regardless; `windows-2025` is a slowly moving target, not a frozen one. No
  immutable hosted-image label exists, so the mitigation is evidence rather than a stronger pin: every
  release build job now records `ImageOS` and `ImageVersion` in the run summary, which turns "built on
  windows-2025" into an exact image a future reader can pin a behavioural difference to.
- Arm64 claims in `ARM64_VALIDATION.md` and `PRODUCTION_READINESS.md` updated to say exactly this much
  and no more: unit tests on native Arm64 are now per-pull-request evidence, and they still do not
  promote any privileged runtime gate.

### v0.10.5 public unsigned-release waiver
- A second public **unsigned** release was explicitly authorized on 2026-07-27. No production
  Authenticode certificate is configured, so the release triggers the normal Windows
  unknown-publisher warning, and this is stated on the download page rather than left to be
  discovered at that warning.
- **The first waiver said "one release only". This is the second, so the pattern is recorded as a
  pattern rather than as another exception.** The trade was: v0.10.5 carries three user-affecting
  corrections, v0.10.4 already shipped unsigned so this is not a regression in posture, and the
  SignPath Foundation application was still unanswered. Withholding the fixes was judged the larger
  harm. `docs/RELEASE.md` carries the full reasoning and states that the waiver expires with v0.10.5.
- `REQUIRE_SIGNED_RELEASE` is opened deliberately for the tagged build and set back to `true`
  immediately after publication - a gate that fails closed, opened briefly, then closed again.
- This exception neither exercises nor establishes the signed Authenticode production chain, and does
  not change the recorded production-readiness verdict.

### WinSight now knows what is protecting the machine, not just whether Microsoft won
- **The tool was Defender-shaped.** It could report Microsoft Defender's Controlled Folder Access
  posture and nothing else, so on a machine protected by Norton, Bitdefender or CrowdStrike it said
  "the ransomware shield is not protecting you" and said nothing at all about the product that actually
  was. Every word of that was true and the impression it left was false - which this project treats as
  worse than silence, and which is exactly the failure it audits other tools for.
- **`root\SecurityCenter2` is the vendor-neutral answer.** Every antivirus that wants Windows to stop
  nagging registers there, so Security Center is the one place that knows what is really running. The
  `integrity` scan now reports every registered product, which of them report themselves as actively
  scanning, and whether their definitions are current. Nothing scanning, or every scanner reporting
  stale definitions, is `Notable`.
- **The CFA verdict is now reported in that light.** When another antivirus is actively scanning, the
  Controlled Folder Access line names it and says this is a normal configuration rather than a fault -
  while stating plainly that WinSight cannot read that product's own ransomware protection, so the
  operator should confirm it is switched on. On a machine with nothing scanning at all, the wording
  stays as blunt as it was.
- **The `productState` encoding is undocumented by Microsoft, and is treated as such.** It was verified
  against a live machine before being relied on - Defender, active with current definitions, reports
  `0x061100` - and any byte outside the values this reader knows decodes to `Unknown` rather than being
  rounded to the nearest guess. A tool that reads "probably enabled" out of a byte it does not recognise
  is inventing protection. An undecodable product is still listed, because "something is registered and
  we could not read its state" is information the operator needs; it simply never counts as protection.
- Distinctions held deliberately apart, each with a test: **Security Center unreadable** (the normal
  state on Windows Server, which does not ship it) is not **no antivirus registered**, which is not
  **registered but not scanning**. "Bitdefender" contains "defender", so the Microsoft-product match is
  anchored on the full vendor names and pinned against exactly that trap.

### The binaries now say who made them, and the project says what leaves your machine
- **Every shipped binary reported itself as a filename.** `ProductName`, `CompanyName` and
  `FileDescription` were all the literal string `winsight-dashboard`, with no copyright at all, because
  nothing set them and .NET derives them from the assembly name. That string is what Windows puts in
  front of the user in the UAC prompt, the SmartScreen dialog and Task Manager - so a tool that asks
  people to trust it was introducing itself with a build artifact's filename. Product identity is now
  set centrally, and the three executables describe what they are ("WinSight Dashboard", "WinSight
  Command-Line Scanner", "WinSight Outbound Firewall Service" - the last of which runs as SYSTEM and is
  read by anyone auditing what is privileged on their machine).
- **`PRIVACY.md`**, and it is precise rather than reassuring. "No telemetry" was already true and stated
  in several places, but the project had no single page saying what happens to data - and a blanket "no
  data leaves your machine" would have been **false**: the opt-in VirusTotal integration sends a SHA-256
  to a third party. The policy names that one flow exactly (`GET /api/v3/files/{sha256}`, hash only,
  never file contents, your own API key, DPAPI-encrypted, off until you switch it on) and says plainly
  why a hash is not nothing: a file unique to you has a hash unique to you.
- **`docs/CODE_SIGNING.md`** - who may authorise a signature, what one would and would not prove, and how
  to verify a release without trusting the document. The maintainer is one person holding Author,
  Reviewer and Approver, which is disclosed as a single point of trust rather than dressed up as a
  process: the compensating controls are technical (MFA, signed commits binding the maintainer's own
  account via `enforce_admins`, signing only in CI from a tagged commit, no signing key on any developer
  machine, tag/version agreement enforced by the workflow).
- The README's security section now links both, and states the unsigned status where a downloader will
  actually read it rather than leaving them to discover it at the Windows warning.

### A notification you can click, and a CFA read that works when Defender is not the antivirus
- **Clicking a detection notification did nothing.** The tray balloon named the threat, stayed a few
  seconds, and vanished; `BalloonTipClicked` was never subscribed, so the one gesture every operator
  makes on a security alert - click it - left the app hidden in the tray and the operator hunting for
  the matching entry. Clicking a balloon now opens the dashboard on the **Alerts** view with that exact
  detection selected. The alert is matched by its round-trip journal timestamp, and the window is
  raised even when the entry cannot be matched, so a click is never silently ignored.
- **The Controlled Folder Access posture read "unavailable" on ordinary machines.** The reader accepted
  only four spellings of Defender's `AMRunningMode` and treated anything else as a provider it could not
  read. Microsoft documents `Normal`, `Passive`, `Passive Mode`, `SxS Passive Mode`, `EDR Block Mode` and
  `Not running`; the two missing ones are exactly what a machine running a non-Microsoft antivirus
  reports. The commonest non-default configuration therefore rendered as "we could not look" when
  WinSight had looked successfully - the worst way for this reader to be wrong, since it hides the
  machine that has *no* kernel-level ransomware blocker at all behind a shrug.
- `Not running` now reports as a distinct **Defender not running** concern that outranks the configured
  CFA value: Controlled Folder Access is a Defender feature, so with the antivirus stopped no configured
  mode protects anything, and telling the operator to "turn CFA on" would point them at a switch that
  changes nothing. Comparison also tolerates surrounding whitespace. Genuinely undocumented modes still
  read as unavailable rather than being guessed at.
- Pinned by unit tests over every documented mode and by two new green provider-contract fixtures
  (`Not running`, and the `Passive` spelling) plus a red one that rejects `Not running` being reported as
  a plain configured "off"; the PowerShell provider contract carries the same vocabulary as the C# triage.
- **The alerts report had no deterministic test.** All four existing tests read whatever the host
  machine happened to have journalled, so on a clean checkout they passed over an empty list and proved
  nothing - including that the view shows every recorded detection. `Adapters.Alerts` gained an internal
  overload taking the journal path, and the report is now proven to surface all 25 entries of a fixture
  journal, newest first, without writing into the operator's own. The timestamp join the notification
  click selects by is pinned there too: if the adapter ever reformatted that stamp, the click would open
  the app on nothing and no other test would notice.
- A notification clicked **during a scan** no longer hijacks the results grid. The running scan owns the
  grid and assigns it on completion, so navigating over it would show the alert for a moment and then have
  the finishing scan overwrite it - reading as the click being undone. The window still opens, and the
  status line says where the detection is.
- **Release runner images are pinned, not floated.** `release.yml` built on `windows-latest` while
  `ci.yml` deliberately pinned `windows-2025` beside `windows-2022` - backwards, since the release
  pipeline is the one producing the signed, attested binaries a user actually downloads. `windows-latest`
  resolves to `windows-2025` today, so this changes nothing now; it stops the image the release is built
  on from moving on GitHub's schedule to one no CI leg has ever exercised. The release build matrix, the
  publish job, and CI's `package` job - the installer-lifecycle rehearsal for the release, which is only
  a rehearsal while it runs on the image the release uses - are all pinned. No floating Windows label
  remains in either workflow.

### v0.10.4 public unsigned-release waiver
- The user explicitly authorized a public **unsigned** v0.10.4 release on 2026-07-26. No production
  Authenticode certificate is configured, so the release is expected to trigger the normal Windows
  unknown-publisher warning.
- This one-release waiver does not establish the Authenticode production chain or product-wide
  production readiness. It preserves the recorded local `PASS_LOCAL` / global not-production-ready
  distinction and closes no privileged Arm64 or other independent gate.

### The ransomware shield WinSight cannot be: it now reports whether Windows' can
- WinSight's ransomware feature detects an encryption wave with decoys and heuristics, in user mode,
  and by design **cannot block** the write - halting a process mid-encryption needs a signed kernel
  minifilter WinSight does not ship. Windows already has that blocker: Microsoft Defender's
  **Controlled Folder Access** refuses untrusted writes to Documents, Pictures and Desktop at the
  kernel. The gap was that nothing told an operator whether it was switched on - measured on the
  development machine, it was **off**, and WinSight's own detection was the only thing standing there.
- The `integrity` scan (already in the balanced overview) now carries Controlled Folder Access's
  configured and observed operational posture beside driver signing, memory integrity and Secure Boot.
  Disabled, audit and disk-modification-only modes are `Notable`, with the Windows Security deep link
  (`windowsdefender://RansomwareProtection`) for operator review. `Protecting` requires Enabled plus
  Defender `AMRunningMode=Normal`, antivirus enabled and real-time protection enabled; this is not a
  guarantee that every attempted write is blocked.
- **Read-only, and it stays that way.** The posture is read from the Defender WMI provider
  (`MSFT_MpPreference`/`MSFT_MpComputerStatus`, the same source as `Get-MpPreference`), without
  elevation. WinSight reports the setting and points at the Windows control; it never changes Defender
  configuration itself - the operator flips it. This keeps the "everything observes, nothing acts"
  posture: the only WinSight features that write anything remain the opt-in firewall and the ransomware
  decoys.
- Runtime evidence that is passive, disabled, missing or contradictory is never used to infer that a
  third-party product owns protection; it simply does not establish a Defender-protecting posture.
  The provider may refuse the **allowed-applications** list to a non-elevated caller, so that carve-out
  list is marked "requires elevation" rather than shown as empty; malformed or unavailable list data
  makes the overall posture unavailable. A successfully read unsupported CFA mode remains a distinct
  notable unknown mode with its numeric value; a missing or failing provider produces `Unavailable`. Pure
  `ControlledFolderAccessTriage` and the SELECT-only WMI reader (finite enumeration timeout and no
  explicit scope connect) are split for deterministic tests without depending on the host's Defender state.

### The signature requirement now applies to the person who can violate it
- `main` required signed commits and did not get them: three commits from a `--rebase` merge landed
  unsigned. The rule was real, the enforcement was not - `enforce_admins` was false, so branch
  protection exempted the only account able to bypass it. A control that does not bind the one actor
  capable of breaking it is theatre, and this is the audit motif applied to repository configuration
  rather than code.
- `enforce_admins` is now enabled. Normal work is unaffected: branch, pull request, CI, squash merge.
  Only bypassing is blocked.
- **Verified by behaviour, not by reading the setting back.** Reading configuration is exactly the
  weak signal that failed here - `required_signatures` read `true` throughout the period it was not
  enforced. A direct push of a probe commit to `main` was attempted and rejected:
  `Changes must be made through a pull request` and
  `Required status check "build-test" is expected`. The probe was discarded and the tree reset.
- The three unsigned commits stay unsigned, for the reason recorded below. This closes the hole going
  forward rather than rewriting the past over it.

### An index for the validation records, and an honest note on three signatures
- Four validation records existed with no way to see at a glance what was actually proven, against
  which commit. [`docs/validation/README.md`](docs/validation/README.md) indexes them: what is closed
  on x64 with its commit and CI-run binding, what is superseded, and what has not been run. The
  README's qualification paragraph said real SCM, multi-user IPC, DACL and WFP "still requires the
  isolated-VM gates" - that had been true when written and was not any more.
- **Three commits on `main` are unsigned**: `214a25f`, `d5ee120` and `e964779`, from a pull request
  merged with `--rebase`. GitHub replays rebased commits without signing them, and they landed on a
  branch with `required_signatures: true` because `enforce_admins` is false. Every commit before and
  after them verifies; squash merges are signed by GitHub, which is why every later merge is clean.
- They are **deliberately not re-signed**. A signature is part of the commit object, so signing them
  changes their hashes and every descendant hash - including `f0a3f16`, `f84ac36` and `c9177cd`, the
  three commits a real VM actually qualified. Rewriting would either leave the validation records
  pointing at commits no longer in the branch, or require editing those records to hashes that did not
  exist when the VM ran. The second is falsification and the first destroys the binding that makes the
  evidence worth anything. An unsigned-but-honest history beats a signed-but-unverifiable one.
- The rule this establishes: **squash, never rebase**, on this repository.

### The multi-user IPC boundary passed on a real VM: 7 checks, 0 failures
- The authenticated pipe gates capability per caller, proven end to end on a clean VM against candidate
  `c9177cd`, x64. Recorded in
  [`docs/validation/2026-07-23-ipc-boundary-c9177cd.md`](docs/validation/2026-07-23-ipc-boundary-c9177cd.md).
- The elevated console read status and mutated policy over the real pipe (`CanMutate`, `Applied`); a
  SAFER basic-user token via `runas /trustlevel` - password-free, no second account - read status but
  was refused the mutation (`CanReadOnly`, `Unauthorized`). That refused mutation is the whole point:
  an unprivileged caller can look but not touch.
- Closes the multi-user IPC boundary on x64. The unelevated-admin case is covered by proxy (a SAFER
  basic-user token is the same non-admin capability class), and the network-logon deny by the pipe
  DACL unit test; neither is a dedicated live logon here. Native Arm64 remains a separate gate.

### The IPC gate's restricted leg read the output file a beat too early
- On a real VM the elevated leg passed cleanly - `outcome=CanMutate`, `mutation=Applied` over the real
  pipe - but the restricted leg reported three empty observations. The service was fine; the harness
  read too early. `cmd`'s `>` creates the redirect target the instant the command starts, so waiting
  on the output file's existence found it immediately, empty, before the diagnostic under the
  restricted token had written its line.
- Fixed with a separate DONE marker the wrapper writes only after the diagnostic has fully exited; the
  script now waits on that marker, not on the output file. Verified on the host: the wait blocks until
  the restricted process actually finishes (~3s) and then reads the complete line. If the marker never
  appears within the deadline, the script now says so - and names the Secondary Logon service, whose
  absence would stop `runas /trustlevel` - rather than reporting empty tokens.

### A shipped IPC self-test, so the multi-user boundary can be run on a VM
- The multi-user IPC gate had no runnable end-to-end check because only the dashboard ever spoke to
  the pipe. `winsight firewall-ipc-selftest` is a shipped diagnostic that reports what capability the
  authenticated pipe grants the caller's identity, over the real client the dashboard uses, without
  changing machine state. It reads status, and its single mutation probe removes the policy for a
  path that is never a real application - a no-op for an authorized caller, refused before dispatch
  for an unauthorized one - and is skipped entirely when the machine is armed, because a diagnostic
  must never reconcile WFP on a live machine.
- The classification is mutation-verified: removing the armed-machine guard makes the safety test
  fail, and swapping the `Unauthorized -> CanReadOnly` mapping makes the boundary test fail. Five
  unit tests drive the real gateway through a fake client.
- `Test-IpcBoundary.ps1` (VM-only, shipped in the package) runs two passes against one service: the
  elevated console (expected to mutate, or read an armed machine), and the same executable under a
  SAFER basic-user token via `runas /trustlevel` - password-free, no second account. The restricted
  leg is the security-critical one: an unprivileged caller must read status yet be refused the
  mutation (`outcome=CanReadOnly`, `mutation=Unauthorized`). No closures, ASCII, verified under
  Windows PowerShell 5.1 through both `-File` and the call operator.

### The pipe ACL could be widened without any test noticing
- The multi-user IPC boundary rests on the named-pipe DACL (SYSTEM and Administrators full, Interactive
  read/write, Network denied) and on the per-caller capability mapping. The DACL test asserted the
  right principals were *present* with `Assert.Contains`, which stays green even if a broad allow ACE -
  Everyone, Anonymous, Authenticated Users - is *also* added. The control channel could have been
  opened to every local account and nothing would have failed. That is the audit motif applied to the
  test itself: the health signal was structurally unable to see the widening.
- Closed with an allow-list assertion: the only allowed principals are SYSTEM, Administrators and
  Interactive, and a separate test rejects World/Anonymous/AuthenticatedUsers/Network as allow ACEs.
  Proven by mutation - adding `Everyone:FullControl` to the source fails both new tests while the
  original `Assert.Contains` test stayed green, confirming the gap was real.
- The capability mapping was only tested null->false and current->true. Added direct tests: a null
  identity maps to `None` (the fail-closed sentinel), and the current identity maps to exactly the
  capability its elevation earns - `MutateMachinePolicy` for an administrator, `ReadStatus` otherwise,
  never `None`. Mutation-verified on both branches (elevated and non-elevated hosts each catch a
  mis-mapping of the branch they exercise).
- This is the CI-pinnable half of the multi-user IPC gate, bound to every commit. The end-to-end run
  across real elevated/unelevated/standard-user tokens remains a VM gate.

### The corrected trust gate passed on a real VM: 11 checks, 0 failures
- The adversarial service-path trust boundary completed on a clean VM against candidate `f84ac36`,
  bound to CI run `30032903041`. Recorded in
  [`docs/validation/2026-07-23-trust-boundary-f84ac36.md`](docs/validation/2026-07-23-trust-boundary-f84ac36.md).
- Every hostile state returned its correct typed code: user-writable leaf, missing component,
  TrustedInstaller-owned leaf (`UNTRUSTED_OWNER`, correct by policy), a protected copy (trusted), and
  a reparse point (`REPARSE_POINT`). The 40-iteration ACL-flip race held both properties together -
  never trusted while user-writable, always trusted while protected - so the verdict tracks the real
  security state and never lags into a stale trusted.
- This closes the adversarial trust/TOCTOU boundary on x64, except the explicit foreign-owner-SID
  variant, which needs a standard account via `-HostileAccount`. The owner-trust path is already
  proven by the TrustedInstaller leaf refusal; the remaining variant is one skipped check away.

### The trust gate met a real VM, and the VM broke the test - correctly
- The trust-boundary gate ran on a real VM and reported 5 failures. The service was right on every
  one of them; both defects were in the test harness, which is exactly what an adversarial gate is
  supposed to expose about itself.
- Four failures were output-capture pollution. The refusal is a single `[FW_...]` token written to
  stderr, and Windows PowerShell 5.1 decorates native stderr merged with `2>&1` (`<exe> : ...`,
  `Au caractere ... + $raw = ...`). The script compared the whole decorated capture instead of the
  token. It now extracts the token with a regex, verified on the host to survive the exact decoration
  the VM produced. The VM even surfaced `REPARSE_POINT`, which the host could not reproduce, so that
  case is now asserted to its measured code rather than to "any denial".
- The fifth failure was a meaningless race. It copied user-writable *content* into the *protected*
  root and then treated the trusted verdict as a bug - but the path model evaluates the path's ACLs,
  not where the bytes came from, so a file in a protected directory is correctly trusted. The race is
  rebuilt to flip one file's ACL between "an unprivileged principal can write" and "protected" on
  every iteration, asserting the verdict tracks the real security state and never lags into a stale
  trusted. It uses the well-known `BUILTIN\Users` SID, so it needs no separate account.
- Net: the service passed the adversarial gate on first contact; the gate's own bugs are fixed.

### An adversarial gate for service-path trust
- `scripts/Test-TrustBoundary.ps1` builds the hostile filesystem states CI cannot create - a
  user-writable plant, a missing component, a TrustedInstaller-owned leaf, a reparse point inside a
  protected root, a foreign-owned leaf - and drives the candidate's read-only
  `install-path-trust-check` against each. It never installs a service and never touches WFP.
- Two measured results look like defects and are not, so both are documented rather than left to be
  rediscovered: a System32 executable is refused with `UNTRUSTED_OWNER`, because TrustedInstaller is a
  trusted owner for parent directories but never for the leaf binary; and a junction resolves to its
  target, so a junction in a user-writable tree reports `WRITABLE_BY_UNPRIVILEGED` rather than
  `REPARSE_POINT`. Both were established by running the probe, not by reading the policy.
- The race renames the trusted file aside, plants a user-writable one at the same path, probes, and
  restores - repeatedly. Two properties must hold together: the planted file is never reported
  trusted, **and** the honest file still reads trusted every time. Without the second, the first would
  pass for the boring reason that the probe refuses everything.
- Codes not previously measured are recorded rather than asserted, and the script prints which typed
  code fired. Asserting a code nobody has observed would be inventing evidence; the assertion that
  does hold is that the result is one of the eight typed denials with exit 1, never trusted, never
  empty, never a crash.
- No closures. `GetNewClosure()` captures variables but not functions, which is what killed the WFP
  protocol on a real VM. Verified to parse and run under Windows PowerShell 5.1 through both `-File`
  and the call operator before being committed.

### The corrected protocol passed on a real VM: 25 checks, 0 failures
- The full strict protocol completed on a clean Windows VM against candidate `f0a3f16`, bound to CI
  run `30024427883`, using the protocol script shipped inside that same package. Recorded in
  [`docs/validation/2026-07-23-wfp-qualification-f0a3f16.md`](docs/validation/2026-07-23-wfp-qualification-f0a3f16.md).
  This supersedes the historical `18/18` transcript, which stays invalid and stays in the repository.
- What it closes on x64: real SCM lifecycle from empty (`1060`) through install, canonical-candidate
  binding, start, stop and uninstall back to `1060`; the typed path-trust refusal
  `[FW_INSTALL_PATH_WRITABLE_BY_UNPRIVILEGED]`; a read-only WFP open showing 573 existing filters
  changed by nothing; `[FW_DIRECT_MUTATION_DISABLED]` followed by an inventory proving the refusal
  left no partial state; the exact armed inventory; and complete rollback with connectivity restored.
- The line that actually matters is the control leg. While System32 `curl.exe` was blocked (http 000,
  exit 7), an independent Windows PowerShell HTTP request still returned 200. Had that failed too,
  the "per-app block" would have been a machine-wide cut wearing a per-app label.
- One gap in the record, found by reading the transcript rather than the result: the architecture line
  was **empty**, because `RuntimeInformation::OSArchitecture` returned nothing in that 5.1 session.
  So the run establishes x64 *package* behaviour but does not by itself prove the host was native x64
  rather than Arm64 under emulation. The kit now prescribes `Win32_Processor`, which an emulated
  process cannot misreport, and states plainly that `$env:PROCESSOR_ARCHITECTURE` alone cannot satisfy
  the Arm64 gate - an emulated x64 process reports `AMD64` there.

### The qualification protocol died on a real VM while the contract read 24/24
- Run on an actual VM the way an operator runs a script - `& 'C:\...\Test-WfpValidation.ps1'` from an
  open elevated console - the protocol died on its very first output call:
  `Result: 0 checks, 1 failure(s). output operation violated the zero-output contract`, with
  `Invoke-StrictCapture is not recognized` underneath. Every local gate was green at the time.
- Cause: `GetNewClosure()` captures variables, never functions. Under `-File` the script is the
  top-level scope and a closure can still resolve the script's own functions. Invoked with `&` from
  an existing session the script gets a child scope, and every function call inside a closure throws.
  The adapter is built entirely from such closures, so the whole protocol was one invocation style
  away from not running at all. Confirmed with a five-line reproduction before anything was changed.
- Fixed at the five call sites an AST sweep identified, by capturing the function as a scriptblock
  local that the closure can carry. The same sweep now reports zero remaining, and no other script in
  `scripts/` uses closures at all.
- The real defect was the blind spot, not the bug. `-File` was the only mode ever executed, and the
  contract self-test only ever builds *scripted* host effects - `New-RealHostEffects` and the real
  adapter closures were never run by any test. Both gaps are closed: the contract now runs under both
  invocation modes, and a new test drives the real adapter against a candidate path that does not
  exist, so it stops in the precondition block. Every SCM operation lives strictly after that check,
  so it stays safe even on an elevated runner.
- Reintroducing the defect fails both new call-operator cases, and the real-adapter one reproduces the
  VM's output string exactly. The first attempt at that mutation only reverted one of the two sites
  and produced a single failure - a half-applied mutation proves half as much as it appears to.

### Two independent reviews came back, and their findings are closed
- Fresh independent security and quality reviews of the AC85-AC89 candidate both returned PASS_LOCAL
  with no CRITICAL or HIGH finding. Both independently reproduced the two mutations this milestone
  exists for, and both confirmed they now fail. Their remaining findings are closed here.
- The install route caught `InvalidOperationException or Win32Exception` only, while the read-only
  probe beside it caught everything. Tracing the call graph confirms nothing currently throws
  anything else - which is precisely why nobody would have noticed the day something did. The
  failure mode is the CLR printing an exception type, message and stack trace, including the
  executable path, to stderr instead of `[FW_INSTALL_FAILED]`. The filter is gone; five exception
  types that previously escaped are now pinned by test, and they failed before the fix.
- The contract test resolved its shell as "Windows PowerShell 5.1 if present, otherwise `pwsh` off
  ambient PATH". That test exists because 5.1 is where reading an unmarked file as ANSI turned a
  smart quote into an unterminated string, and where `$ErrorActionPreference = 'Stop'` plus `2>&1`
  turned native stderr into a terminating error. Silently running PowerShell 7 instead would have let
  both defects ship behind a green test. Absent 5.1, the test now fails instead of measuring
  something else.
- `FirewallServiceInstallerTests.cs` had grown to 1,521 lines holding six unrelated test classes,
  against an 800-line guideline. Split one class per file, mirroring the production layout. No test
  was changed in the move; the count went 1,489 to 1,494 purely from the five new ones.

### The VM qualification steps are in the repository now, bound to a commit
- Everything CI cannot reach - real SCM, real WFP, real traffic - needs a VM and a human, and the
  instructions for it lived only in an untracked working directory. Nobody outside this machine could
  replay them. `docs/validation/VM_QUALIFICATION_KIT.md` puts them under version control.
- The kit binds the candidate before it downloads anything. The defect that invalidated the previous
  qualification run was that nothing tied the observed behaviour to a known binary, and a protocol
  that qualifies whatever service happens to be installed qualifies nothing. So the first step proves
  the CI run's `head_sha` matches the intended commit. It also warns that the artifact still unpacks
  as `winsight-v0.10.3-win-x64` while being a build of a later commit: the file name is not the
  candidate's identity, and treating it as such is how the wrong binary gets validated.
- The protocol script ships inside the package, built from the same commit as the service binary, so
  the two cannot drift. The kit uses that copy rather than a separate download from `main`.
- Recorded because both have cost real time on a clean VM: Windows PowerShell 5.1 renders
  `Invoke-WebRequest` progress synchronously and makes a 120 MB download look frozen, and a clean VM
  has no `gh` at all.

### The storage trust guard had no coverage at all
- `FirewallStorageTrustGuard` stands between privileged policy storage and the trust inspector, and
  coverage measured it at 0%. Nothing would have noticed if it started failing open. Seventeen tests
  now pin the two properties that make it a guard rather than a pass-through: a lease whose evidence
  it cannot verify fails closed with `InspectionFailed` without ever consulting the inspector, and
  revalidation stays bound to the evidence captured at inspection time. Re-inspecting instead would
  reopen the very TOCTOU window that evidence exists to close.
- Both properties were mutation-checked: returning the caller's own claim on unverifiable evidence
  costs 2 tests, re-inspecting instead of using the bound evidence costs 1. `winsight-firewall-service`
  goes 53.6% to 54.3%, overall production 73.0% to 73.2%. The rest of the uncovered code in that
  assembly is real SCM and WFP P/Invoke, which needs a privileged VM gate rather than more unit tests.

### The qualification protocol was broken on purpose, and one gate had never run
- The previous correction attempt failed review for a reason no green count can surface: two specific
  mutations left every gate passing. Both were re-applied to the new composition and both now fail --
  replacing the real `PollStopped` with a constant costs 8 contract failures, and routing the
  `install-path-trust-check` verb to Install costs 20 of 321 firewall-service tests. Six more
  mutations were run to close the inventory: an ambient `sc.exe` instead of the absolute System32
  path, an absence poll aimed at the wrong service name, uninstall moved above the Stopped poll, and
  a refusal that reaches stdout, exits 0, or collapses the eight denial codes into one. Every one is
  caught. The wrong-service-name mutation is the one worth naming: it makes the post-uninstall check
  report "no service" while a real SYSTEM service is still installed.
- Collapsing the denial codes did not compile at first -- `refusal` became unused and warnings are
  errors here. That is the compiler catching it, not the tests, so the mutation was made compilable
  before being measured. A mutation that cannot build has not been tested.
- The coverage gate had never run on this candidate. There were 22 TRX and no coverage directory
  beside them, so the sequence read as complete while one gate left no artifact at all -- the same
  shape of defect this milestone is about, one level up. It now runs: engine libraries 87.9% with
  every engine at or above 80%, overall production 73.0%. `winsight-firewall-service` is 53.6%, still
  the least-covered assembly of the ones running as SYSTEM, and it is not an engine library so no
  gate holds it to a bar.
- All of this is portable and non-privileged. It closes no native gate, and no independent security
  review, quality review or judgment has run on this candidate.

### WFP qualification now fails closed and binds SCM to the exact candidate
- `Test-WfpValidation.ps1` parses the provider, sublayer and permit-filter fields as one exact
  structured state. Mixed state, a failed native command or an unexpected output shape is failure;
  each native exit code and its normalized output remain visible together. PowerShell converts an
  `ErrorRecord` to its message, collects through `Out-String`, then trims and prefixes lines for
  display; this is normalized presentation rather than the original native byte stream. Path trust
  stages only one user-writable sentinel as data, then calls the protected candidate's
  `install-path-trust-check <sentinel>` command. The staged service/DLL set is never executed or
  loaded. Candidate provenance, protected deployment and immutable dependencies are operator-owned
  prerequisites and are not self-proven by this command.
- A clean snapshot must have no pre-existing WinSight service. After installation, the SCM
  `PathName` must equal the canonical `-ServicePath` plus the `run` verb, and start/query results must
  succeed before any WFP claim is accepted. Any failed pre-arm check or failed connectivity baseline
  forbids the manual arming prompt. Pre-SCM trust denials are typed product outcomes mapped to eight
  fixed `[FW_INSTALL_PATH_*]` codes; unrelated installation/SCM failures remain
  `[FW_INSTALL_FAILED]`, with no exception message or path printed.
- `-SkipEnforcement` means no WFP arming, not no machine changes: it is an isolated-VM mode that
  installs and starts the candidate, then must stop it, uninstall it and prove SCM error 1060 before
  success. The skip path has exactly **16** mandatory checks; the full path has **25**, and the
  normal non-privileged contract self-test passes **24/24**, while its deliberate lifecycle-order
  negative control exits 1. The former 14/14 and the first local report that accepted it are
  permanently invalid, non-qualifying evidence: a diagnostic-plus-false array had cast to true.
  The intermediate 15/15 was a transient development count, not qualification evidence.
- One `New-ValidationAdapter` owns every command, staging operation, lifecycle poll and workflow
  operation. Real and scripted modes inject only elementary host effects. Scripted effects consume
  one closed ordered queue that rejects any unexpected path, argument, order, cardinality or result
  type; they expose no fabricated `PollRunning`, `PollStopped`, `PollAbsent` or other business
  result. The contract matrices drive Running, Stopped and SCM-absent through that production
  adapter, including delayed success, timeout, exact ten-attempt bounds and rollback ordering.
  Strict typed cardinality remains mandatory: effects emit zero success objects and decisions
  exactly one value of the required type.
- Every elevated OS executable is an absolute protected System32 path: `sc.exe`, `curl.exe` and
  `WindowsPowerShell\v1.0\powershell.exe`; ambient `PATH` is never used. System32 curl is the blocked
  target and PowerShell is a separate control, with both baselined before arming and both required to
  recover afterward. Direct-mutation refusal requires exact output/exit 1 and an immediate exact
  absent/absent/absent WFP inventory. Enforcement status, WFP self-test and block-status outputs are
  exact closed shapes, not substring matches.
- One injected bounded poll owns Running, Stopped and SCM-absence transitions. Cleanup never
  uninstalls before Stopped; after an emergency-disable failure, non-AuditOnly result, non-empty WFP
  tuple or unrestored target/control connectivity, uninstall is unreachable and snapshot recovery is
  mandatory.
- The public `FirewallServiceCommandHost.Execute` route now owns parse, routing, arity, fixed
  result mapping and `TextWriter` stdout/stderr selection. `Program` constructs the Windows
  capabilities and calls that route exactly once, then uses its parsed-verb/handled/exit outcome for
  remaining verbs without reparsing. The path probe handler receives only
  `IServicePathTrustInspector` and directly shares Install's inspect/revalidate primitive; it has no
  install, elevation, process-path, SCM or WFP capability. Tests call that same public `Execute`
  route with recording capabilities, and a non-privileged subprocess smoke proves invalid probe
  arity returns the exact inspection-failed stderr/exit 1 without filesystem inspection or machine
  mutation.
- The recorded 2026-07-23 x64 run used script revision `76b5481` and printed **18/18**. It remains a
  useful historical observation of per-app blocking and restoration, but it is not a production
  qualification gate: that script could accept mixed WFP state, skip a failed path probe, hide
  normalized native output and observe a different pre-existing SCM binary. No strict
  candidate-bound x64 or native Arm64 rerun has occurred.

### Path trust now binds the complete cross-filesystem file identity
- Path revalidation now calls `GetFileInformationByHandleEx(FileIdInfo)` through the existing
  no-follow `SafeFileHandle`. Its stable identity contains the 64-bit volume serial and every bit of
  the 128-bit file identifier. A failed or unsupported query denies inspection; there is no legacy
  64-bit fallback and no `Pack = 4` repair of `BY_HANDLE_FILE_INFORMATION`.
- The ABI is explicit and testable: a 16-byte explicit-layout identifier made of two `ulong` values,
  inside a 24-byte sequential `FILE_ID_INFO` whose fields begin at offsets 0 and 8. The fixed-width
  representation carries all **192** identity bits deterministically.
- Exactly **10** non-privileged ABI/real-filesystem tests cover layout, stable reads of an unchanged
  file, simultaneous distinct files and rename-aside/plant detection. A deterministic sentinel
  independently proves the exact 64-bit volume, `Part0` and `Part1` contribution to the stable
  192-bit representation. The tests do not assume that a volume serial is non-zero or that a deleted
  identifier can never be reused. A live adversarial replacement during the in-process
  inspection/SCM window remains an isolated-VM gate.

## v0.10.3, 2026-07-22

Three shipped scripts could not be parsed by the shell a clean Windows opens. Found by someone
running the validation protocol on a real VM, which is the first time anything here met
Windows PowerShell 5.1.

- **An em dash in a comment broke the whole file.** 5.1 reads a `.ps1` with no byte-order mark as
  *ANSI*. A UTF-8 em dash is three bytes ending in `0x94`, which in code page 1252 is a right double
  quotation mark - and PowerShell opens a string on smart quotes. One em dash in a comment therefore
  opened a string that was never closed, and the file failed to parse with an error pointing at an
  unrelated line near the end. `Build-Release.ps1`, `Measure-Coverage.ps1` and, worst of all,
  `Test-WfpValidation.ps1` - the script whose entire purpose is to run on a freshly imaged VM.
- **CI could not have caught this.** Every workflow step runs `shell: pwsh`, and PowerShell 7 reads
  scripts as UTF-8. The class of bug is invisible from there and from any machine where `pwsh` is the
  habit. A test now asserts every shipped script is ASCII-only or carries a BOM, with a second test
  showing the byte that causes the reinterpretation is really produced - so the rule cannot quietly
  stop describing anything. All nine scripts verified to parse under real 5.1.
- ASCII was chosen over adding a BOM: correct under every encoding, every code page and every tool,
  at the cost of a hyphen.
- The deployment step in the protocol now says it needs an elevated console. Writing under
  `Program Files` does, and without it the copy fails per file with `UnauthorizedAccessException`,
  which reads as a broken command rather than a missing privilege.
- Downloading is documented with `curl.exe`, and the `Invoke-WebRequest` alternative now silences the
  progress bar first: 5.1 redraws it on every chunk, and on the 170 MB archive the rendering, not the
  network, is the bottleneck. Measured **4 seconds** against minutes, byte-identical output.

## v0.10.2, 2026-07-22

Packaging, found by someone actually trying to validate a release on a clean VM.

- **The validation protocol and its script now ship inside the archive.** They did not, so exercising
  the one thing CI cannot cover meant fetching the script separately - on a machine that by design
  has no `git` and no `gh`. Shipping them beside the executables also guarantees the protocol and the
  binaries come from the same commit, which fetching from `main` would not.
- **A flaky test blocked this very release.** `TrustedSilentPeer_ReadDeadlineIsFixedTimeout` awaited
  a 150 ms client deadline *before* confirming the server had read the request. On a loaded runner
  the client gave up and tore down the pipe first, so the server's read failed, its signal never
  arrived, and the test failed on a wait rather than on anything it asserts - one leg of the release
  build, while the other three passed. Restructured to match its own sibling two tests below, which
  had the correct shape all along: start the send, confirm the read while it is still in flight, then
  assert the deadline fires. Verified stable over six consecutive runs. A test that fails once in a
  while is worse than one that fails always, because it teaches people to re-run until green.
- **`Build-Release.ps1 -SkipSbom` failed on the first line of a clean shell.** After calling
  `Install-InnoSetup.ps1` - a PowerShell script, which never sets an exit code of its own - it tested
  `$LASTEXITCODE`, so it was reading whichever native command had run last, anywhere. With `-SkipSbom`
  nothing had run at all and StrictMode threw on the unset variable. CI never saw it because
  `dotnet tool restore` runs first and leaves a value behind, masking the bug by ordering. It now
  validates the path it actually depends on.

## v0.10.1, 2026-07-22

Two defects, both found by making the suite do something it had never done: run the product.

- **A driver in a download folder could answer yes to "does Windows ship this?"** The containment
  half of that check was a raw prefix comparison, so `…\System32\..\..\Users\Public\evil.sys` read as
  inside System32 - and a genuinely Microsoft-signed driver loaded from a user-writable folder is the
  bring-your-own-vulnerable-driver case exactly. Not reachable through the shipping scanner, which
  normalises first; fixed anyway, because the rule was safe by a caller's habit rather than its own
  construction, on a public method.
- **Every enabled firewall rule displayed a blank line** - 420 of 420 here. The detail joined the
  rule's program and ports, and a rule naming neither applies to *everything*, so the broadest rules
  on the machine showed the least information. They now read `any program  any port`.

Behind both: the fifteen scanners are now executed end to end by the test suite, on **two different
Windows builds** in CI (Server 2025 and Server 2022). Until this release not one of them had ever
been run by a test - each was proven correct in isolation and none proven to compose.

The WFP exact-shape predicate, which decides whether enforcement reads Active or collapses to
Degraded, is falsified clause by clause instead of being guarded by grepping its own source. That
guard had two clauses missing from its list, and deleting one left it green while the predicate began
accepting a filter that blocks every program *except* the named one.

`scripts/Test-WfpValidation.ps1` executes the VM protocol and prints a verdict per step.

1 395 tests. Engine libraries 87.9%, overall production 72%.

### CI now proves the suite on two different Windows, not one
- Running all fifteen scanners end to end is only worth what the machine underneath it is worth, and
  that was one machine: `windows-latest`, which resolves to **Server 2025**. `windows-2022` is a
  genuinely different build with a different registry layout and a different set of components
  present - the kind of difference a scanner reading a key one of them lacks falls over on.
- **`build-test` keeps its name.** A matrix leg reports as `verify (windows-2022)`, so making the
  matrix itself the required check would mean re-listing every leg in branch protection and
  re-listing them again whenever the matrix changes. `verify` does the work; `build-test` is a gate
  over it that fails unless every leg passed. One stable name outlives whatever runs behind it, and
  adding a Windows is now a one-line change with nothing to touch in repository settings.
- The gate carries `if: always()` deliberately. Without it the job is *skipped* when a leg fails, and
  a skipped required check does not read as a failed one - it sits there neither passing nor
  failing, which is the worst of the three outcomes.
- `fail-fast` is off: when one Windows breaks, the immediately useful question is whether the other
  broke too, and cancelling the sibling throws that answer away.
- Test-result artifacts are matrix-scoped; two legs uploading one name collide.

### Not one scanner had ever been run by the test suite
- Every scanner's rules were tested through its own module with injected seams - the right place for
  them - and **not one scanner was ever executed end to end**. The only adapter that ran was
  `alerts`, which reads a file. Fifteen scanners proven correct in isolation, none proven to compose.
- That gap is the one that matters for "does this work on somebody else's machine". A scanner reads
  registry keys, WMI, event logs and device classes that exist here and may not exist there: Windows
  Home has no Group Policy keys, a server has no camera, Task Scheduler can be disabled, and Windows
  need not be on `C:`. A scripted source cannot see any of it.
- All fifteen now run for real, three ways: the report is coherent (a tool name, a non-empty summary,
  no item without a title or detail, no blank field key), the `--flagged` view is a subset of the
  full one, and the output survives being rendered to JSON **and parsed back**. Every assertion is
  machine-agnostic - never a count, never a specific finding.
- **The point is CI.** Run here they prove little; run on a GitHub runner - different Windows
  edition, different locale, no interactive session, none of this developer's software - they are
  the only evidence the suite has that WinSight works somewhere nobody developed it.
- Cost is about two minutes, dominated by persistence and modules, and close to free in wall-clock
  terms: `build-test` runs beside the longer packaging job.
- `WinSight.Application` coverage 58.4% → **87.9%**; overall production 65.3% → **72%**.

### Every enabled firewall rule displayed a blank line
- Found by the sweep above on its first run: **420 of 420** enabled rules produced an empty detail.
  The line was built by joining the rule's program and ports, and the reader supplies those only for
  rules that scope themselves - so a rule naming neither, which therefore applies to **everything**,
  rendered as nothing at all. The broadest rules on the machine showed the least information.
- They now read `any program  any port`, which is both the truth and the more interesting reading:
  `Inbound/Block, Antigravity - any program  any port` says something; a blank line did not.

### "Windows ships this" could be answered yes for a driver in a download folder
- `IsWindowsProvided` is what removes a driver from the operator's view: signed by the Windows
  identity, chain valid, **and inside System32**. The location half is not a formality - a genuinely
  Microsoft-signed driver running from a user-writable folder is the bring-your-own-vulnerable-driver
  case exactly: real signature, real Microsoft, loaded on purpose for what it lets an attacker do.
- The containment test was a raw prefix comparison, and it failed in **both** directions.
  `C:\Windows\System32\..\..\Users\Public\evil.sys` starts with the System32 prefix while
  demonstrably living in a user-writable folder - so that driver would have been filed as one Windows
  ships and hidden. `C:/Windows/System32/...` and `C:\Windows\.\System32\...` name the same place and
  were rejected, adding in-box drivers to a list several hundred rows long.
- **Not exploitable through the shipping scanner**, which calls `Path.GetFullPath` before it gets
  here - checked rather than assumed. That made the rule safe by a caller's habit rather than by its
  own construction, on a `public` method. Both sides are now resolved before comparison, and an
  unresolvable path fails **closed**: a driver whose location cannot be established must not be
  presented as shipped by Windows, and falls through to the signature verdict where it stays visible.
- 25 tests, including the BYOVD shape stated outright, and the mutation check: restoring the raw
  prefix fails five of them. `WinSight.Drivers.Tests` 25 → 50 tests.
- The live scan is unchanged - 450 drivers, 6 flagged - which is the expected result for a fix to a
  path nothing currently reaches.

### The WFP exact-shape check was guarded by grepping its own source, and the grep had holes
- `FilterHasExactShape` is the most consequential pure function in the privileged service:
  `VerifyExact` calls it to decide whether enforcement reads **Active** or collapses to
  **Degraded**, and Degraded triggers a rollback that removes every block on the machine. Too strict
  and working protection is torn down - that has already happened here, when the check required
  `Flags == 0` and every real block reads back with the INDEXED flag WFP sets itself. Too loose and
  a filter in the wrong shape is accepted as proof the machine is protected.
- It was private, so it was guarded by asserting its **source text** contained twelve expected
  substrings. **Two clauses were missing from that list**: `condition.MatchType == FwpMatchEqual` and
  `condition.Value is not null`. Demonstrated by deleting the MatchType clause: the source guard
  stayed **green** while the predicate began accepting a filter matching on NOT-equal - a filter that
  blocks every program *except* the named one. The behavioural test fails on it immediately.
- The predicate, its record types and `DesiredBlocks` are now `internal` and falsified clause by
  clause: wrong provider, no provider, wrong sublayer, wrong layer, permit instead of block, zero or
  two conditions, a count of one with no condition behind it, wrong field, wrong match type, wrong
  value type, null value, different value, and a value that is a prefix or extension of the expected
  app id. Plus both directions asserted in one test, so neither a constant `true` nor a constant
  `false` can pass.
- `DesiredBlocks` is covered too: only enabled blocks become filters, paths are canonicalised so one
  app never gets two filters, and two spellings of one path are **refused** rather than silently
  collapsed - they derive the same filter key, so applying both would have the second overwrite the
  first and leave one app unfiltered while both read as blocked.
- The source guard is kept as a cheaper second net over the native call names, with its two missing
  assertions added and its limits written down.
- `winsight-firewall-service` coverage 45.3% → **47.2%**, entirely in the logic that decides whether
  the machine is actually protected.

### VM validation is now a script that returns a verdict, not a document you follow
- `scripts/Test-WfpValidation.ps1` executes the protocol in `docs/ARM64_VALIDATION.md` and prints
  `[PASS]`/`[FAIL]` per step with the visible normalized `FWP_E_*` codes. **A validation nobody can replay is
  indistinguishable, six months later, from one that was never run** - that was the standing
  objection to "covered by VM validation", and this closes it without pretending CI can host it.
- **Historical statement invalidated:** the old text called `-SkipEnforcement` a read-only half safe
  on a working machine. It installs, starts, stops and uninstalls SCM state and therefore belongs
  only in a disposable isolated VM with a clean snapshot, even though it never arms WFP.
- It stops at the two steps that cannot be automated - arming and emergency disable - because
  mutating policy requires authenticated IPC by design and the command-line verbs for it are refused
  on purpose. It says what to click, then verifies the outcome.
- The unblocked leg is asserted as hard as the blocked one: if both fail, the filter is machine-wide
  rather than per-app, which is a defect however convincing the blocked result looks.

## v0.10.0, 2026-07-22

**Objective-See parity is complete.** Every tool on the comparison list is now at parity or ahead -
persistence × 2, outbound firewall, ransomware, camera/mic, keyboard interception, kernel drivers,
process explorer, hijack analysis and physical access - in one application instead of eight, with an
MCP server, an alert journal, four scanners Objective-See has no equivalent for, and three languages.

This release came out of an adversarial audit of the whole repository, not of the recent commits, and
the pattern it hunted was a single one: *a component silently discards what it cannot handle, and the
health signal meant to reveal that is structurally incapable of seeing the rejection.* Six instances
were found and closed, including one inside the coverage gate itself and one inside the component
written to fix an earlier instance of the same defect.

**New capability**
- `presence` - physical-access detection. Resume timeline with Windows' own wake source, flagging
  only wakes attributable to a human hand. Two of the three planned data sources were measured and
  rejected before any code was written.
- `process <pid>` - the per-process view: lineage, unsigned modules, live external sockets.
- `hijack` gains **phantom imports**, closing the last DHS gap, plus UNC paths and non-`.exe` images.
- Ransomware alerts now **name the process doing the encrypting**, and any alert without an author
  now says why it has none.

**Fixed, each one a blind spot rather than a crash**
- A COM failure could never be reported as "could not look", and threw through the whole persistence
  scan instead.
- The coverage gate graded one assembly out of twenty-two - and no workflow ever ran it.
- A swapped binary could be served its old trusted verdict.
- A hijack finding could name a directory the service does not live in.
- A whole scanner was undiscoverable from `--help`.

1 294 tests (from 1 097), engine libraries at 87.5%, coverage now enforced by CI.

### `presence` - physical-access detection, and the two sources measured and rejected first
- The last Objective-See parity gap (DoNotDisturb). **Two of the three planned sources were measured
  and discarded before any code was written**, and why matters more than what remained.
- **Logon failures need Administrator.** The Security log throws unelevated - measured. Building on
  it would have made a whole surface blind in the default mode.
- **USB device history is a trap.** The device keys under `SYSTEM\CurrentControlSet\Enum` *are*
  readable unelevated; their `Properties` subkey, where the first-install and last-arrival timestamps
  live, throws `SecurityException`. An inventory of devices with no dates cannot answer "was
  something plugged in while I was away" - and would have looked complete while failing to.
- What **is** readable is the System log's resume timeline with Windows' own wake source.
- **The measurement then reshaped the rule.** Across 50 resumes on a real desktop: **25 `Unknown`,
  24 a network adapter, 1 a physical input device.** "A device woke the machine" is not "somebody
  touched the machine" - equating them would have produced **24 false accusations** against ordinary
  Wake-on-LAN traffic on this scanner's very first run, while still explaining none of the 25 it
  cannot. Both the network case and the "uniformly optimistic classifier" case are pinned as tests;
  removing the discrimination fails five of them.
- Classification is driven by Windows' **numeric type code, never the rendered message**, which is
  localised - this machine renders it in French. A type code Windows may add later degrades to
  `Unknown`, never to whichever cause sits next to it.
- Built test-first: 31 tests, RED confirmed before each implementation, and the live event-log reader
  held to the same "saw something, or admits it could not look" contract as the scheduled-task
  source. Measured end to end: **647 ms**, 1 finding out of 50 resumes.
- Deliberately **not** in the default overview: a machine in daily use wakes constantly, and the one
  thing that would make a wake suspicious is what Windows most often declines to record. This is a
  timeline you consult when you suspect someone was at your desk.
- Wired through the CLI, MCP (**15 scanners** - all four pinning sites moved together) and the
  dashboard in all three languages.

### `winsight process <pid>` - the per-process view, TaskExplorer's last gap
- Everything WinSight knows about one process in one answer: its image and signer, its lineage
  (parent, and the children it spawned), the unsigned modules loaded into it, and its live external
  sockets. Built **test-first**, and both central rules verified by deliberately breaking them.
- The parity plan called this "UI work, not detection work". Half right - the data was already
  gathered. The other half was not: **the join itself makes decisions**, and each can misname
  something. So the pivot is a pure function over three snapshots, the rendering is a second pure
  function beside it, and only the gather is an edge.
- **An absent pid answers "not running", never "nothing wrong".** A hollow record renders as a
  process that exists with nothing loaded and nothing connected - a confident, reassuring description
  of something that is not there.
- **A process is never its own parent.** The System Idle Process reports pid 0 with parent 0, and the
  process reader falls back to 0 for a row whose id it cannot read. An unguarded lookup recurses
  forever in a tree and claims a process launched itself. Removing the guard fails a test.
- **Modules are counted, not listed.** `explorer.exe` has **353** on this desktop and all but a
  handful are Microsoft-signed; listing them buries the outlier. Removing the unsigned-first ranking
  fails a test.
- Reading one process's modules needed a new entry point. The only one available walked every
  process - 57 s, 14 253 modules, 222 processes - which is a good answer to "what is loaded anywhere
  on this machine" and an absurd one for a view opened on a single pid. Both paths share one
  collection routine, so the skip-don't-fabricate rule that makes this scanner trustworthy cannot
  drift between them.
- **Measured: 11 s live, 4 s for a pid that is not running** (down from 15 s - the process list is
  taken first and short-circuits before the expensive scans). Running the three acquisitions
  concurrently would roughly halve the live case and is deliberately **not** done: the verifier chain
  is shared and its catalog fallback is not proven thread-safe, and an unproven concurrency change
  inside the trust core is not worth four seconds.

### An alert with no author now says why it has none
- Three states hide behind a nameless detection and they call for three different responses: nothing
  was watching, nothing **could** watch because the process is unelevated, or something was watching
  and genuinely saw nothing. `AttributionHealth` exists to draw exactly those distinctions, and its
  own summary says collapsing them "is how a monitor gets trusted when it should not be".
- **Nothing read it.** Outside its own tests, `AttributionHealth` had no consumer anywhere in the
  product: every caller took the author or the absence of one, and the health record reached no
  operator, no journal and no MCP client. The type was right and unwired - the same shape of defect
  as the scheduled-task flag, one layer up.
- Alerts now end with `- written by <path> (pid N)` or `- author unknown (<reason>)`. The reason is
  what makes it actionable: *attribution needs Administrator* means the writer could have been named
  had WinSight been elevated, while *attribution watching, no matching write seen* means it really is
  unknown. A silent absence reads as the second when on an unelevated machine it is always the first.
- **The note rides on the alert, not on a health endpoint** - deliberately. The journal already
  crosses the process boundary (the dashboard writes it, the MCP server reads it), so the caveat
  reaches an LLM with no new file and no new tool. And it has no staleness problem: a health file
  written by a dashboard that has since exited would describe a world that no longer exists, while a
  note beside the detection describes the state at the moment it fired - the only state that can
  explain it.
- Both monitors now share one renderer. They had a copy each, and a security record whose wording
  depends on which code path reached it is one you have to read twice.
- MCP server instructions tell a client the bracketed reason is meaningful and must be repeated
  rather than dropped, and never to present "needs Administrator" as if it were "genuinely unknown".

### Ransomware alerts now name the process doing the encrypting
- `CanaryTouched: decoy.docx` says something is wrong. **`- written by C:\Users\me\AppData\Local\Temp\x.exe (pid 8121)`
  says what to terminate.** Ransomware is the one detection where minutes matter, and it was the one
  still saying *what* without ever saying *who*.
- **The file filter was missing, and missing silently.** The watcher records every registry write but
  only the file writes it is told to look for - a busy machine performs thousands a second and the
  correlation index is small and time-bounded on purpose. `AttributionHost` was constructing that
  watcher with the **default filter, which records nothing**. Registry attribution worked, the health
  counters read healthy, and no file write was ever offered to the index at all. Ransomware and
  Guardian's startup-folder surface could never have been attributed, and nothing said so.
- `AttributionScope` names the two sets worth recording: the startup folders, and the ransomware
  decoys once protection plants them. The protected *directories* - Documents, Desktop, Pictures -
  are deliberately **not** watched wholesale; they are among the busiest paths on a desktop and would
  reintroduce the flooding the filter exists to prevent. Consequence stated rather than hidden: a
  touched decoy carries an author, a rename/delete burst does not.
- **A total, invisible bug fixed on the way.** The filter runs on the path as the kernel spells it,
  before normalisation. The previous rule compared that raw path against the full DOS folder
  (`C:\Users\…`), which cannot match once the volume reads `\Device\HarddiskVolume3\…` - every
  startup-folder write would have been dropped and `winsight attribution --watch` would have looked
  merely quiet. Matching the root-relative tail is correct under **either** spelling. This could not
  be observed from an unelevated machine, so it is written to be right either way rather than betting
  on which form arrives - and pinned by tests in both spellings, plus `\??\`, `\\?\` and forward
  slashes.
- The journal keeps the full path and the author; the balloon still keeps only the file name, because
  a balloon can be read over someone's shoulder and the journal is opened deliberately by someone who
  has just been told their files are being encrypted. A bare-name author (`powershell.exe`, how
  living-off-the-land ransomware runs) is named but marked `full path unknown`, never dressed up as a
  located file.

### `hijack` closes the DHS gap: phantom imports
- A binary declares the modules it needs. When one is answered by **no directory in its search
  order**, the slot is permanently unoccupied - not a race to win but an open invitation: whoever
  can write that name into any searched directory is loaded into the program at its privilege,
  every time it starts. This was the last named parity gap against Objective-See's DHS, and the one
  the plan called "analysis work rather than enumeration".
- **Imports are parsed, never loaded.** Asking Windows what a binary imports means running its
  initialisation code, which is unacceptable in a scanner aimed at files it already suspects. The
  reader bounds-checks every read and caps every count, because it is pointed at files an attacker
  may have written: a malformed image yields nothing rather than an exception, so one hostile binary
  cannot end the sweep. Validated against real 64- and 32-bit system binaries - **376 of 400**
  System32 DLLs parsed, the remaining 24 being resource-only DLLs with no import table, which is the
  correct answer for them.
- **The tests build PEs whose RVAs differ from their file offsets.** A parser that skips the section
  translation agrees with a handcrafted image and disagrees with every binary Windows ships; that is
  the classic way this kind of parser passes its tests and fails in production.
- **The api-set prefix was wrong in a way inspection cannot catch.** Written as `api-ms-win-` /
  `ext-ms-win-` it produced exactly two findings against the live machine:
  `ext-ms-win32-subsystem-query-l1-1-0.dll` in the print spooler and
  `ext-ms-onecore-appmodel-staterepository-internal-l1-1-3.dll` in the search indexer - both
  api-sets, both reported as phantom imports of a SYSTEM service. Two confident false accusations
  against Windows itself, from four characters. Both are now pinned as test cases.
- **Measured after the fix: zero findings across ~90 auto-starting services, 377 ms** (the scan was
  200 ms before). Silent on a healthy machine is the intended shape - and exactly why the rule has
  tests that make it fire on a machine that does not exist.
- Writability is asked **once per directory per scan**, not once per import: ~90 services with
  overlapping search orders would otherwise have written thousands of probe files across the disk.
- Known limit, stated rather than implied: this reads the import table, so a DLL fetched at runtime
  through `LoadLibrary` declares nothing and stays invisible. That needs runtime observation.
- `WinSight.Hijack` coverage 55.6% → **75.6%**.

### The coverage gate was measuring one assembly out of twenty-two, and CI never ran it
- **`Measure-Coverage.ps1` read `Select-Object -First 1`.** The collector writes one cobertura file
  per test project - 19 of them on this repo - each describing only the assemblies that project
  happened to load. The gate graded whichever file the filesystem enumerated first. Caught in the
  act: it printed *"All engine libraries are at or above 80%"* after looking at **100 lines out of
  11,584**, a single assembly. Every report is now merged, unioning per (assembly, file, line).
- **No workflow ever invoked it.** Neither `ci.yml` nor `release.yml` called the script, and its
  `-EngineMinimum` defaulted to `0` - the gate off. The "engine libraries are held to 80%" rule was
  a number no run could contradict. It now runs inside `build-test`, the required check, **in place
  of** the plain `dotnet test` rather than beside it, so the suite still runs exactly once.
- **An unmeasured library is no longer read as a covered one.** If an engine assembly is absent from
  the merged report the gate fails instead of quietly grading the rest - the same "could not look"
  distinction the rest of the suite is built on.
- With the gate finally able to see, it failed honestly: `WinSight.Processes` at **79.5%**. The gap
  was `ProcessInfo.Unsigned` - the only judgement that module makes - having no test at all, and
  `ToUint`'s fallback silently attributing an unreadable row to **pid 0**. Both are now pinned;
  79.5% → **93.2%**. Engine libraries **87.4%**, all twelve above the bar.

### The signature cache could serve a trusted verdict for a file that had been swapped
- Identity was length plus both timestamps, and all three are attacker-controlled - timestomping
  (T1070.006) is one API call. A same-length unsigned replacement was served the cached **trusted**
  verdict for up to five minutes. The window was undocumented, which was the real defect in a trust
  core. The swap is now performed for real on disk in a test rather than described in prose.
- **Measured before choosing**, over 300 System32 DLLs: Authenticode verification **19.25 ms/file**,
  SHA-256 of the content **1.64 ms**, metadata fingerprint **0.052 ms**. Hashing every lookup would
  add ~23 s to a 57 s `modules` scan to close a window that shuts when the process exits seconds
  later - so content verification is opt-in, and **Guardian turns it on**. Guardian is the case the
  cheap fingerprint is wrong for: it runs for days, makes few lookups, and its verdicts sit beside
  persistence alerts, which is the worst possible place for a stale "signed".
- `WinSight.Core` had **no test project of its own** - its coverage came from other modules
  exercising it. The trust core now has one.

### `hijack` was blind to UNC paths and to every image that is not an .exe
- `\\server\share\My App\svc.exe` reported **nothing**: the guard was written as "starts with a
  backslash" while its rationale only covered kernel-loaded driver paths. `CreateProcess`
  prefix-searches a UNC path exactly like a drive path. `\\?\` and `\\.\` stay excluded, now for the
  reason actually stated.
- A registered image does not have to be an `.exe`. `.bat`, `.cmd`, `.scr` and `.pif` are
  prefix-searched identically and were read as nothing at all. `.com` is deliberately **not** in the
  set: it ends almost every domain name, and service arguments are full of those.
- **A candidate must sit below its own root.** `C:\`, `\\server` and `\\server\share` are rooted but
  are not files anyone can plant; emitting them sends an operator to inspect a path that cannot
  exist. One rule now covers drive and UNC roots instead of two spellings that could drift.
- Repeated spaces produced `C:\Program .exe`, which Windows can never create. Prefixes are trimmed
  and de-duplicated.
- An intermediate attempt at guarding arguments required the extension's token to contain a
  separator. It looked right and silently broke `...\sub dir\program name.exe` - an executable whose
  *file name* contains a space, the central case of this feature. Caught by an existing test, and
  now pinned by an explicit one so it cannot be reintroduced.

### Adversarial audit: a health signal that could never fire, and two parsers that disagreed
- **`ComScheduledTaskSource` could never report itself unreadable, and threw instead.** Late binding
  raises COM failures wrapped in `TargetInvocationException`; the catch filters listed only unwrapped
  types, so **no COM failure matched any of them**. A stopped or restricted Task Scheduler service
  therefore threw straight out of `Enumerate` and took the whole persistence scan - 4 354 items on
  this desktop - with it, while `Unreadable`, the flag whose entire purpose is to say "an empty list
  is not a fact about this machine", stayed `false`. Measured, not reasoned: asking the live service
  for a missing folder surfaced `TargetInvocationException` (0x80131604), never `COMException`.
  This is the same defect class the component was written to fix, one layer down - the health signal
  was structurally incapable of reporting the blind spot it guards.
- **The regression test guarding it was passing for the wrong reason.** It drove a `ScriptedSource`
  that simply *returns* `unreadable: true`, proving the enumerator propagates the flag while never
  touching the only implementation that ships. Classification is now a named, directly tested
  predicate driven with the exception shapes the runtime actually produces, plus a contract test
  holding the real source to "either it saw tasks or it says it could not look" - never
  "empty and fine". Both fail against the old filter; verified by mutation.
- The CLR maps well-known HRESULTs before wrapping, so `ERROR_FILE_NOT_FOUND` arrives as
  `FileNotFoundException` and `E_ACCESSDENIED` as `UnauthorizedAccessException`. The recoverable set
  covers those too. The root `ITaskFolder` was also never released, and the empty `if (depth > 0)`
  block asserted a contract nothing honoured; both fixed. Measured leak: 1 handle across 25
  enumerations after a forced GC - real but GC-bounded, so severity is hygiene, not exhaustion.
- **`HijackScanner.ExecutableDirectory` and `UnquotedPath.ExecutableSpan` read the same string and
  disagreed.** Only one got the end-of-token hardening; the other still took the first `.exe`
  anywhere in the line, so `C:\Tools\7z.exe.bak\svc.exe -k` resolved to `C:\Tools` - probing, and on
  a writable machine **accusing, a directory the service does not live in**. That function is what
  decides which directory a finding names, it was `internal` with no `InternalsVisibleTo`, and it had
  **zero** coverage. Both readings now share one parser, the seam is open to tests, and 17 tests pin
  it including UNC, `\??\`, `.bat`, unbalanced quotes and relative paths. Verified by mutation.
- **`winsight hijack` was undiscoverable.** The scanner shipped wired into the dispatcher, the
  default overview, the MCP catalog and the dashboard - and was absent from `--help`, because the
  help text was a hand-maintained copy nothing compared against. The scanner list already had four
  pinning sites that must move together; rather than add a fifth to remember, the help now lives
  beside the dispatcher and its documented commands are **parsed back out of the text**, so a
  scanner without a help line fails a test instead of shipping invisible.
- **Measured, all 14 snapshot scanners unelevated**, to look for surfaces that render nothing
  without elevation: persistence 4 354, av 73, net 151, dns 26, firewall 420, processes 372,
  modules 540, extensions 20, certs 128, hosts 2, input 2, drivers 450, integrity 5, hijack 1.
  None is structurally empty in the default mode.

### `hijack` grows the search-order half: writable service directories and PATH entries
- A program's **own directory** is the first place Windows looks for every DLL it loads. An
  auto-starting service whose folder is writable can therefore have any of its imports answered by a
  planted file - and its executable replaced besides. For a service that means SYSTEM, at boot.
- A writable **machine PATH** entry is the same thing for every process that resolves anything by
  name rather than by full path. An *absent* PATH entry whose parent is writable is that
  vulnerability one step earlier - create the directory, then fill it - and is reported too; an
  absent entry with a closed parent is just stale configuration and stays quiet.
- **Measured before being built.** On a real desktop: 18 machine PATH entries and 88 auto-starting
  services, **none writable**. Both checks are silent on a healthy machine, which is the right shape
  - and is exactly why only tests can prove they fire at all, since a silent detector and a broken
  one look identical from outside. That confusion has already cost this project twice.
- The PATH is read from the registry rather than from this process's environment: the process copy
  is a snapshot taken at launch and can carry per-user entries, while the registry value is what
  every service and every new process will actually receive.
- Only services Windows starts by itself are directory-checked. A manual service that never runs is
  not a boot-time escalation path, and checking all of them would triple the probe count for no
  added signal.

### `hijack`: services another program could run in place of - a vector macOS does not have
- Parity gap #4, and the one place a Windows tool should be *ahead* of the Objective-See family
  rather than catching up. Windows registers a service as a **command line**, not a path, so an
  unquoted `C:\Program Files\My App\svc.exe` is attempted as `C:\Program.exe` first. Anyone able to
  create that earlier file gets their code run by the service's account - usually SYSTEM, at boot,
  before anyone logs in. No elevation needed to detect it: the services key is world-readable.
- **The candidate list is the finding.** "This path is unquoted" is a lint result; "anyone who can
  write `C:\Program.exe` owns this SYSTEM service" is something an operator can act on. The exact
  sequence Windows tries is computed as a pure function with its own tests, because naming the wrong
  path sends someone to inspect an innocent file.
- **Graded by real exploitability, not flagged uniformly.** Unquoted service paths are common and
  nearly all of them sit under Program Files where nothing unprivileged can be planted; flagging
  them equally produces a wall nobody reads. **Latent** is `Info`, **Exploitable** (an earlier
  candidate can be created now) and **Occupied** (it already exists) are `Notable`. Measured on a
  real desktop: **1 finding out of ~700 services**, correctly graded Latent.
- **Writability is settled by asking the filesystem, not by reading the DACL.** Effective access is
  the sum of inherited allow and deny entries across every group plus overriding privileges, and
  reconstructing that is exactly where this class of check gets it quietly wrong. The probe creates
  a uniquely-named temporary file with `FileMode.CreateNew` and `DeleteOnClose`, so it never
  overwrites a real candidate and never leaves litter in Program Files.
- Wired through the CLI, MCP (14 scanners) and the dashboard in all three languages. **A fourth
  MCP-count pinning site turned up** that earlier notes did not list -
  `AdaptersTests.SnapshotCommands_AreUniqueAndComplete` - alongside the MCP integration test,
  `scripts/Test-McpServer.ps1` and the catalog.

### CI: `package` no longer waits for `build-test`
- Measured, not guessed: the wall clock was **8m18** - 2m37 of build and test, then 5m38 of
  packaging that had been queued behind it. Nothing was being reused, because the package job runs
  `Build-Release.ps1` and publishes from source itself, so the dependency serialised two unrelated
  jobs. Run together, the same work lands in about **5m40**, the length of the longest job.
- Formatting and the dependency audit deliberately stay **inside** `build-test` rather than becoming
  a third job: `build-test` is the required status check on `main`, so moving them out would leave
  the required check unable to fail on a formatting violation - protection quietly weakened while
  looking unchanged. They are reordered ahead of the build so a violation is reported without
  waiting for a compile and a full test run.

### A Startup folder nobody could list used to report as an empty one
- The same shape as the scheduled-tasks defect, in the other classic drop point. `StartupFolderEnumerator`
  answered a folder it could not list with an empty array, so a re-ACLed Startup folder - which is
  what somebody hiding a shortcut there would arrange - reported clean. It now counts the folder
  through the coverage mechanism added for scheduled tasks, and the scan summary names it.
- A folder that simply **does not exist** stays quiet: a machine with no all-users Startup folder is
  ordinary, and treating absence as refusal would trade a false reassurance for a false alarm.
- **The test denies itself the ACL rather than faking the symptom.** A first attempt stood a plain
  file in for a locked directory; it passed for the wrong reason - `Directory.Exists` is false for a
  file, so nothing ever threw and no gap was counted. The test now creates a real deny-listing ACE
  on a real directory, which is the situation being defended against, and lifts it again on
  teardown. Mutation-verified.

### An unreadable hosts file used to report as a clean one
- Continuing the audit that produced v0.9.1, applied to the rest of the scanners. `HostsReader`
  answered a file it could not open with an empty list, so the report read **"0 hosts entry(ies),
  0 flagged"** - indistinguishable from a machine with nothing in its hosts file.
- **This one is a detection, not just honest reporting.** On Windows the hosts file is readable by
  every user by default. If WinSight cannot read it, its permissions were changed - which is
  precisely the next move for someone who has just pointed a bank or an update server at their own
  address. It is now a `Notable` finding in its own right, and the summary says the contents are
  unknown rather than implying they are clean.
- A genuinely **absent** hosts file is reported as absent and stays quiet: Windows works fine
  without one, and conflating "no file" with "refused" would only trade one false reassurance for a
  false alarm.

## v0.9.1, 2026-07-22

A corrective release. Every item below is a case of WinSight **looking healthy while seeing
nothing** - the one failure mode a security tool must not have. All four were found the same way:
by running the real CLI elevated and unelevated and comparing, rather than by reasoning about the
code. Three of them were shipped in v0.9.0.

**Scheduled tasks were entirely invisible unless you ran WinSight as Administrator.** A top-tier
persistence vector, listed among the covered surfaces, returning zero rows and reading exactly like
a clean machine - 0 unelevated against 104 elevated on a real desktop, including one item already
flagged as suspicious. Now read through the Task Scheduler service, which needs no elevation and
sees more: **81 unelevated (was 0), 104 elevated (unchanged, so nothing regressed).**

**A program launched by bare name had no identity at all** - `powershell.exe`, `cmd /c …`, `node`,
which is how living-off-the-land attacks run. 9% of every process start on an idle desktop was
being discarded, blinding write attribution *and* the outbound firewall.

**The firewall's own "unattributed connections" counter could never count anything**, because the
connections it was meant to count were dropped before the service saw them.

**Attribution could name the wrong program**: a write to a parent registry key was allowed to
explain a change in any child beneath it, and on the first live run a browser was named as the
author of a key it had never touched.

Also in this release: attribution is wired end to end, so a persistence alert can name the program
that installed the entry when WinSight runs elevated; a persistence scan now reports what it was
*not allowed to read*, so "no findings" and "I could not look" no longer render the same; and the
unreachable `persistence-live` report was removed, its signature verdict moving into the alert
journal line where it is actually read.

### WinSight reported **zero** scheduled tasks unless you ran it as Administrator
- Scheduled tasks are a top-tier persistence vector and one of the 22 surfaces WinSight claims to
  cover. Unelevated it found **none of them**, and said nothing: the report listed the surface,
  showed no rows, and read exactly like a clean machine. Measured on a real desktop: **0 tasks
  unelevated, 104 elevated** - Brave, Edge, NVIDIA, OneDrive and Google updaters, and one already
  flagged as suspicious.
- The cause was a reasonable-looking decision compounding into a silent total failure. The
  enumerator parsed the XML files under `%SystemRoot%\System32\Tasks` "to avoid a COM dependency".
  That directory is administrators-only, and `Directory.GetFiles` does not skip what it cannot
  enumerate - **it throws for the whole tree**. The exception was caught and turned into an empty
  list, so one denied directory became "this machine has no scheduled tasks".
- **Reading through the Task Scheduler service needs no elevation and sees more**: 195 registered
  tasks visible on the same machine, against 104 files the elevated scan could open. It returns the
  identical XML, so the parsing that was already tested is reused unchanged. Measured after the
  change: **81 tasks unelevated (was 0), and 104 elevated - byte-for-byte the previous elevated
  result, so nothing regressed.** The 23 still unseen unelevated are tasks this user genuinely
  cannot enumerate, which is the correct answer rather than a hidden one.
- **A scan now reports what it was not allowed to read.** `ScanWithCoverage` returns the entries
  plus a `PersistenceCoverage`, and the summary line names the gap - a surface that failed outright
  is named, and definitions individually refused are counted. "No findings" and "I was not allowed
  to look" must never render the same, which is precisely how this defect stayed invisible.
- Late binding is used for the four COM calls deliberately: the alternative is an interop assembly
  or a hand-written pile of COM declarations, which is a lot of unverifiable surface to add to a
  security tool. The source sits behind `IScheduledTaskSource`, so the enumerator is tested against
  a scripted task set with no COM and no dependency on the test machine's own tasks.

### The firewall's "unattributed connections" counter could never count anything
- `OutboundObserverService` has always exposed `UnattributedConnections`, and it was structurally
  incapable of counting the case it is named for: the watcher **discarded** a connection whose
  process it could not name, before the service ever saw it. The counter only ever incremented for
  a path the pending log rejected - so a machine quietly losing connections reported zero. A health
  counter that reads clean while the thing it measures is failing is worse than no counter.
- The population it was missing is exactly the one worth knowing about: the same bare-name launches
  that were invisible to attribution - `powershell.exe`, `cmd`, `node`. The watcher now indexes
  those under their kernel-reported image name and reports the connection as unattributed, with a
  name where there is one and the process id either way.
- **It still cannot be ruled on, and that is deliberate.** An unattributed connection never reaches
  the pending log: that log is the list of apps the operator may Allow or Block, and a rule keyed on
  the bare name `powershell.exe` would apply to every powershell on the machine whatever its origin.
  Counting and naming it is the honest answer - the connection is known to have happened, and known
  not to be rulable.

### `powershell.exe` was invisible to attribution *and* to the outbound firewall
- A process's identity is captured at start, from the command line the kernel reports, and anything
  that did not yield a fully qualified path was **discarded entirely**. Measured against a live
  kernel session, that was **9% of every process start on an idle desktop** - and not obscure ones:
  `powershell.exe`, `cmd /c npx …`, `node`, `smss.exe`, `csrss.exe`, `wininit.exe`. Launching by
  bare name through the search path is how living-off-the-land attacks run, so the tool was blind to
  precisely the launches that matter most. Both write attribution and the outbound firewall are
  built on this same index.
- **The Windows directory is now expanded** - `\SystemRoot\…`, `%SystemRoot%\…`, `%windir%\…` -
  which recovered every system process on the dropped list. This is expansion, not guessing: that
  directory is machine-global. General environment expansion stays refused, because `%USERPROFILE%`
  and `%TEMP%` differ per user and per session, and reading another process's command line through
  *our* environment would manufacture a path that never existed.
- **A process with no readable path is now indexed under its image name** rather than dropped. The
  image name is a fact the kernel reported. `powershell.exe (pid 4242, full path unknown)` is a real
  answer; silence is not.
- **The two are kept apart all the way to the alert.** `Resolve` still answers only with real paths,
  because blocking is keyed on the path and a rule matching the bare name `powershell.exe` would
  apply to every powershell on the machine whatever its origin. A test pins that property directly.
  Callers that only need to *name* a process use `ResolveImage` and are told which they got.
- **Found by testing the scenario the feature exists for.** Every earlier probe wrote from the
  probe's own long-lived process - the easy case, which passed. A short-lived `reg.exe` that writes
  a key and exits, which is the actual dropper pattern, failed outright: the key resolved fine and
  the *process* could not be named. It now passes on real hardware.

### The `persistence-live` report is gone; the alert carries its verdict instead
- A whole parallel report of the session's arrivals was built, unit-tested, and **never rendered by
  anything**. Guardian's detections reach the operator through the alert journal, which does the
  same job and survives a restart and a suppressed balloon - the failure modes the journal exists
  for. A second, unreachable rendering path in a security tool is worse than none: it drifts from
  the live one while still looking tested.
- The one thing it showed that the journal did not - the signature verdict - moved into the journal
  line. "A new startup item appeared" and "an *unsigned* new startup item appeared" are different
  emergencies, and an operator reading an alert hours later needs that in the same sentence.

### Attribution named the wrong program, and an elevated probe on real hardware caught it
- The correlation rule let a detection match an observed write when the detection's target
  *continued past it at a boundary* - designed for `…\Run` answering a finding spelled
  `…\Run [Updater]`. A backslash was one of those boundaries, and a backslash does not mean "the
  same thing, spelled more fully": it means a **deeper key**. So any program that wrote anywhere
  under `HKCU\Software` became the author of every finding beneath it. On the very first live run,
  a browser touching a shared ancestor was reported as the author of a key it had never touched.
- **Every unit test passed throughout.** They pinned the rule that was written, using spellings that
  were assumed rather than observed. What broke the tie was asking the kernel: a probe run elevated
  on real hardware showed that a registry value write is reported as the **key**, uppercased, with
  no value name appended - so a legitimate finding is always the observed key, or that key plus a
  display suffix, and never a deeper one. Removing the backslash boundary costs nothing real and
  removes a whole class of false attribution.
- Health counters split `UnresolvedTarget` into `UnannouncedKey` and `UntranslatablePath`. They look
  the same from outside - a write nobody could name - but one is a gap in the kernel's bookkeeping
  replay and the other a gap in WinSight's namespace mapping, with different fixes. The first live
  run reported 114 unresolved against 2 attributed, and that number was useless until it could be
  split; it is now known to be almost entirely unannounced key handles.

### Attribution reaches the alert: a persistence detection can now name the program that installed it
- The correlation index and the ETW watcher were built and tested separately, and nothing joined
  them, so a detection still could not answer the question the whole feature exists for. New
  `AttributionHost` is that join: it owns the watch's lifecycle, feeds the index, and answers
  "who wrote this?" - and Guardian's journal line now carries `written by <path> (pid)` when it can.
- **The host reports its own health, because "no answer" hides three different situations.**
  Attribution can be unavailable (not elevated), running and blind (a key handle the kernel never
  announced), or working and genuinely finding nothing. Collapsing those into one silent empty
  answer is how a monitor gets trusted when it should not be, so `AttributionHealth` counts what was
  attributed, what was seen but unattributable and why, and whether the watch was refused outright.
- **Started only when elevated, and never demanded.** A kernel trace session is privileged and
  WinSight is deliberately unprivileged by default, so an unelevated dashboard simply carries no
  author on its alerts. Attribution is an enrichment: a detection is never withheld because nobody
  could name its author, and a name is never invented when the lookup has none - including when a
  neighbouring key was written at the same moment, which is pinned by a test.
- **The watch is now testable without Administrator.** `IWriteWatcher` exists for the same reason
  the capture-device reader has a seam: a component whose only implementation needs elevation is a
  component whose lifecycle nobody ever exercises, and an untested lifecycle around a security
  monitor is how a monitor comes to be silently dead. Start/stop, idempotence, refusal and prompt
  shutdown are all covered by a scripted watcher.
- The journal line moved out of the WPF event handler into the tested presenter, and a test round-
  trips it through the journal's own format - a detail carrying a tab would have made its own
  record unparseable, writing the alert and then losing it.

### Kernel drivers: WinSight can now answer "what is running inside the kernel?"
- Priority #3 in the parity analysis, and the cheapest genuine capability still missing. A kernel
  driver runs with the same authority as Windows itself: it can hide files from every other scan
  WinSight performs, read any process's memory, and make itself invisible to everything above it.
  That is what a rootkit leaves behind, and WinSight listed none of them.
- New `drivers` scanner (`WinSight.Drivers`), no elevation required: the service control manager's
  own registry names every driver Windows can load, its type, its start disposition and its image,
  and the verdicts come from the Authenticode path every other scan already uses. In the dashboard,
  the CLI and over MCP. Left out of the balanced overview on the `processes`/`modules` precedent -
  450 rows is an inventory you go and ask for, not one a routine scan should hand you.
- **`EnumDeviceDrivers` would name what is actually resident, and was still rejected.** Since
  Windows 8.1 it returns zeroed load addresses to a process that is not elevated, as an
  ASLR-disclosure defence. The call still succeeds and still reports the right count, so the
  failure is silent rather than loud: every one of the 232 loaded modules on this machine resolved
  to `ntoskrnl.exe`. A residency list that answers with the same file 232 times is worse than no
  residency list, so the scan reports what is *registered*, says when Windows loads it, and does
  not claim to know what is resident. Earning that claim costs the elevation this program exists
  to avoid.
- **"Windows ships this" is an exact certificate-subject test, not a name match.** In-box drivers
  are signed `CN=Microsoft Windows`. Drivers somebody else wrote and Microsoft merely attested
  carry a longer name off the same issuer - `Microsoft Windows Hardware Compatibility Publisher`,
  `… Hardware Abstraction Layer Publisher`, `… Early Launch Anti-malware Publisher` - every one of
  which a substring match on "Microsoft Windows" swallows whole. Bring-your-own-vulnerable-driver
  attacks live in precisely that gap. So the common name is compared entire, and the image must
  also sit inside the System32 tree: a genuine Microsoft driver running from a download folder is
  a finding, not an expectation. Live, that test correctly keeps WireGuard and `wintun` - both
  Microsoft-attested - out of the 418 drivers Windows actually ships.
- **`--flagged` narrows harder here than in the input scan, on purpose.** That one flags every
  driver Windows did not install because its list is two lines long; this one is 450, since every
  disk, display and network component registers a driver. A flagged view that answers with eighty
  rows is a flagged view nobody opens twice, so only the two conditions nothing explains away
  survive it: a signature that did not stand up, and a registration whose image is gone. Signed
  third-party drivers stay in the full listing, where they are context rather than noise.
- An unverifiable driver gets its own answer instead of being quietly filed as third-party. Not
  flagging `Unknown` is the standing rule and it holds - but calling it third-party would assert a
  provenance never established, and would hide a condition worth seeing, because when catalog
  verification fails it fails for every catalog-signed file at once.
- **Verified live, and it found things.** 450 drivers registered, 418 shipped by Windows, 26 signed
  by other publishers (Intel, NVIDIA, Realtek, Oracle, Proton, SteelSeries, WireGuard), 6 flagged:
  two in-box Windows 11 drivers carrying no signature at all - `bthmodem.sys` and `usb80236.sys`,
  both confirmed independently - and four registrations pointing at files that no longer exist, one
  of them a Windows Setup filter still set to load at boot, two of them leftovers from uninstalled
  anti-cheat drivers.
- Building it exposed a pre-existing weakness in `AuthenticodeVerifier` that deserves its own fix:
  the catalog fallback spawns `powershell.exe` without sanitising `PSModulePath`, so a WinSight
  started from a PowerShell 7 session hands Windows PowerShell 5.1 PowerShell 7's copy of
  `Microsoft.PowerShell.Security`. That module fails to import and takes `Get-AuthenticodeSignature`
  with it, degrading every catalog-signed file to `Unknown`. This is the first scan to push hundreds
  of them through that path at once, which is why it surfaced now - and it is not cosmetic: it hid
  both genuinely unsigned drivers above until the environment was cleaned.

### Process attribution, increment 2: the live ETW session, and what testing it actually found
- The watcher that answers *who*, not just *what*: an elevated kernel session that reports registry
  and file writes already attributed to the process that made them, feeding the correlation core
  from increment 1. Available as `winsight attribution --watch` (Administrator), which is also how
  it was verified - the dashboard wiring follows in the next increment.
- **Registry ETW does not report the key you would recognise, and the first version failed
  silently because of it.** A write names a *key control block* handle plus, at most, a name
  relative to it; the full path is announced separately when the kernel opens the key. Run
  elevated, that first version printed a healthy-looking burst of fully-qualified keys and then
  recorded nothing at all - the burst was only the rundown of keys already open, and every live
  write went past unresolved. It looked like it was working. `RegistryKeyResolver` now keeps the
  kernel's announcements and joins them, which turned live capture on: verified with a real write
  arriving as `HKLM\SOFTWARE\…\CPSS\DevicePolicy\AllowTelemetry`, attributed to the process.
- Increment 1's path translation was confirmed against reality in the same run: `\REGISTRY\MACHINE`
  read back as `HKLM\`, the current user's hive as `HKCU\`, and the `_Classes` companion hive stayed
  distinct as `HKU\{sid}_Classes` - the decision that was argued for in tests, now observed.
- File writes are filtered at the source, and the default filter accepts nothing. A busy machine
  writes thousands of files a second; feeding those into a bounded index would evict every useful
  observation within seconds, leaving it full and useless at the moment a detection asked it a
  question. Registry writes are not filtered - they are orders of magnitude rarer and are where
  persistence lives.
- **A watcher that cannot say what it missed is indistinguishable from one that is broken.** The
  first version silently discarded every write it could not attribute - the same shape of defect as
  the signature verifier that swallowed its child's stderr. `Watch` now optionally reports
  unattributable writes with the reason: an unknown process, an unannounced key handle, or a key
  that resolved but would not translate. That is a feature, not scaffolding: an operator who is
  told "four hundred writes seen, twelve unattributed" can calibrate; one told nothing cannot.
- **It immediately found a real defect that reading documentation would not have.** Every
  user-hive write was being refused. A plain write to `HKCU\Software\…` does not arrive as
  `\REGISTRY\USER\{sid}\…` at all - it arrives as
  `\REGISTRY\WC\Silo{guid}user_sid\Software\…`, the Windows Container namespace, because Windows
  routes user-hive access through a silo. Machine-hive writes sailed through the whole time, so the
  watcher looked *partly* healthy, which is the worst kind of broken. The normaliser now translates
  that shape, and only that shape: a silo whose segment does not end in `user_sid` is refused rather
  than guessed at, because a container's hive is not the operator's. Verified live afterwards -
  `powershell.exe (pid 2856) → HKCU\Software\Microsoft\SystemCertificates\…` - with untranslatable
  keys dropping from thirteen to three in the same sample.
- **Known limit, measured rather than estimated:** in that same sample, 5,774 writes could not be
  resolved because the kernel never announced their key handle - the key was already open when the
  session started. Keys opened *during* a session resolve correctly, so a long-running monitor
  recovers as keys are reopened, but a short observation window sees a large blind spot. This is
  now visible in the numbers instead of being invisible, which is the prerequisite for fixing it.
  Increment 3 starts there.

### The scan that gives every other kernel finding its meaning
- The drivers scan can say a kernel driver is unsigned. It cannot say whether that *matters*. On a
  machine with test signing turned on, an unsigned driver is not an anomaly at all - it is the
  documented consequence of a setting, and the real finding is the setting. Nothing in WinSight
  asked that question.
- New `integrity` scanner (`WinSight.CodeIntegrity`), no elevation: driver signature enforcement,
  test signing, memory integrity (HVCI), Secure Boot, and whether a kernel debugger is attached. In
  the balanced overview, because it is six lines and reframes everything else.
- **Asked of the kernel, not the registry.** `NtQuerySystemInformation` reports what is actually
  being enforced; the policy keys record what somebody configured. A pending reboot, a policy that
  failed to apply or a hypervisor that could not start all make the two disagree - the same
  distinction the WFP "effective state" fix turned on.
- **Two volumes, deliberately.** Test signing on, driver signing off, or a debugger attached change
  what the machine will load, so they are `Weakened`. Secure Boot and memory integrity being off are
  weaker settings that a great many healthy machines have - reporting those at the same volume would
  train the operator to ignore the scan, so they are `Hardening`. HVCI in *audit* mode is called out
  separately: it reads as enabled everywhere in the UI while enforcing nothing, which is exactly the
  false comfort this tool exists to remove. Anything unreadable is never counted as a weakness.
- Every protection is reported even when healthy, so the reader can tell "verified good" from "never
  looked". Verified on a real machine: driver signing on, test signing off, HVCI enforcing in strict
  mode, no kernel debugger - and **Secure Boot off**, the one thing worth telling its owner.

### Signature verification was failing open, silently, and hiding real findings
- Found while reviewing the drivers scan: it reported four flagged drivers here but six on the
  machine that built it. Same binary, same machine, same minute - the difference was **which shell
  launched it**.
- `AuthenticodeVerifier` shells out to Windows PowerShell, and a child inherits the parent's
  environment including `PSModulePath`. Launched from a PowerShell 7 session it pointed at PS7's
  module directories; Windows PowerShell 5.1 then failed to import
  `Microsoft.PowerShell.Security`, so `Get-AuthenticodeSignature` did not exist and the command
  produced no output at all. Every catalog-signed file degraded to `Unknown`.
- **The failure was invisible twice over**: `Unknown` is deliberately never treated as suspicious,
  and the child's stderr is discarded. So the scan looked healthy while 450 kernel drivers came
  back as 269 trusted / 177 unknown instead of 444 trusted / 2 unsigned - and **two genuinely
  unsigned kernel drivers were simply absent from the results**. This affected every scanner that
  verifies a signature, not just the new one: persistence, processes, modules, keyboard filters.
- Fixed by pinning the child's `PSModulePath` to Windows PowerShell's own module directory.
  Regression tests deliberately pollute the variable first - a test that only ran in a clean
  environment would never have caught this - and were confirmed by removing the fix and watching
  them fail.

### Camera/mic alerting verified on real hardware, and the alert made readable
- Verified end-to-end at last, by driving real device acquisitions rather than reasoning about them.
  **Microphone:** a real hardware transition produced `MicrophoneActivated` in the journal 1.5s
  later (the poll interval), `MicrophoneDeactivated` 0.6s after release, and a tray balloon on
  screen. **Webcam:** confirmed too, and it turned out not to need a camera at all - an app holding
  the webcam *capability* is enough, so `WebcamActivated`/`WebcamDeactivated` were captured on a
  machine whose only "Camera" devices are printers. The whole chain - device →
  CapabilityAccessManager → reader → diff → host → journal and balloon - is now confirmed against
  reality for both device kinds, not just against tests.
- The webcam case also exercised the packaged-app path for free: the Camera app is recorded by
  package family name rather than a path, and is shown as-is rather than being trimmed at a
  separator that does not exist.
- **Looking at the real alert immediately found a defect.** The balloon showed the app's full path,
  which wrapped over four lines and was truncated before it identified anything, while putting the
  operator's folder layout on screen. It now shows the executable's name, matching the deliberate
  choice already made for the ransomware balloon: an alert can be shoulder-surfed or land in a
  screenshot, and the file name is what answers "what is using my microphone". The journal still
  records the full path, because that is opened deliberately to investigate. Packaged apps keep
  their family name, which has no directories to trim.
- Worth recording for anyone testing this later: initialising a capture object is **not** enough to
  register in the consent store - Windows records an app only once the device is genuinely
  streaming. That is the correct boundary rather than a blind spot: without a stream no samples are
  delivered, so nothing is actually hearing or watching.

### Keyboard interception: WinSight can now answer "what can read my keystrokes?"
- The clearest capability gap in the parity analysis, and the one an operator most wants answered.
  macOS lets ReiKey enumerate event taps outright; Windows exposes no documented way to list
  `SetWindowsHookEx` hooks. But a *serious* keylogger does not use a user-mode hook - it installs a
  **filter driver on the keyboard or mouse device stack**, where it sees every keystroke in the
  kernel before any application does. Those are plainly readable from the device setup class keys,
  which makes this both the highest-signal and the most honestly detectable form of input
  interception on this platform.
- New `input` scanner (`WinSight.InputHooks`), no elevation required: a registry read plus the same
  Authenticode verification every other scan uses. Available in the dashboard, the CLI, the balanced
  overview and over MCP.
- **No vendor allowlist, deliberately.** Touchpad and remote-desktop drivers legitimately sit here
  and it is tempting to hard-code their names as benign - but nothing stops a keylogger calling
  itself `SynTP`. Only the class driver Windows itself installs (`kbdclass` / `mouclass`) is treated
  as expected; everything else is reported with its signature standing and the operator decides.
  Reading one extra line costs a moment. Hiding a keylogger because it borrowed a familiar name
  costs everything. A signed third-party driver is still surfaced, because a signed kernel keylogger
  is still a kernel keylogger.
- The judgement is a pure, tested type: recognising the class driver despite casing and padding,
  refusing near-miss names (`kbdclass2`), refusing a class driver in the *other* stack, and never
  treating an unverifiable file as suspicious - WinSight does not cry wolf on files it merely failed
  to check. Verified live on a real machine: two filters, both Microsoft-signed class drivers, zero
  not installed by Windows.

### The camera/microphone monitor now actually alerts someone
- `CameraMicMonitor` describes itself as an OverSight-class real-time monitor and has done for a
  long time - but nothing ever hosted it. Its only caller was a CLI watch command that prints to a
  console, so someone using the app was never told their webcam had turned on, which is the entire
  point of that class. The detection engine was finished; the lifecycle around it was missing.
- `AvWatchHost` supplies it, the way `GuardianHost` does for persistence: the dashboard now hosts
  the poll loop for as long as it runs, raises a tray balloon when an app **activates** the webcam
  or microphone, and journals both activation and release so the record shows how long something
  was watching or listening. Releases do not raise a balloon - a device being freed is not a
  security event.
- It runs unconditionally rather than behind an opt-in, because it is read-only: it polls the
  capability records Windows already keeps. Ransomware protection stays opt-in because it alone
  writes. Localised across the three languages, and covered by lifecycle tests for the two risks a
  hosted poll loop actually has: a leaked thread, and an unsafe second start or dispose.

### The camera/mic alerting path can finally be tested without a webcam
- Verifying the balloon end-to-end meant owning a webcam: `CapabilityAccessReader` was sealed with a
  non-virtual `Read()`, so the alerting path could only be exercised by real hardware. This machine
  has none - its "Camera" devices are printers - and neither does any CI runner. **For a security
  product, an alerting path that cannot be exercised is a defect in its own right.**
- The reader now sits behind `ICapabilityAccessReader`, and two tests drive the whole chain from a
  scripted snapshot: an app taking the microphone reaches the subscriber with the app named, and a
  device *already* in use at startup is treated as the baseline rather than announced as new - which
  would otherwise cry wolf on every launch during a call.
- The read half was separately confirmed against live reality: the `av` scan correctly reported
  Discord holding the microphone open, matching the registry exactly.

### A tool-by-tool comparison against Objective-See, and the plan that follows
- New `docs/OBJECTIVE_SEE_PARITY.md`. WinSight is at **parity on the five tools that matter most** -
  BlockBlock and KnockKnock (Guardian and the persistence scan), LuLu (WFP outbound firewall),
  RansomWhere (canaries and burst detection) and OverSight (the camera/mic watch above) - while
  being one app instead of six, and it carries scanners Objective-See has no equivalent for (MCP,
  DNS cache, browser extensions, trusted roots, hosts, the alert journal).
- The genuine gaps, ranked by security value per unit of work: **process attribution** (in progress
  - a detection says what changed, never who), **keylogger/input-hook detection** (ReiKey-class, no
  coverage at all, no elevation needed), **loaded kernel drivers** (KextViewr-class, exactly what a
  rootkit leaves behind), then DLL-hijack analysis, a per-process drill-down view, and
  physical-access detection.
- Two things are deliberately *not* planned, and the document says so rather than implying them
  away: blocking file/registry writes needs a signed minifilter and an EV certificate, and a
  signature-info shell extension means putting a crash surface in every Explorer window.

### Process attribution, increment 1: the pure core that says *who* touched something
- Today a detection says *what* changed, never *who* changed it - the single biggest gap left in the
  product. Naming the process needs a kernel ETW session, which needs elevation, so the work starts
  with the parts that can be built and proven without either.
- New `WinSight.Attribution` project with the two pieces the rest will hang off, both pure and
  fully unit-tested:
  - `KernelPathNormalizer` translates what a kernel session actually reports into the form findings
    use: `\Device\HarddiskVolume3\...` to `C:\...`, and `\REGISTRY\MACHINE\...` /
    `\REGISTRY\USER\{sid}\...` to the `HKLM\` / `HKCU\` spellings the persistence enumerators emit.
    This is where attribution would fail *silently* - mistranslate and every detection simply comes
    back unattributed while the plumbing looks healthy - so the volume map and current-user SID are
    injected rather than read inline, and the cases that must refuse (unmapped volumes, `\??\` and
    other NT namespaces, another user's hive, the `_Classes` companion hive) are pinned as tightly
    as the ones that must translate.
  - `WriteAttributionIndex` remembers recent writes just long enough to answer "who did this?" when
    a detection lands, since a detection never arrives at the instant of the write that caused it.
    Bounded on both time and count, every timestamp explicit. It matches a finding that names the
    value inside a key (`...\Run [Updater]`) against an observed write to the key, but refuses a
    key that merely starts with the same text (`...\RunOnce`), and refuses anything outside the
    window - a confident wrong name beside a security finding is worse than no name.
- Nothing is wired up yet and no elevation is requested: the ETW session and the opt-in flow follow
  in the next increments.

### The "nothing leaves this PC" promise is now proven by tests, not just asserted in the README
- Coverage had never been measured. Measuring it found that `VirusTotalEnricher` - the only code in
  WinSight that can send anything off the machine - had **no tests at all**. Its guards (lookups must
  be switched on *and* a key present) were load-bearing for the product's central privacy claim and
  entirely unverified.
- The first attempt at tests would have been worthless: asserting "the result came back empty" also
  passes when a request was made and merely failed, so deleting a guard would not have failed
  anything. `Lookup` now takes an injectable stand-in for the client - the pattern already used for
  the journal's path and the burst detector's clock - and the tests assert the lookup was never
  *reached*. Confirmed by deliberately breaking the guard and watching the test go red. The real
  client is also now constructed only after the guards pass and there is something to ask about, so
  a scan that will not use it no longer opens one.
- `scripts/Measure-Coverage.ps1` makes this repeatable, with a per-assembly breakdown and an
  `-EngineMinimum` gate. It reports the detection libraries separately on purpose: the uncovered
  code is concentrated in WFP P/Invoke declarations, the service host and WPF code-behind, which
  unit tests genuinely cannot reach (VM validation and the packaged-installer tests cover those).
  Engine libraries sit at **84.1%**, every one of them above 80; shipped code overall is 63.7%.
  Chasing that global number would mean writing assertions against P/Invoke signatures - a number,
  not confidence.

### The alert journal is reachable over MCP, so a connected LLM sees what protection already caught
- The MCP server exposed the ten machine scanners but not the alert journal added in #91: a connected
  model could scan the machine's current state yet not read what WinSight's real-time protection had
  already flagged, including detections raised while the operator was away from the screen.
- New dedicated tool `winsight_alerts` reads the journal through the same projector as the scanners,
  so it inherits the identical privacy model - profile paths redacted unless the server was launched
  with `WINSIGHT_MCP_ALLOW_SENSITIVE=1`, results bounded, summary-only by default. It is deliberately
  a separate tool rather than a `winsight_scan` scanner: the journal is WinSight's own detection
  history, not a live machine snapshot, so `SnapshotCommands` stays exactly the ten scanners and the
  pinned catalog-parity test is untouched. The stdio integration test now negotiates four tools and
  calls the new one end-to-end.

## v0.9.0, 2026-07-21

WinSight's first release with real-time protection. Guardian watches persistence surfaces live
(BlockBlock-class); Phase 4 adds opt-in ransomware behaviour detection (RansomWhere-class), surfaced
as a header toggle; and every detection is journalled locally and shown in the dashboard, so a tray
balloon the OS suppresses never loses an alert. The WFP fix makes the Phase 2 firewall actually
enforce. The UI gained crash reporting, one shared button/design system, and a layout responsive
down to the minimum window size. Everything here is detect-and-alert and user-mode; blocking still
needs a signed kernel driver. Local-only, no telemetry.

### Ransomware protection moved to the header as a real-time toggle
- It used to be a lone checkbox at the bottom of the "Que voulez-vous vérifier ?" sidebar, wedged
  under the scan button among on-demand controls. That framed the single most consequential switch in
  the app - the only feature that *writes* to disk (decoy files), and a persistent background
  protection rather than a one-shot scan - as a minor scan option.
- It is now a switch-style toggle in the header, beside the "Analyse locale" status badge: a place an
  operator can read the protection's state from any screen. Off, the pill matches the neighbouring
  header controls; on, it turns security-green (shield, track and label) with the knob sliding across,
  matching the green of the status badge. Same `x:Name` and Checked/Unchecked handlers, so behaviour
  is unchanged - planting and removing decoys still work exactly as before.
- The header is now genuinely responsive. The logo is a fixed left anchor, the title/tagline sit in a
  flexible middle column where the tagline ellipsizes, and the right-hand cluster (settings, language,
  protection, status) stays fully visible as the window narrows - where before, at the minimum width,
  the added toggle pushed the status badge off the right edge and clipped it. The now-redundant
  "Langue" caption was dropped (the dropdown shows the language by name; screen readers still get it
  via AutomationProperties.Name), freeing the last of the room.

### Buttons follow one shared style instead of a dozen hand-written ones
- The dashboard had accumulated five different paddings (`12,0`, `12,5`, `10,4`, `14,7` and the
  default), four margin schemes, `MinWidth`s of 90, 120 and 150 picked per button, heights of 32, 42
  and unset, and default square WPF chrome sitting inside cards with 12px rounded corners. Each was
  reasonable when it was written; together they read as unfinished.
- `App.xaml` now holds the whole button system - one base style plus `Primary`, `Danger`, `Success`
  and `OnDark` variants - shared by the dashboard and the settings window. Hover and press are a
  translucent state layer over whatever colour the button already is, so one template covers every
  variant and none can be forgotten when a colour changes. Keyboard focus draws a real accent ring:
  the WPF default is a dotted rectangle that is invisible against these surfaces, and the app is
  meant to be navigable without a mouse.
- Spacing is a single 8px gutter carried by the buttons, with the container cancelling the trailing
  edge via a negative margin. That is what keeps the gaps identical whether a row wraps or not -
  per-button margins are exactly how the four different spacings appeared in the first place.
- Emphasis now means something: only the coloured variants are SemiBold. Beyond the hierarchy it
  reads better, it also keeps the secondary row narrow enough that the guidance text beside it is
  not squeezed.

### Nothing is cut off at the smallest window size any more
- Found while checking whether the results list scrolls (it always has - a `DataGrid` brings its own
  scrolling, and so does the tool list). The real defect was next to it: shrink the window to the
  minimum it advertised and the bottom of the page was clipped, taking the guidance text and the
  *Open file* / *Copy* / *Export* buttons with it. No scrollbar appeared, so there was no way to
  reach them at all. With the outbound-firewall controls on screen the results grid collapsed to
  nothing as well.
- Three causes, three fixes. The action buttons sat in an `Auto` column, which a Grid grants the
  width it asks for and then lets overflow, so at narrow widths they starved the guidance text down
  to a sliver that wrapped one character per line and still spilled the last button off the edge;
  their width is now capped at "the panel minus the width the text needs", which keeps the single
  row wherever one fits and wraps only where it does not. The results grid had a 200px floor that
  stopped the star-sized row from yielding, so the page overflowed instead of the grid shrinking.
  And `MinHeight` claimed 680 when the content genuinely needs 750, which is what it now says.
- Deliberately not fixed with a page-level `ScrollViewer`. That was tried first and is worse than
  the problem: measuring inside one makes the available height unbounded, so the star-sized row
  grows to its full content height, the results grid loses the internal scrolling it had, and the
  guidance panel is pushed off-screen. Verified on a real machine before reverting it.

### The alert journal is now readable from the dashboard, not just from disk
- Journalling a detection that only a text editor can read solves half the problem. "Alertes
  récentes" is a normal entry in the tool catalog, so the same list, filter, detail pane and JSON
  export that every other check uses now work on WinSight's own detection history - this is how an
  operator sees an alert raised while they were away from the screen.
- Every row is `Notable`, because everything in the journal is by definition something WinSight
  judged worth interrupting the operator for; the "show only what deserves attention" filter
  therefore hides nothing here. Rows carry `time`, `source`, `kind` and `detail` as structured
  fields, so the JSON export stays machine-readable rather than re-parsing a display string.
- It is deliberately **not** part of the overview scan: the overview answers "what does this machine
  look like right now", and history is a different question. It also reads rather than inspects the
  machine, making it the one tool that costs nothing to open.
- An empty journal reads as "no real-time detections recorded yet", never as a failure - a fresh
  install has no history and that is the expected, reassuring case.

### Detections are journalled locally, so a suppressed balloon no longer loses them
- Live testing made the weakness concrete: a detection's only visible output was a tray balloon, and
  Windows is free to drop those - Focus Assist ("Ne pas déranger", including its automatic
  full-screen rule) suppresses them, and the shell throttles an app posting several toasts quickly.
  Both are indistinguishable from "nothing was detected", and a security tool must not depend on a
  single channel the OS may silently discard.
- `AlertJournal` (in `WinSight.Application`) appends every Guardian and ransomware detection to
  `%LocalAppData%\WinSight\alerts.log` - **before** the balloon is raised, so the record exists even
  if the balloon never appears. Local-only, never sent anywhere; bounded to the newest
  `MaxEntries` so it cannot grow without limit; and it never throws, because journalling a detection
  must not become the thing that breaks the monitor that detected it. Fields containing tabs or
  newlines are sanitised so an attacker-influenced filename cannot corrupt the journal or split one
  record into two. Unlike a balloon it records the full path: a balloon can be shoulder-surfed or
  land in a screenshot, whereas the journal is the place you open precisely to learn *which* file
  was touched. The path is injectable and the tests use a temp one, so the suite never writes into
  the operator's real journal (the mistake caught in #88).

### Docs brought back in line with what actually ships
- `RANSOMWARE_DESIGN.md` still said "increments 1–2 implemented" while listing 3 and 4 as done, and
  described the burst detector without mentioning that **someone has to re-arm it** - the exact
  omission behind the bug below. Status, increment list, and that design obligation are now correct.
- `README.md` listed Phase 4 as upcoming and claimed "everything is read-only", which stopped being
  true when ransomware protection started planting decoys. It now states what ships and names the two
  deliberate, opt-in exceptions. `ARCHITECTURE.md` no longer calls ransomware behavior deferred.

### Ransomware protection re-arms after an alert instead of going silent for the session
- Found by testing the installed build end-to-end on a real machine, not by reading the code: after
  the first alert (a touched canary or a rename/delete burst), `RansomwareBurstDetector` stayed
  "fired" forever - by design it fires once per burst, but nothing ever called `Reset()`. A second
  wave of encryption, or a burst the operator missed the first time, produced no further alert for
  the rest of the session. For a security tool, a silence that no longer means "nothing is
  happening" is worse than not alerting at all. `RansomwareMonitor` now re-arms the detector right
  after forwarding each `Detected` event, so the next burst or canary touch alerts again. A new test
  (`Monitor_ReArmsAfterAnAlert_SoASecondWaveStillFires`) touches the canary twice and asserts two
  separate alerts.
- Diagnosed via a from-scratch, step-by-step trace (subscribe → Start → FileSystemWatcher event →
  classify → burst detector → Dispatcher.Invoke → ShowBalloonTip) that confirmed every step up to
  and including `ShowBalloonTip` returning successfully; the earlier appearance of "no alert" during
  investigation was Windows' own per-app toast throttling after many rapid manual tests in the same
  session, not a code defect - confirmed by Guardian's independently-working alert also going quiet
  under the same conditions.

### The dashboard now records crashes instead of vanishing
- Investigating a reported crash during analysis turned up something worse than the crash: the app
  had **no unhandled-exception handling at all** - no `DispatcherUnhandledException`, no
  `AppDomain.UnhandledException`, no `UnobservedTaskException`. A failure killed the process with no
  message, no log, and nothing reliable in the Windows event log, so "it crashed" was impossible to
  act on by design.
- `CrashReporter` now hooks all three channels and writes a local report
  (`%LocalAppData%\WinSight\crashes`) with the exception, stack, version and OS - diagnostics only,
  no scan findings, never sent anywhere. Reports are capped so a crash loop cannot fill the disk, and
  capture itself swallows failures: reporting must never become the thing that crashes the app. A UI
  exception is recorded and the app keeps running, because for a monitoring tool staying alive
  preserves protection.
- Two follow-ups found by running it for real: the capture test wrote into the **real**
  `%LocalAppData%` crash folder, leaving files in the user's own application data - it now takes an
  explicit directory and uses a temp one. And that test then proved `TryCapture` could still throw:
  a malformed path raises `ArgumentException`/`NotSupportedException`, not `IOException`, so the
  guard missed it. Both are now covered, and the "never throws" promise actually holds.

### Security review of the new real-time code, before shipping it
- **A concurrency defect that could silently kill filesystem monitoring.** Both watchers set
  `FileSystemWatcher.EnableRaisingEvents` inside their create helper, so an event could fire on a
  thread-pool thread while `Start` was still registering watchers - reading `_targetByWatcher` while
  that `Dictionary` was being written. A Dictionary read racing a write can throw, return garbage, or
  spin forever; the failure mode was the persistence monitor's filesystem half dying quietly, which
  is the worst thing a security tool can do. Events now begin only after every watcher is registered.
- **A shutdown race.** `Dispose` iterated the watcher list outside the lock while `Start` could still
  be appending to it. Both watchers now snapshot the list under the lock before iterating.
- **The entropy sampler no longer follows reparse points, and never opens a directory.** A file
  dropped into a watched folder can be a symlink or junction pointing at a device or a slow network
  share, and reading it would block a thread-pool thread - so anyone able to write into the user's own
  folder could starve the monitor. Links are now detected, not followed.

### Phase 4 (ransomware): entropy-on-write sampling
- The third detection signal lands, with the anti-false-positive gating that was the reason to defer
  it. `RansomwareEntropySampler` reads a bounded 4 KB prefix - with sharing flags that never fight the
  writer, and returning false rather than throwing on any I/O trouble - and scores it with
  `ShannonEntropy`. Formats **compressed by design** are skipped outright: .zip/.jpg/.mp4 and,
  critically, .docx/.xlsx/.pptx, which are ZIP containers whose entropy is legitimately near maximum.
  Scoring those would flag a user saving a Word file as ransomware. Ransomware's own extensions
  (.locked, .encrypted, …) are still scored, and in-place encryption keeping the original extension
  stays covered by the canary. The classifier gained a `looksEncrypted` argument (defaulted, so
  existing behaviour is unchanged) and the watcher only scores a create/change of an ordinary file.

### Phase 4 (ransomware): opt-in dashboard protection + alert
- The dashboard now exposes ransomware protection as an **opt-in** toggle, cleared by default. This is
  the only WinSight feature that *writes* into the operator's personal folders (everything else only
  reads), so nothing is planted until they ask for it; clearing the toggle or closing WinSight removes
  every decoy. Planting runs off the UI thread.
- `CanaryManager.RemoveOrphans` sweeps decoys left behind by a run that died without disposing (a
  crash or a kill), so the user's folders never accumulate hidden files; the monitor calls it before
  planting. A real user file matching nothing of ours is never touched (asserted by a test).
- `RansomwarePresenter` maps a detection to a localization key and a detail line that shows only the
  file NAME, never the directory tree - an alert cannot leak a folder layout into a screenshot or a
  shoulder-surfed balloon. A touched canary is presented as critical, a rename/delete burst as a
  warning, on the proven `ShowBalloonTip` path, localized en/fr/es.

### Phase 4 (ransomware): canary planting + file watcher
- The thin I/O layer over the heuristics core, all user-mode (it watches the user's own
  Documents/Desktop/Pictures - no elevation). `CanaryManager` plants hidden decoy files and answers
  `IsCanary`; `RansomwareSignalClassifier` (pure, tested) maps a filesystem change to a signal;
  `RansomwareFileWatcher` runs a `FileSystemWatcher`, classifies each change, and feeds the bounded
  burst detector, raising `Detected` once; `RansomwareMonitor` wires planting + watching and removes
  the decoys on dispose. A touched canary fires immediately (a decoy has no legitimate reason to
  change); a rename/delete burst fires once. Validated by real-`FileSystemWatcher` functional tests
  (canary touch, rename burst, plant-detect-cleanup). Entropy-on-write is deliberately not wired yet:
  legitimately compressed files (.docx/.jpg/.zip) are high-entropy and would false-positive.
  Attribution (which process) and stopping the write both need elevation / a minifilter - deferred.

### Phase 4 (ransomware): heuristics core
- First slice of RansomWhere-class behavior detection: a pure, unit-tested `WinSight.Ransomware`
  core, same "decisions in a tested core, thin watcher later" discipline as the firewall and Guardian.
  `ShannonEntropy` scores a byte buffer in bits/byte and flags "looks encrypted" only above a
  conservative threshold *and* a minimum sample size, so a tiny high-entropy fragment cannot trigger.
  `RansomwareBurstDetector` is a bounded, clock-injected sliding-window counter that fires exactly
  once per burst - or immediately on a touched canary/decoy - and stops accumulating until `Reset`,
  so a flood cannot grow its state. Detect-and-alert only; the file-system watcher, canary planting,
  entropy-on-write sampling, and dashboard alert are the next increments, and *stopping* the
  encryption needs a minifilter + EV cert (deferred). See `docs/RANSOMWARE_DESIGN.md`.

### Guardian: scoped re-scan - near-instant detection
- A change now re-scans only the surface that fired, not all 22. The change source carries the watch
  target that fired (`PersistenceSurfaceChangedEventArgs.ChangedTargets`); the monitor maps it to the
  owning enumerator(s) via `WatchTargets` and re-scans just those, falling back to a full scan when
  the origin is unknown. Validated on a real machine: detecting a new HKCU Run value dropped from
  ~20s (a full re-scan that also re-verifies signatures) to **~0.5s** (a 500 ms debounce plus a
  ~30 ms scoped scan). Writing-process attribution and live WMI/ETW surfaces stay deferred - both
  need elevation, which would break the unprivileged in-dashboard model; a future opt-in elevated
  "deep monitoring" mode could add them.

### Guardian: broaden real-time coverage to more registry persistence surfaces
- The live registry watcher now covers, beyond Run/Services/Winlogon, the high-value surfaces most
  abused for persistence: Image File Execution Options (IFEO debugger hijacks), AppInit_DLLs, Active
  Setup, SilentProcessExit, LSA packages, BootExecute, AppCertDlls, time providers, print
  monitors/providers, netsh helpers, credential providers, browser helper objects, and Windows
  Load/Run - ~17 live surfaces in total. Each just declares `WatchTargets` and reuses the proven
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
  and - since Guardian re-scans fully on every change - the cache avoids re-verifying unchanged
  binaries each time. Re-validated on a real machine: `notepad.exe` now reads `SignatureValid`,
  signer `CN=Microsoft Windows`.

### Guardian: on-start reconciliation across runs
- The baseline is now persisted across runs, so persistence that appears while WinSight is not
  running surfaces on the next launch (once), instead of being silently absorbed into a fresh
  baseline. `FilePersistenceBaselineStore` writes a small local-only file
  (`%LocalAppData%\WinSight\guardian-baseline.tsv`, atomic temp+move, bounded, corrupt-tolerant -
  a missing or malformed file is treated as a first run, never a crash). `PersistenceMonitorCore`
  gains `ReconcileFromPersistedBaseline`: it diffs the current scan against the persisted baseline,
  surfaces the new entries, then resets the baseline to exactly the current state so items removed
  while WinSight was off drop out and cannot re-alert. Wired by default via `GuardianHost`; a first
  run with no saved baseline stays silent and only records one for next time.

### Guardian: real-time persistence monitoring (Phase 3, BlockBlock-class)
- The persistence scanner is promoted from on-demand to live. The 22 autostart enumerators stay
  the single source of truth; new watchers are only dumb triggers. On a change signal the monitor
  debounces, re-scans the affected surface, diffs against a baseline, and surfaces genuinely new
  entries - verdict-checked through the same Authenticode path as the manual scan.
- **Pure core** (`PersistenceIdentity`, `PersistenceDiffEngine`, `PersistenceChangeLog`,
  `PersistenceMonitorCore`): bounded like `PendingOutboundLog` (caps at `MaxChanges`, counts
  dropped arrivals instead of silently truncating), seeds a silent baseline on first scan so a
  machine does not alert on pre-existing persistence, and reports each new entry once. Fully
  unit-tested.
- **Registry watcher** (`RegNotifyChangeKeyValue` on Run/Services/Winlogon) and **filesystem
  watcher** (`FileSystemWatcher` on the Startup folders and `\System32\Tasks`), combined by a
  composite source. Each has a real-Windows functional test (private HKCU key, temp folder) that
  asserts a change actually signals - validated off a VM.
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
  removed the filters, and reported `Degraded`. Enforcement never survived enabling - or a reboot -
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

### Firewall: enforcement can be enabled again - the product can actually filter
- WinSight could not block anything. `EnforcementCoordinator.EnableAsync` existed, but nothing
  could reach it: the console verb `enforce-enable` was disabled by the LocalSystem hardening
  (6d5d908), and the pipe's `IFirewallMutationAuthority` only ever exposed UpsertPolicy,
  RemovePolicy and EmergencyDisable. The machine had a brake and no accelerator, so it was stuck
  in audit-only permanently: policies were saved and reported, and never filtered. Verified on a
  real VM - the dashboard offers only "Emergency disable".
- This is the "separate, later, explicitly gated increment" the dispatcher documented. Enabling
  enforcement now goes over the authenticated pipe as `FirewallCommand.EnableEnforcement`, which
  keeps both invariants that were in tension:
  - the hardening's invariant - only the SYSTEM service mutates WFP, after validating its trusted
    storage. The console stays out of the WFP engine; re-enabling the console verb would have
    reopened exactly the hole 6d5d908 closed.
  - the original design's invariant - enabling is "not something the unprivileged dashboard can
    trigger". It is a mutation, so it needs `MutateMachinePolicy`: an elevated administrator or
    SYSTEM. An unprivileged dashboard holds only `ReadStatus` and is refused. Confirmed on a real
    VM in both directions: non-elevated dashboard reads the state but is refused the mutation;
    elevated is accepted.
- Enforcement is refused outright when the engine cannot filter, rather than persisting a mode
  that reports as armed while nothing is enforced. That case is now reported as its own outcome
  ("this machine has no usable filtering engine") instead of collapsing into a generic rejection
  a user might retry, expecting protection that could never arrive.
- Dashboard: an "Enable enforcement" button sits next to the emergency disable - accelerator and
  brake in one place - with a confirmation that states plainly that saved blocks take effect
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
    or delete the already-existing, independently protected next link - that needs
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
  legitimate installed shim as unsigned/suspicious - a guaranteed false positive. Removed
  it; the credential-provider, browser-helper-object and Windows Load/Run surfaces stay.

### Firewall: block feedback now tells you whether it is actually enforcing
- A block only filters traffic once enforcement is enabled (an elevated action). Blocking
  an app while enforcement was off said "applied" yet nothing happened on the network - the
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
