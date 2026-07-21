## Unreleased

Step-by-step progress log. Newest first. Every CI-green step lands here.

### `hijack`: services another program could run in place of — a vector macOS does not have
- Parity gap #4, and the one place a Windows tool should be *ahead* of the Objective-See family
  rather than catching up. Windows registers a service as a **command line**, not a path, so an
  unquoted `C:\Program Files\My App\svc.exe` is attempted as `C:\Program.exe` first. Anyone able to
  create that earlier file gets their code run by the service's account — usually SYSTEM, at boot,
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
  MCP-count pinning site turned up** that earlier notes did not list —
  `AdaptersTests.SnapshotCommands_AreUniqueAndComplete` — alongside the MCP integration test,
  `scripts/Test-McpServer.ps1` and the catalog.

### CI: `package` no longer waits for `build-test`
- Measured, not guessed: the wall clock was **8m18** — 2m37 of build and test, then 5m38 of
  packaging that had been queued behind it. Nothing was being reused, because the package job runs
  `Build-Release.ps1` and publishes from source itself, so the dependency serialised two unrelated
  jobs. Run together, the same work lands in about **5m40**, the length of the longest job.
- Formatting and the dependency audit deliberately stay **inside** `build-test` rather than becoming
  a third job: `build-test` is the required status check on `main`, so moving them out would leave
  the required check unable to fail on a formatting violation — protection quietly weakened while
  looking unchanged. They are reordered ahead of the build so a violation is reported without
  waiting for a compile and a full test run.

### A Startup folder nobody could list used to report as an empty one
- The same shape as the scheduled-tasks defect, in the other classic drop point. `StartupFolderEnumerator`
  answered a folder it could not list with an empty array, so a re-ACLed Startup folder — which is
  what somebody hiding a shortcut there would arrange — reported clean. It now counts the folder
  through the coverage mechanism added for scheduled tasks, and the scan summary names it.
- A folder that simply **does not exist** stays quiet: a machine with no all-users Startup folder is
  ordinary, and treating absence as refusal would trade a false reassurance for a false alarm.
- **The test denies itself the ACL rather than faking the symptom.** A first attempt stood a plain
  file in for a locked directory; it passed for the wrong reason — `Directory.Exists` is false for a
  file, so nothing ever threw and no gap was counted. The test now creates a real deny-listing ACE
  on a real directory, which is the situation being defended against, and lifts it again on
  teardown. Mutation-verified.

### An unreadable hosts file used to report as a clean one
- Continuing the audit that produced v0.9.1, applied to the rest of the scanners. `HostsReader`
  answered a file it could not open with an empty list, so the report read **"0 hosts entry(ies),
  0 flagged"** — indistinguishable from a machine with nothing in its hosts file.
- **This one is a detection, not just honest reporting.** On Windows the hosts file is readable by
  every user by default. If WinSight cannot read it, its permissions were changed — which is
  precisely the next move for someone who has just pointed a bank or an update server at their own
  address. It is now a `Notable` finding in its own right, and the summary says the contents are
  unknown rather than implying they are clean.
- A genuinely **absent** hosts file is reported as absent and stays quiet: Windows works fine
  without one, and conflating "no file" with "refused" would only trade one false reassurance for a
  false alarm.

## v0.9.1, 2026-07-22

A corrective release. Every item below is a case of WinSight **looking healthy while seeing
nothing** — the one failure mode a security tool must not have. All four were found the same way:
by running the real CLI elevated and unelevated and comparing, rather than by reasoning about the
code. Three of them were shipped in v0.9.0.

**Scheduled tasks were entirely invisible unless you ran WinSight as Administrator.** A top-tier
persistence vector, listed among the covered surfaces, returning zero rows and reading exactly like
a clean machine — 0 unelevated against 104 elevated on a real desktop, including one item already
flagged as suspicious. Now read through the Task Scheduler service, which needs no elevation and
sees more: **81 unelevated (was 0), 104 elevated (unchanged, so nothing regressed).**

**A program launched by bare name had no identity at all** — `powershell.exe`, `cmd /c …`, `node`,
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
  unelevated, 104 elevated** — Brave, Edge, NVIDIA, OneDrive and Google updaters, and one already
  flagged as suspicious.
- The cause was a reasonable-looking decision compounding into a silent total failure. The
  enumerator parsed the XML files under `%SystemRoot%\System32\Tasks` "to avoid a COM dependency".
  That directory is administrators-only, and `Directory.GetFiles` does not skip what it cannot
  enumerate — **it throws for the whole tree**. The exception was caught and turned into an empty
  list, so one denied directory became "this machine has no scheduled tasks".
- **Reading through the Task Scheduler service needs no elevation and sees more**: 195 registered
  tasks visible on the same machine, against 104 files the elevated scan could open. It returns the
  identical XML, so the parsing that was already tested is reused unchanged. Measured after the
  change: **81 tasks unelevated (was 0), and 104 elevated — byte-for-byte the previous elevated
  result, so nothing regressed.** The 23 still unseen unelevated are tasks this user genuinely
  cannot enumerate, which is the correct answer rather than a hidden one.
- **A scan now reports what it was not allowed to read.** `ScanWithCoverage` returns the entries
  plus a `PersistenceCoverage`, and the summary line names the gap — a surface that failed outright
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
  a path the pending log rejected — so a machine quietly losing connections reported zero. A health
  counter that reads clean while the thing it measures is failing is worse than no counter.
- The population it was missing is exactly the one worth knowing about: the same bare-name launches
  that were invisible to attribution — `powershell.exe`, `cmd`, `node`. The watcher now indexes
  those under their kernel-reported image name and reports the connection as unattributed, with a
  name where there is one and the process id either way.
- **It still cannot be ruled on, and that is deliberate.** An unattributed connection never reaches
  the pending log: that log is the list of apps the operator may Allow or Block, and a rule keyed on
  the bare name `powershell.exe` would apply to every powershell on the machine whatever its origin.
  Counting and naming it is the honest answer — the connection is known to have happened, and known
  not to be rulable.

### `powershell.exe` was invisible to attribution *and* to the outbound firewall
- A process's identity is captured at start, from the command line the kernel reports, and anything
  that did not yield a fully qualified path was **discarded entirely**. Measured against a live
  kernel session, that was **9% of every process start on an idle desktop** — and not obscure ones:
  `powershell.exe`, `cmd /c npx …`, `node`, `smss.exe`, `csrss.exe`, `wininit.exe`. Launching by
  bare name through the search path is how living-off-the-land attacks run, so the tool was blind to
  precisely the launches that matter most. Both write attribution and the outbound firewall are
  built on this same index.
- **The Windows directory is now expanded** — `\SystemRoot\…`, `%SystemRoot%\…`, `%windir%\…` —
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
  probe's own long-lived process — the easy case, which passed. A short-lived `reg.exe` that writes
  a key and exits, which is the actual dropper pattern, failed outright: the key resolved fine and
  the *process* could not be named. It now passes on real hardware.

### The `persistence-live` report is gone; the alert carries its verdict instead
- A whole parallel report of the session's arrivals was built, unit-tested, and **never rendered by
  anything**. Guardian's detections reach the operator through the alert journal, which does the
  same job and survives a restart and a suppressed balloon — the failure modes the journal exists
  for. A second, unreachable rendering path in a security tool is worse than none: it drifts from
  the live one while still looking tested.
- The one thing it showed that the journal did not — the signature verdict — moved into the journal
  line. "A new startup item appeared" and "an *unsigned* new startup item appeared" are different
  emergencies, and an operator reading an alert hours later needs that in the same sentence.

### Attribution named the wrong program, and an elevated probe on real hardware caught it
- The correlation rule let a detection match an observed write when the detection's target
  *continued past it at a boundary* — designed for `…\Run` answering a finding spelled
  `…\Run [Updater]`. A backslash was one of those boundaries, and a backslash does not mean "the
  same thing, spelled more fully": it means a **deeper key**. So any program that wrote anywhere
  under `HKCU\Software` became the author of every finding beneath it. On the very first live run,
  a browser touching a shared ancestor was reported as the author of a key it had never touched.
- **Every unit test passed throughout.** They pinned the rule that was written, using spellings that
  were assumed rather than observed. What broke the tie was asking the kernel: a probe run elevated
  on real hardware showed that a registry value write is reported as the **key**, uppercased, with
  no value name appended — so a legitimate finding is always the observed key, or that key plus a
  display suffix, and never a deeper one. Removing the backslash boundary costs nothing real and
  removes a whole class of false attribution.
- Health counters split `UnresolvedTarget` into `UnannouncedKey` and `UntranslatablePath`. They look
  the same from outside — a write nobody could name — but one is a gap in the kernel's bookkeeping
  replay and the other a gap in WinSight's namespace mapping, with different fixes. The first live
  run reported 114 unresolved against 2 attributed, and that number was useless until it could be
  split; it is now known to be almost entirely unannounced key handles.

### Attribution reaches the alert: a persistence detection can now name the program that installed it
- The correlation index and the ETW watcher were built and tested separately, and nothing joined
  them, so a detection still could not answer the question the whole feature exists for. New
  `AttributionHost` is that join: it owns the watch's lifecycle, feeds the index, and answers
  "who wrote this?" — and Guardian's journal line now carries `written by <path> (pid)` when it can.
- **The host reports its own health, because "no answer" hides three different situations.**
  Attribution can be unavailable (not elevated), running and blind (a key handle the kernel never
  announced), or working and genuinely finding nothing. Collapsing those into one silent empty
  answer is how a monitor gets trusted when it should not be, so `AttributionHealth` counts what was
  attributed, what was seen but unattributable and why, and whether the watch was refused outright.
- **Started only when elevated, and never demanded.** A kernel trace session is privileged and
  WinSight is deliberately unprivileged by default, so an unelevated dashboard simply carries no
  author on its alerts. Attribution is an enrichment: a detection is never withheld because nobody
  could name its author, and a name is never invented when the lookup has none — including when a
  neighbouring key was written at the same moment, which is pinned by a test.
- **The watch is now testable without Administrator.** `IWriteWatcher` exists for the same reason
  the capture-device reader has a seam: a component whose only implementation needs elevation is a
  component whose lifecycle nobody ever exercises, and an untested lifecycle around a security
  monitor is how a monitor comes to be silently dead. Start/stop, idempotence, refusal and prompt
  shutdown are all covered by a scripted watcher.
- The journal line moved out of the WPF event handler into the tested presenter, and a test round-
  trips it through the journal's own format — a detail carrying a tab would have made its own
  record unparseable, writing the alert and then losing it.

### Kernel drivers: WinSight can now answer "what is running inside the kernel?"
- Priority #3 in the parity analysis, and the cheapest genuine capability still missing. A kernel
  driver runs with the same authority as Windows itself: it can hide files from every other scan
  WinSight performs, read any process's memory, and make itself invisible to everything above it.
  That is what a rootkit leaves behind, and WinSight listed none of them.
- New `drivers` scanner (`WinSight.Drivers`), no elevation required: the service control manager's
  own registry names every driver Windows can load, its type, its start disposition and its image,
  and the verdicts come from the Authenticode path every other scan already uses. In the dashboard,
  the CLI and over MCP. Left out of the balanced overview on the `processes`/`modules` precedent —
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
  carry a longer name off the same issuer — `Microsoft Windows Hardware Compatibility Publisher`,
  `… Hardware Abstraction Layer Publisher`, `… Early Launch Anti-malware Publisher` — every one of
  which a substring match on "Microsoft Windows" swallows whole. Bring-your-own-vulnerable-driver
  attacks live in precisely that gap. So the common name is compared entire, and the image must
  also sit inside the System32 tree: a genuine Microsoft driver running from a download folder is
  a finding, not an expectation. Live, that test correctly keeps WireGuard and `wintun` — both
  Microsoft-attested — out of the 418 drivers Windows actually ships.
- **`--flagged` narrows harder here than in the input scan, on purpose.** That one flags every
  driver Windows did not install because its list is two lines long; this one is 450, since every
  disk, display and network component registers a driver. A flagged view that answers with eighty
  rows is a flagged view nobody opens twice, so only the two conditions nothing explains away
  survive it: a signature that did not stand up, and a registration whose image is gone. Signed
  third-party drivers stay in the full listing, where they are context rather than noise.
- An unverifiable driver gets its own answer instead of being quietly filed as third-party. Not
  flagging `Unknown` is the standing rule and it holds — but calling it third-party would assert a
  provenance never established, and would hide a condition worth seeing, because when catalog
  verification fails it fails for every catalog-signed file at once.
- **Verified live, and it found things.** 450 drivers registered, 418 shipped by Windows, 26 signed
  by other publishers (Intel, NVIDIA, Realtek, Oracle, Proton, SteelSeries, WireGuard), 6 flagged:
  two in-box Windows 11 drivers carrying no signature at all — `bthmodem.sys` and `usb80236.sys`,
  both confirmed independently — and four registrations pointing at files that no longer exist, one
  of them a Windows Setup filter still set to load at boot, two of them leftovers from uninstalled
  anti-cheat drivers.
- Building it exposed a pre-existing weakness in `AuthenticodeVerifier` that deserves its own fix:
  the catalog fallback spawns `powershell.exe` without sanitising `PSModulePath`, so a WinSight
  started from a PowerShell 7 session hands Windows PowerShell 5.1 PowerShell 7's copy of
  `Microsoft.PowerShell.Security`. That module fails to import and takes `Get-AuthenticodeSignature`
  with it, degrading every catalog-signed file to `Unknown`. This is the first scan to push hundreds
  of them through that path at once, which is why it surfaced now — and it is not cosmetic: it hid
  both genuinely unsigned drivers above until the environment was cleaned.

### Process attribution, increment 2: the live ETW session, and what testing it actually found
- The watcher that answers *who*, not just *what*: an elevated kernel session that reports registry
  and file writes already attributed to the process that made them, feeding the correlation core
  from increment 1. Available as `winsight attribution --watch` (Administrator), which is also how
  it was verified — the dashboard wiring follows in the next increment.
- **Registry ETW does not report the key you would recognise, and the first version failed
  silently because of it.** A write names a *key control block* handle plus, at most, a name
  relative to it; the full path is announced separately when the kernel opens the key. Run
  elevated, that first version printed a healthy-looking burst of fully-qualified keys and then
  recorded nothing at all — the burst was only the rundown of keys already open, and every live
  write went past unresolved. It looked like it was working. `RegistryKeyResolver` now keeps the
  kernel's announcements and joins them, which turned live capture on: verified with a real write
  arriving as `HKLM\SOFTWARE\…\CPSS\DevicePolicy\AllowTelemetry`, attributed to the process.
- Increment 1's path translation was confirmed against reality in the same run: `\REGISTRY\MACHINE`
  read back as `HKLM\`, the current user's hive as `HKCU\`, and the `_Classes` companion hive stayed
  distinct as `HKU\{sid}_Classes` — the decision that was argued for in tests, now observed.
- File writes are filtered at the source, and the default filter accepts nothing. A busy machine
  writes thousands of files a second; feeding those into a bounded index would evict every useful
  observation within seconds, leaving it full and useless at the moment a detection asked it a
  question. Registry writes are not filtered — they are orders of magnitude rarer and are where
  persistence lives.
- **A watcher that cannot say what it missed is indistinguishable from one that is broken.** The
  first version silently discarded every write it could not attribute — the same shape of defect as
  the signature verifier that swallowed its child's stderr. `Watch` now optionally reports
  unattributable writes with the reason: an unknown process, an unannounced key handle, or a key
  that resolved but would not translate. That is a feature, not scaffolding: an operator who is
  told "four hundred writes seen, twelve unattributed" can calibrate; one told nothing cannot.
- **It immediately found a real defect that reading documentation would not have.** Every
  user-hive write was being refused. A plain write to `HKCU\Software\…` does not arrive as
  `\REGISTRY\USER\{sid}\…` at all — it arrives as
  `\REGISTRY\WC\Silo{guid}user_sid\Software\…`, the Windows Container namespace, because Windows
  routes user-hive access through a silo. Machine-hive writes sailed through the whole time, so the
  watcher looked *partly* healthy, which is the worst kind of broken. The normaliser now translates
  that shape, and only that shape: a silo whose segment does not end in `user_sid` is refused rather
  than guessed at, because a container's hive is not the operator's. Verified live afterwards —
  `powershell.exe (pid 2856) → HKCU\Software\Microsoft\SystemCertificates\…` — with untranslatable
  keys dropping from thirteen to three in the same sample.
- **Known limit, measured rather than estimated:** in that same sample, 5,774 writes could not be
  resolved because the kernel never announced their key handle — the key was already open when the
  session started. Keys opened *during* a session resolve correctly, so a long-running monitor
  recovers as keys are reopened, but a short observation window sees a large blind spot. This is
  now visible in the numbers instead of being invisible, which is the prerequisite for fixing it.
  Increment 3 starts there.

### The scan that gives every other kernel finding its meaning
- The drivers scan can say a kernel driver is unsigned. It cannot say whether that *matters*. On a
  machine with test signing turned on, an unsigned driver is not an anomaly at all — it is the
  documented consequence of a setting, and the real finding is the setting. Nothing in WinSight
  asked that question.
- New `integrity` scanner (`WinSight.CodeIntegrity`), no elevation: driver signature enforcement,
  test signing, memory integrity (HVCI), Secure Boot, and whether a kernel debugger is attached. In
  the balanced overview, because it is six lines and reframes everything else.
- **Asked of the kernel, not the registry.** `NtQuerySystemInformation` reports what is actually
  being enforced; the policy keys record what somebody configured. A pending reboot, a policy that
  failed to apply or a hypervisor that could not start all make the two disagree — the same
  distinction the WFP "effective state" fix turned on.
- **Two volumes, deliberately.** Test signing on, driver signing off, or a debugger attached change
  what the machine will load, so they are `Weakened`. Secure Boot and memory integrity being off are
  weaker settings that a great many healthy machines have — reporting those at the same volume would
  train the operator to ignore the scan, so they are `Hardening`. HVCI in *audit* mode is called out
  separately: it reads as enabled everywhere in the UI while enforcing nothing, which is exactly the
  false comfort this tool exists to remove. Anything unreadable is never counted as a weakness.
- Every protection is reported even when healthy, so the reader can tell "verified good" from "never
  looked". Verified on a real machine: driver signing on, test signing off, HVCI enforcing in strict
  mode, no kernel debugger — and **Secure Boot off**, the one thing worth telling its owner.

### Signature verification was failing open, silently, and hiding real findings
- Found while reviewing the drivers scan: it reported four flagged drivers here but six on the
  machine that built it. Same binary, same machine, same minute — the difference was **which shell
  launched it**.
- `AuthenticodeVerifier` shells out to Windows PowerShell, and a child inherits the parent's
  environment including `PSModulePath`. Launched from a PowerShell 7 session it pointed at PS7's
  module directories; Windows PowerShell 5.1 then failed to import
  `Microsoft.PowerShell.Security`, so `Get-AuthenticodeSignature` did not exist and the command
  produced no output at all. Every catalog-signed file degraded to `Unknown`.
- **The failure was invisible twice over**: `Unknown` is deliberately never treated as suspicious,
  and the child's stderr is discarded. So the scan looked healthy while 450 kernel drivers came
  back as 269 trusted / 177 unknown instead of 444 trusted / 2 unsigned — and **two genuinely
  unsigned kernel drivers were simply absent from the results**. This affected every scanner that
  verifies a signature, not just the new one: persistence, processes, modules, keyboard filters.
- Fixed by pinning the child's `PSModulePath` to Windows PowerShell's own module directory.
  Regression tests deliberately pollute the variable first — a test that only ran in a clean
  environment would never have caught this — and were confirmed by removing the fix and watching
  them fail.

### Camera/mic alerting verified on real hardware, and the alert made readable
- Verified end-to-end at last, by driving real device acquisitions rather than reasoning about them.
  **Microphone:** a real hardware transition produced `MicrophoneActivated` in the journal 1.5s
  later (the poll interval), `MicrophoneDeactivated` 0.6s after release, and a tray balloon on
  screen. **Webcam:** confirmed too, and it turned out not to need a camera at all — an app holding
  the webcam *capability* is enough, so `WebcamActivated`/`WebcamDeactivated` were captured on a
  machine whose only "Camera" devices are printers. The whole chain — device →
  CapabilityAccessManager → reader → diff → host → journal and balloon — is now confirmed against
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
  register in the consent store — Windows records an app only once the device is genuinely
  streaming. That is the correct boundary rather than a blind spot: without a stream no samples are
  delivered, so nothing is actually hearing or watching.

### Keyboard interception: WinSight can now answer "what can read my keystrokes?"
- The clearest capability gap in the parity analysis, and the one an operator most wants answered.
  macOS lets ReiKey enumerate event taps outright; Windows exposes no documented way to list
  `SetWindowsHookEx` hooks. But a *serious* keylogger does not use a user-mode hook — it installs a
  **filter driver on the keyboard or mouse device stack**, where it sees every keystroke in the
  kernel before any application does. Those are plainly readable from the device setup class keys,
  which makes this both the highest-signal and the most honestly detectable form of input
  interception on this platform.
- New `input` scanner (`WinSight.InputHooks`), no elevation required: a registry read plus the same
  Authenticode verification every other scan uses. Available in the dashboard, the CLI, the balanced
  overview and over MCP.
- **No vendor allowlist, deliberately.** Touchpad and remote-desktop drivers legitimately sit here
  and it is tempting to hard-code their names as benign — but nothing stops a keylogger calling
  itself `SynTP`. Only the class driver Windows itself installs (`kbdclass` / `mouclass`) is treated
  as expected; everything else is reported with its signature standing and the operator decides.
  Reading one extra line costs a moment. Hiding a keylogger because it borrowed a familiar name
  costs everything. A signed third-party driver is still surfaced, because a signed kernel keylogger
  is still a kernel keylogger.
- The judgement is a pure, tested type: recognising the class driver despite casing and padding,
  refusing near-miss names (`kbdclass2`), refusing a class driver in the *other* stack, and never
  treating an unverifiable file as suspicious — WinSight does not cry wolf on files it merely failed
  to check. Verified live on a real machine: two filters, both Microsoft-signed class drivers, zero
  not installed by Windows.

### The camera/microphone monitor now actually alerts someone
- `CameraMicMonitor` describes itself as an OverSight-class real-time monitor and has done for a
  long time — but nothing ever hosted it. Its only caller was a CLI watch command that prints to a
  console, so someone using the app was never told their webcam had turned on, which is the entire
  point of that class. The detection engine was finished; the lifecycle around it was missing.
- `AvWatchHost` supplies it, the way `GuardianHost` does for persistence: the dashboard now hosts
  the poll loop for as long as it runs, raises a tray balloon when an app **activates** the webcam
  or microphone, and journals both activation and release so the record shows how long something
  was watching or listening. Releases do not raise a balloon — a device being freed is not a
  security event.
- It runs unconditionally rather than behind an opt-in, because it is read-only: it polls the
  capability records Windows already keeps. Ransomware protection stays opt-in because it alone
  writes. Localised across the three languages, and covered by lifecycle tests for the two risks a
  hosted poll loop actually has: a leaked thread, and an unsafe second start or dispose.

### The camera/mic alerting path can finally be tested without a webcam
- Verifying the balloon end-to-end meant owning a webcam: `CapabilityAccessReader` was sealed with a
  non-virtual `Read()`, so the alerting path could only be exercised by real hardware. This machine
  has none — its "Camera" devices are printers — and neither does any CI runner. **For a security
  product, an alerting path that cannot be exercised is a defect in its own right.**
- The reader now sits behind `ICapabilityAccessReader`, and two tests drive the whole chain from a
  scripted snapshot: an app taking the microphone reaches the subscriber with the app named, and a
  device *already* in use at startup is treated as the baseline rather than announced as new — which
  would otherwise cry wolf on every launch during a call.
- The read half was separately confirmed against live reality: the `av` scan correctly reported
  Discord holding the microphone open, matching the registry exactly.

### A tool-by-tool comparison against Objective-See, and the plan that follows
- New `docs/OBJECTIVE_SEE_PARITY.md`. WinSight is at **parity on the five tools that matter most** —
  BlockBlock and KnockKnock (Guardian and the persistence scan), LuLu (WFP outbound firewall),
  RansomWhere (canaries and burst detection) and OverSight (the camera/mic watch above) — while
  being one app instead of six, and it carries scanners Objective-See has no equivalent for (MCP,
  DNS cache, browser extensions, trusted roots, hosts, the alert journal).
- The genuine gaps, ranked by security value per unit of work: **process attribution** (in progress
  — a detection says what changed, never who), **keylogger/input-hook detection** (ReiKey-class, no
  coverage at all, no elevation needed), **loaded kernel drivers** (KextViewr-class, exactly what a
  rootkit leaves behind), then DLL-hijack analysis, a per-process drill-down view, and
  physical-access detection.
- Two things are deliberately *not* planned, and the document says so rather than implying them
  away: blocking file/registry writes needs a signed minifilter and an EV certificate, and a
  signature-info shell extension means putting a crash surface in every Explorer window.

### Process attribution, increment 1: the pure core that says *who* touched something
- Today a detection says *what* changed, never *who* changed it — the single biggest gap left in the
  product. Naming the process needs a kernel ETW session, which needs elevation, so the work starts
  with the parts that can be built and proven without either.
- New `WinSight.Attribution` project with the two pieces the rest will hang off, both pure and
  fully unit-tested:
  - `KernelPathNormalizer` translates what a kernel session actually reports into the form findings
    use: `\Device\HarddiskVolume3\...` to `C:\...`, and `\REGISTRY\MACHINE\...` /
    `\REGISTRY\USER\{sid}\...` to the `HKLM\` / `HKCU\` spellings the persistence enumerators emit.
    This is where attribution would fail *silently* — mistranslate and every detection simply comes
    back unattributed while the plumbing looks healthy — so the volume map and current-user SID are
    injected rather than read inline, and the cases that must refuse (unmapped volumes, `\??\` and
    other NT namespaces, another user's hive, the `_Classes` companion hive) are pinned as tightly
    as the ones that must translate.
  - `WriteAttributionIndex` remembers recent writes just long enough to answer "who did this?" when
    a detection lands, since a detection never arrives at the instant of the write that caused it.
    Bounded on both time and count, every timestamp explicit. It matches a finding that names the
    value inside a key (`...\Run [Updater]`) against an observed write to the key, but refuses a
    key that merely starts with the same text (`...\RunOnce`), and refuses anything outside the
    window — a confident wrong name beside a security finding is worse than no name.
- Nothing is wired up yet and no elevation is requested: the ETW session and the opt-in flow follow
  in the next increments.

### The "nothing leaves this PC" promise is now proven by tests, not just asserted in the README
- Coverage had never been measured. Measuring it found that `VirusTotalEnricher` — the only code in
  WinSight that can send anything off the machine — had **no tests at all**. Its guards (lookups must
  be switched on *and* a key present) were load-bearing for the product's central privacy claim and
  entirely unverified.
- The first attempt at tests would have been worthless: asserting "the result came back empty" also
  passes when a request was made and merely failed, so deleting a guard would not have failed
  anything. `Lookup` now takes an injectable stand-in for the client — the pattern already used for
  the journal's path and the burst detector's clock — and the tests assert the lookup was never
  *reached*. Confirmed by deliberately breaking the guard and watching the test go red. The real
  client is also now constructed only after the guards pass and there is something to ask about, so
  a scan that will not use it no longer opens one.
- `scripts/Measure-Coverage.ps1` makes this repeatable, with a per-assembly breakdown and an
  `-EngineMinimum` gate. It reports the detection libraries separately on purpose: the uncovered
  code is concentrated in WFP P/Invoke declarations, the service host and WPF code-behind, which
  unit tests genuinely cannot reach (VM validation and the packaged-installer tests cover those).
  Engine libraries sit at **84.1%**, every one of them above 80; shipped code overall is 63.7%.
  Chasing that global number would mean writing assertions against P/Invoke signatures — a number,
  not confidence.

### The alert journal is reachable over MCP, so a connected LLM sees what protection already caught
- The MCP server exposed the ten machine scanners but not the alert journal added in #91: a connected
  model could scan the machine's current state yet not read what WinSight's real-time protection had
  already flagged, including detections raised while the operator was away from the screen.
- New dedicated tool `winsight_alerts` reads the journal through the same projector as the scanners,
  so it inherits the identical privacy model — profile paths redacted unless the server was launched
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
  the app — the only feature that *writes* to disk (decoy files), and a persistent background
  protection rather than a one-shot scan — as a minor scan option.
- It is now a switch-style toggle in the header, beside the "Analyse locale" status badge: a place an
  operator can read the protection's state from any screen. Off, the pill matches the neighbouring
  header controls; on, it turns security-green (shield, track and label) with the knob sliding across,
  matching the green of the status badge. Same `x:Name` and Checked/Unchecked handlers, so behaviour
  is unchanged — planting and removing decoys still work exactly as before.
- The header is now genuinely responsive. The logo is a fixed left anchor, the title/tagline sit in a
  flexible middle column where the tagline ellipsizes, and the right-hand cluster (settings, language,
  protection, status) stays fully visible as the window narrows — where before, at the minimum width,
  the added toggle pushed the status badge off the right edge and clipped it. The now-redundant
  "Langue" caption was dropped (the dropdown shows the language by name; screen readers still get it
  via AutomationProperties.Name), freeing the last of the room.

### Buttons follow one shared style instead of a dozen hand-written ones
- The dashboard had accumulated five different paddings (`12,0`, `12,5`, `10,4`, `14,7` and the
  default), four margin schemes, `MinWidth`s of 90, 120 and 150 picked per button, heights of 32, 42
  and unset, and default square WPF chrome sitting inside cards with 12px rounded corners. Each was
  reasonable when it was written; together they read as unfinished.
- `App.xaml` now holds the whole button system — one base style plus `Primary`, `Danger`, `Success`
  and `OnDark` variants — shared by the dashboard and the settings window. Hover and press are a
  translucent state layer over whatever colour the button already is, so one template covers every
  variant and none can be forgotten when a colour changes. Keyboard focus draws a real accent ring:
  the WPF default is a dotted rectangle that is invisible against these surfaces, and the app is
  meant to be navigable without a mouse.
- Spacing is a single 8px gutter carried by the buttons, with the container cancelling the trailing
  edge via a negative margin. That is what keeps the gaps identical whether a row wraps or not —
  per-button margins are exactly how the four different spacings appeared in the first place.
- Emphasis now means something: only the coloured variants are SemiBold. Beyond the hierarchy it
  reads better, it also keeps the secondary row narrow enough that the guidance text beside it is
  not squeezed.

### Nothing is cut off at the smallest window size any more
- Found while checking whether the results list scrolls (it always has — a `DataGrid` brings its own
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
  export that every other check uses now work on WinSight's own detection history — this is how an
  operator sees an alert raised while they were away from the screen.
- Every row is `Notable`, because everything in the journal is by definition something WinSight
  judged worth interrupting the operator for; the "show only what deserves attention" filter
  therefore hides nothing here. Rows carry `time`, `source`, `kind` and `detail` as structured
  fields, so the JSON export stays machine-readable rather than re-parsing a display string.
- It is deliberately **not** part of the overview scan: the overview answers "what does this machine
  look like right now", and history is a different question. It also reads rather than inspects the
  machine, making it the one tool that costs nothing to open.
- An empty journal reads as "no real-time detections recorded yet", never as a failure — a fresh
  install has no history and that is the expected, reassuring case.

### Detections are journalled locally, so a suppressed balloon no longer loses them
- Live testing made the weakness concrete: a detection's only visible output was a tray balloon, and
  Windows is free to drop those — Focus Assist ("Ne pas déranger", including its automatic
  full-screen rule) suppresses them, and the shell throttles an app posting several toasts quickly.
  Both are indistinguishable from "nothing was detected", and a security tool must not depend on a
  single channel the OS may silently discard.
- `AlertJournal` (in `WinSight.Application`) appends every Guardian and ransomware detection to
  `%LocalAppData%\WinSight\alerts.log` — **before** the balloon is raised, so the record exists even
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
  described the burst detector without mentioning that **someone has to re-arm it** — the exact
  omission behind the bug below. Status, increment list, and that design obligation are now correct.
- `README.md` listed Phase 4 as upcoming and claimed "everything is read-only", which stopped being
  true when ransomware protection started planting decoys. It now states what ships and names the two
  deliberate, opt-in exceptions. `ARCHITECTURE.md` no longer calls ransomware behavior deferred.

### Ransomware protection re-arms after an alert instead of going silent for the session
- Found by testing the installed build end-to-end on a real machine, not by reading the code: after
  the first alert (a touched canary or a rename/delete burst), `RansomwareBurstDetector` stayed
  "fired" forever — by design it fires once per burst, but nothing ever called `Reset()`. A second
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
  session, not a code defect — confirmed by Guardian's independently-working alert also going quiet
  under the same conditions.

### The dashboard now records crashes instead of vanishing
- Investigating a reported crash during analysis turned up something worse than the crash: the app
  had **no unhandled-exception handling at all** — no `DispatcherUnhandledException`, no
  `AppDomain.UnhandledException`, no `UnobservedTaskException`. A failure killed the process with no
  message, no log, and nothing reliable in the Windows event log, so "it crashed" was impossible to
  act on by design.
- `CrashReporter` now hooks all three channels and writes a local report
  (`%LocalAppData%\WinSight\crashes`) with the exception, stack, version and OS — diagnostics only,
  no scan findings, never sent anywhere. Reports are capped so a crash loop cannot fill the disk, and
  capture itself swallows failures: reporting must never become the thing that crashes the app. A UI
  exception is recorded and the app keeps running, because for a monitoring tool staying alive
  preserves protection.
- Two follow-ups found by running it for real: the capture test wrote into the **real**
  `%LocalAppData%` crash folder, leaving files in the user's own application data — it now takes an
  explicit directory and uses a temp one. And that test then proved `TryCapture` could still throw:
  a malformed path raises `ArgumentException`/`NotSupportedException`, not `IOException`, so the
  guard missed it. Both are now covered, and the "never throws" promise actually holds.

### Security review of the new real-time code, before shipping it
- **A concurrency defect that could silently kill filesystem monitoring.** Both watchers set
  `FileSystemWatcher.EnableRaisingEvents` inside their create helper, so an event could fire on a
  thread-pool thread while `Start` was still registering watchers — reading `_targetByWatcher` while
  that `Dictionary` was being written. A Dictionary read racing a write can throw, return garbage, or
  spin forever; the failure mode was the persistence monitor's filesystem half dying quietly, which
  is the worst thing a security tool can do. Events now begin only after every watcher is registered.
- **A shutdown race.** `Dispose` iterated the watcher list outside the lock while `Start` could still
  be appending to it. Both watchers now snapshot the list under the lock before iterating.
- **The entropy sampler no longer follows reparse points, and never opens a directory.** A file
  dropped into a watched folder can be a symlink or junction pointing at a device or a slow network
  share, and reading it would block a thread-pool thread — so anyone able to write into the user's own
  folder could starve the monitor. Links are now detected, not followed.

### Phase 4 (ransomware): entropy-on-write sampling
- The third detection signal lands, with the anti-false-positive gating that was the reason to defer
  it. `RansomwareEntropySampler` reads a bounded 4 KB prefix — with sharing flags that never fight the
  writer, and returning false rather than throwing on any I/O trouble — and scores it with
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
  file NAME, never the directory tree — an alert cannot leak a folder layout into a screenshot or a
  shoulder-surfed balloon. A touched canary is presented as critical, a rename/delete burst as a
  warning, on the proven `ShowBalloonTip` path, localized en/fr/es.

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
