# WinSight vs Objective-See: capabilities and remaining gaps

Objective-See is the reference for "free, local, no-telemetry security tools that treat the operator
as an adult". This is an honest, tool-by-tool comparison and the plan that follows from it.

Two structural differences shape everything below:

- **Objective-See ships a dozen separate apps; WinSight is one.** That is WinSight's advantage and
  is not worth giving up: a single scan surface, one alert journal, one language setting.
- **The response models differ.** WinSight implements detection and alerts plus explicit WFP
  network rules. It does not implement persistence removal, automatic ransomware process
  suspension, or an interactive decision before an unknown application's first connection.
  Those are product gaps; the existence of a Windows detection surface does not establish parity.

## Tool-by-tool

| Objective-See | What it does | WinSight today | Gap |
|---|---|---|---|
| **BlockBlock** | Persistence monitoring with a user response that can remove the detected persistence | **Guardian** - live registry/file surfaces and a decision window per new item: **Allow** (a journalled rule that silences the item; listed by `winsight rules`, undone by `winsight revoke`), **Block** (quarantine-then-remove after revalidation; undone by `winsight restore`) or decide later, with the coalesced tray balloon as fallback | Parity for the user-privilege vectors (HKCU Run/RunOnce, per-user Startup files). HKLM, services, tasks and WMI still offer Allow only, until the service response tier ships. |
| **KnockKnock** | One-shot persistence enumeration with #unsigned/#nonApple filters | **Persistence scan** - 27 autostart surfaces with signature verdicts, filterable with `--unsigned`/`--nonmicrosoft` | Comparable purpose and triage filters; surface counts across operating systems do not prove equal detection. |
| **LuLu** | Blocks unknown outgoing connections pending a user decision | **Outbound firewall** - WFP per-app rules, enforcement opt-in, survives reboot | Explicit rules; no equivalent first-connection decision workflow. |
| **RansomWhere?** | Detects suspicious encryption and can suspend the process for a user decision | **Ransomware protection** - canaries, rename/delete burst, entropy-on-write, opt-in; plus `winsight holders <path>` (unelevated Restart Manager identification of processes holding a file) and separately confirmed `winsight suspend|resume|terminate <pid> --confirm` actions | Detection alerts through the journal/tray but does not bind the event to a responsible process or open a ransomware decision window. The operator can investigate and act manually; automatic attribution/suspension is absent. |
| **OverSight** | Webcam/mic activation alerts | **Camera/mic watch** - Windows consent-store polling with an event-driven `RegNotifyChangeKeyValue` watcher for immediate reads, tray alert, journalled; plus a process-level locator that maps a desktop app's device use to revalidated process identities | Process identification is surfaced by `winsight av --watch`, which names the process per activation; packaged-app package-family mapping, the terminate-the-process Block decision, and allow/always rules are pending. |
| **Netiquette** | Network connection list | **Connections scan** - with process attribution | Similar inventory; comparative coverage and latency have not been measured. |
| **TaskExplorer** | Process explorer with signatures, libraries, network, and #unsigned/#nonApple filters | **Processes + Modules scans, plus `process <pid>`** - lineage, unsigned modules and live external sockets in one view, filterable with `--unsigned`/`--nonmicrosoft` | Similar triage data and filters on the CLI; the auto-refreshing dashboard task view is pending; no measured feature or detection equivalence. |
| **What's Your Sign?** | Signature info in the file manager | **`winsight sign <path>`** and an out-of-process Explorer verb (`HKA\Software\Classes\...` -> `--signature "%1"`) reporting Authenticode state, signer, anchor, revocation and MD5/SHA-1/SHA-256 | Parity on the entry point: installer scope selects HKCU or HKLM and uninstall removes the same key; portable installs retain manual per-user register/unregister commands. The modern Windows 11 packaged `IExplorerCommand` and an opt-in VirusTotal view remain out of scope; no in-process shell extension by design. |
| **ReiKey** | Keyboard event-tap (keylogger) detection, with a real-time alert on new taps | **Keyboard interception scan** - filter drivers on the keyboard/mouse stacks, with signature verdicts; plus a live `InputFilterWatcher` that alerts the moment a keyboard/mouse class filter is added or removed | Real-time class-filter alerting is available through `winsight input --watch`; surfacing it in the dashboard UI and per-device-instance `Enum` filters are pending. Still a different layer from user-mode keyboard hooks. |
| **DHS** | Dylib hijack scanner | **Hijack scan** - unquoted command lines, writable service directories and PATH entries, and **phantom imports**; **modules scan** flags unsigned/untrusted loaded modules | Windows-specific exposure checks; dynamic library-loading coverage remains incomplete. |
| **KextViewr** | Kernel extension viewer | **Drivers scan** - registered kernel drivers, start disposition and signature verdicts | Registered inventory does not establish which drivers are currently resident. |
| **DoNotDisturb** | Physical-access ("evil maid") detection | **Presence scan** - resume timeline and Windows wake source | Narrower evidence; unknown wake sources and activity without a recorded wake remain unresolved. |

The response distinctions above follow the official descriptions of
[BlockBlock](https://objective-see.org/products/blockblock.html),
[LuLu](https://objective-see.org/products/lulu.html) and
[RansomWhere?](https://objective-see.org/products/ransomwhere.html) and
[OverSight](https://objective-see.org/products/oversight.html), rechecked on 2026-09-14.
This is a capability comparison, not a comparative effectiveness benchmark.

The historical v0.12.0 x64 result is candidate-bound. Exact candidate `dbaded1` passed
the native Windows VM campaign: WFP/SCM 35/35, adversarial trust 13/13, local IPC 7/7, and a real
second-VM Network Logon campaign 7/7 plus independent observer 3/3. The published downloads then
passed checksum, provenance/SBOM attestation, architecture and x64 installer-smoke verification.
The authoritative evidence and exact hashes are linked from
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

Current production readiness is not established: the September audit identified defects outside
those historical scenarios. The corrected candidate needs fresh qualification; native Arm64
privileged behavior and x64-on-Arm64 identity remain hardware-bound gates. Authenticode remains an
explicitly accepted unsigned-distribution limitation until a publisher certificate becomes available.

The local protocol's 26/26 contract self-test and deliberate exit-1 negative control remain portable
regression evidence. They do not qualify different executable bytes, Arm64 privileged runtime,
signing, release publication or any other separate technical gate.

User attestation for EN/FR/ES human presentation was completed on 2026-07-26; this is not independent
evidence.
That candidate remains an operator-provided trust-root prerequisite, not something the probe can
prove about itself.

### WinSight's additional integration and Windows-specific capabilities

- **Command-line triage on autostart entries.** WinSight inspects arguments as well as file
  signatures, including signed Windows interpreters that execute a separate payload. This adds
  context that a trusted executable signature alone cannot provide.
- **An MCP server**, so any LLM can run the read-only scanners, pivot onto a single process, and read
  the detection history.
- **DNS cache, browser extensions, trusted-root certificates, hosts file** scanners.
- **A local alert journal** surviving suppressed toasts, surfaced in-app and over MCP.
- **A Controlled Folder Access posture report.** WinSight reports Defender Controlled Folder
  Access's configured and
  observed operational posture and links to the Windows control. It does not treat a configured
  value alone as proof that a particular write will be blocked.
- **Three languages**, and a single unified UI.

## What is missing, in priority order

Ranked by security value per unit of work, not by how interesting they are to build.

### 1. Process attribution - *ransomware and persistence now name the writer*
Detections used to say **what** changed and never **who** changed it. The pure core (kernel-path
translation, write correlation) and the elevated ETW session behind an opt-in both landed earlier;
Guardian's persistence alerts have carried an author since. Ransomware now does too, which is where
it matters most: `CanaryTouched: decoy.docx` says something is wrong, while naming the writing
process says what to terminate, and ransomware is the one detection where minutes matter.

**The file filter was the missing piece, and it was missing silently.** The watcher records every
registry write but only the file writes it is told to look for - a busy machine performs thousands of
file writes a second, and the correlation index is small and time-bounded on purpose, so recording
everything would evict every useful observation within seconds. The host was constructing that
watcher with the default filter, which records *nothing*: registry attribution worked, the health
counters looked healthy, and no file write was ever offered to the index at all. Ransomware, and
Guardian's file-based startup-folder surface, could never have been attributed.

`AttributionScope` now names the two sets worth recording - the startup folders and, once protection
plants them, the ransomware decoys. Both are small and precisely known. The protected *directories*
(Documents, Desktop, Pictures) are deliberately not watched wholesale: they are among the busiest
paths on a desktop and would reintroduce exactly the flooding the filter exists to prevent. The
consequence is stated rather than hidden - a touched decoy carries an author, a rename/delete burst
does not.

**One bug worth recording, because it was invisible and total.** The filter runs on the path as the
kernel spells it, before normalisation. The previous rule compared that raw path against the full DOS
folder (`C:\Users\…`), which cannot match once the volume is spelled `\Device\HarddiskVolume3\…` -
so every startup-folder write would have been dropped and the watch would have looked simply quiet.
Matching the root-relative tail is correct under either spelling, which is the point: this could not
be observed from an unelevated machine, so the code is written to be right either way rather than
betting on which form arrives.

**An absent author now says why it is absent.** Three states hide behind a nameless alert and they
call for three different responses: nothing was watching, nothing *could* watch because the process
is unelevated, or something was watching and genuinely saw nothing. `AttributionHealth` was built to
draw exactly those distinctions - and was read by nothing outside its own tests, so no operator,
journal or MCP client ever saw any of them. Every alert now carries the reason
(`author unknown (attribution needs Administrator)`), which matters because a silent absence reads as
the *last* of the three when on an unelevated machine it is always the second.

The note rides on the alert rather than on a separate health endpoint, deliberately. The journal
already crosses the process boundary - the dashboard writes it, the MCP server reads it - so the
caveat reaches an LLM with no new file and no new tool. More importantly it has no staleness problem:
a health file written by a dashboard that has since exited would describe a world that no longer
exists, whereas a note beside the detection describes the state at the moment that detection fired,
which is the only state that can explain it. The MCP server instructions tell a client that the
bracketed reason is meaningful and must not be dropped.

### ~~2. Keylogger / input-hook detection (ReiKey-class)~~ - **done**
Shipped as the `input` scanner. Worth recording *why it took the shape it did*, because the obvious
approach is a dead end: Windows has **no documented way to enumerate `SetWindowsHookEx` hooks**, so a
direct ReiKey port is not possible. What is both enumerable and higher-signal is the **filter driver
on the keyboard or mouse device stack** - kernel-resident, sees every keystroke before any
application, and exactly where a serious keylogger installs itself. Read from the device setup class
keys, verdicts through the existing Authenticode path, no elevation.

Remaining, lower-value follow-ups in the same area: hook DLLs identifiable by being loaded into an
unusual number of processes (an extension of the modules scan), and per-device-instance filters
under `Enum\…\UpperFilters` rather than only the class-level ones.

### ~~3. Loaded kernel drivers (KextViewr-class)~~ - **done**
Shipped as the `drivers` scanner. Two decisions are worth recording, because the obvious versions
of both are wrong.

**`EnumDeviceDrivers` names what is resident and was still rejected.** Since Windows 8.1 it returns
zeroed load addresses to an unelevated process, as an ASLR-disclosure defence. The call succeeds and
still reports the right count, so the failure is silent: every entry resolves to whatever sits at
address 0, which on the development machine meant all 232 loaded modules naming `ntoskrnl.exe`. A
residency list that answers with the same file 232 times is worse than none. The scan therefore
reads the service control manager's registry, reports what is **registered** and says when Windows
loads it, and does not claim to know what is resident - that claim costs elevation.

**"Windows ships this" is an exact certificate-subject test.** In-box drivers are signed
`CN=Microsoft Windows`; drivers somebody else wrote and Microsoft merely attested carry a longer
name off the same issuer (`… Hardware Compatibility Publisher`, `… Hardware Abstraction Layer
Publisher`, `… Early Launch Anti-malware Publisher`). A substring match on "Microsoft Windows"
swallows all of them, and bring-your-own-vulnerable-driver attacks live in exactly that gap.

Remaining, lower-value follow-up in the same area: an opt-in elevated pass that would name the
resident set, and boot-configuration checks (test signing, DSE state) that give the flagged
findings their context.

### ~~4. Hijacking scan (DHS-class)~~ - **done, shipped as the `hijack` scanner**
The first and highest-signal half is done: **unquoted service command lines**, which is the
Windows-specific vector with no macOS analogue at all. Windows registers a service as a command
line, so `C:\Program Files\My App\svc.exe` unquoted is attempted as `C:\Program.exe` first, and
whoever can write that path runs as SYSTEM at boot.

The scan grades each finding by whether it is actually exploitable *on this machine* rather than
listing every unquoted path: **Latent** (nothing writable ahead of it - the common, boring case),
**Exploitable** (an earlier candidate can be created right now), **Occupied** (it already exists).
Writability is settled by Windows' own `AccessCheck` against the current user's non-elevated token,
never by a hand-rolled reading of the DACL, because that is where this class of check quietly gets
it wrong - and without writing a probe file. Measured on a real desktop:
1 finding out of roughly 700 services, correctly graded Latent.

The search-order half now covers the two directories that decide it. A program's **own directory**
is the first place Windows looks for every DLL it loads, so an auto-starting service whose folder is
writable can have any of its imports answered by a planted file - and its executable replaced
besides. A writable **machine PATH** entry is the same thing for every process that resolves
anything by name; an *absent* PATH entry whose parent is writable is that vulnerability one step
earlier, and is reported too.

Both are silent on a healthy machine by design - measured on a real desktop, 18 machine PATH entries
and 88 auto-starting services, none writable. That is the right shape for a check like this, and it
is also why only tests can prove they fire: a silent detector and a broken one look identical from
outside.

**Phantom imports** complete the set. A binary declares the modules it needs; when one of them is
answered by no directory in its search order, the slot is permanently unoccupied - not a race an
attacker has to win, but an open invitation. Whoever can write that name into any searched directory
is loaded into the program at its privilege, every time it starts.

The imports are read by parsing the PE headers, never by loading the image: asking Windows what a
binary imports means running its initialisation code, which is unacceptable in a scanner aimed at
files it already suspects. The parser bounds-checks every read and caps every count, because it is
pointed at files an attacker may have written - a malformed image yields nothing rather than an
exception, so one hostile binary cannot end the sweep.

**Two exclusions carry the entire signal-to-noise ratio, and one of them was measured the hard way.**
*API sets* (`api-ms-…`, `ext-ms-…`) are resolved by the loader from a schema and exist as no file
anywhere; they are the majority of every binary's import table. *KnownDLLs* are mapped from a
pre-loaded section and never resolved through the search order at all, so planting one earlier
achieves nothing - and the list is read from the registry rather than hardcoded, because it is
machine state a tampered machine should reveal.

The api-set prefix was first written as `api-ms-win-`/`ext-ms-win-`, which looks right. Against the
live machine it produced exactly two findings: `ext-ms-win32-subsystem-query-l1-1-0.dll` in the print
spooler and `ext-ms-onecore-appmodel-staterepository-internal-l1-1-3.dll` in the search indexer -
both api-sets, both missed by the narrower prefix, both reported as phantom imports of a SYSTEM
service. Two confident false accusations against Windows itself, from four characters. With the
prefixes corrected: **zero findings across ~90 auto-starting services, in 377 ms**. That is the
intended shape, and it is why the rule has tests that make it fire on a machine that does not exist -
a silent detector and a broken one are indistinguishable from outside.

Known limit, stated rather than implied: this reads the **import table**. A DLL fetched at runtime
through `LoadLibrary` - which is how several of the classic Windows phantoms are reached - declares
nothing, so it is not visible here. Covering those needs runtime observation, not static analysis.

### ~~5. Per-process drill-down (TaskExplorer-class)~~ - **done, shipped as `winsight process <pid>`**
Half of "this is UI work, not detection work" was right: the data was already gathered by the
processes, modules and connections scanners. The other half was not. The **join itself makes
decisions** - what counts as this process's parent, what is worth surfacing out of hundreds of loaded
modules, what to do when three snapshots taken seconds apart disagree - and every one of them can be
wrong in a way that misnames something. So the pivot is a pure function over three snapshots with its
own tests, and the rendering is a second pure function beside it; only the gather is an edge.

Three decisions worth recording:

**An absent pid answers "not running", never "nothing wrong".** A hollow insight would render as a
process that exists and has nothing loaded and nothing connected - a confident, reassuring
description of something that is not there.

**A process is never its own parent.** Not hypothetical: the System Idle Process reports pid 0 with
parent 0, and WinSight's own reader falls back to 0 for a row whose id it cannot read. An unguarded
lineage lookup recurses forever in a tree view and claims a process launched itself.

**Modules are counted, not listed.** Measured on this desktop, `explorer.exe` has **353** of them and
all but a handful are Microsoft-signed. Listing them buries the outlier, so the count is reported and
only the unsigned ones are named - the same reasoning that grades hijack findings by exploitability.

Reading one process's modules also needed a new entry point: the only one available walked every
process (57 s, 14 253 modules, 222 processes), which is a fine price for "what is loaded anywhere on
this machine" and an absurd one for a view opened on one pid.

Measured end to end: **11 s** for a live process, **4 s** for one that is not running - the process
list is taken first and short-circuits before the expensive scans. The remaining cost is dominated by
signature verification across the full process and connection lists. Running the three acquisitions
concurrently would roughly halve it, and is deliberately **not** done yet: the verifier chain is
shared and its catalog fallback has not been proven thread-safe, and an unproven concurrency change
inside the trust core is not worth four seconds.

### ~~6. Physical-access detection (DoNotDisturb-class)~~ - **done, shipped as the `presence` scanner**
The plan named three sources. **Two of them were measured and rejected before a line was written**,
and recording why matters more than the code that remained.

**Logon failures live in the Security log, which requires Administrator** - measured, reading it
unelevated throws. Building the check on it would have made a whole surface blind in the default
mode, which is the defect this project keeps finding in itself.

**USB device history was the obvious second source and is a trap.** The device keys under
`SYSTEM\CurrentControlSet\Enum` *are* readable unelevated. Their `Properties` subkey - where the
first-install and last-arrival timestamps live - throws `SecurityException` without elevation. An
inventory of devices with no dates cannot answer "was something plugged in while I was away", and
would have looked complete while failing to.

What is readable unelevated is the **System log's resume timeline**, including Windows' own wake
source. That is the closest honest Windows analogue to DoNotDisturb's lid-open.

**The measurement then reshaped the rule.** Windows records a numeric `WakeSourceType` plus a device
name. Across fifty resumes on a real desktop: **25 `Unknown`, 24 a network adapter, 1 a physical
input device.** So "a device woke the machine" is emphatically not "somebody touched the machine" -
had the two been equated, this scanner's first run would have produced **24 false accusations**
against ordinary Wake-on-LAN traffic while still explaining none of the 25 it cannot.

The rule therefore claims physical presence only for devices a person's hands operate, reports
everything else in Windows' own vocabulary, and says "cause not recorded by Windows" when that is the
truth. Classification is driven by the numeric type, never the rendered message, which is localised -
this machine renders it in French.

**Deliberately not in the default overview.** A machine in daily use wakes constantly, and the one
thing that would make a wake suspicious is what Windows most often declines to record. This is a
timeline you consult when you suspect somebody was at your desk, not a routine check.

### Deliberately not planned

- **Blocking file/registry writes.** WinSight currently detects and alerts on these surfaces.
  Adding prevention or process response would require a separate design and safety qualification.
- **A shell extension for signature info.** Real value, but it means shipping an in-process
  Explorer component - a crash surface in every file window, for a convenience feature.

## The bar this sets

WinSight combines Windows-specific scanners, a shared alert journal, an MCP interface and three
languages in one application. That integration is useful, but it does not establish superiority in
detection, prevention, false positives, latency or resource use. No controlled comparative benchmark
has established those claims.

Remaining work includes response workflows, resident-driver visibility, per-device input filters,
dynamic library-loading observation and measured detection coverage. Priorities should follow
reproducible scenarios and operator safety. Current release qualification is tracked separately in
[`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md). The implementation plan for the remaining gaps
is [`OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md`](OBJECTIVE_SEE_IMPLEMENTATION_PLAN.md).
