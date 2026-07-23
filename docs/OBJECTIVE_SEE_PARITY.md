# WinSight vs Objective-See: parity and what is left

Objective-See is the reference for "free, local, no-telemetry security tools that treat the operator
as an adult". This is an honest, tool-by-tool comparison and the plan that follows from it.

Two structural differences shape everything below:

- **Objective-See ships a dozen separate apps; WinSight is one.** That is WinSight's advantage and
  is not worth giving up: a single scan surface, one alert journal, one language setting.
- **Objective-See's blocking tools rest on Apple's endpoint APIs.** The Windows equivalents for
  *blocking* (file/registry interception) require a signed kernel minifilter and an EV certificate.
  WinSight is deliberately detect-and-alert plus WFP network enforcement, which needs no driver.
  Everything marked "cannot block" below is that constraint, not an oversight.

## Tool-by-tool

| Objective-See | What it does | WinSight today | Gap |
|---|---|---|---|
| **BlockBlock** | Real-time persistence alerts | **Guardian** — ~17 live registry/file surfaces, tray alert, journalled | **Parity.** Cannot block the write (driver). |
| **KnockKnock** | One-shot persistence enumeration | **Persistence scan** — 22 autostart surfaces with signature verdicts | **Parity, arguably ahead** (more surfaces, Authenticode + catalog). |
| **LuLu** | Per-app outbound firewall | **Outbound firewall** — WFP per-app, enforcement opt-in, survives reboot | **Feature parity in code; native qualification pending.** A [historical x64 observation](validation/2026-07-23-firewall-enforcement-x64.md) recorded per-app blocking, but it is not a strict production gate. Corrected candidate-bound x64 and native Arm64 runs remain pending. |
| **RansomWhere?** | Ransomware behaviour detection | **Ransomware protection** — canaries, rename/delete burst, entropy-on-write, opt-in | **Parity.** Cannot halt the process mid-encryption (driver). |
| **OverSight** | Webcam/mic activation alerts | **Camera/mic watch** — live, tray alert, journalled | **Parity** (the host landed 2026-07-21; the detector predated it). |
| **Netiquette** | Network connection list | **Connections scan** — with process attribution | **Parity.** |
| **TaskExplorer** | Process explorer with signatures, libraries, network | **Processes + Modules scans, plus `process <pid>`** — lineage, unsigned modules and live external sockets in one view | **Parity.** |
| **What's Your Sign?** | Signature info in the file manager | *(none)* | **Missing** — Explorer shell extension. |
| **ReiKey** | Keyboard event-tap (keylogger) detection | **Keyboard interception scan** — filter drivers on the keyboard/mouse stacks, with signature verdicts | **Parity, by the route Windows actually allows** (see below). |
| **DHS** | Dylib hijack scanner | **Hijack scan** — unquoted command lines, writable service directories and PATH entries, and **phantom imports**; **modules scan** flags unsigned/untrusted loaded modules | **Parity, arguably ahead.** DHS finds weak/rpath dylibs; the Windows equivalents are all covered, each graded by real exploitability on this machine. |
| **KextViewr** | Kernel extension viewer | **Drivers scan** — every registered kernel driver, its start disposition and signature verdict | **Parity**, with one honest limit: registered, not resident (see below). |
| **DoNotDisturb** | Physical-access ("evil maid") detection | **Presence scan** — resume timeline with Windows' wake source, flagging only wakes attributable to a human hand | **Parity, with a narrower honest claim.** A lid open is unambiguous; a Windows wake source is `Unknown` half the time, and the scan says so rather than guessing. |

Firewall qualification remains explicitly `NOT_RUN`/`BLOCKED`: corrected candidate-bound x64,
native Arm64, real SCM/WFP, owner/DACL/nested-reparse/live-TOCTOU, connectivity and EN/FR/ES human
presentation have not passed their isolated-VM gates. The feature comparison above and historical
x64 observation do not imply production readiness. The current local protocol's normal contract
self-test is 24/24 and its deliberate lifecycle-order negative control exits 1, but those
non-privileged checks do not promote any native gate. The former 14/14 and historical 18/18 remain
invalid as qualification; the intermediate 15/15 was transient and is not evidence. One production
validation adapter now owns commands, staging and all three lifecycle polls while real/scripted modes
inject only elementary host effects through a closed exact queue. One public command host is likewise
shared by `Program` and probe tests; its probe handler has inspection capability only, with a
non-privileged invalid-arity subprocess smoke covering the real root. The path boundary still uses a
protected candidate to inspect only a user-writable sentinel; no staged service or DLL is executed.
That candidate remains an operator-provided trust-root prerequisite, not something the probe can
prove about itself.

### What WinSight has that Objective-See does not

- **An MCP server**, so any LLM can run the read-only scanners and read the detection history.
- **DNS cache, browser extensions, trusted-root certificates, hosts file** scanners.
- **A local alert journal** surviving suppressed toasts, surfaced in-app and over MCP.
- **Three languages**, and a single unified UI.

## What is missing, in priority order

Ranked by security value per unit of work, not by how interesting they are to build.

### 1. Process attribution — *ransomware and persistence now name the writer*
Detections used to say **what** changed and never **who** changed it. The pure core (kernel-path
translation, write correlation) and the elevated ETW session behind an opt-in both landed earlier;
Guardian's persistence alerts have carried an author since. Ransomware now does too, which is where
it matters most: `CanaryTouched: decoy.docx` says something is wrong, while naming the writing
process says what to terminate, and ransomware is the one detection where minutes matter.

**The file filter was the missing piece, and it was missing silently.** The watcher records every
registry write but only the file writes it is told to look for — a busy machine performs thousands of
file writes a second, and the correlation index is small and time-bounded on purpose, so recording
everything would evict every useful observation within seconds. The host was constructing that
watcher with the default filter, which records *nothing*: registry attribution worked, the health
counters looked healthy, and no file write was ever offered to the index at all. Ransomware, and
Guardian's file-based startup-folder surface, could never have been attributed.

`AttributionScope` now names the two sets worth recording — the startup folders and, once protection
plants them, the ransomware decoys. Both are small and precisely known. The protected *directories*
(Documents, Desktop, Pictures) are deliberately not watched wholesale: they are among the busiest
paths on a desktop and would reintroduce exactly the flooding the filter exists to prevent. The
consequence is stated rather than hidden — a touched decoy carries an author, a rename/delete burst
does not.

**One bug worth recording, because it was invisible and total.** The filter runs on the path as the
kernel spells it, before normalisation. The previous rule compared that raw path against the full DOS
folder (`C:\Users\…`), which cannot match once the volume is spelled `\Device\HarddiskVolume3\…` —
so every startup-folder write would have been dropped and the watch would have looked simply quiet.
Matching the root-relative tail is correct under either spelling, which is the point: this could not
be observed from an unelevated machine, so the code is written to be right either way rather than
betting on which form arrives.

**An absent author now says why it is absent.** Three states hide behind a nameless alert and they
call for three different responses: nothing was watching, nothing *could* watch because the process
is unelevated, or something was watching and genuinely saw nothing. `AttributionHealth` was built to
draw exactly those distinctions — and was read by nothing outside its own tests, so no operator,
journal or MCP client ever saw any of them. Every alert now carries the reason
(`author unknown (attribution needs Administrator)`), which matters because a silent absence reads as
the *last* of the three when on an unelevated machine it is always the second.

The note rides on the alert rather than on a separate health endpoint, deliberately. The journal
already crosses the process boundary — the dashboard writes it, the MCP server reads it — so the
caveat reaches an LLM with no new file and no new tool. More importantly it has no staleness problem:
a health file written by a dashboard that has since exited would describe a world that no longer
exists, whereas a note beside the detection describes the state at the moment that detection fired,
which is the only state that can explain it. The MCP server instructions tell a client that the
bracketed reason is meaningful and must not be dropped.

### ~~2. Keylogger / input-hook detection (ReiKey-class)~~ — **done**
Shipped as the `input` scanner. Worth recording *why it took the shape it did*, because the obvious
approach is a dead end: Windows has **no documented way to enumerate `SetWindowsHookEx` hooks**, so a
direct ReiKey port is not possible. What is both enumerable and higher-signal is the **filter driver
on the keyboard or mouse device stack** — kernel-resident, sees every keystroke before any
application, and exactly where a serious keylogger installs itself. Read from the device setup class
keys, verdicts through the existing Authenticode path, no elevation.

Remaining, lower-value follow-ups in the same area: hook DLLs identifiable by being loaded into an
unusual number of processes (an extension of the modules scan), and per-device-instance filters
under `Enum\…\UpperFilters` rather than only the class-level ones.

### ~~3. Loaded kernel drivers (KextViewr-class)~~ — **done**
Shipped as the `drivers` scanner. Two decisions are worth recording, because the obvious versions
of both are wrong.

**`EnumDeviceDrivers` names what is resident and was still rejected.** Since Windows 8.1 it returns
zeroed load addresses to an unelevated process, as an ASLR-disclosure defence. The call succeeds and
still reports the right count, so the failure is silent: every entry resolves to whatever sits at
address 0, which on the development machine meant all 232 loaded modules naming `ntoskrnl.exe`. A
residency list that answers with the same file 232 times is worse than none. The scan therefore
reads the service control manager's registry, reports what is **registered** and says when Windows
loads it, and does not claim to know what is resident — that claim costs elevation.

**"Windows ships this" is an exact certificate-subject test.** In-box drivers are signed
`CN=Microsoft Windows`; drivers somebody else wrote and Microsoft merely attested carry a longer
name off the same issuer (`… Hardware Compatibility Publisher`, `… Hardware Abstraction Layer
Publisher`, `… Early Launch Anti-malware Publisher`). A substring match on "Microsoft Windows"
swallows all of them, and bring-your-own-vulnerable-driver attacks live in exactly that gap.

Remaining, lower-value follow-up in the same area: an opt-in elevated pass that would name the
resident set, and boot-configuration checks (test signing, DSE state) that give the flagged
findings their context.

### ~~4. Hijacking scan (DHS-class)~~ — **done, shipped as the `hijack` scanner**
The first and highest-signal half is done: **unquoted service command lines**, which is the
Windows-specific vector with no macOS analogue at all. Windows registers a service as a command
line, so `C:\Program Files\My App\svc.exe` unquoted is attempted as `C:\Program.exe` first, and
whoever can write that path runs as SYSTEM at boot.

The scan grades each finding by whether it is actually exploitable *on this machine* rather than
listing every unquoted path: **Latent** (nothing writable ahead of it — the common, boring case),
**Exploitable** (an earlier candidate can be created right now), **Occupied** (it already exists).
Writability is settled by asking the filesystem, never by reconstructing effective access from the
DACL, because that is where this class of check quietly gets it wrong. Measured on a real desktop:
1 finding out of roughly 700 services, correctly graded Latent.

The search-order half now covers the two directories that decide it. A program's **own directory**
is the first place Windows looks for every DLL it loads, so an auto-starting service whose folder is
writable can have any of its imports answered by a planted file — and its executable replaced
besides. A writable **machine PATH** entry is the same thing for every process that resolves
anything by name; an *absent* PATH entry whose parent is writable is that vulnerability one step
earlier, and is reported too.

Both are silent on a healthy machine by design — measured on a real desktop, 18 machine PATH entries
and 88 auto-starting services, none writable. That is the right shape for a check like this, and it
is also why only tests can prove they fire: a silent detector and a broken one look identical from
outside.

**Phantom imports** complete the set. A binary declares the modules it needs; when one of them is
answered by no directory in its search order, the slot is permanently unoccupied — not a race an
attacker has to win, but an open invitation. Whoever can write that name into any searched directory
is loaded into the program at its privilege, every time it starts.

The imports are read by parsing the PE headers, never by loading the image: asking Windows what a
binary imports means running its initialisation code, which is unacceptable in a scanner aimed at
files it already suspects. The parser bounds-checks every read and caps every count, because it is
pointed at files an attacker may have written — a malformed image yields nothing rather than an
exception, so one hostile binary cannot end the sweep.

**Two exclusions carry the entire signal-to-noise ratio, and one of them was measured the hard way.**
*API sets* (`api-ms-…`, `ext-ms-…`) are resolved by the loader from a schema and exist as no file
anywhere; they are the majority of every binary's import table. *KnownDLLs* are mapped from a
pre-loaded section and never resolved through the search order at all, so planting one earlier
achieves nothing — and the list is read from the registry rather than hardcoded, because it is
machine state a tampered machine should reveal.

The api-set prefix was first written as `api-ms-win-`/`ext-ms-win-`, which looks right. Against the
live machine it produced exactly two findings: `ext-ms-win32-subsystem-query-l1-1-0.dll` in the print
spooler and `ext-ms-onecore-appmodel-staterepository-internal-l1-1-3.dll` in the search indexer —
both api-sets, both missed by the narrower prefix, both reported as phantom imports of a SYSTEM
service. Two confident false accusations against Windows itself, from four characters. With the
prefixes corrected: **zero findings across ~90 auto-starting services, in 377 ms**. That is the
intended shape, and it is why the rule has tests that make it fire on a machine that does not exist —
a silent detector and a broken one are indistinguishable from outside.

Known limit, stated rather than implied: this reads the **import table**. A DLL fetched at runtime
through `LoadLibrary` — which is how several of the classic Windows phantoms are reached — declares
nothing, so it is not visible here. Covering those needs runtime observation, not static analysis.

### ~~5. Per-process drill-down (TaskExplorer-class)~~ — **done, shipped as `winsight process <pid>`**
Half of "this is UI work, not detection work" was right: the data was already gathered by the
processes, modules and connections scanners. The other half was not. The **join itself makes
decisions** — what counts as this process's parent, what is worth surfacing out of hundreds of loaded
modules, what to do when three snapshots taken seconds apart disagree — and every one of them can be
wrong in a way that misnames something. So the pivot is a pure function over three snapshots with its
own tests, and the rendering is a second pure function beside it; only the gather is an edge.

Three decisions worth recording:

**An absent pid answers "not running", never "nothing wrong".** A hollow insight would render as a
process that exists and has nothing loaded and nothing connected — a confident, reassuring
description of something that is not there.

**A process is never its own parent.** Not hypothetical: the System Idle Process reports pid 0 with
parent 0, and WinSight's own reader falls back to 0 for a row whose id it cannot read. An unguarded
lineage lookup recurses forever in a tree view and claims a process launched itself.

**Modules are counted, not listed.** Measured on this desktop, `explorer.exe` has **353** of them and
all but a handful are Microsoft-signed. Listing them buries the outlier, so the count is reported and
only the unsigned ones are named — the same reasoning that grades hijack findings by exploitability.

Reading one process's modules also needed a new entry point: the only one available walked every
process (57 s, 14 253 modules, 222 processes), which is a fine price for "what is loaded anywhere on
this machine" and an absurd one for a view opened on one pid.

Measured end to end: **11 s** for a live process, **4 s** for one that is not running — the process
list is taken first and short-circuits before the expensive scans. The remaining cost is dominated by
signature verification across the full process and connection lists. Running the three acquisitions
concurrently would roughly halve it, and is deliberately **not** done yet: the verifier chain is
shared and its catalog fallback has not been proven thread-safe, and an unproven concurrency change
inside the trust core is not worth four seconds.

### ~~6. Physical-access detection (DoNotDisturb-class)~~ — **done, shipped as the `presence` scanner**
The plan named three sources. **Two of them were measured and rejected before a line was written**,
and recording why matters more than the code that remained.

**Logon failures live in the Security log, which requires Administrator** — measured, reading it
unelevated throws. Building the check on it would have made a whole surface blind in the default
mode, which is the defect this project keeps finding in itself.

**USB device history was the obvious second source and is a trap.** The device keys under
`SYSTEM\CurrentControlSet\Enum` *are* readable unelevated. Their `Properties` subkey — where the
first-install and last-arrival timestamps live — throws `SecurityException` without elevation. An
inventory of devices with no dates cannot answer "was something plugged in while I was away", and
would have looked complete while failing to.

What is readable unelevated is the **System log's resume timeline**, including Windows' own wake
source. That is the closest honest Windows analogue to DoNotDisturb's lid-open.

**The measurement then reshaped the rule.** Windows records a numeric `WakeSourceType` plus a device
name. Across fifty resumes on a real desktop: **25 `Unknown`, 24 a network adapter, 1 a physical
input device.** So "a device woke the machine" is emphatically not "somebody touched the machine" —
had the two been equated, this scanner's first run would have produced **24 false accusations**
against ordinary Wake-on-LAN traffic while still explaining none of the 25 it cannot.

The rule therefore claims physical presence only for devices a person's hands operate, reports
everything else in Windows' own vocabulary, and says "cause not recorded by Windows" when that is the
truth. Classification is driven by the numeric type, never the rendered message, which is localised —
this machine renders it in French.

**Deliberately not in the default overview.** A machine in daily use wakes constantly, and the one
thing that would make a wake suspicious is what Windows most often declines to record. This is a
timeline you consult when you suspect somebody was at your desk, not a routine check.

### Deliberately not planned

- **Blocking file/registry writes.** Needs a signed minifilter and an EV certificate. The honest
  position is detect-and-alert, stated plainly rather than implied away.
- **A shell extension for signature info.** Real value, but it means shipping an in-process
  Explorer component — a crash surface in every file window, for a convenience feature.

## The bar this sets

Beating Objective-See on Windows is not a checklist race. WinSight has feature coverage at parity or
ahead on the eight tools that matter most — persistence × 2, firewall, ransomware, camera/mic,
keyboard interception, kernel drivers and hijack analysis — while being one app instead of eight,
with an MCP server, an alert journal and four scanners Objective-See has no equivalent for. That is
a product-capability comparison, not a claim that every privileged path is production-qualified:
the firewall still needs the strict candidate-bound x64 and native Arm64 gates.

**Every tool on the list above now has parity-or-better feature coverage**, in one app instead of
eight, with an MCP server, an alert journal, four scanners Objective-See has no equivalent for, and
three languages. The wording does not convert the historical x64 observation into production
qualification.

What is left is not parity work. It is depth: the elevated resident-driver pass, boot-configuration
context for the driver findings, per-device-instance input filters, and runtime observation for the
DLL hijacks that `LoadLibrary` reaches rather than the import table. Each is a smaller increment than
anything above, and each is worth doing only with the same rule the list was built on — measure the
signal before building the check, and say plainly what it cannot see.
