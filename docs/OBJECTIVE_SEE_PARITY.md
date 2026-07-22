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
| **LuLu** | Per-app outbound firewall | **Outbound firewall** — WFP per-app, enforcement opt-in, survives reboot | **Parity.** Real blocking, no driver needed. |
| **RansomWhere?** | Ransomware behaviour detection | **Ransomware protection** — canaries, rename/delete burst, entropy-on-write, opt-in | **Parity.** Cannot halt the process mid-encryption (driver). |
| **OverSight** | Webcam/mic activation alerts | **Camera/mic watch** — live, tray alert, journalled | **Parity** (the host landed 2026-07-21; the detector predated it). |
| **Netiquette** | Network connection list | **Connections scan** — with process attribution | **Parity.** |
| **TaskExplorer** | Process explorer with signatures, libraries, network | **Processes + Modules scans** | **Partial** — no single per-process drill-down view. |
| **What's Your Sign?** | Signature info in the file manager | *(none)* | **Missing** — Explorer shell extension. |
| **ReiKey** | Keyboard event-tap (keylogger) detection | **Keyboard interception scan** — filter drivers on the keyboard/mouse stacks, with signature verdicts | **Parity, by the route Windows actually allows** (see below). |
| **DHS** | Dylib hijack scanner | **Hijack scan** grades pre-emptable service command lines; **modules scan** flags unsigned/untrusted loaded modules | **Partial** — unquoted-path hijacking is covered and graded by real exploitability; DLL search-order and phantom-DLL analysis are not. |
| **KextViewr** | Kernel extension viewer | **Drivers scan** — every registered kernel driver, its start disposition and signature verdict | **Parity**, with one honest limit: registered, not resident (see below). |
| **DoNotDisturb** | Physical-access ("evil maid") detection | *(none)* | **Missing** — lid/logon/USB-while-locked. |

### What WinSight has that Objective-See does not

- **An MCP server**, so any LLM can run the read-only scanners and read the detection history.
- **DNS cache, browser extensions, trusted-root certificates, hosts file** scanners.
- **A local alert journal** surviving suppressed toasts, surfaced in-app and over MCP.
- **Three languages**, and a single unified UI.

## What is missing, in priority order

Ranked by security value per unit of work, not by how interesting they are to build.

### 1. Process attribution — *in progress*
Every detection currently says **what** changed, never **who** changed it. This is the single
biggest weakness: "a Run key appeared" is far less actionable than "`dropper.exe` (PID 4242) wrote
this Run key". Increment 1 (pure core: kernel-path translation + write correlation) has landed.
Remaining: the elevated ETW session behind an opt-in, then wiring into Guardian and ransomware
alerts, the journal and the MCP surface. Follow `WinSight.NetMonitor/OutboundConnectionWatcher.cs`:
private session name, capture PID→path at process start (never resolve after the fact).

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

### 4. Hijacking scan (DHS-class) — **partly shipped as the `hijack` scanner**
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

Still open here: **phantom DLLs** — imports a binary declares that are absent from its search path,
which an attacker can supply. That needs PE import-table parsing and careful handling of delay-loads
and side-by-side assemblies, or it becomes noise.

### 5. Per-process drill-down (TaskExplorer-class)
The data mostly exists across the processes, modules and connections scanners; what is missing is
one view that pivots on a single process. This is UI work, not detection work.

### 6. Physical-access detection (DoNotDisturb-class)
Logon failures, USB insertion and lid events while locked, from the Windows event log. Genuinely
useful, but the lowest signal-to-noise of the list on a machine in daily use.

### Deliberately not planned

- **Blocking file/registry writes.** Needs a signed minifilter and an EV certificate. The honest
  position is detect-and-alert, stated plainly rather than implied away.
- **A shell extension for signature info.** Real value, but it means shipping an in-process
  Explorer component — a crash surface in every file window, for a convenience feature.

## The bar this sets

Beating Objective-See on Windows is not a checklist race. WinSight is now at parity on the seven
tools that matter most — persistence × 2, firewall, ransomware, camera/mic, keyboard interception
and kernel drivers — while being one app instead of eight. What still separates it from "a set of
scanners" is **#1**: naming the process behind a detection. **#4** (DLL hijacking) is the next
genuine capability win, and unlike the two before it, it is analysis work rather than enumeration.
