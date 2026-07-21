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
| **ReiKey** | Keyboard event-tap (keylogger) detection | *(none)* | **Missing** — the clearest capability gap. |
| **DHS** | Dylib hijack scanner | **Modules scan** flags unsigned/untrusted loaded modules | **Partial** — no DLL search-order/phantom-DLL analysis. |
| **KextViewr** | Kernel extension viewer | *(none)* | **Missing** — no loaded-driver enumeration. |
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

### 2. Keylogger / input-hook detection (ReiKey-class)
No coverage at all, and it is a classic, cheap-to-implement attack surface on Windows:
low-level keyboard hooks (`SetWindowsHookEx` with `WH_KEYBOARD_LL`), raw-input registrations, and
hook DLLs injected across processes. Detection is enumerable from user mode. High value, no
elevation, fits the existing scanner shape (a new `WinSight.InputHooks` project and one catalog
entry).

### 3. Loaded kernel drivers (KextViewr-class)
Unsigned or unexpected kernel drivers are exactly what a rootkit leaves behind, and WinSight lists
none of them. Enumerable via the service control manager and `EnumDeviceDrivers`, verdicts through
the existing Authenticode path. Reuses everything the persistence scanner already does.

### 4. DLL hijacking scan (DHS-class)
Extend the modules work into a real search-order analysis: writable directories ahead of system
ones on a process's search path, and phantom DLLs (imported-but-absent) that an attacker can drop
in. Higher analysis effort than #2 and #3; build after them.

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

Beating Objective-See on Windows is not a checklist race. WinSight is already at parity on the five
tools that matter most (persistence × 2, firewall, ransomware, camera/mic) while being one app
instead of six. What actually separates it from "a set of scanners" is **#1**: naming the process
behind a detection. Items #2 and #3 are the next-cheapest genuine capability wins.
