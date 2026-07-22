# WFP enforcement — runtime validation, x64

**This is the artifact that answers "was the firewall actually validated?" with something a third
party can read, not a recollection.** CI cannot cover the part of the firewall that reaches WFP
through P/Invoke and cuts real traffic; `scripts/Test-WfpValidation.ps1` runs that protocol on a VM
and prints a verdict per step. This file records one such run in full.

## What was run

- **Date:** 2026-07-23
- **Architecture:** x64
- **Binaries:** the published `winsight-v0.10.2-win-x64` release, deployed to
  `C:\Program Files\WinSight-VM`. The enforcement code (`WfpProvisioning.cs`,
  `EnforcementCoordinator.cs`) is byte-identical from `v0.10.2` through commit `b3d04e4`
  (`git log v0.10.2..b3d04e4 -- <those files>` is empty), so this run validates the current
  enforcement path, not a superseded one.
- **Host:** clean Windows VM (VirtualBox), Windows PowerShell 5.1, elevated console.
- **Script:** `scripts/Test-WfpValidation.ps1` at `main`, full protocol (no `-SkipEnforcement`).
- **Arming:** performed through the real elevated dashboard → authenticated IPC → service, exactly as
  a user arms it. The one step the protocol deliberately does not automate.

## What it proves

Every check passed — **18/18**. The load-bearing ones:

- **`the target reads as blocked`** and **`blocked app cannot reach the network`** — a per-app WFP
  block filter was created and it actually stops that program's traffic (http 000 where the baseline
  was 200).
- **`an unblocked copy still reaches the network`** — the single most important line. A second,
  unblocked copy of curl still reached the network, so the block is **scoped to the one application**,
  not a machine-wide cut. If this had failed while the blocked leg passed, that would have been a
  defect, not a success.
- **`WFP provider and sublayer exist`** while armed, and **`all WFP state removed`** after emergency
  disable — the owned WFP namespace is created on arm and fully torn down on rollback, leaving nothing
  orphaned.
- **`the target reaches the network again`** after rollback, and **`uninstall leaves no service`** —
  the machine returns exactly to its prior state.
- The read-only and boundary halves also passed: the WFP engine opens, direct command-line mutation is
  refused, and installation from a user-writable path is refused (`[FW_INSTALL_FAILED]`).

## What this does NOT cover

- **Arm64.** These binaries are x64. Emulated-x64 app-id behaviour and Arm64 struct marshalling remain
  open — see [`ARM64_VALIDATION.md`](../ARM64_VALIDATION.md).
- **The adversarial TOCTOU race** on service-path trust (WFP_DESIGN.md) is a separate, narrower
  validation and is not exercised here.

## Reproduce

```powershell
# read-only half, safe on any machine (arms nothing):
./scripts/Test-WfpValidation.ps1 -ServicePath '<deployed>\winsight-firewall-service.exe' -SkipEnforcement
# full protocol, on a VM with a snapshot:
./scripts/Test-WfpValidation.ps1 -ServicePath '<deployed>\winsight-firewall-service.exe'
```

## Transcript

```
== Preconditions ==
  [PASS] console is elevated
  [PASS] service binary exists

  NOTE: take a VM snapshot before continuing. Enforcement really does cut traffic for
        one process. Everything is reversible, but a snapshot means never having to
        trust that.

== Service lifecycle ==
  [PASS] service reaches RUNNING
  [PASS] starts in audit-only

== Path trust boundary ==
  > install from a user-writable path
    [FW_INSTALL_FAILED]
  [PASS] install refused from a user-writable path

== WFP engine, read-only ==
  [PASS] WFP engine opens
  [PASS] no WFP state before arming
  [PASS] direct WFP mutation is refused

== Enforcement -- manual gate ==
  [PASS] target reaches the network before blocking

  ACTION REQUIRED -- this cannot be automated by design.
  Mutating policy requires authenticated IPC, so do this in an ELEVATED dashboard:
    1. Outbound firewall -> Start analysis
    2. Block an app...   -> C:\curltest\curl.exe
    3. Enable enforcement -> confirm

  Press Enter once enforcement is enabled:

  [PASS] enforcement is persisted
  [PASS] WFP provider and sublayer exist
  [PASS] the target reads as blocked
  [PASS] blocked app cannot reach the network
  [PASS] an unblocked copy still reaches the network

== Rollback ==
  ACTION REQUIRED: dashboard -> Emergency disable
  Press Enter once emergency disable has completed:

  [PASS] back to audit-only
  [PASS] all WFP state removed
  [PASS] the target reaches the network again

== Clean up ==
  [PASS] uninstall leaves no service

== Result ==
  18 checks, 0 failure(s).
```
