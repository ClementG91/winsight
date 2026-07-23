# WFP enforcement — runtime validation, x64

> [!WARNING]
> **Historical observation only — not a production qualification gate.** This run used
> `Test-WfpValidation.ps1` revision `76b5481`. Its reported **18/18** is invalid as strict evidence:
> that revision could accept mixed WFP state, skip a path-trust probe whose staging failed, ignore
> native failures or hide visible native output, and observe a pre-existing service registered to a different
> binary. The transcript still records useful x64 behavior, but no corrected candidate-bound x64 or
> native Arm64 rerun has occurred.

CI cannot cover the part of the firewall that reaches WFP through P/Invoke and cuts real traffic.
This file therefore preserves what the 2026-07-23 run printed, including its limitations, rather
than retroactively presenting it as evidence produced by the stricter current protocol.

## What was run

- **Date:** 2026-07-23
- **Architecture:** x64
- **Binaries:** the published `winsight-v0.10.2-win-x64` release, deployed to
  `C:\Program Files\WinSight-VM`. The enforcement code (`WfpProvisioning.cs`,
  `EnforcementCoordinator.cs`) was reported byte-identical from `v0.10.2` through commit `b3d04e4`.
  The old script did not, however, bind the live SCM registration to this exact binary, so that
  source comparison cannot establish which candidate the native observations exercised.
- **Host:** clean Windows VM (VirtualBox), Windows PowerShell 5.1, elevated console.
- **Script:** `scripts/Test-WfpValidation.ps1` revision `76b5481`, full protocol (no
  `-SkipEnforcement`).
- **Arming:** performed through the real elevated dashboard → authenticated IPC → service, exactly as
  recorded by the operator. The old protocol did not prove the service/candidate binding.

## Useful observations in the historical transcript

The old script printed **18/18**. That count is retained as historical output, not treated as a
strict verdict. The useful observations it records are:

- **`the target reads as blocked`** and **`blocked app cannot reach the network`** — a per-app WFP
  block filter was created and it actually stops that program's traffic (http 000 where the baseline
  was 200).
- **`an unblocked copy still reaches the network`** — the single most important line. A second,
  unblocked copy of curl still reached the network, so the block is **scoped to the one application**,
  not a machine-wide cut. If this had failed while the blocked leg passed, that would have been a
  defect, not a success.
- The transcript printed **`WFP provider and sublayer exist`** while armed and **`all WFP state
  removed`** after emergency disable. Its old token predicates did not prove the exact
  provider/sublayer/permit tuple, so this record does **not** establish full teardown or the absence
  of orphaned WinSight objects.
- The transcript also printed **`the target reaches the network again`** and **`uninstall leaves no
  service`**. Those observations are useful, but without exact WFP state and SCM candidate binding
  they do **not** prove restoration to the machine's exact prior state.
- The read-only and boundary halves also passed: the WFP engine opens, direct command-line mutation is
  refused, and installation from a user-writable path printed the generic
  `[FW_INSTALL_FAILED]`. The old output did not prove which path-trust rule denied it.

Those observations do not repair the old predicate/evidence gaps. In particular, the transcript
does not contain the exact parsed provider/sublayer/permit tuple, every native exit code with visible
normalized output, mandatory probe-staging proof, or an SCM `PathName` bound to the requested
candidate.

## What this does NOT cover

- **Arm64.** These binaries are x64. Emulated-x64 app-id behaviour and Arm64 struct marshalling remain
  open — see [`ARM64_VALIDATION.md`](../ARM64_VALIDATION.md).
- **The adversarial TOCTOU race** on service-path trust (WFP_DESIGN.md) is a separate, narrower
  validation and is not exercised here.
- **`NOT_RUN`/`BLOCKED`: strict candidate qualification.** The corrected protocol has not run on a
  clean x64 VM or native Arm64 VM. Real SCM/WFP, owner/DACL/nested-reparse/live-TOCTOU, connectivity
  and EN/FR/ES human-presentation gates also remain blocked; this historical transcript closes none
  of them.

## Reproduce

```powershell
$candidate = 'C:\Program Files\WinSight-VM'
$service = Join-Path $candidate 'winsight-firewall-service.exe'
$protocol = Join-Path $candidate 'Test-WfpValidation.ps1'

# Non-privileged contract checks. The negative control must fail with exit 1.
& $protocol -ContractSelfTest
& $protocol -ContractSelfTest -ContractNegativeControl

# VM-only pre-arm qualification: no WFP arming, but SCM is installed, started, stopped and removed.
& $protocol -ServicePath $service -SkipEnforcement

# Full strict protocol, only on a clean VM snapshot.
& $protocol -ServicePath $service
```

These commands describe the corrected candidate-bound protocol; they do not reproduce or upgrade
the historical 18/18 below. `-SkipEnforcement` is not machine-read-only, and success requires its
mandatory bounded stop/uninstall/SCM-absence cleanup. The current script never reaches the arm prompt
after a failed pre-arm/baseline gate and forbids uninstall when AuditOnly, exact WFP absence or
restored connectivity is unproven. Its displayed native output is normalized (`ErrorRecord` message,
`Out-String`, trimmed/prefixed lines) and remains paired with the exit code rather than preserving
the original native byte stream.

The final normal non-privileged `ContractSelfTest` passes **24/24**, and its deliberate
lifecycle-order negative control exits **1**. The former 14/14 and the first local report based on it
are invalid, non-qualifying evidence; the intermediate 15/15 was a transient development count, not
proof. VM skip/full flows still require exactly **16**/**25** checks. One
`New-ValidationAdapter` owns command construction, staging, workflow operations and the Running,
Stopped and SCM-absent polls. Real and scripted modes inject only elementary host effects. The
scripted effects consume a closed exact ordered queue and reject unexpected paths, arguments, order,
cardinality or result types; they expose no fake business poll. Their matrices drive all three
lifecycle polls through the production adapter, including delayed success, timeout, exact
ten-attempt bounds and rollback/uninstall ordering. Effects return zero success objects and
decisions exactly one value of the expected type.

The corrected path-trust check creates only an empty `user-writable-sentinel.exe` data file, then
asks the protected candidate to inspect it with `install-path-trust-check <sentinel>`. It never
executes or loads a staged service or DLL. The protected candidate is therefore an operator-provided
trust-root prerequisite whose provenance, protected deployment and immutable dependencies must be
established separately; the probe is not self-proof, and it does not impose an invented ProgramData
location rule on the executable.

The public `FirewallServiceCommandHost.Execute` route is also the route called exactly once by
`Program`; it owns parsing, routing, probe arity, result mapping and stdout/stderr selection. Its
probe handler receives only an `IServicePathTrustInspector` and cannot access install or SCM/WFP
capabilities. Portable tests call that public route directly for trusted, all eight denials,
invalid-arity and unexpected failures. A non-privileged invalid-arity subprocess smoke traverses the
real `Program` root and returns exact inspection-failed stderr/exit 1 without filesystem inspection
or machine mutation. These portable results do not promote the historical transcript or a native
gate.

All elevated OS tools are resolved by absolute protected System32 paths: `sc.exe`, `curl.exe` and
`WindowsPowerShell\v1.0\powershell.exe`; ambient `PATH` is not used. System32 curl is the target and
Windows PowerShell is an independent HTTP control. Both must return `200`/exit 0 before arming and
after rollback; only curl may return `000`/non-zero while blocked, while the control remains
`200`/exit 0. Service Running, Stopped and absent states are established through bounded injected
polling, not a fixed sleep.

The exact accepted output shapes include:

```text
Persisted desired enforcement mode: <AuditOnly|Enforcement>. Effective runtime state: unknown (query the authenticated running service).
WFP engine opened. Existing filters visible: <non-negative integer>. Read-only: no filter, provider or sublayer was added or changed.
[FW_APP_BLOCKED]
```

Direct mutation must return exactly `[FW_DIRECT_MUTATION_DISABLED]` with exit 1. The immediate
post-refusal inventory must return exit 0 and exactly:

```text
WinSight WFP provider: absent, sublayer: absent, permit-filter: absent. Per-app blocks are queried with wfp-block-status <path>.
```

## Portable evidence: the protocol was broken on purpose

A passing count proves nothing until the thing it measures has been broken deliberately. The earlier
correction attempt failed review precisely because two mutations left every gate green. Each mutation
below was applied to the source, measured, and reverted. All of them are non-privileged and replayable
on any machine with the SDK -- no VM, no elevation, no SCM or WFP.

| Mutation applied | Measured result |
|---|---|
| `PollStopped` replaced by a constant `$true` | contract 24 checks, 8 failures, exit 1 |
| adapter `$scPath` downgraded to ambient `sc.exe` | 24 checks, 11 failures, exit 1 |
| absence poll queries a different service name | 24 checks, 8 failures, exit 1 |
| uninstall moved above the Stopped poll | 24 checks, 8 failures, exit 1 |
| `install-path-trust-check` verb routed to Install | 20 failures / 321 firewall-service tests |
| refusal written to stdout instead of stderr | 28 failures / 321 |
| refusal exit code changed from 1 to 0 | 28 failures / 321 |
| the eight distinct denial codes collapsed into one | 14 failures / 321 |

The last four are the ones that matter for a security boundary: a refusal that reaches stdout, or
exits 0, or loses its reason, is a refusal a caller can mistake for success. The third row is the
quietest and the worst -- querying the wrong service name makes the post-uninstall check report
"absent" while a real SYSTEM service is still installed.

After restoring every mutation: contract 24/24 exit 0, its deliberate negative control exit 1,
Release build 0 warnings and 0 errors, and 1,472/1,472 tests across 22 projects. The coverage gate
passes with engine libraries at 87.9% (every engine at or above 80%) and overall production at 73.0%.
`winsight-firewall-service` sits at 53.6% and remains the least-covered assembly that runs as SYSTEM.

This is portable evidence only. It does not promote the historical transcript below, and it closes
none of the native or privileged gates listed above.

## Transcript

The following block is preserved as emitted by the older script and must not be read as a current
strict PASS.

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
