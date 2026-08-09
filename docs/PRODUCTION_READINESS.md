# Production readiness

This is the authoritative status as of 2026-08-09. Evidence is candidate-bound: a successful result
for one commit or package does not automatically qualify a later one. The current AC109 candidate
changes named-pipe ownership/admission, service-listener lifecycle and privileged policy storage
concurrency. A local pre-publish x64 package passed the isolated-VM gates recorded below, but it is
not an immutable CI or release artifact. The earlier privileged evidence was gathered against
historical candidate `3ad4b92`; see
[Current AC109 candidate delta](#current-ac109-candidate-delta).

| Target | Verdict |
|---|---|
| **x64** | **Not production-ready** - the AC109 local package passed installer, trust, IPC and hostile-listener VM gates, but exact release-artifact CI/CodeQL, full WFP enforcement, literal Network Logon and human review remain open |
| **Arm64 (native)** | **Not production-ready** - native CI build/package/installer passed for `3ad4b92`; privileged WFP/SCM/trust/IPC/session behavior remains unverified |
| **x64 on Arm64** | **Not production-ready** - emulated application identity and privileged runtime behavior remain unverified |

## Current x64 evidence

Candidate:

- commit `3ad4b92d0b9a6ebc6ab0b99b082e2a0c4569f327`;
- CI run `30536205557`, successful for verify and native x64/Arm64 package/installer jobs;
- CodeQL run `30536201742`, successful;
- clean Windows 11 native-x64 VM campaign supplied on 2026-07-30;
- sealed VM manifest: 46 entries, SHA-256
  `20e3b8f8651923f9b09dda1db7eeba5210726cba5651bbf1d9ea4bea97cc63e3`.

The supplied VM campaign confirmed:

- ETW session names bind profile, PID and process-start identity;
- closing the dashboard with **X** keeps the tray process and its live session by design;
- forced termination leaves an orphan, and relaunch reclaims it without deleting another live
  instance's session;
- repeated Attribution cycles remain bounded by live dashboard instances;
- tray Exit releases Attribution sessions;
- DNS kill/relaunch recovery works and Ctrl+C exits 0 with cleanup;
- an Outbound service restart reclaims the old service session;
- no `.NET Runtime` event 1026 occurred during the qualification window;
- the former `0x800705AA` ETW exhaustion crash did not recur;
- WFP full gate 25/25, trust 12/12, installer lifecycle and final SCM/WFP/connectivity cleanup passed.

Full supplied-result classification:
[`validation/2026-07-30-x64-qualification-3ad4b92.md`](validation/2026-07-30-x64-qualification-3ad4b92.md).

## Why x64 is still not production-ready

Three protocol gaps prevented a complete campaign:

1. **IPC default-path drift.** The shipped probe still defaulted to the obsolete
   `C:\Program Files\WinSight-VM` root. The gate passed 7/7 only when the operator supplied the
   protected CLI path explicitly. The corrected probe derives both binaries from its own package
   directory, and the runbook still passes the paths explicitly. This correction needs a new
   candidate-bound package and VM rerun.
2. **Network Logon was `NOT_RUN`.** A real Network token proved pipe denial under impersonation, but
   that was not the literal process-level protocol. The corrected runbook requires a second isolated
   control machine and WinRM. The probe itself fails unless `S-1-5-2` is present, `S-1-5-4` is absent,
   the self-test returns exit 3 / `ServiceUnavailable` / no mutation, and the same SCM process and
   command remain running.
3. **S0/S1/S2 were `NOT_RUN`.** Snapshot take/restore is an authority of the hypervisor host;
   `VBoxManage` is not expected inside the guest. The corrected runbook labels host-only operations,
   records `showvminfo` evidence outside the VM disk, and makes the guest stop when that evidence is
   missing.

The following independent gates also remain open:

- native Arm64 privileged WFP/SCM/trust/IPC/session qualification;
- x64-on-Arm64 application-identity qualification;
- independent human EN/FR/ES review for the exact candidate;
- a new exact-candidate CI, CodeQL, package/installer and clean-VM rerun after the protocol changes.

## Historical candidate delta review, v0.11.0 and v0.11.1

Evidence here is candidate-bound, so a release after `3ad4b92` requires this section rather than
letting the statement above age into an implied pass for code it never covered.

**What changed:** autostart command-line triage and scheduled-task argument capture, both in the
unprivileged detection engine; three presentation paths that render a persistence verdict; and the
MCP server's tool, prompt and resource surface.

**v0.11.1 on top of that** changed one MCP tool's description string, a count in `README.md`, and
tests. No behaviour, and nothing outside the unprivileged process. The review below therefore covers
both candidates without weakening: a smaller delta over the same surface cannot reopen a gate the
larger one left closed.

**What it touched at that historical point:** nothing on the privileged boundary. For the v0.11.1
candidate reviewed here, the WFP engine, SCM lifecycle, service-path trust check and authenticated
named-pipe IPC were byte-identical to their recorded predecessors. That statement does not apply to
the current AC109 candidate, which changes the named-pipe and policy-store implementation.

**What it does not change:** the verdict. All three targets remain **not production-ready** for
exactly the reasons above. The three x64 protocol gaps, native Arm64 privileged behaviour and
x64-on-Arm64 identity are all still open, and native Arm64 is blocked on hardware the project does
not have rather than on unwritten work.

**What was verified for this candidate:** the full suite on x64 including the packaged MCP stdio
contract, the engine-library and privileged-managed coverage gates, and formatting. Native Arm64
build, packaging and installer lifecycle run in CI on a native runner as usual; the Arm64 *privileged
runtime* remains `NOT_RUN`.

## Current AC109 candidate delta

AC109 replaces the fixed named-pipe accept pool with successor-before-dispatch ownership, separates
bounded read and machine-policy-mutation admission, makes unexpected listener/handler loss terminal,
awaits readiness as a lifecycle signal, and serializes complete policy-store load/save operations.
An x64 VM then exposed an overlapped-accept race: a peer that vanished before Windows completed
`WaitForConnectionAsync` produced a per-instance `IOException` and stopped the service. The listener
now posts that failed instance's successor before closing it; creation and security failures remain
terminal. Diagnostics classify listener failures with fixed redacted categories and never log the
exception object or its message. The corrected diagnostic build survived 25 hostile rounds (150
silent peers, 150 parallel valid clients — 25 served and 125 explicitly unavailable under deliberate
same-privilege lane saturation — and 625 abrupt closes), emitted no listener-failure event, and
cleaned up to SCM 1060 with WFP empty.
The current dashboard is v3-only while the service retains legacy replies for older clients. Trusted
loads retry a concurrent path-identity replacement only twice from a fresh inspection; every other
trust failure remains fail-closed. Endpoint loss closes pipes, drains for two seconds, then arms an
eight-second watchdog before fallible diagnostics or graceful-stop calls. On expiry it invokes
`FailFast` with a fixed code, bypassing `ProcessExit` handlers/finalizers rather than promising exit
code 1. Requested shutdown arms the same watchdog silently after the listener returns; normal process
exit removes the background thread, while stuck privileged teardown remains bounded. These are
security and availability changes inside the LocalSystem service boundary, not a docs-only or
unprivileged delta.

The full local x64 package was then rebuilt from the corrected source. On the clean Windows 11 x64
VM it passed native PE and installer install/uninstall, MCP stdio, dashboard smoke tests in EN/FR/ES,
protected-path trust, the 26/26 WFP protocol contract plus its one-failure negative control, 16/16
pre-arm cleanup, the 12/12 hostile-account trust boundary, LocalSystem SCM binding and the 7/7
elevated/restricted IPC boundary. The packaged service repeated the 25 hostile rounds above with the
same 150 silent, 150 valid and 625 abrupt-client counts, no listener-failure event, WFP empty and SCM
1060 after cleanup. The VM was then powered off and restored to its named clean snapshot.

This is strong local pre-publish evidence, but it does not qualify bytes that CI has not built and
attested yet. Before the release can be treated as production-ready, the immutable release artifact
still requires green CI and CodeQL, the full 25/25 WFP enforcement transition, the literal Network
Logon scenario and independent human review. Native Arm64 CI continues to build, test and run the
installer on GitHub's native runner; privileged Arm64 WFP/SCM/session qualification and x64-on-Arm64
identity remain blocked on suitable hardware. Until those records exist, all targets remain
**not production-ready**.

## Authenticode policy

Public binaries have no Authenticode publisher certificate. SignPath Foundation declined the free
application on 2026-07-29 because public adoption signals were insufficient. The current repository
policy is therefore deliberately `REQUIRE_SIGNED_RELEASE=false`.

This is an accepted and visible distribution limitation, not a passed security gate:

- Windows displays an unknown publisher;
- the four release targets must report `NotSigned`, with no signer or timestamp;
- users must verify SHA-256 checksums and GitHub provenance/SBOM attestations;
- the workflow fails if the signing-policy variable is absent or malformed;
- unsigned policy forces `-DisableSignature`, so residual credentials cannot sign opportunistically;
- the optional signed path remains available for a future certificate and requires full
  publisher/timestamp verification when re-enabled.

Unsigned distribution does not by itself make the product production-ready or unsafe; it removes
Windows publisher identity and shifts artifact authentication to explicit hash and provenance checks.

## Required next qualification

Use [`validation/VM_QUALIFICATION_KIT.md`](validation/VM_QUALIFICATION_KIT.md) from the exact new
package:

1. bind commit, successful CI run, architecture and both artifact hashes;
2. create and record S0 from the hypervisor host;
3. install prerequisites in the guest and construct the protected candidate root;
4. record the expected unsigned status and run the installer/integrity gates;
5. restore S0 from the host, recreate the protected candidate and record S1;
6. run ETW lifecycle gates, then WFP 25/25, trust 12/12 and local IPC 7/7 from separate S1 restores;
7. create S2 on the host before full WFP and prove every restore from the host;
8. while the AuditOnly service is running, run Network Logon 10/10 from a second isolated machine;
9. seal manifests outside the VM disk, restore S0 from the host and verify final absence.

Only a complete evidence set for the exact candidate can change the verdict above.
